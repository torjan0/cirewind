package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func TestBuildGraphV2DoesNotMutateFrozenGraph(t *testing.T) {
	revisionID := "frev1:" + strings.Repeat("1", 64)
	evidenceID := "ev1:" + strings.Repeat("2", 64)
	legacy := graph.Graph{
		SchemaVersion: graph.SchemaVersion,
		Nodes: []graph.Node{{
			ID: "repository", Type: graph.NodeRepository, Label: "example/repository",
			EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID},
		}},
		Edges: []graph.Edge{},
	}
	finding := report.Finding{
		FindingRevisionID: revisionID,
		State:             string(model.CurrentReferenceOnly),
		Provenance:        string(model.L1Possible),
		Repository:        "example/repository",
		Workflow:          ".github/workflows/test.yml",
		IndicatorID:       "synthetic-indicator",
	}
	before, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildGraphV2(index{}, legacy, []report.Finding{finding}, nil, report.CaseKindSynthetic); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("v0.2 projection mutated the frozen v1 graph")
	}
}

func TestDependencyDefinitionBasisSplitsFrozenEdgeWithoutUsingFindingState(t *testing.T) {
	t.Parallel()
	caller := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("1", 40)})
	target := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("2", 40)})
	repository := model.RepositorySlug("example/repository")
	makeFact := func(basis archive.DefinitionBasis, evidenceDigit string) archive.Fact {
		return archive.Fact{
			Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{model.EvidenceID("ev1:" + strings.Repeat(evidenceDigit, 64))},
			Dependency: &archive.DependencyFact{
				Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: basis,
				CallerRepositoryID: 1, CallerRepository: repository, CallerPath: ".github/workflows/ci.yml", CallerWorkflowObjectID: &caller,
				TargetRepository: repository, TargetActionObjectID: &target, ContradictsFactIDs: []string{}, EventTime: unknownTime(),
			},
		}
	}
	historical := makeFact(archive.DefinitionHistoricalAtRun, "a")
	current := makeFact(archive.DefinitionCurrentSnapshot, "b")
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	builder.projectDependency(index{}, historical, "", false)
	builder.projectDependency(index{}, current, "", false)
	if len(builder.edges) != 1 {
		t.Fatalf("frozen v1 graph did not aggregate the same proposition: %d edges", len(builder.edges))
	}
	var legacy graph.Edge
	for _, edge := range builder.edges {
		legacy = edge
	}
	if legacy.DerivationRule != "" || legacy.Inferred {
		t.Fatalf("frozen v1 edge was changed: %#v", legacy)
	}
	classified := classificationsForEdge(index{dependencies: []archive.Fact{historical, current}}, legacy)
	if len(classified) != 2 {
		t.Fatalf("v2 did not split current and historical bases: %#v", classified)
	}
	want := map[string]string{
		graph.DefinitionBasisHistoricalAtRunRule: "ev1:" + strings.Repeat("a", 64),
		graph.DefinitionBasisCurrentSnapshotRule: "ev1:" + strings.Repeat("b", 64),
	}
	for _, value := range classified {
		if value.class != graph.EvidenceClassExactObservation || len(value.evidenceIDs) != 1 || want[value.rule] != value.evidenceIDs[0] {
			t.Fatalf("incorrect definition-basis classification: %#v", value)
		}
	}
}

func TestFindingIndexRequiresExactMechanicalCoverageClosure(t *testing.T) {
	repository := model.RepositorySubject{ID: 1, Name: model.RepositorySlug("fixture/repository")}
	runID := model.WorkflowRunID(42)
	attempt := model.RunAttempt(2)
	jobID := model.JobID(20)
	scope := model.CoverageScope{RepositoryID: ptr(repository.ID), RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	one := uint64(1)
	jobLogID := model.CoverageAssessmentID("cova1:" + strings.Repeat("a", 64))
	grammarID := model.CoverageAssessmentID("cova1:" + strings.Repeat("b", 64))
	coverageFact := func(kind model.CoverageKind, id model.CoverageAssessmentID, valueScope model.CoverageScope) archive.Fact {
		return archive.Fact{Kind: archive.FactCoverage, Coverage: &archive.CoverageFact{
			Unit:       model.CoverageUnit{Kind: kind, Scope: valueScope, RequiredForNegative: true},
			Assessment: model.CoverageAssessment{ID: id, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1},
		}}
	}
	validCoverage := []archive.Fact{
		coverageFact(model.CoverageJobLog, jobLogID, scope),
		coverageFact(model.CoverageParserGrammar, grammarID, scope),
	}
	baseFinding := report.Finding{
		FindingRevisionID: "frev1:" + strings.Repeat("b", 64),
		State:             string(model.NoMatchConfirmed),
		Provenance:        string(model.L4Certain),
		Repository:        string(repository.Name),
		Workflow:          ".github/workflows/demo.yml",
		IndicatorID:       "fixture-indicator",
		RunID:             int64(runID), RunAttempt: int(attempt), JobID: int64(jobID),
		CollectionCoverage: []string{string(jobLogID), string(grammarID)},
	}
	baseIndex := index{repositories: map[model.RepositoryID]model.RepositorySubject{repository.ID: repository}, coverage: validCoverage}

	valid := buildFindingIndex(baseIndex, []report.Finding{baseFinding}, nil)[0]
	if !valid.CoverageClosed {
		t.Fatal("exact mechanical coverage closure was not projected")
	}

	tests := []struct {
		name   string
		idx    index
		mutate func(*report.Finding)
	}{
		{name: "missing required capability", idx: index{repositories: baseIndex.repositories, coverage: validCoverage[:1]}},
		{name: "swapped coverage IDs", idx: baseIndex, mutate: func(finding *report.Finding) {
			finding.CollectionCoverage[0], finding.CollectionCoverage[1] = finding.CollectionCoverage[1], finding.CollectionCoverage[0]
		}},
		{name: "unrelated coverage ID", idx: baseIndex, mutate: func(finding *report.Finding) {
			finding.CollectionCoverage[1] = "cova1:" + strings.Repeat("c", 64)
		}},
		{name: "wrong scope", idx: func() index {
			wrongJob := model.JobID(21)
			wrongScope := scope
			wrongScope.JobID = &wrongJob
			return index{repositories: baseIndex.repositories, coverage: []archive.Fact{
				coverageFact(model.CoverageJobLog, jobLogID, wrongScope),
				coverageFact(model.CoverageParserGrammar, grammarID, wrongScope),
			}}
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := baseFinding
			finding.CollectionCoverage = append([]string(nil), baseFinding.CollectionCoverage...)
			if test.mutate != nil {
				test.mutate(&finding)
			}
			candidate := buildFindingIndex(test.idx, []report.Finding{finding}, nil)[0]
			candidate.ExactKnownGood = true
			candidate.ExactIdentityKind = graph.ExactIdentityActionCommitSHA
			candidate.ExactIdentity = "sha1:" + strings.Repeat("0", 40)
			if candidate.CoverageClosed {
				t.Fatal("malformed NO_MATCH projected closed coverage")
			}

			firstAttempt := model.RunAttempt(1)
			anchor := graph.FindingIndexEntry{
				FindingRevisionID: "frev1:" + strings.Repeat("a", 64), State: model.ConfirmedExecuted, ProvenanceLevel: model.L4Certain,
				Repository: candidate.Repository, WorkflowPath: candidate.WorkflowPath, IndicatorID: candidate.IndicatorID,
				RunID: &runID, RunAttempt: &firstAttempt, ExactIdentityKind: graph.ExactIdentityActionCommitSHA, ExactIdentity: "sha1:" + strings.Repeat("1", 40),
			}
			if graph.IsKnownGoodComparison(anchor, candidate) {
				t.Fatal("malformed NO_MATCH entered the known-good comparison predicate")
			}
			path, err := graph.BuildTemporalEvidencePath(context.Background(), graph.GraphV2{
				SchemaVersion: graph.SchemaVersionV2, CaseKind: graph.CaseKindSynthetic,
				FindingIndex: []graph.FindingIndexEntry{anchor, candidate}, Nodes: []graph.NodeV2{}, Edges: []graph.EdgeV2{}, ProjectionNotices: []graph.ProjectionNotice{},
			}, graph.PathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, lane := range path.Lanes {
				if lane.Finding.FindingRevisionID == candidate.FindingRevisionID {
					t.Fatal("malformed NO_MATCH entered the temporal comparison lane")
				}
			}
		})
	}
}

func TestBuildGraphV2AddsOnlyNarrowPendingEnvironmentTarget(t *testing.T) {
	revisionID := "frev1:" + strings.Repeat("1", 64)
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("2", 64))
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	finding := report.Finding{
		FindingRevisionID: revisionID,
		State:             string(model.RunInWindowMutableRef),
		Provenance:        string(model.L2Probable),
		Repository:        "example/repository",
		Workflow:          ".github/workflows/test.yml",
		IndicatorID:       "synthetic-indicator",
		RunID:             10,
		RunAttempt:        1,
		JobID:             20,
		EvidenceIDs:       []string{string(evidenceID)},
	}
	base := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{
			1: {ID: 1, Name: model.RepositorySlug("example/repository")},
		},
		jobs: map[string]archive.JobFact{
			execution.String(): {Execution: execution, Status: "waiting"},
		},
		exposures: []archive.Fact{{
			Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID},
			Exposure: &archive.ExposureFact{
				Execution: execution,
				Environment: &archive.EnvironmentEligibilityFact{
					EnvironmentName: "production", GateState: "pending", JobStarted: false, SecretNames: []model.SecretName{},
				},
				EventTime: unknownTime(),
			},
		}},
	}
	project := func(t *testing.T, idx index) graph.GraphV2 {
		t.Helper()
		result, err := buildGraphV2(idx, graph.Graph{SchemaVersion: graph.SchemaVersion}, []report.Finding{finding}, nil, report.CaseKindSynthetic)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	result := project(t, base)
	var targeted, crossed, eligible int
	for _, edge := range result.Edges {
		switch edge.Type {
		case graph.EdgeTargetedEnvironment:
			targeted++
		case graph.EdgeEnvironmentGateSatisfied:
			crossed++
		case graph.EdgeEnvironmentSecretEligible:
			eligible++
		}
	}
	if targeted != 1 || crossed != 0 || eligible != 0 {
		t.Fatalf("pending environment edges targeted/crossed/eligible=%d/%d/%d", targeted, crossed, eligible)
	}
	for _, edge := range result.Edges {
		if edge.Type == graph.EdgeTargetedEnvironment &&
			(edge.EvidenceClass != graph.EvidenceClassInference || edge.DerivationRule != graph.EnvironmentTargetPendingRule) {
			t.Fatalf("pending target used an unsupported evidence basis: %#v", edge)
		}
	}

	started := base
	started.jobs = map[string]archive.JobFact{execution.String(): {Execution: execution, Status: "completed", Conclusion: "success"}}
	started.exposures = append([]archive.Fact(nil), base.exposures...)
	startedExposure := *started.exposures[0].Exposure
	startedEnvironment := *startedExposure.Environment
	startedEnvironment.GateState = "crossed"
	startedEnvironment.JobStarted = true
	startedExposure.Environment = &startedEnvironment
	started.exposures[0].Exposure = &startedExposure
	for _, edge := range project(t, started).Edges {
		if edge.Type == graph.EdgeTargetedEnvironment || edge.Type == graph.EdgeEnvironmentGateSatisfied || edge.Type == graph.EdgeEnvironmentSecretEligible {
			t.Fatalf("non-executed finding gained started environment edge %s", edge.Type)
		}
	}

	withLifecycle := base
	withLifecycle.actions = []archive.Fact{{ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
		Execution: execution,
		Kind:      model.ObservationLifecycleStarted,
	}}}}
	for _, edge := range project(t, withLifecycle).Edges {
		if edge.Type == graph.EdgeTargetedEnvironment {
			t.Fatal("pending environment target was added despite an execution lifecycle observation")
		}
	}
}

func TestCredentialClassificationJoinsExactPropositionEndpoints(t *testing.T) {
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("3", 64))
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	credential := func(permission string, basis model.CredentialExposureBasis) model.CredentialExposure {
		return model.CredentialExposure{
			Kind: model.ExposureGitHubTokenPermission, Basis: basis,
			Permission: permission, Access: "write", Conclusion: "bounded fixture capability",
			EvidenceIDs: []model.EvidenceID{evidenceID},
		}
	}
	exact := credential("contents", model.ExposureBasisRuntimeObserved)
	unrelated := credential("actions", model.ExposureBasisStaticInferred)
	exposure := func(value model.CredentialExposure) archive.Fact {
		return archive.Fact{Exposure: &archive.ExposureFact{Execution: execution, Credential: &value, EventTime: unknownTime()}}
	}

	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	jobNode := builder.jobNode(execution, []string{string(evidenceID)}, "")
	builder.projectCredential(exact, jobNode, jobNode, false, unknownTime(), "")
	var edge graph.Edge
	for _, candidate := range builder.edges {
		if candidate.Type == graph.EdgeHadTokenPermission {
			edge = candidate
		}
	}
	if edge.ID == "" {
		t.Fatal("fixture failed to project token edge")
	}

	classes := credentialClassifications(index{exposures: []archive.Fact{exposure(exact), exposure(unrelated)}}, edge)
	if len(classes) != 1 || classes[0].class != graph.EvidenceClassExactObservation || classes[0].rule != "" || classes[0].omit {
		t.Fatalf("unrelated permission contaminated edge classification: %#v", classes)
	}
}

func TestRetainedV1CredentialBasisPreservesFindingAndOmitsOnlyUnclassifiableEdge(t *testing.T) {
	t.Parallel()
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.ValidateReader(context.Background(), bytes.NewReader(bundle.PackYAML))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Derive(bundle.Snapshot, pack, bundle.AnalysisTime, ModeReplay)
	if err != nil {
		t.Fatal(err)
	}

	for _, basis := range []model.CredentialExposureBasis{"", "removed-basis-v0"} {
		t.Run(map[bool]string{true: "empty", false: "unrecognized"}[basis == ""], func(t *testing.T) {
			snapshot := bundle.Snapshot
			snapshot.Facts = append([]archive.Fact(nil), bundle.Snapshot.Facts...)
			var exposureEvidence string
			changed := false
			for index := range snapshot.Facts {
				fact := snapshot.Facts[index]
				if fact.Exposure == nil || fact.Exposure.Credential == nil || fact.Exposure.Credential.Kind != model.ExposureSecretPassedToStep {
					continue
				}
				exposure := *fact.Exposure
				credential := *exposure.Credential
				credential.EvidenceIDs = append([]model.EvidenceID(nil), credential.EvidenceIDs...)
				credential.Basis = basis
				exposure.Credential = &credential
				fact.Exposure = &exposure
				fact.ID = ""
				fact, err = archive.NormalizeRetainedV1Fact(fact)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.Facts[index] = fact
				exposureEvidence = string(credential.EvidenceIDs[0])
				changed = true
				break
			}
			if !changed {
				t.Fatal("synthetic fixture lacks direct secret exposure")
			}
			encoded, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := archive.DecodeSnapshot(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if !archive.HasRetainedLegacyCredentialBasis(retained) {
				t.Fatal("retained-v1 compatibility marker was not preserved")
			}
			result, err := Derive(retained, pack, bundle.AnalysisTime, ModeReplay)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Case.Findings) != len(baseline.Case.Findings) || result.Case.Counts() != baseline.Case.Counts() {
				t.Fatalf("legacy basis changed canonical counts: findings=%d/%d counts=%+v/%+v", len(result.Case.Findings), len(baseline.Case.Findings), result.Case.Counts(), baseline.Case.Counts())
			}
			wantPresentationBasis := string(basis)
			if basis == "" {
				wantPresentationBasis = report.RetainedLegacyUnclassifiedBasis
			}
			preserved := false
			for _, finding := range result.Case.Findings {
				for _, exposure := range finding.CredentialExposure {
					if exposure.Kind == string(model.ExposureSecretPassedToStep) {
						preserved = preserved || exposure.Basis == wantPresentationBasis
					}
				}
			}
			if !preserved {
				t.Fatalf("legacy credential presentation basis %q was not preserved as %q", basis, wantPresentationBasis)
			}
			for _, edge := range result.Case.GraphV2.Edges {
				if edge.Type == graph.EdgePassedSecretTo {
					t.Fatal("unclassifiable legacy secret edge was projected")
				}
			}
			if len(result.Case.GraphV2.ProjectionNotices) != 1 {
				t.Fatalf("projection notices=%#v", result.Case.GraphV2.ProjectionNotices)
			}
			notice := result.Case.GraphV2.ProjectionNotices[0]
			if notice.Code != graph.ProjectionNoticeUnclassifiableLegacyBasis || notice.Relationship != graph.EdgePassedSecretTo || len(notice.EvidenceIDs) != 1 || notice.EvidenceIDs[0] != exposureEvidence {
				t.Fatalf("projection notice=%#v", notice)
			}
		})
	}
}

func TestBuildGraphV2ScopesEnvironmentsAndKeepsGateStateOnEdges(t *testing.T) {
	revisionOne := "frev1:" + strings.Repeat("1", 64)
	revisionPending := "frev1:" + strings.Repeat("2", 64)
	revisionTwo := "frev1:" + strings.Repeat("3", 64)
	evidenceOne := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	evidencePending := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	evidenceTwo := model.EvidenceID("ev1:" + strings.Repeat("c", 64))
	executionOne := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	executionPending := model.JobExecutionIdentity{RepositoryID: 1, RunID: 11, RunAttempt: 1, JobID: 21}
	executionTwo := model.JobExecutionIdentity{RepositoryID: 2, RunID: 10, RunAttempt: 1, JobID: 20}

	finding := func(revision, repository string, execution model.JobExecutionIdentity, state model.FindingState, evidenceID model.EvidenceID) report.Finding {
		provenance := model.L4Certain
		if state != model.ConfirmedExecuted {
			provenance = model.L2Probable
		}
		return report.Finding{
			FindingRevisionID: revision,
			State:             string(state),
			Provenance:        string(provenance),
			Repository:        repository,
			Workflow:          ".github/workflows/environment.yml",
			IndicatorID:       "synthetic-environment",
			RunID:             int64(execution.RunID),
			RunAttempt:        int(execution.RunAttempt),
			JobID:             int64(execution.JobID),
			EvidenceIDs:       []string{string(evidenceID)},
		}
	}
	findings := []report.Finding{
		finding(revisionOne, "example/one", executionOne, model.ConfirmedExecuted, evidenceOne),
		finding(revisionPending, "example/one", executionPending, model.RunInWindowMutableRef, evidencePending),
		finding(revisionTwo, "example/two", executionTwo, model.ConfirmedExecuted, evidenceTwo),
	}
	environmentFact := func(execution model.JobExecutionIdentity, evidenceID model.EvidenceID, gate string, started bool) archive.Fact {
		return archive.Fact{
			Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID},
			Exposure: &archive.ExposureFact{
				Execution: execution,
				Environment: &archive.EnvironmentEligibilityFact{
					EnvironmentName: "production", GateState: gate, JobStarted: started, SecretNames: []model.SecretName{},
				},
				EventTime: unknownTime(),
			},
		}
	}
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{
			1: {ID: 1, Name: "example/one"},
			2: {ID: 2, Name: "example/two"},
		},
		jobs: map[string]archive.JobFact{
			executionPending.String(): {Execution: executionPending, Status: "waiting"},
		},
		exposures: []archive.Fact{
			environmentFact(executionOne, evidenceOne, "crossed", true),
			environmentFact(executionPending, evidencePending, "pending", false),
			environmentFact(executionTwo, evidenceTwo, "crossed", true),
		},
	}

	legacy := buildGraph(idx, findings)
	legacyBefore, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := buildGraphV2(idx, legacy, findings, nil, report.CaseKindSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	legacyAfter, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyBefore, legacyAfter) {
		t.Fatal("v2 environment reprojection changed frozen v1 graph bytes")
	}

	var environments []graph.NodeV2
	for _, node := range projected.Nodes {
		if node.Type == graph.NodeEnvironment {
			environments = append(environments, node)
			if node.Label != "production" {
				t.Fatalf("environment label contains mutable gate state: %q", node.Label)
			}
		}
	}
	if len(environments) != 2 {
		t.Fatalf("same-named repository environments were conflated: %#v", environments)
	}
	if environments[0].ID == environments[1].ID {
		t.Fatal("repository-scoped environment identities collided")
	}

	type counts struct{ targeted, crossed, eligible int }
	byFinding := map[string]*counts{
		revisionOne: {}, revisionPending: {}, revisionTwo: {},
	}
	for _, edge := range projected.Edges {
		for _, focus := range edge.FocusFindingIDs {
			count := byFinding[focus]
			if count == nil {
				continue
			}
			switch edge.Type {
			case graph.EdgeTargetedEnvironment:
				count.targeted++
				wantRule := graph.EnvironmentTargetHistoricalRule
				if focus == revisionPending {
					wantRule = graph.EnvironmentTargetPendingRule
				}
				if edge.EvidenceClass != graph.EvidenceClassInference || edge.DerivationRule != wantRule {
					t.Fatalf("environment target focus=%s class/rule=%s/%s", focus, edge.EvidenceClass, edge.DerivationRule)
				}
			case graph.EdgeEnvironmentGateSatisfied:
				count.crossed++
				if edge.EvidenceClass != graph.EvidenceClassInference || edge.DerivationRule != graph.EnvironmentGateSatisfiedCrossedRule {
					t.Fatalf("environment gate focus=%s class/rule=%s/%s", focus, edge.EvidenceClass, edge.DerivationRule)
				}
			case graph.EdgeEnvironmentSecretEligible:
				count.eligible++
			}
		}
	}
	if got := *byFinding[revisionOne]; got != (counts{targeted: 1, crossed: 1}) {
		t.Fatalf("crossed environment lane one = %+v", got)
	}
	if got := *byFinding[revisionPending]; got != (counts{targeted: 1}) {
		t.Fatalf("pending environment lane = %+v", got)
	}
	if got := *byFinding[revisionTwo]; got != (counts{targeted: 1, crossed: 1}) {
		t.Fatalf("crossed environment lane two = %+v", got)
	}

	var repositoryOneEnvironment, repositoryTwoEnvironment string
	for _, edge := range projected.Edges {
		if edge.Type != graph.EdgeTargetedEnvironment {
			continue
		}
		for _, focus := range edge.FocusFindingIDs {
			switch focus {
			case revisionOne, revisionPending:
				if repositoryOneEnvironment != "" && repositoryOneEnvironment != edge.Target {
					t.Fatal("same repository environment name did not retain one stable identity")
				}
				repositoryOneEnvironment = edge.Target
			case revisionTwo:
				repositoryTwoEnvironment = edge.Target
			}
		}
	}
	if repositoryOneEnvironment == "" || repositoryTwoEnvironment == "" || repositoryOneEnvironment == repositoryTwoEnvironment {
		t.Fatalf("environment scope targets one=%q two=%q", repositoryOneEnvironment, repositoryTwoEnvironment)
	}
}

func TestBuildGraphV2ScopesAmbiguousExposureNodesToExecution(t *testing.T) {
	revisionOne := "frev1:" + strings.Repeat("4", 64)
	revisionTwo := "frev1:" + strings.Repeat("5", 64)
	executionOne := model.JobExecutionIdentity{RepositoryID: 1, RunID: 30, RunAttempt: 1, JobID: 40}
	executionTwo := model.JobExecutionIdentity{RepositoryID: 2, RunID: 30, RunAttempt: 1, JobID: 40}
	secretName := model.SecretName("SHARED_NAME")
	runnerID := int64(77)

	makeFinding := func(revision, repository string, execution model.JobExecutionIdentity, evidenceID model.EvidenceID) report.Finding {
		return report.Finding{
			FindingRevisionID: revision, State: string(model.ConfirmedExecuted), Provenance: string(model.L4Certain),
			Repository: repository, Workflow: ".github/workflows/scope.yml", IndicatorID: "synthetic-scope",
			RunID: int64(execution.RunID), RunAttempt: int(execution.RunAttempt), JobID: int64(execution.JobID),
			EvidenceIDs: []string{string(evidenceID)},
		}
	}
	findings := []report.Finding{
		makeFinding(revisionOne, "example/one", executionOne, model.EvidenceID("ev1:"+strings.Repeat("1", 64))),
		makeFinding(revisionTwo, "example/two", executionTwo, model.EvidenceID("ev1:"+strings.Repeat("2", 64))),
	}
	var exposures []archive.Fact
	for _, execution := range []model.JobExecutionIdentity{executionOne, executionTwo} {
		characters := []string{"3", "4", "5", "6"}
		credentialEvidence := model.EvidenceID("ev1:" + strings.Repeat(characters[0], 64))
		runnerEvidence := model.EvidenceID("ev1:" + strings.Repeat(characters[1], 64))
		resourceEvidence := model.EvidenceID("ev1:" + strings.Repeat(characters[2], 64))
		environmentEvidence := model.EvidenceID("ev1:" + strings.Repeat(characters[3], 64))
		// The overlap between the two iterations is intentional: evidence-ID
		// equality alone must never collapse separately scoped propositions.
		exposures = append(exposures,
			archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{credentialEvidence}, Exposure: &archive.ExposureFact{
				Execution: execution, Credential: &model.CredentialExposure{
					Kind: model.ExposureSecretReferencedByJob, Basis: model.ExposureBasisHistoricalDefinitionReference,
					SecretName: &secretName, Conclusion: "synthetic named-secret reference only", EvidenceIDs: []model.EvidenceID{credentialEvidence},
				}, EventTime: unknownTime(),
			}},
			archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{runnerEvidence}, Exposure: &archive.ExposureFact{
				Execution: execution, Runner: &archive.RunnerContextFact{
					Classification: "self-hosted", RunnerID: &runnerID, RunnerName: "shared-runner", RunnerGroup: "shared-group", Labels: []string{},
				}, EventTime: unknownTime(),
			}},
			archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{resourceEvidence}, Exposure: &archive.ExposureFact{
				Execution: execution, Resource: &model.ResourceExposure{
					Kind: model.ResourceDeployment, ResourceID: "shared-resource-id", Correlation: model.CorrelationDirect,
					Conclusion: "synthetic direct attribution", EvidenceIDs: []model.EvidenceID{resourceEvidence},
				}, EventTime: unknownTime(),
			}},
			archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{environmentEvidence}, Exposure: &archive.ExposureFact{
				Execution: execution, Environment: &archive.EnvironmentEligibilityFact{
					EnvironmentName: "production", GateState: "crossed", JobStarted: true, SecretNames: []model.SecretName{secretName},
				}, EventTime: unknownTime(),
			}},
		)
	}
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{
			1: {ID: 1, Name: "example/one"},
			2: {ID: 2, Name: "example/two"},
		},
		exposures: exposures,
	}
	legacy := buildGraph(idx, findings)
	projected, err := buildGraphV2(idx, legacy, findings, nil, report.CaseKindSynthetic)
	if err != nil {
		t.Fatal(err)
	}

	wantCounts := map[graph.NodeType]int{
		// A direct named-secret relationship and an environment-eligibility
		// relationship with the same spelling are distinct scopes in each job.
		graph.NodeSecretMetadata: 4,
		graph.NodeRunner:         2,
		graph.NodeRunnerGroup:    2,
		graph.NodeEnvironment:    2,
		graph.NodeDeployment:     2,
	}
	actualCounts := map[graph.NodeType]int{}
	for _, node := range projected.Nodes {
		if _, scoped := wantCounts[node.Type]; !scoped {
			continue
		}
		actualCounts[node.Type]++
		if len(node.FocusFindingIDs) != 1 {
			t.Errorf("scoped %s node leaked focus across executions: %#v", node.Type, node.FocusFindingIDs)
		}
	}
	for nodeType, want := range wantCounts {
		if actualCounts[nodeType] != want {
			t.Errorf("%s nodes=%d, want %d", nodeType, actualCounts[nodeType], want)
		}
	}

	for _, edgeType := range []graph.EdgeType{
		graph.EdgeReferencedSecret,
		graph.EdgeExecutedOnRunner,
		graph.EdgeRunnerInGroup,
		graph.EdgeEnvironmentSecretEligible,
		graph.EdgeCreatedDeployment,
	} {
		seen := map[string]bool{}
		for _, edge := range projected.Edges {
			if edge.Type != edgeType {
				continue
			}
			if len(edge.FocusFindingIDs) != 1 {
				t.Fatalf("%s edge leaked focus across executions: %#v", edgeType, edge.FocusFindingIDs)
			}
			seen[edge.FocusFindingIDs[0]] = true
		}
		if !seen[revisionOne] || !seen[revisionTwo] || len(seen) != 2 {
			t.Errorf("%s did not retain both separate execution scopes: %#v", edgeType, seen)
		}
	}

	firstJSON, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	reversedFindings := append([]report.Finding(nil), findings...)
	for left, right := 0, len(reversedFindings)-1; left < right; left, right = left+1, right-1 {
		reversedFindings[left], reversedFindings[right] = reversedFindings[right], reversedFindings[left]
	}
	reversedIndex := idx
	reversedIndex.exposures = append([]archive.Fact(nil), idx.exposures...)
	for left, right := 0, len(reversedIndex.exposures)-1; left < right; left, right = left+1, right-1 {
		reversedIndex.exposures[left], reversedIndex.exposures[right] = reversedIndex.exposures[right], reversedIndex.exposures[left]
	}
	reversed, err := buildGraphV2(reversedIndex, buildGraph(reversedIndex, reversedFindings), reversedFindings, nil, report.CaseKindSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	reversedJSON, err := json.Marshal(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, reversedJSON) {
		t.Fatal("scoped exposure projection depends on finding or fact order")
	}
}

func TestFindingExactIdentityBindsSharedEvidenceToIncidentComponent(t *testing.T) {
	const (
		indicatorID = "synthetic-exact-action"
		componentID = "affected-subpath"
		workflow    = ".github/workflows/shared-setup.yml"
	)
	affectedSHA := strings.Repeat("b", 40)
	knownGoodLexicalFirstSHA := strings.Repeat("a", 40)
	knownGoodSHA := strings.Repeat("c", 40)
	unrelatedSHA := strings.Repeat("0", 40)
	pack := &incident.ValidatedPack{Pack: incident.Pack{Spec: incident.Spec{
		Components: []incident.Component{{
			ID: componentID, Type: "github-action",
			Repository: incident.Repository{Owner: "fixture", Name: "affected-action"},
			Subpaths:   []string{"target"},
		}},
		Indicators: []incident.Indicator{{
			ID: indicatorID, ComponentID: componentID, Kind: "action-commit",
			Value: incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: affectedSHA}},
		}},
		KnownGood: []incident.KnownGood{
			{ID: "known-good-lexical-first", ComponentID: componentID, Kind: "action-commit", Value: incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: knownGoodLexicalFirstSHA}}},
			{ID: "known-good-current", ComponentID: componentID, Kind: "action-commit", Value: incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: knownGoodSHA}}},
		},
	}}}

	runID := model.WorkflowRunID(70)
	jobID := model.JobID(90)
	subject := func(attempt model.RunAttempt) archive.FactSubject {
		return archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	}
	actionFact := func(attempt model.RunAttempt, evidenceID model.EvidenceID, repository, subpath, sha string) archive.Fact {
		object := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: sha})
		return archive.Fact{
			Kind: archive.FactActionOccurrence, Subject: subject(attempt), EvidenceIDs: []model.EvidenceID{evidenceID},
			ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
				Execution:        model.JobExecutionIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt, JobID: jobID},
				ActionRepository: model.RepositorySlug(repository), ActionSubpath: subpath, SourceObjectID: &object,
			}},
		}
	}
	finding := func(revision string, attempt model.RunAttempt, evidenceID model.EvidenceID, state model.FindingState) report.Finding {
		return report.Finding{
			FindingRevisionID: revision, State: string(state), Provenance: string(model.L4Certain),
			Repository: "acme/service", Workflow: workflow, IndicatorID: indicatorID,
			RunID: int64(runID), RunAttempt: int(attempt), JobID: int64(jobID), EvidenceIDs: []string{string(evidenceID)},
		}
	}

	positiveAttempt := model.RunAttempt(1)
	knownGoodAttempt := model.RunAttempt(2)
	positiveEvidence := model.EvidenceID("ev1:" + strings.Repeat("1", 64))
	knownGoodEvidence := model.EvidenceID("ev1:" + strings.Repeat("2", 64))
	findings := []report.Finding{
		finding("frev1:"+strings.Repeat("1", 64), positiveAttempt, positiveEvidence, model.ConfirmedExecuted),
		finding("frev1:"+strings.Repeat("2", 64), knownGoodAttempt, knownGoodEvidence, model.NoMatchConfirmed),
	}
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{1: {ID: 1, Name: "acme/service"}},
		actions: []archive.Fact{
			// All four observations share one setup-log evidence object. The
			// unlisted identity, other repository, and other subpath must not
			// compete with the affected component identity.
			actionFact(positiveAttempt, positiveEvidence, "fixture/affected-action", "target", unrelatedSHA),
			actionFact(positiveAttempt, positiveEvidence, "aaa/unrelated-action", "", knownGoodLexicalFirstSHA),
			actionFact(positiveAttempt, positiveEvidence, "fixture/affected-action", "other", knownGoodLexicalFirstSHA),
			actionFact(positiveAttempt, positiveEvidence, "fixture/affected-action", "target", affectedSHA),
			// The NO_MATCH finding is similarly bound to its exact known-good
			// identity even when an affected identity sorts before it.
			actionFact(knownGoodAttempt, knownGoodEvidence, "fixture/affected-action", "target", unrelatedSHA),
			actionFact(knownGoodAttempt, knownGoodEvidence, "aaa/unrelated-action", "", affectedSHA),
			actionFact(knownGoodAttempt, knownGoodEvidence, "fixture/affected-action", "other", knownGoodLexicalFirstSHA),
			actionFact(knownGoodAttempt, knownGoodEvidence, "fixture/affected-action", "target", knownGoodSHA),
		},
	}

	got := buildFindingIndex(idx, findings, pack)
	if len(got) != 2 {
		t.Fatalf("finding index entries=%d, want 2", len(got))
	}
	if got[0].ExactIdentityKind != graph.ExactIdentityActionCommitSHA || got[0].ExactIdentity != "sha1:"+affectedSHA || got[0].ExactKnownGood {
		t.Fatalf("affected identity was not component-bound: %#v", got[0])
	}
	if got[1].ExactIdentityKind != graph.ExactIdentityActionCommitSHA || got[1].ExactIdentity != "sha1:"+knownGoodSHA || !got[1].ExactKnownGood {
		t.Fatalf("NO_MATCH identity was not bound to exact known-good evidence: %#v", got[1])
	}

	reversed := idx
	reversed.actions = append([]archive.Fact(nil), idx.actions...)
	for left, right := 0, len(reversed.actions)-1; left < right; left, right = left+1, right-1 {
		reversed.actions[left], reversed.actions[right] = reversed.actions[right], reversed.actions[left]
	}
	reversedIndex := buildFindingIndex(reversed, findings, pack)
	firstJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	reversedJSON, err := json.Marshal(reversedIndex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, reversedJSON) {
		t.Fatalf("exact identity binding depends on fact order:\n%s\n%s", firstJSON, reversedJSON)
	}
}

func TestFindingExactIdentityFailsClosedOnDistinctEligibleIdentities(t *testing.T) {
	affectedSHA := strings.Repeat("1", 40)
	knownGoodSHA := strings.Repeat("2", 40)
	pack := &incident.ValidatedPack{Pack: incident.Pack{Spec: incident.Spec{
		Components: []incident.Component{{
			ID: "affected", Type: "github-action", Repository: incident.Repository{Owner: "fixture", Name: "affected-action"},
		}},
		Indicators: []incident.Indicator{{
			ID: "affected-sha", ComponentID: "affected", Kind: "action-commit",
			Value: incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: affectedSHA}},
		}},
		KnownGood: []incident.KnownGood{{
			ID: "known-good", ComponentID: "affected", Kind: "action-commit",
			Value: incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: knownGoodSHA}},
		}},
	}}}
	runID, attempt, jobID := model.WorkflowRunID(71), model.RunAttempt(1), model.JobID(91)
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("3", 64))
	subject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	actionFact := func(sha string) archive.Fact {
		object := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: sha})
		return archive.Fact{
			Kind: archive.FactActionOccurrence, Subject: subject, EvidenceIDs: []model.EvidenceID{evidenceID},
			ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
				Execution:        model.JobExecutionIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt, JobID: jobID},
				ActionRepository: "fixture/affected-action", SourceObjectID: &object,
			}},
		}
	}
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{1: {ID: 1, Name: "acme/service"}},
		actions:      []archive.Fact{actionFact(knownGoodSHA), actionFact(affectedSHA), actionFact(affectedSHA)},
	}
	finding := report.Finding{
		FindingRevisionID: "frev1:" + strings.Repeat("3", 64), State: string(model.ContradictoryEvidence), Provenance: string(model.L4Certain),
		Repository: "acme/service", Workflow: ".github/workflows/ambiguous.yml", IndicatorID: "affected-sha",
		RunID: int64(runID), RunAttempt: int(attempt), JobID: int64(jobID), EvidenceIDs: []string{string(evidenceID)},
	}

	entry := buildFindingIndex(idx, []report.Finding{finding}, pack)[0]
	if entry.ExactIdentityKind != "" || entry.ExactIdentity != "" || entry.ExactKnownGood {
		t.Fatalf("ambiguous shared evidence did not fail closed: %#v", entry)
	}
}

func TestRunnerGroupIdentityPreservesOptionalNumericID(t *testing.T) {
	t.Parallel()
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 30, RunAttempt: 1, JobID: 40}
	zero, seven := int64(0), int64(7)
	base := archive.RunnerContextFact{Classification: "self-hosted", RunnerGroup: "shared-group", Labels: []string{}}

	absent := strings.Join(runnerGroupIdentity(execution, base), "\x00")
	base.RunnerGroupID = &zero
	meaningfulZero := strings.Join(runnerGroupIdentity(execution, base), "\x00")
	base.RunnerGroupID = &seven
	numeric := strings.Join(runnerGroupIdentity(execution, base), "\x00")
	if absent == meaningfulZero || meaningfulZero == numeric || absent == numeric {
		t.Fatalf("runner-group identities collapsed absent, zero, or numeric API IDs: %q %q %q", absent, meaningfulZero, numeric)
	}
	if !strings.HasSuffix(meaningfulZero, "runner-group-id\x000") || !strings.HasSuffix(numeric, "runner-group-id\x007") {
		t.Fatalf("runner-group identity lacks typed numeric component: %q %q", meaningfulZero, numeric)
	}
}

func TestProjectRunnerRetainsNumericOnlyGroup(t *testing.T) {
	t.Parallel()
	focus := "frev1:" + strings.Repeat("8", 64)
	evidence := []string{"ev1:" + strings.Repeat("8", 64)}
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 30, RunAttempt: 1, JobID: 40}
	groupID := int64(23)
	builder := newV2ScopedExposureBuilder()
	if err := builder.projectRunner(execution, archive.RunnerContextFact{
		Classification: "unknown", RunnerGroupID: &groupID, Labels: []string{},
	}, evidence, unknownTime(), focus); err != nil {
		t.Fatal(err)
	}
	result := graph.GraphV2{
		SchemaVersion: graph.SchemaVersionV2, CaseKind: graph.CaseKindSynthetic,
		FindingIndex: []graph.FindingIndexEntry{{
			FindingRevisionID: focus, State: model.ConfirmedExecuted, ProvenanceLevel: model.L4Certain,
			Repository: "fixture/repository", WorkflowPath: ".github/workflows/demo.yml", IndicatorID: "fixture-indicator",
		}},
	}
	builder.mergeInto(&result)
	if err := result.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	groupNodes, groupEdges := 0, 0
	for _, node := range result.Nodes {
		if node.Type == graph.NodeRunnerGroup {
			groupNodes++
			if node.Label != "runner group ID 23" {
				t.Fatalf("numeric-only runner-group label=%q", node.Label)
			}
		}
	}
	for _, edge := range result.Edges {
		if edge.Type == graph.EdgeRunnerInGroup {
			groupEdges++
		}
	}
	if groupNodes != 1 || groupEdges != 1 {
		t.Fatalf("numeric-only runner group was omitted: nodes=%d edges=%d", groupNodes, groupEdges)
	}
}
