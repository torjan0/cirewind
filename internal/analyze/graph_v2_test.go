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
		case graph.EdgeCrossedEnvironmentGate:
			crossed++
		case graph.EdgeEnvironmentSecretEligible:
			eligible++
		}
	}
	if targeted != 1 || crossed != 0 || eligible != 0 {
		t.Fatalf("pending environment edges targeted/crossed/eligible=%d/%d/%d", targeted, crossed, eligible)
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
		if edge.Type == graph.EdgeTargetedEnvironment || edge.Type == graph.EdgeCrossedEnvironmentGate || edge.Type == graph.EdgeEnvironmentSecretEligible {
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
