package analyze

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func loadPack(t *testing.T) *incident.ValidatedPack {
	t.Helper()
	data, err := os.ReadFile("../../incidents/synthetic/mutable-tag.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func TestExactLifecycleProducesExecutedAndSuppressesMutableFallback(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	path, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	slug, _ := model.NewRepositorySlug("acme/service")
	actionSlug, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	oid, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
	actionOID, _ := model.NewActionSourceObjectID(oid)
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	stepNo := model.APIStepNumber(2)
	step := model.StepIdentity{Job: execution, APIStepNumber: &stepNo, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
	snapshot := archive.Snapshot{
		Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("b", 64)},
		Facts: []archive.Fact{
			{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: slug}}},
			{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1}, Run: &archive.RunFact{RepositoryID: 1, RunID: 10, WorkflowPath: &path, EventTime: event}},
			{ID: "fact1:" + strings.Repeat("c", 64), Kind: archive.FactActionOccurrence, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20)), StepKey: step.Key()}, EventTime: event, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: actionSlug, DeclaredRef: "v1", SourceObjectID: &actionOID, EventTime: event}}},
		},
	}
	result, err := Derive(snapshot, loadPack(t), time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), "replay")
	if err != nil {
		t.Fatal(err)
	}
	var executed, mutable int
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.ConfirmedExecuted) {
			executed++
		}
		if finding.State == string(model.RunInWindowMutableRef) {
			mutable++
		}
	}
	if executed != 1 || mutable != 0 {
		t.Fatalf("executed=%d mutable=%d findings=%#v", executed, mutable, result.Case.Findings)
	}
}

func TestExactRuntimeAndTransitiveSupportSelectOneStrongestRevision(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
	repository, _ := model.NewRepositorySlug("acme/service")
	actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	object, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
	actionObject, _ := model.NewActionSourceObjectID(object)
	callerObject := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("2", 40)})
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	subject := archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20))}
	runtimeEvidence := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	definitionEvidence := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	snapshot := archive.Snapshot{
		Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("c", 64)},
		Facts: []archive.Fact{
			{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
			{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1}, Run: &archive.RunFact{RepositoryID: 1, RunID: 10, WorkflowPath: &workflowPath, EventTime: event}},
			{
				ID: "fact1:" + strings.Repeat("d", 64), Kind: archive.FactActionOccurrence, Subject: subject, EventTime: event,
				EvidenceIDs: []model.EvidenceID{runtimeEvidence},
				ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
					Kind: model.ObservationPreparationComplete, Execution: execution, ActionRepository: actionRepository,
					SourceObjectID: &actionObject, EventTime: event,
				}},
			},
			{
				ID: "fact1:" + strings.Repeat("e", 64), Kind: archive.FactDependency, Subject: subject, EventTime: event,
				EvidenceIDs: []model.EvidenceID{definitionEvidence},
				Dependency: &archive.DependencyFact{
					Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction,
					Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: 1, CallerRepository: repository,
					CallerPath: "action.yml", CallerWorkflowObjectID: &callerObject,
					TargetRepository: actionRepository, TargetActionObjectID: &actionObject,
					TransitiveDepth: 1, Execution: &execution, EventTime: event,
				},
			},
		},
	}
	result, err := Derive(snapshot, loadPack(t), when.Time.Add(time.Hour), ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	var matches []report.Finding
	for _, finding := range result.Case.Findings {
		if finding.IndicatorID == "synthetic-compromised-commit" && finding.RunID == 10 && finding.RunAttempt == 1 && finding.JobID == 20 {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("got %d selected revisions for one logical finding: %#v", len(matches), matches)
	}
	if matches[0].State != string(model.ConfirmedDownloaded) {
		t.Fatalf("strong exact evidence lost to transitive evidence: %#v", matches[0])
	}
	if len(matches[0].EvidenceIDs) != 2 {
		t.Fatalf("supporting evidence paths were not merged: %#v", matches[0].EvidenceIDs)
	}
}

func TestMaterialChildGapRemainsVisibleBesidePotentialAttemptFinding(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisDefinitionCommit}
	repository, _ := model.NewRepositorySlug("acme/service")
	actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	object, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
	actionObject, _ := model.NewActionSourceObjectID(object)
	callerObject := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("2", 40)})
	runID, attempt, jobID := model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	attemptIdentity := model.RunAttemptIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt}
	attemptSubject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt}
	jobSubject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	dependencyEvidence := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	unitID := model.CoverageUnitID("cov1:" + strings.Repeat("b", 64))
	assessmentID := model.CoverageAssessmentID("cova1:" + strings.Repeat("c", 64))
	unit := model.CoverageUnit{
		ID: unitID, Kind: model.CoverageJobLog,
		Scope:      model.CoverageScope{RepositoryID: ptr(model.RepositoryID(1)), RunID: &runID, RunAttempt: &attempt, JobID: &jobID},
		LogicalKey: "job-log:missing", RequiredForNegative: true,
	}
	assessment := model.CoverageAssessment{
		ID: assessmentID, UnitID: unitID, Status: model.CoverageGap,
		Gap: &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: true}, EvidenceIDs: []model.EvidenceID{},
	}
	snapshot := archive.Snapshot{
		Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("d", 64)},
		Facts: []archive.Fact{
			{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
			{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1}, Run: &archive.RunFact{RepositoryID: 1, RunID: runID, WorkflowPath: &workflowPath, EventTime: event}},
			{
				ID: "fact1:" + strings.Repeat("e", 64), Kind: archive.FactDependency, Subject: attemptSubject, EventTime: event,
				EvidenceIDs: []model.EvidenceID{dependencyEvidence},
				Dependency: &archive.DependencyFact{
					Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction,
					Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: 1, CallerRepository: repository,
					CallerPath: string(workflowPath), CallerWorkflowObjectID: &callerObject,
					TargetRepository: actionRepository, TargetActionObjectID: &actionObject,
					TransitiveDepth: 1, AttemptExecution: &attemptIdentity, EventTime: event,
				},
			},
			{
				ID: "fact1:" + strings.Repeat("f", 64), Kind: archive.FactCoverageGap, Subject: jobSubject,
				EventTime: unknownTime(), CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment},
			},
		},
	}
	result, err := Derive(snapshot, loadPack(t), when.Time.Add(time.Hour), ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	var potential, jobUnknown bool
	for _, finding := range result.Case.Findings {
		if finding.IndicatorID != "synthetic-compromised-commit" || finding.RunID != int64(runID) || finding.RunAttempt != int(attempt) {
			continue
		}
		if finding.State == string(model.PotentialTransitive) && finding.JobID == 0 {
			potential = true
		}
		if finding.State == string(model.UnknownEvidenceGap) && finding.JobID == int64(jobID) {
			jobUnknown = true
			if len(finding.CollectionCoverage) != 1 || finding.CollectionCoverage[0] != string(assessmentID) {
				t.Fatalf("missing-log finding lost exact coverage: %#v", finding)
			}
			if len(finding.EvidenceGaps) == 0 || !strings.Contains(strings.Join(finding.EvidenceGaps, " "), string(model.GapRetentionOrDeletion)) {
				t.Fatalf("missing-log reason is not visible: %#v", finding.EvidenceGaps)
			}
		}
	}
	if !potential || !jobUnknown {
		t.Fatalf("potential reachability hid its child evidence gap: potential=%v unknown=%v findings=%#v", potential, jobUnknown, result.Case.Findings)
	}
}

func TestMaterialCoverageGapNeverProducesNoMatch(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	slug, _ := model.NewRepositorySlug("acme/service")
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	unitID := model.CoverageUnitID("cov1:" + strings.Repeat("c", 64))
	assessmentID := model.CoverageAssessmentID("cova1:" + strings.Repeat("d", 64))
	material := true
	unit := model.CoverageUnit{ID: unitID, Kind: model.CoverageAttemptLog, Scope: model.CoverageScope{RepositoryID: ptr(model.RepositoryID(1))}, LogicalKey: "attempt-log:missing", RequiredForNegative: true}
	assessment := model.CoverageAssessment{ID: assessmentID, UnitID: unitID, Status: model.CoverageGap, Gap: &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: material}, EvidenceIDs: []model.EvidenceID{evidenceID}}
	snapshot := archive.Snapshot{Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("b", 64)}, Facts: []archive.Fact{
		{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: slug}}},
		{ID: "fact1:" + strings.Repeat("e", 64), Kind: archive.FactCoverageGap, Subject: archive.FactSubject{RepositoryID: 1}, EventTime: unknownTime(), EvidenceIDs: []model.EvidenceID{evidenceID}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}},
	}}
	result, err := Derive(snapshot, loadPack(t), when.Time, "replay")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Case.Findings) == 0 {
		t.Fatal("expected evidence-gap findings")
	}
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.NoMatchConfirmed) {
			t.Fatal("missing logs produced NO_MATCH_CONFIRMED")
		}
	}
}

func TestMaterialCoverageGapsCoalesceToOneSelectedRevisionPerSubject(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	repository, _ := model.NewRepositorySlug("acme/service")
	runID, attempt, jobID := model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	subject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	makeGap := func(character string, reason model.GapReason) archive.Fact {
		unitID := model.CoverageUnitID("cov1:" + strings.Repeat(character, 64))
		assessmentID := model.CoverageAssessmentID("cova1:" + strings.Repeat(character, 64))
		unit := model.CoverageUnit{
			ID: unitID, Kind: model.CoverageJobLog,
			Scope:      model.CoverageScope{RepositoryID: ptr(model.RepositoryID(1)), RunID: &runID, RunAttempt: &attempt, JobID: &jobID},
			LogicalKey: "job-log:" + character, RequiredForNegative: true,
		}
		assessment := model.CoverageAssessment{
			ID: assessmentID, UnitID: unitID, Status: model.CoverageGap,
			Gap: &model.CoverageGapDetail{Reason: reason, Material: true}, EvidenceIDs: []model.EvidenceID{},
		}
		return archive.Fact{
			ID: "fact1:" + strings.Repeat(character, 64), Kind: archive.FactCoverageGap,
			Subject: subject, EventTime: unknownTime(),
			CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment},
		}
	}
	snapshot := archive.Snapshot{
		Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("b", 64)},
		Facts: []archive.Fact{
			{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
			makeGap("c", model.GapRetentionOrDeletion),
			makeGap("d", model.GapAmbiguousCorrelation),
		},
	}
	result, err := Derive(snapshot, loadPack(t), when.Time, ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, finding := range result.Case.Findings {
		if seen[finding.FindingID] {
			t.Fatalf("analysis selected multiple revisions for logical finding %s", finding.FindingID)
		}
		seen[finding.FindingID] = true
		if finding.State != string(model.UnknownEvidenceGap) {
			t.Fatalf("material gaps produced %s", finding.State)
		}
		if len(finding.CollectionCoverage) != 2 {
			t.Fatalf("coalesced finding lost gap coverage: %#v", finding.CollectionCoverage)
		}
	}
	if len(result.Case.Findings) != len(loadPack(t).Pack.Spec.Indicators) {
		t.Fatalf("got %d findings for %d indicators", len(result.Case.Findings), len(loadPack(t).Pack.Spec.Indicators))
	}
}

func TestIdentityCorrelationGapSurvivesConfirmedValidSibling(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
	repository, _ := model.NewRepositorySlug("acme/service")
	actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	affectedObject, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
	affectedAction, _ := model.NewActionSourceObjectID(affectedObject)
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 2, JobID: 21}
	stepNumber := model.APIStepNumber(2)
	step := model.StepIdentity{Job: execution, APIStepNumber: &stepNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	unitID := model.CoverageUnitID("cov1:" + strings.Repeat("c", 64))
	assessmentID := model.CoverageAssessmentID("cova1:" + strings.Repeat("d", 64))
	runID, invalidAttempt := model.WorkflowRunID(10), model.RunAttempt(1)
	gapScope := model.CoverageScope{RepositoryID: ptr(model.RepositoryID(1)), RunID: &runID, RunAttempt: &invalidAttempt}
	unit := model.CoverageUnit{ID: unitID, Kind: model.CoverageRunAttempt, Scope: gapScope, LogicalKey: "workflow_run_attempt:1:10:1:0", RequiredForNegative: true}
	assessment := model.CoverageAssessment{ID: assessmentID, UnitID: unitID, Status: model.CoverageGap, Gap: &model.CoverageGapDetail{Reason: model.GapAmbiguousCorrelation, Material: true}, EvidenceIDs: []model.EvidenceID{}}
	snapshot := archive.Snapshot{Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("b", 64)}, Facts: []archive.Fact{
		{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
		{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1}, Run: &archive.RunFact{RepositoryID: 1, RunID: 10, WorkflowPath: &workflowPath, EventTime: event}},
		{ID: "fact1:" + strings.Repeat("e", 64), Kind: archive.FactActionOccurrence, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: ptr(model.RunAttempt(2)), JobID: ptr(model.JobID(21)), StepKey: step.Key()}, EventTime: event, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: actionRepository, SourceObjectID: &affectedAction, EventTime: event}}},
		{ID: "fact1:" + strings.Repeat("f", 64), Kind: archive.FactCoverageGap, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &invalidAttempt}, EventTime: unknownTime(), EvidenceIDs: []model.EvidenceID{}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}},
	}}
	result, err := Derive(snapshot, loadPack(t), when.Time.Add(time.Hour), ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	var executedSibling, quarantinedUnknown bool
	for _, finding := range result.Case.Findings {
		if finding.IndicatorID != "synthetic-compromised-commit" {
			continue
		}
		if finding.State == string(model.ConfirmedExecuted) && finding.RunAttempt == 2 && finding.JobID == 21 {
			executedSibling = true
		}
		if finding.State == string(model.UnknownEvidenceGap) && finding.RunAttempt == 1 && finding.JobID == 0 {
			quarantinedUnknown = true
			if len(finding.CollectionCoverage) != 1 || finding.CollectionCoverage[0] != string(assessmentID) {
				t.Fatalf("identity unknown lost its exact coverage assessment: %#v", finding)
			}
		}
		if finding.State == string(model.ConfirmedExecuted) && finding.RunAttempt == 1 {
			t.Fatalf("quarantined attempt became confirmed execution: %#v", finding)
		}
	}
	if !executedSibling || !quarantinedUnknown {
		t.Fatalf("partial identity coverage was hidden: executed=%v unknown=%v findings=%#v", executedSibling, quarantinedUnknown, result.Case.Findings)
	}
}

func TestKnownGoodRuntimeNeedsExplicitClosedCoverageForNoMatch(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
	repository, _ := model.NewRepositorySlug("acme/service")
	actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	safeObject, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("0", 40))
	safeAction, _ := model.NewActionSourceObjectID(safeObject)
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	stepNumber := model.APIStepNumber(2)
	step := model.StepIdentity{Job: execution, APIStepNumber: &stepNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	coverageID := model.CoverageAssessmentID("cova1:" + strings.Repeat("d", 64))
	grammarCoverageID := model.CoverageAssessmentID("cova1:" + strings.Repeat("e", 64))
	one := uint64(1)
	coverageScope := model.CoverageScope{RepositoryID: ptr(model.RepositoryID(1)), RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20))}
	coverage := archive.Fact{ID: "fact1:" + strings.Repeat("e", 64), Kind: archive.FactCoverage,
		Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20))}, EvidenceIDs: []model.EvidenceID{evidenceID},
		Coverage: &archive.CoverageFact{Unit: model.CoverageUnit{Kind: model.CoverageJobLog, Scope: coverageScope, RequiredForNegative: true}, Assessment: model.CoverageAssessment{ID: coverageID, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1}}}
	grammarCoverage := archive.Fact{ID: "fact1:" + strings.Repeat("f", 64), Kind: archive.FactCoverage,
		Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20))}, EvidenceIDs: []model.EvidenceID{evidenceID},
		Coverage: &archive.CoverageFact{Unit: model.CoverageUnit{Kind: model.CoverageParserGrammar, Scope: coverageScope, RequiredForNegative: true}, Assessment: model.CoverageAssessment{ID: grammarCoverageID, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1}}}
	snapshot := archive.Snapshot{Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("b", 64)}, Facts: []archive.Fact{
		{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
		{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1}, Run: &archive.RunFact{RepositoryID: 1, RunID: 10, WorkflowPath: &workflowPath, EventTime: event}},
		{ID: "fact1:" + strings.Repeat("c", 64), Kind: archive.FactActionOccurrence, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20)), StepKey: step.Key()}, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: actionRepository, SourceObjectID: &safeAction, EventTime: event}}},
		coverage, grammarCoverage,
	}}
	result, err := Derive(snapshot, loadPack(t), when.Time, "replay")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.NoMatchConfirmed) {
			found = true
			if len(finding.CollectionCoverage) != 2 {
				t.Fatalf("NO_MATCH_CONFIRMED lost coverage support: %#v", finding.CollectionCoverage)
			}
		}
	}
	if !found {
		t.Fatal("known-good exact runtime plus explicit closed coverage did not produce NO_MATCH_CONFIRMED")
	}

	onlyJobLog := snapshot
	onlyJobLog.Facts = append([]archive.Fact(nil), snapshot.Facts[:4]...)
	result, err = Derive(onlyJobLog, loadPack(t), when.Time, "replay")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.NoMatchConfirmed) {
			t.Fatal("one arbitrary required coverage capability produced NO_MATCH_CONFIRMED")
		}
	}

	withoutCoverage := snapshot
	withoutCoverage.Facts = withoutCoverage.Facts[:3]
	result, err = Derive(withoutCoverage, loadPack(t), when.Time, "replay")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.NoMatchConfirmed) {
			t.Fatal("known-good runtime without explicit coverage produced NO_MATCH_CONFIRMED")
		}
		if finding.State == string(model.ConfirmedExecuted) || finding.State == string(model.ConfirmedDownloaded) {
			t.Fatalf("known-good runtime was mislabeled as affected: %s", finding.State)
		}
	}
}

func TestCalledWorkflowConfirmationRequiresExactAttemptMetadata(t *testing.T) {
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	event := model.EventInterval{Start: &when, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
	repository, _ := model.NewRepositorySlug("acme/service")
	target, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-workflows")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	caller := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("2", 40)})
	called := model.CalledWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("3", 40)})
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 2, JobID: 20}
	attempt := model.RunAttemptIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 2}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	base := []archive.Fact{
		{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
		{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10))}, Run: &archive.RunFact{RepositoryID: 1, RunID: 10, WorkflowPath: &workflowPath, EventTime: event}},
	}
	historical := archive.Fact{ID: "fact1:" + strings.Repeat("b", 64), Kind: archive.FactDependency, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(2)), JobID: ptr(model.JobID(20))}, EvidenceIDs: []model.EvidenceID{evidenceID}, Dependency: &archive.DependencyFact{
		Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow, Basis: archive.DefinitionHistoricalAtRun,
		CallerRepositoryID: 1, CallerRepository: repository, CallerPath: ".github/workflows/build.yml", CallerWorkflowObjectID: &caller,
		TargetRepository: target, TargetPath: ".github/workflows/reusable.yaml", TargetCalledWorkflowObjectID: &called, Execution: &execution, ContradictsFactIDs: []string{}, EventTime: event,
	}}
	runtime := archive.Fact{ID: "fact1:" + strings.Repeat("c", 64), Kind: archive.FactDependency, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(2))}, EvidenceIDs: []model.EvidenceID{evidenceID}, Dependency: &archive.DependencyFact{
		Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow, Basis: archive.DefinitionRuntimeAttemptMetadata,
		CallerRepositoryID: 1, CallerRepository: repository, CallerPath: ".github/workflows/build.yml", TargetRepository: target,
		TargetPath: ".github/workflows/reusable.yaml", TargetCalledWorkflowObjectID: &called, AttemptExecution: &attempt, ContradictsFactIDs: []string{}, EventTime: event,
	}}
	for _, test := range []struct {
		name string
		fact archive.Fact
		want model.FindingState
	}{
		{name: "historical YAML is declaration only", fact: historical, want: model.DeclaredAtRunSHA},
		{name: "GitHub attempt metadata confirms call", fact: runtime, want: model.ConfirmedCalledWorkflow},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := archive.Snapshot{Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("d", 64)}, Facts: append(append([]archive.Fact(nil), base...), test.fact)}
			result, err := Derive(snapshot, loadPack(t), when.Time.Add(time.Hour), ModeReplay)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range result.Case.Findings {
				if finding.IndicatorID == "synthetic-called-workflow" {
					found = true
					if finding.State != string(test.want) {
						t.Fatalf("state=%s, want %s", finding.State, test.want)
					}
				}
			}
			if !found {
				t.Fatal("called-workflow indicator produced no finding")
			}
		})
	}
}

func TestContradictionRequiresLinkedStaticRuntimeConflictAtSameStep(t *testing.T) {
	repository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	safe := mustTestActionOID(t, strings.Repeat("0", 40))
	affected := mustTestActionOID(t, strings.Repeat("1", 40))
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	stepNumber := model.APIStepNumber(2)
	step := model.StepIdentity{Job: execution, APIStepNumber: &stepNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	runtime := archive.Fact{ID: "fact1:" + strings.Repeat("a", 64), Kind: archive.FactActionOccurrence, Subject: archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20)), StepKey: step.Key()}, EvidenceIDs: []model.EvidenceID{model.EvidenceID("ev1:" + strings.Repeat("a", 64))}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: repository, SourceObjectID: &affected}}}
	definition := archive.Fact{ID: "fact1:" + strings.Repeat("b", 64), Kind: archive.FactDependency, Subject: runtime.Subject, EvidenceIDs: []model.EvidenceID{model.EvidenceID("ev1:" + strings.Repeat("b", 64))}, Dependency: &archive.DependencyFact{Basis: archive.DefinitionHistoricalAtRun, TargetRepository: repository, TargetActionObjectID: &safe, ContradictsFactIDs: []string{runtime.ID}}}
	idx := index{actions: []archive.Fact{runtime}, dependencies: []archive.Fact{definition}, factsByID: map[string]archive.Fact{runtime.ID: runtime, definition.ID: definition}}
	ids, evidenceIDs := runtimeDefinitionContradictions(idx, runtime)
	if len(ids) != 1 || ids[0] != definition.ID || len(evidenceIDs) != 1 {
		t.Fatalf("valid contradiction ids=%v evidence=%v", ids, evidenceIDs)
	}

	for _, test := range []struct {
		name   string
		mutate func(*archive.Fact)
	}{
		{name: "arbitrary missing link", mutate: func(fact *archive.Fact) {
			fact.Dependency.ContradictsFactIDs = []string{"fact1:" + strings.Repeat("f", 64)}
		}},
		{name: "same identity", mutate: func(fact *archive.Fact) { fact.Dependency.TargetActionObjectID = &affected }},
		{name: "different step", mutate: func(fact *archive.Fact) { fact.Subject.StepKey += "/different" }},
		{name: "current snapshot", mutate: func(fact *archive.Fact) { fact.Dependency.Basis = archive.DefinitionCurrentSnapshot }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := definition
			dep := *definition.Dependency
			changed.Dependency = &dep
			test.mutate(&changed)
			changedIdx := idx
			changedIdx.dependencies = []archive.Fact{changed}
			if ids, _ := runtimeDefinitionContradictions(changedIdx, runtime); len(ids) != 0 {
				t.Fatalf("unqualified contradiction accepted: %v", ids)
			}
		})
	}
}

func TestOIDCCapabilityRequiresTypedRuntimePermission(t *testing.T) {
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	subject := archive.FactSubject{RepositoryID: 1, RunID: ptr(model.WorkflowRunID(10)), RunAttempt: ptr(model.RunAttempt(1)), JobID: ptr(model.JobID(20))}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	permission := archive.Fact{Kind: archive.FactExposure, Subject: subject, Exposure: &archive.ExposureFact{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "id-token", Access: "write", Conclusion: "typed runtime permission", EvidenceIDs: []model.EvidenceID{evidenceID}}}}
	direct := archive.Fact{Kind: archive.FactExposure, Subject: subject, Exposure: &archive.ExposureFact{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureOIDCMintingCapability, Basis: model.ExposureBasisRuntimeObserved, Conclusion: "untrusted precomputed assertion", EvidenceIDs: []model.EvidenceID{evidenceID}}}}
	credentials, _ := exposuresFor(index{exposures: []archive.Fact{permission, direct}}, subject, model.ConfirmedExecuted)
	var capability *report.Exposure
	for index := range credentials {
		if credentials[index].Kind == string(model.ExposureOIDCMintingCapability) {
			capability = &credentials[index]
		}
	}
	if capability == nil || capability.Capability != "id-token:write" || !strings.Contains(capability.Conclusion, OIDCCapabilityRuleVersion) {
		t.Fatalf("typed OIDC derivation=%#v", credentials)
	}
	credentials, _ = exposuresFor(index{exposures: []archive.Fact{direct}}, subject, model.ConfirmedExecuted)
	for _, credential := range credentials {
		if credential.Kind == string(model.ExposureOIDCMintingCapability) {
			t.Fatal("precomputed OIDC assertion self-certified capability")
		}
	}
}

func mustTestActionOID(t *testing.T, value string) model.ActionSourceObjectID {
	t.Helper()
	object, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		t.Fatal(err)
	}
	action, err := model.NewActionSourceObjectID(object)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func TestInvestigateUsesRequestedWindowButReplayDoesNot(t *testing.T) {
	requested := boundedEvent(
		time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC),
		model.BoundsClosedOpen,
	)
	discovery := boundedEvent(
		time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC),
		model.BoundsClosedOpen,
	)
	old := instantEventAt(time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC))
	straddlesStart := boundedEvent(
		time.Date(2026, 8, 19, 9, 59, 0, 0, time.UTC),
		time.Date(2026, 8, 19, 10, 1, 0, 0, time.UTC),
		model.BoundsClosedOpen,
	)
	inWindow := instantEventAt(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	atOpenEnd := instantEventAt(time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC))

	repository, _ := model.NewRepositorySlug("acme/service")
	actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
	workflowPath, _ := model.NewWorkflowPath(".github/workflows/build.yml")
	object, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
	actionObject, _ := model.NewActionSourceObjectID(object)
	runID := model.WorkflowRunID(10)
	snapshot := archive.Snapshot{
		Metadata: archive.SnapshotMetadata{ArchiveID: "arc1:" + strings.Repeat("9", 64)},
		Collections: []archive.CollectionSession{{
			ID: model.CollectionSessionID("collection:" + strings.Repeat("8", 64)), Mode: ModeInvestigate,
			Scope: archive.CollectionScope{RequestedEventWindow: &requested, DiscoveryEventWindow: &discovery},
		}},
		Facts: []archive.Fact{
			{Kind: archive.FactRepository, Subject: archive.FactSubject{RepositoryID: 1}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: repository}}},
			{Kind: archive.FactRun, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID}, Run: &archive.RunFact{RepositoryID: 1, RunID: runID, WorkflowPath: &workflowPath, EventTime: old}},
		},
	}
	for index, event := range []model.EventInterval{old, straddlesStart, inWindow, atOpenEnd} {
		attempt := model.RunAttempt(index + 1)
		jobID := model.JobID(20 + index)
		execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt, JobID: jobID}
		subject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
		evidenceID := model.EvidenceID("ev1:" + strings.Repeat(string(rune('a'+index)), 64))
		snapshot.Facts = append(snapshot.Facts,
			archive.Fact{Kind: archive.FactAttempt, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt}, EventTime: event, Attempt: &archive.AttemptFact{RepositoryID: 1, RunID: runID, RunAttempt: attempt, EventTime: event}},
			archive.Fact{ID: "fact1:" + strings.Repeat(string(rune('a'+index)), 64), Kind: archive.FactActionOccurrence, Subject: subject, EventTime: event, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{Kind: model.ObservationLifecycleStarted, Execution: execution, ActionRepository: actionRepository, SourceObjectID: &actionObject, EventTime: event}}},
		)
	}

	analysisTime := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	investigation, err := Derive(snapshot, loadPack(t), analysisTime, ModeInvestigate)
	if err != nil {
		t.Fatal(err)
	}
	assertExecutedAttempts(t, investigation, []int{2, 3})

	replay, err := Derive(snapshot, loadPack(t), analysisTime, ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	assertExecutedAttempts(t, replay, []int{1, 2, 3, 4})
}

func TestInvestigateRequiresRequestedWindow(t *testing.T) {
	_, err := Derive(archive.Snapshot{}, loadPack(t), time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), ModeInvestigate)
	if err == nil || !strings.Contains(err.Error(), "requested event window") {
		t.Fatalf("error=%v", err)
	}
}

func TestWindowRestrictionUsesAttemptTimeAndPreservesUnknownGap(t *testing.T) {
	runID := model.WorkflowRunID(10)
	oldAttempt, currentAttempt := model.RunAttempt(1), model.RunAttempt(2)
	old := instantEventAt(time.Date(2026, 8, 19, 9, 30, 0, 0, time.UTC))
	current := instantEventAt(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	window := boundedEvent(time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC), time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC), model.BoundsClosedOpen)
	idx := index{
		runs: map[string]archive.RunFact{}, jobs: map[string]archive.JobFact{},
		attempts: map[string]archive.AttemptFact{
			attemptKey(1, runID, oldAttempt):     {RepositoryID: 1, RunID: runID, RunAttempt: oldAttempt, EventTime: old},
			attemptKey(1, runID, currentAttempt): {RepositoryID: 1, RunID: runID, RunAttempt: currentAttempt, EventTime: current},
		},
		gaps: []archive.Fact{
			{ID: "old", Kind: archive.FactCoverageGap, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &oldAttempt}, EventTime: unknownTime()},
			{ID: "current", Kind: archive.FactCoverageGap, Subject: archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &currentAttempt}, EventTime: unknownTime()},
			{ID: "repository-unknown", Kind: archive.FactCoverageGap, Subject: archive.FactSubject{RepositoryID: 1}, EventTime: unknownTime()},
		},
	}
	filtered := restrictIndexToWindows(idx, []model.EventInterval{window})
	if len(filtered.gaps) != 2 || filtered.gaps[0].ID != "current" || filtered.gaps[1].ID != "repository-unknown" {
		t.Fatalf("filtered gaps=%#v", filtered.gaps)
	}
}

func TestBuildMetadataConsumesCanonicalCapabilityCounts(t *testing.T) {
	capabilities := completeCoreCapabilities()
	for index := range capabilities {
		switch capabilities[index].Name {
		case "attempt_logs":
			capabilities[index].Status = archive.CapabilityGap
			capabilities[index].Details = map[string]string{"collected_count": "7", "gap_count": "2"}
		case "job_logs":
			capabilities[index].Status = archive.CapabilityHashOnly
			capabilities[index].Details = map[string]string{"collected_count": "5"}
		case "workflow_definitions":
			capabilities[index].Details = map[string]string{"definition_count": "4"}
		case "action_definitions":
			capabilities[index].Details = map[string]string{"parsed_count": "3"}
		case "repository_visibility":
			capabilities[index].Details = map[string]string{
				"requested_count": "5", "accessible_count": "3", "denied_count": "1",
				"unresolved_count": "1", "requested_total_known": "true",
			}
		case "runtime_permissions":
			capabilities[index].Status = archive.CapabilityNotCollected
			capabilities[index].Details = map[string]string{"reason": "permission-denied"}
		}
	}
	capabilities = append(capabilities,
		archive.Capability{Name: "artifacts", Status: archive.CapabilityGap, Details: map[string]string{"reason": "permission-denied"}},
		archive.Capability{Name: "raw_logs", Status: archive.CapabilityNotCollected, Details: map[string]string{"policy": "disabled"}},
	)
	snapshot := archive.Snapshot{Capabilities: capabilities}
	metadata := buildMetadata(snapshot, loadPack(t), time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), ModeInvestigate, index{repositories: map[model.RepositoryID]model.RepositorySubject{}, runs: map[string]archive.RunFact{}, attempts: map[string]archive.AttemptFact{}, jobs: map[string]archive.JobFact{}})
	coverage := metadata.Coverage
	if coverage.RepositoriesRequested != 5 || coverage.RepositoriesAccessible != 3 || coverage.RepositoriesDenied != 1 {
		t.Fatalf("repository coverage=%+v", coverage)
	}
	if coverage.LogsRetrieved != 12 || coverage.LogsMissing != 2 {
		t.Fatalf("log coverage=%+v", coverage)
	}
	if coverage.WorkflowDefinitionsRetrieved != 4 || coverage.ActionDefinitionsRetrieved != 3 {
		t.Fatalf("definition coverage=%+v", coverage)
	}
	if !coverage.Partial || len(coverage.OptionalCapabilitiesDenied) != 1 || coverage.OptionalCapabilitiesDenied[0] != "artifacts" {
		t.Fatalf("partial coverage=%+v", coverage)
	}
	if metadata.RawLogsRetained {
		t.Fatal("not-collected raw logs were reported retained")
	}
	for _, message := range coverage.IncompleteEvidence {
		if strings.Contains(message, "raw_logs") {
			t.Fatalf("raw_logs not-collected was treated as a coverage failure: %q", message)
		}
	}
}

func TestRawLogsNotCollectedAloneDoesNotMakeCoveragePartial(t *testing.T) {
	capabilities := append(completeCoreCapabilities(), archive.Capability{Name: "raw_logs", Status: archive.CapabilityNotCollected, Details: map[string]string{"policy": "disabled"}})
	metadata := buildMetadata(archive.Snapshot{Capabilities: capabilities}, loadPack(t), time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), ModeReplay, index{repositories: map[model.RepositoryID]model.RepositorySubject{}, runs: map[string]archive.RunFact{}, attempts: map[string]archive.AttemptFact{}, jobs: map[string]archive.JobFact{}})
	if metadata.Coverage.Partial || len(metadata.Coverage.IncompleteEvidence) != 0 || metadata.RawLogsRetained {
		t.Fatalf("metadata=%+v", metadata)
	}
}

func TestAggregateCoverageFactsBeatLatestCapabilityCounts(t *testing.T) {
	idx := index{}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	for number := 1; number <= 3; number++ {
		unitID := model.CoverageUnitID("cov1:" + strings.Repeat(string(rune('a'+number)), 64))
		idx.coverage = append(idx.coverage, archive.Fact{Coverage: &archive.CoverageFact{
			Unit:       model.CoverageUnit{ID: unitID, Kind: model.CoverageAttemptLog},
			Assessment: model.CoverageAssessment{EvidenceIDs: []model.EvidenceID{evidenceID}},
		}})
	}
	for number := 1; number <= 2; number++ {
		unitID := model.CoverageUnitID("cov1:" + strings.Repeat(string(rune('f'+number)), 64))
		idx.gaps = append(idx.gaps, archive.Fact{CoverageGap: &archive.CoverageGapFact{
			Unit:       model.CoverageUnit{ID: unitID, Kind: model.CoverageAttemptLog},
			Assessment: model.CoverageAssessment{EvidenceIDs: []model.EvidenceID{evidenceID}},
		}})
	}
	coverage := report.Coverage{RepositoriesRequested: 5, RepositoriesAccessible: 4, RepositoriesDenied: 1}
	incomplete := map[string]struct{}{}
	// This models a latest-row capability upsert from a later batch. It must
	// not erase the append-only aggregate facts retained from earlier batches.
	applyLogCapability(&coverage, incomplete, archive.Capability{
		Name: "attempt_logs", Status: archive.CapabilityStructuredOnly,
		Details: map[string]string{"collected_count": "1", "gap_count": "0"},
	}, idx)
	applyRepositoryVisibility(&coverage, incomplete, archive.Capability{
		Name: "repository_visibility", Status: archive.CapabilityStructuredOnly,
		Details: map[string]string{"requested_count": "1", "accessible_count": "1", "denied_count": "0"},
	})
	if coverage.LogsRetrieved != 3 || coverage.LogsMissing != 2 {
		t.Fatalf("aggregate log coverage was reduced by latest capability: %+v", coverage)
	}
	if coverage.RepositoriesRequested != 5 || coverage.RepositoriesAccessible != 4 || coverage.RepositoriesDenied != 1 {
		t.Fatalf("repository coverage was reduced by latest capability: %+v", coverage)
	}
}

func TestRepositoryVisibilityAcceptsExplicitUnknownOrganizationPopulation(t *testing.T) {
	coverage := report.Coverage{}
	incomplete := map[string]struct{}{}
	applyRepositoryVisibility(&coverage, incomplete, archive.Capability{
		Name: "repository_visibility", Status: archive.CapabilityStructuredOnly,
		Details: map[string]string{
			"accessible_count": "3", "enumerated_count": "3", "denied_count": "unknown",
			"unresolved_count": "unknown", "requested_total_known": "false",
		},
	})
	if coverage.RepositoriesAccessible != 3 || coverage.RepositoriesDenied != 0 {
		t.Fatalf("organization visibility = %+v", coverage)
	}
	for message := range incomplete {
		if strings.Contains(message, "invalid denied_count") || strings.Contains(message, "invalid unresolved_count") {
			t.Fatalf("explicit unknown population was called malformed: %s", message)
		}
	}
	if _, ok := incomplete["The total requested repository population is unknown because organization visibility may be partial."]; !ok {
		t.Fatalf("unknown population not surfaced as partial coverage: %v", incomplete)
	}
}

func TestDefinitionCoverageFactsBeatLatestCapabilityCounts(t *testing.T) {
	idx := index{}
	for number, kind := range []model.CoverageKind{
		model.CoverageWorkflowDefinition,
		model.CoverageWorkflowDefinition,
		model.CoverageActionDefinition,
		model.CoverageActionDefinition,
		model.CoverageActionDefinition,
	} {
		unitID := model.CoverageUnitID("cov1:" + strings.Repeat(string(rune('k'+number)), 64))
		idx.coverage = append(idx.coverage, archive.Fact{Coverage: &archive.CoverageFact{Unit: model.CoverageUnit{ID: unitID, Kind: kind}}})
	}
	incomplete := map[string]struct{}{}
	workflowCount, actionCount := 0, 0
	applyDefinitionCapability(&workflowCount, incomplete, archive.Capability{
		Name: "workflow_definitions", Status: archive.CapabilityStructuredOnly, Details: map[string]string{"definition_count": "1"},
	}, definitionCoverageCount(idx, model.CoverageWorkflowDefinition))
	applyDefinitionCapability(&actionCount, incomplete, archive.Capability{
		Name: "action_definitions", Status: archive.CapabilityStructuredOnly, Details: map[string]string{"parsed_count": "1"},
	}, definitionCoverageCount(idx, model.CoverageActionDefinition))
	if workflowCount != 2 || actionCount != 3 || len(incomplete) != 0 {
		t.Fatalf("definition coverage workflow=%d action=%d incomplete=%v", workflowCount, actionCount, incomplete)
	}
}

func TestGlobalRepositoryVisibilityGapDoesNotInventFindingRepository(t *testing.T) {
	pack := loadPack(t)
	indicator := pack.Pack.Spec.Indicators[0]
	component := pack.Pack.Spec.Components[0]
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{},
		runs:         map[string]archive.RunFact{}, attempts: map[string]archive.AttemptFact{}, jobs: map[string]archive.JobFact{},
		gaps: []archive.Fact{{
			Kind:    archive.FactCoverageGap,
			Subject: archive.FactSubject{},
			CoverageGap: &archive.CoverageGapFact{Assessment: model.CoverageAssessment{
				Status: model.CoverageGap,
				Gap:    &model.CoverageGapDetail{Reason: model.GapForbidden, Material: true},
			}},
		}},
	}
	findings, err := deriveIndicator(idx, pack, component, indicator, time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("global visibility gap invented findings: %#v", findings)
	}
}

func completeCoreCapabilities() []archive.Capability {
	result := make([]archive.Capability, 0, len(coreCapabilities()))
	for _, name := range coreCapabilities() {
		details := map[string]string{}
		if name == "repository_visibility" {
			details = map[string]string{"requested_count": "0", "accessible_count": "0", "denied_count": "0", "requested_total_known": "true"}
		}
		result = append(result, archive.Capability{Name: name, Status: archive.CapabilityStructuredOnly, Details: details})
	}
	return result
}

func boundedEvent(from, to time.Time, bounds model.IntervalBounds) model.EventInterval {
	start, end := model.MustInstant(from), model.MustInstant(to)
	return model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
}

func instantEventAt(when time.Time) model.EventInterval {
	instant := model.MustInstant(when)
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
}

func assertExecutedAttempts(t *testing.T, result Result, want []int) {
	t.Helper()
	var got []int
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.ConfirmedExecuted) {
			got = append(got, finding.RunAttempt)
		}
	}
	sort.Ints(got)
	if len(got) != len(want) {
		t.Fatalf("executed attempts=%v want=%v findings=%#v", got, want, result.Case.Findings)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("executed attempts=%v want=%v", got, want)
		}
	}
}

func ptr[T any](value T) *T { return &value }
