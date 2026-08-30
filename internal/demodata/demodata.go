// Package demodata constructs the harmless deterministic archive used by the
// offline demonstration. All identities are synthetic and intentionally
// repetitive; they are not claims about a real incident.
package demodata

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

var demoTime = time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)

const (
	consumerRepositoryID model.RepositoryID = 101
	consumerRepository                      = "cirewind-demo/consumer"
	affectedAction                          = "cirewind-fixtures/harmless-action"
	affectedWorkflow                        = "cirewind-fixtures/harmless-workflows"
)

type builder struct {
	session  archive.CollectionSession
	evidence []evidence.Envelope
	facts    []archive.Fact
	nextReq  int
	when     model.Instant
}

// Snapshot returns a self-contained compact archive exercising exact runtime,
// downloaded-only, called-workflow, historical declaration, mutable ref,
// transitive, current-only, contradiction, missing-log, credential, OIDC,
// environment, runner, resource, rerun-attempt, matrix, local Action, and
// pull_request_target evidence boundaries.
func Snapshot(ctx context.Context) (archive.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archive.Snapshot{}, err
	}
	when := model.MustInstant(demoTime)
	b := &builder{when: when, session: archive.CollectionSession{
		ID: "collection:synthetic-demo", Mode: "fixture", AuthKind: "none", StartedAt: when, EndedAt: when,
		Scope:  archive.CollectionScope{Repositories: []model.RepositoryID{consumerRepositoryID}},
		Limits: map[string]uint64{"raw_log_bytes": 0, "watch_horizon_days": 65},
	}}
	repositorySlug := mustRepository(consumerRepository)
	repoEvidence, err := b.source(ctx, "repository", model.CoverageScope{RepositoryID: ptr(consumerRepositoryID)}, `{"repository":"cirewind-demo/consumer"}`)
	if err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.add(archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{repoEvidence}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: consumerRepositoryID, Name: repositorySlug}, Visibility: "public", DefaultBranch: "main"}}); err != nil {
		return archive.Snapshot{}, err
	}

	// Each scenario has a distinct run/attempt/job identity. Attempt 2 proves
	// reruns are never merged with their original attempt.
	scenarios := []struct {
		run, job int64
		attempt  uint32
		event    string
		workflow string
		name     string
		status   string
		result   string
	}{
		{1001, 2001, 1, "push", ".github/workflows/a-direct-executed.yml", "A-direct-executed", "completed", "success"},
		{1002, 2002, 1, "push", ".github/workflows/d-downloaded-skipped.yml", "D-downloaded-skipped", "completed", "success"},
		{1003, 2003, 2, "workflow_call", ".github/workflows/reusable-caller.yml", "F-rerun-called-workflow", "completed", "success"},
		{1004, 2004, 1, "workflow_call", ".github/workflows/c-transitive-composite.yml", "C-transitive-composite", "completed", "success"},
		{1005, 2005, 1, "push", ".github/workflows/mutable.yml", "E-mutable-window", "waiting", ""},
		{1007, 2007, 1, "push", ".github/workflows/n-missing-logs.yml", "N-missing-logs", "completed", "success"},
		{1008, 2008, 1, "push", ".github/workflows/contradiction.yml", "P-contradiction", "completed", "success"},
		{1009, 2009, 1, "pull_request_target", ".github/workflows/local.yml", "L-pull-request-target", "completed", "success"},
		{1010, 2010, 1, "push", ".github/workflows/historical.yml", "O-historical-definition", "completed", "success"},
		{1011, 2011, 1, "push", ".github/workflows/m-matrix-linux.yml", "M-matrix-linux", "completed", "success"},
	}
	for _, scenario := range scenarios {
		if err := b.addExecution(ctx, scenario.run, scenario.attempt, scenario.job, scenario.event, scenario.workflow, scenario.name, scenario.status, scenario.result); err != nil {
			return archive.Snapshot{}, err
		}
	}
	// Attempt 2 belongs to the existing run 1001 and therefore contributes only
	// its attempt and distinct job facts. Emitting another run fact here could
	// create a fictitious per-attempt workflow identity.
	if err := b.addAttemptJob(ctx, 1001, 2, 2101, "A-restored-known-good", "completed", "success"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addAttemptJob(ctx, 1011, 1, 2012, "M-matrix-windows", "completed", "success"); err != nil {
		return archive.Snapshot{}, err
	}

	affectedOID := mustActionOID(strings.Repeat("1", 40))
	safeOID := mustActionOID(strings.Repeat("0", 40))
	callerOID := mustCallerOID(strings.Repeat("a", 40))
	calledOID := mustCalledOID(strings.Repeat("3", 40))

	// Exact lifecycle start (A) and completed preparation without lifecycle (D).
	if err := b.addRuntime(ctx, execution(1001, 1, 2001), 2, model.ObservationLifecycleStarted, affectedOID, "v1", "paired-rerun"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addRuntime(ctx, execution(1001, 2, 2101), 2, model.ObservationLifecycleStarted, safeOID, "v1", "paired-rerun"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addClosedCoverage(ctx, execution(1001, 2, 2101)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addRuntime(ctx, execution(1002, 1, 2002), 0, model.ObservationPreparationComplete, affectedOID, "v1", ""); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addRuntime(ctx, execution(1008, 1, 2008), 2, model.ObservationLifecycleStarted, affectedOID, "v1", ""); err != nil {
		return archive.Snapshot{}, err
	}
	contradictionRuntimeID, err := b.runtimeFactID(execution(1008, 1, 2008), 2)
	if err != nil {
		return archive.Snapshot{}, err
	}

	// Exact called reusable-workflow identity (F), transitive composite (C),
	// mutable historical declaration (E), current-only snapshot, and exact
	// historical declaration (O).
	calledAttempt := model.RunAttemptIdentity{RepositoryID: consumerRepositoryID, RunID: 1003, RunAttempt: 2}
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow, Basis: archive.DefinitionRuntimeAttemptMetadata, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/reusable-caller.yml", TargetRepository: mustRepository(affectedWorkflow), TargetPath: ".github/workflows/reusable.yaml", DeclaredRef: "v1", TargetCalledWorkflowObjectID: &calledOID, AttemptExecution: &calledAttempt, ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyActionContainsAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/actions/wrapper/action.yml", CallerActionObjectID: &safeOID, TargetRepository: mustRepository(affectedAction), DeclaredRef: "v1", TargetActionObjectID: &affectedOID, TransitiveDepth: 2, Execution: ptr(execution(1004, 1, 2004)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/mutable.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: mustRepository(affectedAction), DeclaredRef: "v1", Execution: ptr(execution(1005, 1, 2005)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionCurrentSnapshot, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/current.yml", TargetRepository: mustRepository(affectedAction), DeclaredRef: strings.Repeat("1", 40), TargetActionObjectID: &affectedOID, ContradictsFactIDs: []string{}, EventTime: unknownEvent()}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/historical.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: mustRepository(affectedAction), DeclaredRef: strings.Repeat("1", 40), TargetActionObjectID: &affectedOID, Execution: ptr(execution(1010, 1, 2010)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	// Local Action reconstruction is retained even though it does not match the
	// affected repository in this pack.
	localOID := mustActionOID(strings.Repeat("b", 40))
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyLocalActionResolvedTo, TargetKind: archive.DependencyTargetLocalAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/local.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: repositorySlug, TargetPath: ".github/actions/local", TargetActionObjectID: &localOID, Execution: ptr(execution(1009, 1, 2009)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	// Contradiction: the historical definition says safe A for the exact step,
	// while runner lifecycle evidence resolves affected B for that occurrence.
	contradictionStep := model.StepIdentity{Job: execution(1008, 1, 2008), APIStepNumber: ptr(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
	if err := b.addDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/contradiction.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: mustRepository(affectedAction), DeclaredRef: strings.Repeat("0", 40), TargetActionObjectID: &safeOID, Execution: ptr(execution(1008, 1, 2008)), StepKey: contradictionStep, ContradictsFactIDs: []string{contradictionRuntimeID}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	if err := b.addMissingLog(ctx, execution(1007, 1, 2007)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addExposures(ctx, execution(1001, 1, 2001)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.addPendingEnvironment(ctx, execution(1005, 1, 2005)); err != nil {
		return archive.Snapshot{}, err
	}

	metadata := archive.SnapshotMetadata{SchemaVersion: archive.SnapshotSchemaVersion, StoreSchemaVersion: store.SchemaVersion, ArchiveID: "arc1:" + strings.Repeat("d", 64), CreatedAt: when}
	snapshot := archive.Snapshot{Metadata: metadata, Collections: []archive.CollectionSession{b.session}, Payloads: []archive.Payload{}, Evidence: b.evidence, Facts: b.facts,
		Capabilities: []archive.Capability{
			{Name: "action_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "synthetic-v2", Details: map[string]string{}},
			{Name: "attempt_logs", Status: archive.CapabilityStructuredOnly, ExtractorVersion: logparse.GrammarVersion, Details: map[string]string{"raw": "discarded"}},
			{Name: "workflow_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "synthetic-v2", Details: map[string]string{}},
		}, Checkpoints: []archive.Checkpoint{}}
	normalized, err := archive.NormalizeSnapshot(snapshot)
	if err != nil {
		return archive.Snapshot{}, err
	}
	if err := ValidateSnapshot(normalized); err != nil {
		return archive.Snapshot{}, fmt.Errorf("validate synthetic demo facts: %w", err)
	}
	return normalized, nil
}

func (b *builder) addExecution(ctx context.Context, run int64, attempt uint32, job int64, eventType, workflow, name, status, conclusion string) error {
	runID, attemptID, jobID := model.WorkflowRunID(run), model.RunAttempt(attempt), model.JobID(job)
	workflowPath := mustWorkflowPath(workflow)
	scope := model.CoverageScope{RepositoryID: ptr(consumerRepositoryID), RunID: &runID, RunAttempt: &attemptID, JobID: &jobID}
	evidenceID, err := b.source(ctx, fmt.Sprintf("run-%d-attempt-%d-job-%d", run, attempt, job), scope, fmt.Sprintf(`{"run":%d,"attempt":%d,"job":%d}`, run, attempt, job))
	if err != nil {
		return err
	}
	event := instantEvent(b.when)
	for _, fact := range []archive.Fact{
		{Kind: archive.FactRun, EvidenceIDs: []model.EvidenceID{evidenceID}, Run: &archive.RunFact{RepositoryID: consumerRepositoryID, RunID: runID, WorkflowPath: &workflowPath, EventType: eventType, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{evidenceID}, Attempt: &archive.AttemptFact{RepositoryID: consumerRepositoryID, RunID: runID, RunAttempt: attemptID, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{evidenceID}, Job: &archive.JobFact{Execution: model.JobExecutionIdentity{RepositoryID: consumerRepositoryID, RunID: runID, RunAttempt: attemptID, JobID: jobID}, DisplayName: name, Status: status, Conclusion: conclusion, EventTime: event}},
	} {
		if err := b.add(fact); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) addAttemptJob(ctx context.Context, run int64, attempt uint32, job int64, name, status, conclusion string) error {
	runID, attemptID, jobID := model.WorkflowRunID(run), model.RunAttempt(attempt), model.JobID(job)
	scope := model.CoverageScope{RepositoryID: ptr(consumerRepositoryID), RunID: &runID, RunAttempt: &attemptID, JobID: &jobID}
	evidenceID, err := b.source(ctx, fmt.Sprintf("run-%d-attempt-%d-job-%d", run, attempt, job), scope, fmt.Sprintf(`{"run":%d,"attempt":%d,"job":%d}`, run, attempt, job))
	if err != nil {
		return err
	}
	event := instantEvent(b.when)
	for _, fact := range []archive.Fact{
		{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{evidenceID}, Attempt: &archive.AttemptFact{RepositoryID: consumerRepositoryID, RunID: runID, RunAttempt: attemptID, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{evidenceID}, Job: &archive.JobFact{Execution: model.JobExecutionIdentity{RepositoryID: consumerRepositoryID, RunID: runID, RunAttempt: attemptID, JobID: jobID}, DisplayName: name, Status: status, Conclusion: conclusion, EventTime: event}},
	} {
		if err := b.add(fact); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) addRuntime(ctx context.Context, execution model.JobExecutionIdentity, stepNumber int32, kind model.RuntimeObservationKind, oid model.ActionSourceObjectID, declaredRef, subpath string) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "runtime-"+execution.String()+"-"+string(kind), scope, `{"synthetic":"runner-control"}`)
	if err != nil {
		return err
	}
	observation := model.RuntimeActionObservation{Kind: kind, Execution: execution, ActionRepository: mustRepository(affectedAction), ActionSubpath: subpath, DeclaredRef: declaredRef, SourceObjectID: &oid, EventTime: instantEvent(b.when), SourceEvidenceIDs: []model.EvidenceID{evidenceID}, SourceSpan: model.SourceSpan{ByteStart: 0, ByteEnd: 32, LineStart: 1, LineEnd: 1}, ExtractorName: "synthetic-runner-log", ExtractorVersion: logparse.GrammarVersion, RulesetSHA256: strings.Repeat("e", 64)}
	if stepNumber > 0 {
		number := model.APIStepNumber(stepNumber)
		observation.Step = &model.StepIdentity{Job: execution, APIStepNumber: &number, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	}
	observation.ID, err = evidence.NewRuntimeObservationID(observation)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: observation}})
}

func (b *builder) runtimeFactID(execution model.JobExecutionIdentity, stepNumber model.APIStepNumber) (string, error) {
	for index := len(b.facts) - 1; index >= 0; index-- {
		fact := b.facts[index]
		if fact.ActionOccurrence == nil || fact.ActionOccurrence.Observation.Execution != execution || fact.ActionOccurrence.Observation.Step == nil {
			continue
		}
		step := fact.ActionOccurrence.Observation.Step
		if step.APIStepNumber != nil && *step.APIStepNumber == stepNumber {
			return fact.ID, nil
		}
	}
	return "", fmt.Errorf("runtime fact for %s step %d is absent", execution, stepNumber)
}

func (b *builder) addDependency(ctx context.Context, dependency archive.DependencyFact) error {
	fact, err := b.normalizedDependency(ctx, dependency)
	if err != nil {
		return err
	}
	b.facts = append(b.facts, fact)
	return nil
}

func (b *builder) normalizedDependency(ctx context.Context, dependency archive.DependencyFact) (archive.Fact, error) {
	scope := model.CoverageScope{RepositoryID: ptr(dependency.CallerRepositoryID)}
	if dependency.Execution != nil {
		scope.RunID, scope.RunAttempt, scope.JobID = ptr(dependency.Execution.RunID), ptr(dependency.Execution.RunAttempt), ptr(dependency.Execution.JobID)
	}
	evidenceID, err := b.source(ctx, "dependency-"+dependency.CallerPath+"-"+dependency.DeclaredRef+fmt.Sprint(b.nextReq), scope, `{"synthetic":"historical-definition"}`)
	if err != nil {
		return archive.Fact{}, err
	}
	return archive.NormalizeFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{evidenceID}, Dependency: &dependency})
}

func (b *builder) addMissingLog(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "missing-log-"+execution.String(), scope, `{"status":404,"classification":"retention_or_deletion"}`)
	if err != nil {
		return err
	}
	unit := model.CoverageUnit{Kind: model.CoverageJobLog, Scope: scope, LogicalKey: "job-log:" + execution.String(), RequiredForNegative: true}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{UnitID: unit.ID, Status: model.CoverageGap, ExpectedCount: &one, Gap: &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: true, SanitizedMessage: "synthetic retained log is unavailable"}, EvidenceIDs: []model.EvidenceID{evidenceID}}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactCoverageGap, EvidenceIDs: []model.EvidenceID{evidenceID}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}})
}

func (b *builder) addClosedCoverage(ctx context.Context, execution model.JobExecutionIdentity) error {
	for _, kind := range []model.CoverageKind{model.CoverageJobLog, model.CoverageParserGrammar} {
		if err := b.addClosedCoverageKind(ctx, execution, kind); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) addClosedCoverageKind(ctx context.Context, execution model.JobExecutionIdentity, kind model.CoverageKind) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "closed-"+strings.ToLower(string(kind))+"-"+execution.String(), scope, `{"status":200,"complete":true,"synthetic":true}`)
	if err != nil {
		return err
	}
	unit := model.CoverageUnit{Kind: kind, Scope: scope, LogicalKey: strings.ToLower(string(kind)) + ":" + execution.String(), RequiredForNegative: true}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{UnitID: unit.ID, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1, EvidenceIDs: []model.EvidenceID{evidenceID}}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: []model.EvidenceID{evidenceID}, Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}})
}

func (b *builder) addExposures(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "exposure-"+execution.String(), scope, `{"synthetic":"credential-and-runner-context"}`)
	if err != nil {
		return err
	}
	secret, _ := model.NewSecretName("FAKE_DEPLOY_KEY")
	stepNumber := model.APIStepNumber(2)
	affectedStep := model.StepIdentity{Job: execution, APIStepNumber: &stepNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
	exposures := []archive.ExposureFact{
		{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "contents", Access: "write", Conclusion: "The affected lifecycle could use the runtime-observed contents: write permission; no repository write was proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: instantEvent(b.when)},
		{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "id-token", Access: "write", Conclusion: "The affected lifecycle had the runtime-observed id-token: write permission; this typed permission supports only the bounded OIDC capability inference.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: instantEvent(b.when)},
		{Execution: execution, StepKey: affectedStep, Credential: &model.CredentialExposure{Kind: model.ExposureSecretPassedToStep, Basis: model.ExposureBasisHistoricalDefinitionFlow, SecretName: &secret, Conclusion: "The historical definition passed the fake named secret to the affected step; no value, read, or exfiltration was proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: instantEvent(b.when)},
		{Execution: execution, Runner: &archive.RunnerContextFact{Classification: "self-hosted", RunnerName: "synthetic-runner", RunnerGroup: "fixture", Labels: []string{"linux", "self-hosted"}}, EventTime: instantEvent(b.when)},
		{Execution: execution, Resource: &model.ResourceExposure{Kind: model.ResourceDeployment, ResourceID: "synthetic-deployment", Correlation: model.CorrelationObservedAfter, Conclusion: "A synthetic deployment was observed after the affected step; causation was not proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: instantEvent(b.when)},
	}
	for _, exposureFact := range exposures {
		if err := b.add(archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID}, Exposure: &exposureFact}); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) addPendingEnvironment(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "environment-"+execution.String(), scope, `{"synthetic":"pending-environment-gate"}`)
	if err != nil {
		return err
	}
	exposure := archive.ExposureFact{
		Execution: execution,
		Environment: &archive.EnvironmentEligibilityFact{
			EnvironmentName: "production-fixture",
			GateState:       "pending",
			JobStarted:      false,
			SecretNames:     []model.SecretName{},
		},
		EventTime: instantEvent(b.when),
	}
	return b.add(archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID}, Exposure: &exposure})
}

func (b *builder) source(ctx context.Context, name string, scope model.CoverageScope, content string) (model.EvidenceID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.nextReq++
	envelope, err := evidence.NewEnvelope(evidence.EnvelopeInput{
		Kind: evidence.SourceOtherBounded, CanonicalSourceID: "synthetic/" + name, Provider: evidence.ProviderCIRewind,
		RequestParameters: evidence.RequestParameters{}, Scope: scope, EventTime: instantEvent(b.when), MediaType: "application/json",
		SourceBytes: []byte(content), Complete: true,
		Extractor:         evidence.ExtractorDescriptor{Name: "synthetic-fixture", Version: "v2", RulesetSHA256: strings.Repeat("e", 64)},
		Redaction:         evidence.RedactionDescriptor{Status: evidence.RedactionStructuredAllowlist, PolicyVersion: "synthetic-v2"},
		CollectionSession: b.session.ID, RequestID: model.RequestID(fmt.Sprintf("request:synthetic:%04d", b.nextReq)),
		CollectionTime: model.CollectionWindow{StartedAt: b.when, EndedAt: b.when},
	})
	if err != nil {
		return "", err
	}
	b.evidence = append(b.evidence, envelope)
	return envelope.Evidence.ID, nil
}

func (b *builder) add(fact archive.Fact) error {
	normalized, err := archive.NormalizeFact(fact)
	if err != nil {
		return err
	}
	for _, existing := range b.facts {
		if existing.ID == normalized.ID {
			return nil
		}
	}
	b.facts = append(b.facts, normalized)
	return nil
}

func execution(run int64, attempt uint32, job int64) model.JobExecutionIdentity {
	return model.JobExecutionIdentity{RepositoryID: consumerRepositoryID, RunID: model.WorkflowRunID(run), RunAttempt: model.RunAttempt(attempt), JobID: model.JobID(job)}
}

func instantEvent(instant model.Instant) model.EventInterval {
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
}

func unknownEvent() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}

func mustRepository(value string) model.RepositorySlug {
	result, err := model.NewRepositorySlug(value)
	if err != nil {
		panic(err)
	}
	return result
}

func mustWorkflowPath(value string) model.WorkflowPath {
	result, err := model.NewWorkflowPath(value)
	if err != nil {
		panic(err)
	}
	return result
}

func mustActionOID(value string) model.ActionSourceObjectID {
	git, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		panic(err)
	}
	result, err := model.NewActionSourceObjectID(git)
	if err != nil {
		panic(err)
	}
	return result
}

func mustCallerOID(value string) model.CallerWorkflowObjectID {
	git, _ := model.NewGitObjectID(model.HashSHA1, value)
	result, _ := model.NewCallerWorkflowObjectID(git)
	return result
}

func mustCalledOID(value string) model.CalledWorkflowObjectID {
	git, _ := model.NewGitObjectID(model.HashSHA1, value)
	result, _ := model.NewCalledWorkflowObjectID(git)
	return result
}

func ptr[T any](value T) *T { return &value }
