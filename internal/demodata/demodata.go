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
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/syntheticarchive"
)

var demoTime = time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)

const (
	consumerRepositoryID model.RepositoryID = 101
	consumerRepository                      = "cirewind-demo/consumer"
	affectedAction                          = "cirewind-fixtures/harmless-action"
	affectedWorkflow                        = "cirewind-fixtures/harmless-workflows"
)

// Snapshot returns a self-contained compact archive exercising exact runtime,
// downloaded-only, called-workflow, historical declaration, mutable ref,
// transitive, current-only, contradiction, missing-log, credential, OIDC,
// environment, runner, resource, rerun-attempt, matrix, local Action, and
// pull_request_target evidence boundaries.
func Snapshot(ctx context.Context) (archive.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return archive.Snapshot{}, err
	}
	b, err := syntheticarchive.New(syntheticarchive.Options{
		RepositoryID: consumerRepositoryID, Repository: consumerRepository,
		SessionID: "collection:synthetic-demo", When: demoTime,
	})
	if err != nil {
		return archive.Snapshot{}, err
	}
	when := b.When()
	repositorySlug := mustRepository(consumerRepository)
	if err := b.AddRepository(ctx, "public", "main"); err != nil {
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
		if err := b.AddExecution(ctx, scenario.run, scenario.attempt, scenario.job, scenario.event, scenario.workflow, scenario.name, scenario.status, scenario.result); err != nil {
			return archive.Snapshot{}, err
		}
	}
	// Attempt 2 belongs to the existing run 1001 and therefore contributes only
	// its attempt and distinct job facts. Emitting another run fact here could
	// create a fictitious per-attempt workflow identity.
	if err := b.AddAttemptJob(ctx, 1001, 2, 2101, "A-restored-known-good", "completed", "success"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddAttemptJob(ctx, 1011, 1, 2012, "M-matrix-windows", "completed", "success"); err != nil {
		return archive.Snapshot{}, err
	}

	affected := mustRepository(affectedAction)
	affectedOID := mustActionOID(strings.Repeat("1", 40))
	safeOID := mustActionOID(strings.Repeat("0", 40))
	callerOID := mustCallerOID(strings.Repeat("a", 40))
	calledOID := mustCalledOID(strings.Repeat("3", 40))

	// Exact lifecycle start (A) and completed preparation without lifecycle (D).
	if err := b.AddRuntime(ctx, execution(1001, 1, 2001), 2, model.ObservationLifecycleStarted, affected, affectedOID, "v1", "paired-rerun"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddRuntime(ctx, execution(1001, 2, 2101), 2, model.ObservationLifecycleStarted, affected, safeOID, "v1", "paired-rerun"); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddClosedCoverage(ctx, execution(1001, 2, 2101)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddRuntime(ctx, execution(1002, 1, 2002), 0, model.ObservationPreparationComplete, affected, affectedOID, "v1", ""); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddRuntime(ctx, execution(1008, 1, 2008), 2, model.ObservationLifecycleStarted, affected, affectedOID, "v1", ""); err != nil {
		return archive.Snapshot{}, err
	}
	contradictionRuntimeID, err := b.RuntimeFactID(execution(1008, 1, 2008), 2)
	if err != nil {
		return archive.Snapshot{}, err
	}

	// Exact called reusable-workflow identity (F), transitive composite (C),
	// mutable historical declaration (E), current-only snapshot, and exact
	// historical declaration (O).
	calledAttempt := model.RunAttemptIdentity{RepositoryID: consumerRepositoryID, RunID: 1003, RunAttempt: 2}
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow, Basis: archive.DefinitionRuntimeAttemptMetadata, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/reusable-caller.yml", TargetRepository: mustRepository(affectedWorkflow), TargetPath: ".github/workflows/reusable.yaml", DeclaredRef: "v1", TargetCalledWorkflowObjectID: &calledOID, AttemptExecution: &calledAttempt, ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyActionContainsAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/actions/wrapper/action.yml", CallerActionObjectID: &safeOID, TargetRepository: affected, DeclaredRef: "v1", TargetActionObjectID: &affectedOID, TransitiveDepth: 2, Execution: ptr(execution(1004, 1, 2004)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/mutable.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: affected, DeclaredRef: "v1", Execution: ptr(execution(1005, 1, 2005)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionCurrentSnapshot, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/current.yml", TargetRepository: affected, DeclaredRef: strings.Repeat("1", 40), TargetActionObjectID: &affectedOID, ContradictsFactIDs: []string{}, EventTime: unknownEvent()}); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/historical.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: affected, DeclaredRef: strings.Repeat("1", 40), TargetActionObjectID: &affectedOID, Execution: ptr(execution(1010, 1, 2010)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	// Local Action reconstruction is retained even though it does not match the
	// affected repository in this pack.
	localOID := mustActionOID(strings.Repeat("b", 40))
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyLocalActionResolvedTo, TargetKind: archive.DependencyTargetLocalAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/local.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: repositorySlug, TargetPath: ".github/actions/local", TargetActionObjectID: &localOID, Execution: ptr(execution(1009, 1, 2009)), ContradictsFactIDs: []string{}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	// Contradiction: the historical definition says safe A for the exact step,
	// while runner lifecycle evidence resolves affected B for that occurrence.
	contradictionStep := model.StepIdentity{Job: execution(1008, 1, 2008), APIStepNumber: ptr(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
	if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: consumerRepositoryID, CallerRepository: repositorySlug, CallerPath: ".github/workflows/contradiction.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: affected, DeclaredRef: strings.Repeat("0", 40), TargetActionObjectID: &safeOID, Execution: ptr(execution(1008, 1, 2008)), StepKey: contradictionStep, ContradictsFactIDs: []string{contradictionRuntimeID}, EventTime: instantEvent(when)}); err != nil {
		return archive.Snapshot{}, err
	}

	if err := b.AddMissingLog(ctx, execution(1007, 1, 2007)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddExposures(ctx, execution(1001, 1, 2001)); err != nil {
		return archive.Snapshot{}, err
	}
	if err := b.AddPendingEnvironment(ctx, execution(1005, 1, 2005)); err != nil {
		return archive.Snapshot{}, err
	}

	normalized, err := b.Snapshot("arc1:"+strings.Repeat("d", 64), syntheticarchive.DefaultCapabilities())
	if err != nil {
		return archive.Snapshot{}, err
	}
	if err := ValidateSnapshot(normalized); err != nil {
		return archive.Snapshot{}, fmt.Errorf("validate synthetic demo facts: %w", err)
	}
	return normalized, nil
}

func execution(run int64, attempt uint32, job int64) model.JobExecutionIdentity {
	return model.JobExecutionIdentity{RepositoryID: consumerRepositoryID, RunID: model.WorkflowRunID(run), RunAttempt: model.RunAttempt(attempt), JobID: model.JobID(job)}
}

func instantEvent(instant model.Instant) model.EventInterval {
	return syntheticarchive.InstantEvent(instant)
}

func unknownEvent() model.EventInterval { return syntheticarchive.UnknownEvent() }

func mustRepository(value string) model.RepositorySlug { return syntheticarchive.MustRepository(value) }

func mustActionOID(value string) model.ActionSourceObjectID {
	return syntheticarchive.MustActionOID(value)
}

func mustCallerOID(value string) model.CallerWorkflowObjectID {
	return syntheticarchive.MustCallerOID(value)
}

func mustCalledOID(value string) model.CalledWorkflowObjectID {
	return syntheticarchive.MustCalledOID(value)
}

func ptr[T any](value T) *T { return &value }
