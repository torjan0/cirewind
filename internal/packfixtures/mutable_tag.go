package packfixtures

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/syntheticarchive"
)

// mutableTagSpec parameterizes the scenario family for an incident in which a
// mutable Action tag pointed at a malicious commit during a published window.
// Only the affected Action, its malicious object, the declared refs, and the
// window are real; every consumer, run, log, and secret name is synthetic.
type mutableTagSpec struct {
	consumerID   model.RepositoryID
	consumer     string
	action       string
	maliciousSHA string
	// declaredRef is the mutable ref the synthetic workflows declared.
	declaredRef string
	// inside, before, lastInside, and after are instants inside the window,
	// just before its start, inside its final unit of precision, and exactly
	// at its exclusive end.
	inside, before, lastInside, after time.Time
	analysisTime                      time.Time
}

// mutableTagScenarios composes the twelve scenarios of the family: exact
// execution, download-only, the window on both sides of each boundary, a
// retained-log gap, a current-only reference, a transitive wrapper, a
// runtime/definition contradiction, a full-SHA declaration, and a rerun
// attempt that resolved a different object. The two boundary scenarios carry
// an explicit retained-log gap: with complete coverage and no runtime
// observation the derivation reports an evidence gap without a gap code,
// which the oracle rejects, so that engine behavior is recorded for review
// rather than encoded here.
func mutableTagScenarios(ctx context.Context, spec mutableTagSpec) ([]Scenario, error) {
	affected := syntheticarchive.MustRepository(spec.action)
	maliciousOID := syntheticarchive.MustActionOID(spec.maliciousSHA)
	otherOID := syntheticarchive.MustActionOID(strings.Repeat("0", 40))
	wrapperOID := syntheticarchive.MustActionOID(strings.Repeat("b", 40))
	callerOID := syntheticarchive.MustCallerOID(strings.Repeat("a", 40))
	ref := spec.declaredRef

	type build func(ctx context.Context, b *syntheticarchive.Builder) error
	scenario := func(id string, when time.Time, forbidden []ForbiddenState, compose build) (Scenario, error) {
		b, err := syntheticarchive.New(syntheticarchive.Options{
			RepositoryID: spec.consumerID, Repository: spec.consumer,
			SessionID: model.CollectionSessionID("collection:fixture-" + id), When: when,
		})
		if err != nil {
			return Scenario{}, err
		}
		if err := b.AddRepository(ctx, "public", "main"); err != nil {
			return Scenario{}, err
		}
		if err := compose(ctx, b); err != nil {
			return Scenario{}, fmt.Errorf("scenario %s: %w", id, err)
		}
		snapshot, err := b.Snapshot("arc1:"+strings.Repeat("f", 64), syntheticarchive.DefaultCapabilities())
		if err != nil {
			return Scenario{}, fmt.Errorf("scenario %s: %w", id, err)
		}
		return Scenario{ID: id, Snapshot: snapshot, AnalysisTime: spec.analysisTime, Forbidden: forbidden}, nil
	}
	noExecution := []ForbiddenState{{State: model.ConfirmedExecuted, Rationale: "No lifecycle start for the malicious object was observed in this scenario; download or declaration evidence must never promote to confirmed execution."}}
	noWindow := []ForbiddenState{
		{State: model.RunInWindowMutableRef, Rationale: "The run is outside the minute-precision window, so the mutable ref cannot be an in-window finding."},
		{State: model.NoMatchConfirmed, Rationale: "The retained log is unavailable, so the run cannot be cleared."},
	}

	declared := func(b *syntheticarchive.Builder, run, job int64, workflow string, declaredRef string, target *model.ActionSourceObjectID, basis archive.DefinitionBasis, event model.EventInterval) error {
		execution := b.Execution(run, 1, job)
		dependency := archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: basis, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: workflow, TargetRepository: affected, DeclaredRef: declaredRef, TargetActionObjectID: target, ContradictsFactIDs: []string{}, EventTime: event}
		if basis != archive.DefinitionCurrentSnapshot {
			dependency.CallerWorkflowObjectID = &callerOID
			dependency.Execution = &execution
		}
		return b.AddDependency(ctx, dependency)
	}

	specs := []struct {
		id        string
		when      time.Time
		forbidden []ForbiddenState
		compose   build
	}{
		{"exact-execution-in-window", spec.inside, nil, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3001, 1, 4001, "push", ".github/workflows/lint.yml", "lint", "completed", "success"); err != nil {
				return err
			}
			if err := b.AddRuntime(ctx, b.Execution(3001, 1, 4001), 2, model.ObservationLifecycleStarted, affected, maliciousOID, ref, ""); err != nil {
				return err
			}
			return b.AddExposures(ctx, b.Execution(3001, 1, 4001))
		}},
		{"download-only", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3002, 1, 4002, "push", ".github/workflows/lint-skipped.yml", "lint-skipped", "completed", "success"); err != nil {
				return err
			}
			return b.AddRuntime(ctx, b.Execution(3002, 1, 4002), 0, model.ObservationPreparationComplete, affected, maliciousOID, ref, "")
		}},
		{"mutable-ref-in-window", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3003, 1, 4003, "push", ".github/workflows/mutable.yml", "mutable", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3003, 4003, ".github/workflows/mutable.yml", ref, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"mutable-ref-before-window", spec.before, append(noExecution, noWindow...), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3004, 1, 4004, "push", ".github/workflows/mutable.yml", "mutable-before", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3004, 4004, ".github/workflows/mutable.yml", ref, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3004, 1, 4004))
		}},
		{"mutable-ref-last-minute", spec.lastInside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3005, 1, 4005, "push", ".github/workflows/mutable.yml", "mutable-last-minute", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3005, 4005, ".github/workflows/mutable.yml", ref, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"mutable-ref-after-window", spec.after, append(noExecution, noWindow...), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3006, 1, 4006, "push", ".github/workflows/mutable.yml", "mutable-after", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3006, 4006, ".github/workflows/mutable.yml", ref, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3006, 1, 4006))
		}},
		{"missing-log", spec.inside, append(noExecution, ForbiddenState{State: model.NoMatchConfirmed, Rationale: "A retained-log gap can never become a clean result."}), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3007, 1, 4007, "push", ".github/workflows/mutable.yml", "mutable-missing-log", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3007, 4007, ".github/workflows/mutable.yml", ref, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3007, 1, 4007))
		}},
		{"current-reference-only", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			return declared(b, 0, 0, ".github/workflows/current.yml", spec.maliciousSHA, &maliciousOID, archive.DefinitionCurrentSnapshot, syntheticarchive.UnknownEvent())
		}},
		{"transitive-wrapper", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3009, 1, 4009, "workflow_call", ".github/workflows/wrapper.yml", "wrapper", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3009, 1, 4009)
			return b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyActionContainsAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: ".github/actions/wrapper/action.yml", CallerActionObjectID: &wrapperOID, TargetRepository: affected, DeclaredRef: ref, TargetActionObjectID: &maliciousOID, TransitiveDepth: 2, Execution: &execution, ContradictsFactIDs: []string{}, EventTime: syntheticarchive.InstantEvent(b.When())})
		}},
		{"contradiction", spec.inside, nil, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3010, 1, 4010, "push", ".github/workflows/contradiction.yml", "contradiction", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3010, 1, 4010)
			if err := b.AddRuntime(ctx, execution, 2, model.ObservationLifecycleStarted, affected, maliciousOID, ref, ""); err != nil {
				return err
			}
			runtimeID, err := b.RuntimeFactID(execution, 2)
			if err != nil {
				return err
			}
			step := model.StepIdentity{Job: execution, APIStepNumber: ptr(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
			return b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: ".github/workflows/contradiction.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: affected, DeclaredRef: strings.Repeat("0", 40), TargetActionObjectID: &otherOID, Execution: &execution, StepKey: step, ContradictsFactIDs: []string{runtimeID}, EventTime: syntheticarchive.InstantEvent(b.When())})
		}},
		{"declared-at-run-sha", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3011, 1, 4011, "push", ".github/workflows/historical.yml", "historical", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3011, 4011, ".github/workflows/historical.yml", spec.maliciousSHA, &maliciousOID, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"rerun-resolved-other-object", spec.inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3012, 2, 4012, "push", ".github/workflows/lint.yml", "lint-rerun", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3012, 2, 4012)
			if err := b.AddRuntime(ctx, execution, 2, model.ObservationLifecycleStarted, affected, otherOID, ref, ""); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, execution)
		}},
	}
	scenarios := make([]Scenario, 0, len(specs))
	for _, item := range specs {
		built, err := scenario(item.id, item.when, item.forbidden, item.compose)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, built)
	}
	return scenarios, nil
}

func ptr[T any](value T) *T { return &value }
