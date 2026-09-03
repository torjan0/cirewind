// Package packfixtures composes deterministic synthetic archive snapshots that
// exercise a real incident pack's matching fields. Every run, repository
// other than the affected component, log, secret name, and timestamp is
// synthetic; only the incident's own component identity, object, ref, and
// window are real. No fixture contains payload content or victim data.
package packfixtures

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/syntheticarchive"
)

// ForbiddenState is a finding state a scenario must never derive.
type ForbiddenState struct {
	State     model.FindingState
	Rationale string
}

// Scenario is one fixture snapshot with its analysis instant and the states
// it must never produce.
type Scenario struct {
	ID           string
	Snapshot     archive.Snapshot
	AnalysisTime time.Time
	Forbidden    []ForbiddenState
}

// Generator builds the scenario set for one incident pack version.
type Generator func(ctx context.Context) ([]Scenario, error)

var generators = map[string]Generator{
	"CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0": reviewdogActionSetup2025,
}

// Generate returns the scenarios registered for an incident pack version.
func Generate(ctx context.Context, incidentID, packVersion string) ([]Scenario, error) {
	generator, ok := generators[incidentID+"/"+packVersion]
	if !ok {
		return nil, fmt.Errorf("no fixture generator is registered for %s %s", incidentID, packVersion)
	}
	scenarios, err := generator(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].ID < scenarios[j].ID })
	return scenarios, nil
}

// Registered lists the incident pack versions with fixture generators.
func Registered() []string {
	keys := make([]string, 0, len(generators))
	for key := range generators {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

const (
	reviewdogConsumerID     model.RepositoryID = 501
	reviewdogConsumer                          = "cirewind-fixtures/reviewdog-consumer"
	reviewdogAffectedAction                    = "reviewdog/action-setup"
	reviewdogMaliciousSHA                      = "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"
	reviewdogAnalysisTime                      = "2025-03-20T00:00:00Z"
)

// reviewdogActionSetup2025 exercises the CIR-REVIEWDOG-ACTION-SETUP-2025 pack:
// exact execution, download-only, the minute-precision window on both sides
// of each boundary, a missing log, a current-only reference, a transitive
// wrapper, a runtime/definition contradiction, a full-SHA declaration, and a
// rerun attempt that resolved a different object. The two boundary scenarios
// carry an explicit retained-log gap: with complete coverage and no runtime
// observation the derivation reports an evidence gap without a gap code,
// which the oracle rejects, so that engine behavior is recorded for review
// rather than encoded here.
func reviewdogActionSetup2025(ctx context.Context) ([]Scenario, error) {
	analysisTime, err := time.Parse(time.RFC3339, reviewdogAnalysisTime)
	if err != nil {
		return nil, err
	}
	inside := time.Date(2025, 3, 11, 19, 10, 0, 0, time.UTC)
	before := time.Date(2025, 3, 11, 18, 41, 59, 0, time.UTC)
	lastMinute := time.Date(2025, 3, 11, 20, 31, 30, 0, time.UTC)
	after := time.Date(2025, 3, 11, 20, 32, 0, 0, time.UTC)
	affected := syntheticarchive.MustRepository(reviewdogAffectedAction)
	maliciousOID := syntheticarchive.MustActionOID(reviewdogMaliciousSHA)
	otherOID := syntheticarchive.MustActionOID(strings.Repeat("0", 40))
	wrapperOID := syntheticarchive.MustActionOID(strings.Repeat("b", 40))
	callerOID := syntheticarchive.MustCallerOID(strings.Repeat("a", 40))

	type build func(ctx context.Context, b *syntheticarchive.Builder) error
	scenario := func(id string, when time.Time, forbidden []ForbiddenState, compose build) (Scenario, error) {
		b, err := syntheticarchive.New(syntheticarchive.Options{
			RepositoryID: reviewdogConsumerID, Repository: reviewdogConsumer,
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
		return Scenario{ID: id, Snapshot: snapshot, AnalysisTime: analysisTime, Forbidden: forbidden}, nil
	}
	noExecution := []ForbiddenState{{State: model.ConfirmedExecuted, Rationale: "No lifecycle start for the malicious object was observed in this scenario; download or declaration evidence must never promote to confirmed execution."}}
	noWindow := []ForbiddenState{
		{State: model.RunInWindowMutableRef, Rationale: "The run is outside the minute-precision window, so the mutable ref cannot be an in-window finding."},
		{State: model.NoMatchConfirmed, Rationale: "The retained log is unavailable, so the run cannot be cleared."},
	}

	declared := func(b *syntheticarchive.Builder, run, job int64, workflow string, ref string, target *model.ActionSourceObjectID, basis archive.DefinitionBasis, event model.EventInterval) error {
		execution := b.Execution(run, 1, job)
		dependency := archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: basis, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: workflow, TargetRepository: affected, DeclaredRef: ref, TargetActionObjectID: target, ContradictsFactIDs: []string{}, EventTime: event}
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
		{"exact-execution-in-window", inside, nil, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3001, 1, 4001, "push", ".github/workflows/lint.yml", "lint", "completed", "success"); err != nil {
				return err
			}
			if err := b.AddRuntime(ctx, b.Execution(3001, 1, 4001), 2, model.ObservationLifecycleStarted, affected, maliciousOID, "v1", ""); err != nil {
				return err
			}
			return b.AddExposures(ctx, b.Execution(3001, 1, 4001))
		}},
		{"download-only", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3002, 1, 4002, "push", ".github/workflows/lint-skipped.yml", "lint-skipped", "completed", "success"); err != nil {
				return err
			}
			return b.AddRuntime(ctx, b.Execution(3002, 1, 4002), 0, model.ObservationPreparationComplete, affected, maliciousOID, "v1", "")
		}},
		{"mutable-ref-in-window", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3003, 1, 4003, "push", ".github/workflows/mutable.yml", "mutable", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3003, 4003, ".github/workflows/mutable.yml", "v1", nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"mutable-ref-before-window", before, append(noExecution, noWindow...), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3004, 1, 4004, "push", ".github/workflows/mutable.yml", "mutable-before", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3004, 4004, ".github/workflows/mutable.yml", "v1", nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3004, 1, 4004))
		}},
		{"mutable-ref-last-minute", lastMinute, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3005, 1, 4005, "push", ".github/workflows/mutable.yml", "mutable-last-minute", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3005, 4005, ".github/workflows/mutable.yml", "v1", nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"mutable-ref-after-window", after, append(noExecution, noWindow...), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3006, 1, 4006, "push", ".github/workflows/mutable.yml", "mutable-after", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3006, 4006, ".github/workflows/mutable.yml", "v1", nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3006, 1, 4006))
		}},
		{"missing-log", inside, append(noExecution, ForbiddenState{State: model.NoMatchConfirmed, Rationale: "A retained-log gap can never become a clean result."}), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3007, 1, 4007, "push", ".github/workflows/mutable.yml", "mutable-missing-log", "completed", "success"); err != nil {
				return err
			}
			if err := declared(b, 3007, 4007, ".github/workflows/mutable.yml", "v1", nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(3007, 1, 4007))
		}},
		{"current-reference-only", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			return declared(b, 0, 0, ".github/workflows/current.yml", reviewdogMaliciousSHA, &maliciousOID, archive.DefinitionCurrentSnapshot, syntheticarchive.UnknownEvent())
		}},
		{"transitive-wrapper", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3009, 1, 4009, "workflow_call", ".github/workflows/wrapper.yml", "wrapper", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3009, 1, 4009)
			return b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyActionContainsAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: ".github/actions/wrapper/action.yml", CallerActionObjectID: &wrapperOID, TargetRepository: affected, DeclaredRef: "v1", TargetActionObjectID: &maliciousOID, TransitiveDepth: 2, Execution: &execution, ContradictsFactIDs: []string{}, EventTime: syntheticarchive.InstantEvent(b.When())})
		}},
		{"contradiction", inside, nil, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3010, 1, 4010, "push", ".github/workflows/contradiction.yml", "contradiction", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3010, 1, 4010)
			if err := b.AddRuntime(ctx, execution, 2, model.ObservationLifecycleStarted, affected, maliciousOID, "v1", ""); err != nil {
				return err
			}
			runtimeID, err := b.RuntimeFactID(execution, 2)
			if err != nil {
				return err
			}
			step := model.StepIdentity{Job: execution, APIStepNumber: ptr(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
			return b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: ".github/workflows/contradiction.yml", CallerWorkflowObjectID: &callerOID, TargetRepository: affected, DeclaredRef: strings.Repeat("0", 40), TargetActionObjectID: &otherOID, Execution: &execution, StepKey: step, ContradictsFactIDs: []string{runtimeID}, EventTime: syntheticarchive.InstantEvent(b.When())})
		}},
		{"declared-at-run-sha", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3011, 1, 4011, "push", ".github/workflows/historical.yml", "historical", "completed", "success"); err != nil {
				return err
			}
			return declared(b, 3011, 4011, ".github/workflows/historical.yml", reviewdogMaliciousSHA, &maliciousOID, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"rerun-resolved-other-object", inside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 3012, 2, 4012, "push", ".github/workflows/lint.yml", "lint-rerun", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(3012, 2, 4012)
			if err := b.AddRuntime(ctx, execution, 2, model.ObservationLifecycleStarted, affected, otherOID, "v1", ""); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, execution)
		}},
	}
	scenarios := make([]Scenario, 0, len(specs))
	for _, spec := range specs {
		built, err := scenario(spec.id, spec.when, spec.forbidden, spec.compose)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, built)
	}
	return scenarios, nil
}

func ptr[T any](value T) *T { return &value }
