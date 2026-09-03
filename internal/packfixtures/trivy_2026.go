package packfixtures

import (
	"context"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/syntheticarchive"
)

// trivyEcosystem2026 exercises the CIR-AQUASECURITY-TRIVY-2026 pack, whose
// components carry separate windows: aquasecurity/trivy-action tags during
// [2026-03-19T17:43:00Z, 2026-03-20T05:41:00Z), aquasecurity/setup-trivy tags
// during [2026-03-19T17:43:00Z, 2026-03-19T21:45:00Z), and the Trivy v0.69.4
// release assets during [2026-03-19T18:22:00Z, 2026-03-19T21:43:00Z). The
// malicious Action objects were never published, so no scenario can resolve
// to a malicious identity; every affected-ref scenario must stay below
// confirmed execution. One release-asset digest from the maintainer table is
// reused only to prove that a digest never matches outside its namespace.
func trivyEcosystem2026(ctx context.Context) ([]Scenario, error) {
	const (
		consumerID         = model.RepositoryID(503)
		consumer           = "cirewind-fixtures/trivy-consumer"
		affectedTag        = "0.28.0"
		safeTag            = "0.35.0"
		restoredTag        = "v0.28.0"
		setupTag           = "v0.2.6"
		releaseAssetDigest = "385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6"
	)
	var (
		trivyAction  = syntheticarchive.MustRepository("aquasecurity/trivy-action")
		setupTrivy   = syntheticarchive.MustRepository("aquasecurity/setup-trivy")
		unknownOID   = syntheticarchive.MustActionOID(strings.Repeat("1", 40))
		otherOID     = syntheticarchive.MustActionOID(strings.Repeat("2", 40))
		wrapperOID   = syntheticarchive.MustActionOID(strings.Repeat("3", 40))
		callerOID    = syntheticarchive.MustCallerOID(strings.Repeat("a", 40))
		actionInside = time.Date(2026, 3, 19, 23, 0, 0, 0, time.UTC)
		actionBefore = time.Date(2026, 3, 19, 17, 42, 30, 0, time.UTC)
		actionLast   = time.Date(2026, 3, 20, 5, 40, 30, 0, time.UTC)
		actionAfter  = time.Date(2026, 3, 20, 5, 41, 0, 0, time.UTC)
		setupInside  = time.Date(2026, 3, 19, 19, 0, 0, 0, time.UTC)
		setupEnd     = time.Date(2026, 3, 19, 21, 45, 0, 0, time.UTC)
		binaryInside = time.Date(2026, 3, 19, 19, 30, 0, 0, time.UTC)
		postIncident = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
		analysisTime = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	)
	noExecution := []ForbiddenState{{State: model.ConfirmedExecuted, Rationale: "The malicious trivy-action and setup-trivy objects were never published, so no identity can promote a tag resolution or declaration to confirmed execution."}}
	noClear := ForbiddenState{State: model.NoMatchConfirmed, Rationale: "A run that resolved an affected tag inside its component window, or whose log is missing, can never be cleared."}
	outsideWindow := ForbiddenState{State: model.RunInWindowMutableRef, Rationale: "The run lies outside the minute-precision window of the component it declared, so the ref cannot be an in-window finding."}
	notAnIndicator := ForbiddenState{State: model.RunInWindowMutableRef, Rationale: "The declared ref is not an affected ref of the pack: 0.35.0 was not repointed and the v-prefixed replacement names are distinct refs created after the incident."}
	noDownload := ForbiddenState{State: model.ConfirmedDownloaded, Rationale: "A release-asset digest value presented as an Action package digest belongs to a different namespace and must not match."}

	declared := func(ctx context.Context, b *syntheticarchive.Builder, target model.RepositorySlug, run, job int64, workflow, declaredRef string, object *model.ActionSourceObjectID, basis archive.DefinitionBasis, event model.EventInterval) error {
		execution := b.Execution(run, 1, job)
		dependency := archive.DependencyFact{Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction, Basis: basis, CallerRepositoryID: b.RepositoryID(), CallerRepository: b.Repository(), CallerPath: workflow, TargetRepository: target, DeclaredRef: declaredRef, TargetActionObjectID: object, ContradictsFactIDs: []string{}, EventTime: event}
		if basis != archive.DefinitionCurrentSnapshot {
			dependency.CallerWorkflowObjectID = &callerOID
			dependency.Execution = &execution
		}
		return b.AddDependency(ctx, dependency)
	}
	runtime := func(ctx context.Context, b *syntheticarchive.Builder, target model.RepositorySlug, run, job int64, workflow, name, declaredRef string, object model.ActionSourceObjectID, digest *model.PackageDigest) error {
		if err := b.AddExecution(ctx, run, 1, job, "push", workflow, name, "completed", "success"); err != nil {
			return err
		}
		return b.AddRuntimeWithDigest(ctx, b.Execution(run, 1, job), 2, model.ObservationLifecycleStarted, target, object, declaredRef, "", digest)
	}
	actionPackageDigest, err := model.NewPackageDigest(model.DigestGitHubActionPackage, model.HashSHA256, releaseAssetDigest)
	if err != nil {
		return nil, err
	}

	specs := []struct {
		id        string
		when      time.Time
		forbidden []ForbiddenState
		compose   composeFunc
	}{
		{"trivy-action-tag-in-window-runtime", actionInside, append(noExecution, noClear), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, trivyAction, 6001, 7001, ".github/workflows/scan.yml", "scan", affectedTag, unknownOID, nil); err != nil {
				return err
			}
			return b.AddExposures(ctx, b.Execution(6001, 1, 7001))
		}},
		{"trivy-action-tag-in-window-declared", actionInside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6002, 1, 7002, "push", ".github/workflows/scan.yml", "scan-declared", "completed", "success"); err != nil {
				return err
			}
			return declared(ctx, b, trivyAction, 6002, 7002, ".github/workflows/scan.yml", affectedTag, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"trivy-action-tag-before-window", actionBefore, append(noExecution, outsideWindow, noClear), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6003, 1, 7003, "push", ".github/workflows/scan.yml", "scan-before", "completed", "success"); err != nil {
				return err
			}
			if err := declared(ctx, b, trivyAction, 6003, 7003, ".github/workflows/scan.yml", affectedTag, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(6003, 1, 7003))
		}},
		{"trivy-action-tag-last-minute", actionLast, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6004, 1, 7004, "push", ".github/workflows/scan.yml", "scan-last-minute", "completed", "success"); err != nil {
				return err
			}
			return declared(ctx, b, trivyAction, 6004, 7004, ".github/workflows/scan.yml", affectedTag, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When()))
		}},
		{"trivy-action-tag-after-window", actionAfter, append(noExecution, outsideWindow, noClear), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6005, 1, 7005, "push", ".github/workflows/scan.yml", "scan-after", "completed", "success"); err != nil {
				return err
			}
			if err := declared(ctx, b, trivyAction, 6005, 7005, ".github/workflows/scan.yml", affectedTag, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(6005, 1, 7005))
		}},
		{"trivy-action-safe-tag-in-window", actionInside, append(noExecution, notAnIndicator), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, trivyAction, 6006, 7006, ".github/workflows/scan.yml", "scan-safe-tag", safeTag, otherOID, nil); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, b.Execution(6006, 1, 7006))
		}},
		{"trivy-action-restored-tag-after-incident", postIncident, append(noExecution, notAnIndicator), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, trivyAction, 6007, 7007, ".github/workflows/scan.yml", "scan-restored-tag", restoredTag, otherOID, nil); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, b.Execution(6007, 1, 7007))
		}},
		{"trivy-action-missing-log-in-window", actionInside, append(noExecution, noClear), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6008, 1, 7008, "push", ".github/workflows/scan.yml", "scan-missing-log", "completed", "success"); err != nil {
				return err
			}
			if err := declared(ctx, b, trivyAction, 6008, 7008, ".github/workflows/scan.yml", affectedTag, nil, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			return b.AddMissingLog(ctx, b.Execution(6008, 1, 7008))
		}},
		{"trivy-action-current-reference-only", actionInside, append(noExecution, ForbiddenState{State: model.RunInWindowMutableRef, Rationale: "A current workflow definition is not a historical run and carries no run instant."}), func(ctx context.Context, b *syntheticarchive.Builder) error {
			return declared(ctx, b, trivyAction, 0, 0, ".github/workflows/current.yml", affectedTag, nil, archive.DefinitionCurrentSnapshot, syntheticarchive.UnknownEvent())
		}},
		{"setup-trivy-tag-in-window-runtime", setupInside, append(noExecution, noClear), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, setupTrivy, 6010, 7010, ".github/workflows/install.yml", "install", setupTag, unknownOID, nil); err != nil {
				return err
			}
			return b.AddExposures(ctx, b.Execution(6010, 1, 7010))
		}},
		{"setup-trivy-tag-at-window-end", setupEnd, append(noExecution, outsideWindow), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, setupTrivy, 6011, 7011, ".github/workflows/install.yml", "install-recreated", setupTag, otherOID, nil); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, b.Execution(6011, 1, 7011))
		}},
		{"sha-pinned-trivy-action-nested-setup-trivy", setupInside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := b.AddExecution(ctx, 6012, 1, 7012, "push", ".github/workflows/pinned.yml", "pinned", "completed", "success"); err != nil {
				return err
			}
			execution := b.Execution(6012, 1, 7012)
			if err := declared(ctx, b, trivyAction, 6012, 7012, ".github/workflows/pinned.yml", strings.Repeat("3", 40), &wrapperOID, archive.DefinitionHistoricalAtRun, syntheticarchive.InstantEvent(b.When())); err != nil {
				return err
			}
			if err := b.AddDependency(ctx, archive.DependencyFact{Relation: archive.DependencyActionContainsAction, TargetKind: archive.DependencyTargetAction, Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: b.RepositoryID(), CallerRepository: trivyAction, CallerPath: "action.yml", CallerActionObjectID: &wrapperOID, TargetRepository: setupTrivy, DeclaredRef: setupTag, TransitiveDepth: 1, Execution: &execution, ContradictsFactIDs: []string{}, EventTime: syntheticarchive.InstantEvent(b.When())}); err != nil {
				return err
			}
			return b.AddRuntime(ctx, execution, 3, model.ObservationLifecycleStarted, setupTrivy, unknownOID, setupTag, "")
		}},
		{"digest-namespace-isolation", setupInside, append(noExecution, noDownload, ForbiddenState{State: model.RunInWindowMutableRef, Rationale: "The action was declared by full object, not by an affected ref."}), func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, trivyAction, 6013, 7013, ".github/workflows/pinned.yml", "pinned-digest", strings.Repeat("3", 40), wrapperOID, &actionPackageDigest); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, b.Execution(6013, 1, 7013))
		}},
		{"sha-pinned-version-latest-unobservable", binaryInside, noExecution, func(ctx context.Context, b *syntheticarchive.Builder) error {
			if err := runtime(ctx, b, trivyAction, 6014, 7014, ".github/workflows/pinned.yml", "pinned-latest", strings.Repeat("3", 40), wrapperOID, nil); err != nil {
				return err
			}
			return b.AddClosedCoverage(ctx, b.Execution(6014, 1, 7014))
		}},
	}
	scenarios := make([]Scenario, 0, len(specs))
	for _, item := range specs {
		built, err := buildScenario(ctx, consumerID, consumer, item.id, item.when, analysisTime, item.forbidden, item.compose)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, built)
	}
	return scenarios, nil
}
