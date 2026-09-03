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
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
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
	"CIR-AQUASECURITY-TRIVY-2026/1.0.0":       trivyEcosystem2026,
	"CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0":   reviewdogActionSetup2025,
	"CIR-TJ-ACTIONS-CHANGED-FILES-2025/1.0.0": tjActionsChangedFiles2025,
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

// reviewdogActionSetup2025 exercises the CIR-REVIEWDOG-ACTION-SETUP-2025 pack:
// the reviewdog/action-setup v1 tag pointed at
// f0d342d24037bb11d26b9bd8496e0808ba32e9ec during the minute-precision
// window [2025-03-11T18:42:00Z, 2025-03-11T20:32:00Z).
func reviewdogActionSetup2025(ctx context.Context) ([]Scenario, error) {
	return mutableTagScenarios(ctx, mutableTagSpec{
		consumerID: 501, consumer: "cirewind-fixtures/reviewdog-consumer",
		action: "reviewdog/action-setup", maliciousSHA: "f0d342d24037bb11d26b9bd8496e0808ba32e9ec", declaredRef: "v1",
		inside:       time.Date(2025, 3, 11, 19, 10, 0, 0, time.UTC),
		before:       time.Date(2025, 3, 11, 18, 41, 59, 0, time.UTC),
		lastInside:   time.Date(2025, 3, 11, 20, 31, 30, 0, time.UTC),
		after:        time.Date(2025, 3, 11, 20, 32, 0, 0, time.UTC),
		analysisTime: time.Date(2025, 3, 20, 0, 0, 0, 0, time.UTC),
	})
}

// tjActionsChangedFiles2025 exercises the CIR-TJ-ACTIONS-CHANGED-FILES-2025
// pack: tj-actions/changed-files tags pointed at
// 0e58ed8671d6b60d0890c21b07f8835ace038e67 during the day-precision,
// conservatively expanded window [2025-03-14T00:00:00Z, 2025-03-16T00:00:00Z).
// The declared ref is the maintainer-named example tag v44.5.1.
func tjActionsChangedFiles2025(ctx context.Context) ([]Scenario, error) {
	return mutableTagScenarios(ctx, mutableTagSpec{
		consumerID: 502, consumer: "cirewind-fixtures/changed-files-consumer",
		action: "tj-actions/changed-files", maliciousSHA: "0e58ed8671d6b60d0890c21b07f8835ace038e67", declaredRef: "v44.5.1",
		inside:       time.Date(2025, 3, 14, 18, 0, 0, 0, time.UTC),
		before:       time.Date(2025, 3, 13, 23, 59, 59, 0, time.UTC),
		lastInside:   time.Date(2025, 3, 15, 23, 59, 59, 0, time.UTC),
		after:        time.Date(2025, 3, 16, 0, 0, 0, 0, time.UTC),
		analysisTime: time.Date(2025, 3, 23, 0, 0, 0, 0, time.UTC),
	})
}
