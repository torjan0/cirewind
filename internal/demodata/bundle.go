package demodata

import (
	"context"
	_ "embed"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
)

const (
	// BundleID versions the complete fixture and expected-result contract.
	BundleID = "cirewind.demo/v2"
	// FixtureVersion matches metadata.packVersion in the embedded pack.
	FixtureVersion = "2.0.0"
	// OIDCCapabilityRuleID names the bounded inference applied to the observed
	// id-token permission. It never represents a cloud trust or role assumption.
	OIDCCapabilityRuleID = "oidc-minting-capability/v1"
)

var analysisTime = time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

//go:embed synthetic/mutable-tag.yaml
var embeddedPackYAML []byte

// DemoBundle is one fresh, immutable-by-convention copy of the embedded
// synthetic inputs and result oracle. No field controls executable behavior,
// network access, or filesystem paths.
type DemoBundle struct {
	ID             string
	FixtureVersion string
	PackYAML       []byte
	Snapshot       archive.Snapshot
	AnalysisTime   time.Time
	Oracle         Oracle
}

// Bundle constructs a fresh normalized snapshot and defensive copies of all
// slice and map-backed bundle data.
func Bundle(ctx context.Context) (DemoBundle, error) {
	if err := ctx.Err(); err != nil {
		return DemoBundle{}, err
	}
	snapshot, err := Snapshot(ctx)
	if err != nil {
		return DemoBundle{}, err
	}
	return DemoBundle{
		ID:             BundleID,
		FixtureVersion: FixtureVersion,
		PackYAML:       append([]byte(nil), embeddedPackYAML...),
		Snapshot:       snapshot,
		AnalysisTime:   analysisTime,
		Oracle:         newOracle(),
	}, nil
}
