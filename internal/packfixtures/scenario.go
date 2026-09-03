package packfixtures

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/syntheticarchive"
)

// composeFunc adds the facts of one scenario to a fresh consumer archive.
type composeFunc func(ctx context.Context, b *syntheticarchive.Builder) error

// buildScenario creates one deterministic consumer archive whose only real
// content is the incident component identity, ref, object, and window the
// scenario exercises.
func buildScenario(ctx context.Context, consumerID model.RepositoryID, consumer, id string, when, analysisTime time.Time, forbidden []ForbiddenState, compose composeFunc) (Scenario, error) {
	b, err := syntheticarchive.New(syntheticarchive.Options{
		RepositoryID: consumerID, Repository: consumer,
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
