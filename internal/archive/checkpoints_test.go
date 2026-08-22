package archive

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/model"
)

func TestCheckpointsReturnsValidatedSchedulerStateWithoutSnapshot(t *testing.T) {
	ctx := context.Background()
	store, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), Options{CreatedAt: model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	batch := testBatch(t)
	if err := store.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := store.Checkpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 || len(checkpoints[0].WatchedParents) != 1 {
		t.Fatalf("checkpoints = %#v", checkpoints)
	}
	checkpoints[0].WatchedParents[0].FinalRefreshComplete = false
	again, err := store.Checkpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !again[0].WatchedParents[0].FinalRefreshComplete {
		t.Fatal("caller mutation changed persisted scheduler state")
	}
}

func TestCheckpointsPreservesExplicitEmptyWatchedParents(t *testing.T) {
	ctx := context.Background()
	store, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), Options{CreatedAt: model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	batch := testBatch(t)
	batch.Checkpoints[0].WatchedParents = []WatchedParent{}
	if err := store.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := store.Checkpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 || checkpoints[0].WatchedParents == nil || len(checkpoints[0].WatchedParents) != 0 {
		t.Fatalf("empty watched-parent state was not preserved: %#v", checkpoints)
	}
}

func TestCheckpointsRejectsCorruptedPolicyState(t *testing.T) {
	ctx := context.Background()
	store, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), Options{CreatedAt: model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	batch := testBatch(t)
	if err := store.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.store.DB().ExecContext(ctx, `UPDATE archive_checkpoints SET discovery_watermark='not-a-time'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Checkpoints(ctx); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("corrupt checkpoint error = %v", err)
	}
}
