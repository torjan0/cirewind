package demodata

import (
	"context"
	"testing"

	"github.com/torjan0/cirewind/internal/archive"
)

func TestSnapshotIsSelfContainedAndDeterministic(t *testing.T) {
	first, err := Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, err := archive.NormalizeSnapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := archive.NormalizeSnapshot(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Facts) < 40 || len(a.Evidence) == 0 || len(a.Facts) != len(b.Facts) || a.Facts[0].ID != b.Facts[0].ID {
		t.Fatalf("unexpected deterministic snapshot: facts=%d evidence=%d", len(a.Facts), len(a.Evidence))
	}
}
