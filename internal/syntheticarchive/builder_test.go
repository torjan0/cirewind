package syntheticarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/model"
)

func TestBuilderIsDeterministicAndRejectsIncompleteOptions(t *testing.T) {
	ctx := context.Background()
	when := time.Date(2025, 3, 11, 19, 0, 0, 0, time.UTC)
	build := func() []byte {
		b, err := New(Options{RepositoryID: 7, Repository: "cirewind-fixtures/consumer", SessionID: "collection:test", When: when})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.AddRepository(ctx, "public", "main"); err != nil {
			t.Fatal(err)
		}
		if err := b.AddExecution(ctx, 1, 1, 2, "push", ".github/workflows/a.yml", "a", "completed", "success"); err != nil {
			t.Fatal(err)
		}
		affected := MustRepository("cirewind-fixtures/harmless-action")
		if err := b.AddRuntime(ctx, b.Execution(1, 1, 2), 2, model.ObservationLifecycleStarted, affected, MustActionOID(strings.Repeat("1", 40)), "v1", ""); err != nil {
			t.Fatal(err)
		}
		if err := b.SetWhen(when.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := b.AddMissingLog(ctx, b.Execution(1, 1, 2)); err != nil {
			t.Fatal(err)
		}
		snapshot, err := b.Snapshot("arc1:"+strings.Repeat("c", 64), DefaultCapabilities())
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Metadata.CreatedAt != b.createdAt || len(snapshot.Facts) == 0 || len(snapshot.Evidence) == 0 {
			t.Fatalf("snapshot metadata or content is empty: %+v", snapshot.Metadata)
		}
		data, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if !bytes.Equal(build(), build()) {
		t.Fatal("two builds with identical inputs differ")
	}
	for name, options := range map[string]Options{
		"missing repository id": {Repository: "a/b", SessionID: "collection:x", When: when},
		"bad repository":        {RepositoryID: 1, Repository: "not a slug", SessionID: "collection:x", When: when},
		"missing session":       {RepositoryID: 1, Repository: "a/b", When: when},
		"zero time":             {RepositoryID: 1, Repository: "a/b", SessionID: "collection:x"},
	} {
		if _, err := New(options); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
