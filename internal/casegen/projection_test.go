package casegen

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/store"
)

func TestRelationalProjectorRejectsPersistedFactAndProvenanceDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate string
		args   []any
		want   string
	}{
		{
			name:   "fact kind column",
			mutate: `UPDATE archive_facts SET kind='run' WHERE fact_id=(SELECT fact_id FROM archive_facts WHERE kind='repository' LIMIT 1)`,
			want:   "identity columns disagree",
		},
		{
			name:   "fact subject column",
			mutate: `UPDATE archive_facts SET run_id=run_id+1 WHERE fact_id=(SELECT fact_id FROM archive_facts WHERE run_id IS NOT NULL LIMIT 1)`,
			want:   "subject columns disagree",
		},
		{
			name:   "fact event column",
			mutate: `UPDATE archive_facts SET event_time_json='{}' WHERE fact_id=(SELECT fact_id FROM archive_facts LIMIT 1)`,
			want:   "event-time column disagrees",
		},
		{
			name:   "fact evidence link",
			mutate: `DELETE FROM archive_fact_evidence WHERE rowid=(SELECT rowid FROM archive_fact_evidence LIMIT 1)`,
			want:   "evidence links disagree",
		},
		{
			name:   "typed coverage row",
			mutate: `UPDATE coverage_units SET logical_scope=logical_scope||'-drift' WHERE coverage_id=(SELECT coverage_id FROM coverage_units LIMIT 1)`,
			want:   "disagrees with typed coverage fact",
		},
		{
			name:   "batch content hash",
			mutate: `UPDATE archive_batches SET content_sha256=?`,
			args:   []any{strings.Repeat("0", 64)},
			want:   "content hash disagrees",
		},
		{
			name:   "uncommitted collection provenance",
			mutate: `DELETE FROM archive_batch_collections`,
			want:   "collection provenance count",
		},
		{
			name:   "case classification spoof",
			mutate: `UPDATE collection_sessions SET mode='archive'`,
			want:   "typed graph projection disagrees",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			databasePath, expected, pack, cleanup := persistedDemoDatabase(t)
			defer cleanup()
			database, err := store.Open(context.Background(), databasePath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.DB().ExecContext(context.Background(), test.mutate, test.args...); err != nil {
				_ = database.Close()
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			_, err = reprojectCaseDatabase(context.Background(), databasePath, expected, pack, false)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("projection error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestRelationalProjectorDerivesSyntheticKindFromPersistedCollections(t *testing.T) {
	databasePath, expected, pack, cleanup := persistedDemoDatabase(t)
	defer cleanup()
	projected, err := reprojectCaseDatabase(context.Background(), databasePath, expected, pack, false)
	if err != nil {
		t.Fatal(err)
	}
	if projected.typed.CaseKind != "synthetic" {
		t.Fatalf("persisted case kind=%q, want synthetic", projected.typed.CaseKind)
	}
}

func persistedDemoDatabase(t *testing.T) (string, report.Case, *incident.ValidatedPack, func()) {
	t.Helper()
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.ValidateReader(context.Background(), bytes.NewReader(bundle.PackYAML))
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	rawMaterialized := false
	analysis.Case.Metadata.RawMaterialized = &rawMaterialized
	builder, err := casefile.NewBuilderV2(t.TempDir()+"/published", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCaseDatabase(context.Background(), builder, Options{
		Snapshot: bundle.Snapshot,
		Pack:     pack,
		Case:     analysis.Case,
	}); err != nil {
		_ = builder.Abort()
		t.Fatal(err)
	}
	path, err := builder.Path("case.db")
	if err != nil {
		_ = builder.Abort()
		t.Fatal(err)
	}
	return path, analysis.Case, pack, func() { _ = builder.Abort() }
}
