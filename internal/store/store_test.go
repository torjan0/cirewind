package store

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCreateOpenAndHeader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "case.db")
	s, err := Create(ctx, path, KindCase)
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := s.Kind(ctx); err != nil || kind != KindCase {
		t.Fatalf("Kind() = %q, %v", kind, err)
	}
	if err := s.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("mode = %o", got)
	}

	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := ro.DB().QueryRowContext(ctx, `SELECT count(*) FROM findings`).Scan(new(int)); err != nil {
		t.Fatal(err)
	}
	if _, err := ro.DB().ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('x','y')`); err == nil {
		t.Fatal("read-only store accepted a write")
	}
}

func TestFinalizeCaseSealsJournalForReadOnlyInspection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "case.db")
	created, err := Create(ctx, path, KindCase)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Finalize(ctx); err != nil {
		_ = created.Close()
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoSQLiteSidecars(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Deliberately omit immutable=1. This models an ordinary forensic SQLite
	// reader and catches a finalized database whose header still selects WAL.
	inspector, err := sql.Open("sqlite", sqliteDSN(path, "ro", false))
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := inspector.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		_ = inspector.Close()
		t.Fatal(err)
	}
	if journalMode != "delete" {
		_ = inspector.Close()
		t.Fatalf("finalized case journal mode = %q, want delete", journalMode)
	}
	var findings int
	if err := inspector.QueryRowContext(ctx, `SELECT count(*) FROM findings`).Scan(&findings); err != nil {
		_ = inspector.Close()
		t.Fatal(err)
	}
	if err := inspector.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoSQLiteSidecars(t, path)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("ordinary read-only inspection changed finalized case.db")
	}
}

func TestFinalizeArchiveRetainsIncrementalWALMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	created, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), KindArchive)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	if err := created.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := created.DB().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("finalized incremental archive journal mode = %q, want wal", journalMode)
	}
}

func assertNoSQLiteSidecars(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("unexpected SQLite sidecar %s: %v", path+suffix, err)
		}
	}
}

func TestConstraintsRejectAttemptAndEnums(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), KindArchive)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO coverage_units(coverage_id,collection_id,kind,logical_scope,expected,collected,not_applicable,gaps,status,material,retryable) VALUES('c','missing','x','x',1,0,0,0,'open',1,0)`); err == nil {
		t.Fatal("invalid coverage/FK accepted")
	}
}

func TestRejectExistingAndSymlink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "case.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, path, KindCase); err == nil {
		t.Fatal("existing file accepted")
	}
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err == nil {
		if _, err := Create(ctx, filepath.Join(dir, "link", "bad.db"), KindCase); err == nil {
			t.Fatal("symlink path accepted")
		}
	}
}

func TestCreateRejectsSymlinkAncestorBeforeCreatingParents(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	redirectTarget := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(redirectTarget, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	path := filepath.Join(link, "must-not-be-created", "archive.db")
	if _, err := Create(context.Background(), path, KindArchive); err == nil {
		t.Fatal("store path with a symlink ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(redirectTarget, "must-not-be-created")); !os.IsNotExist(err) {
		t.Fatalf("store creation mutated the symlink target before rejection: %v", err)
	}
}

func TestTrustedRootAliasCanonicalizationKeepsDescendantLinksHostile(t *testing.T) {
	t.Parallel()
	aliasParent := t.TempDir()
	canonicalRoot := t.TempDir()
	aliasRoot := filepath.Join(aliasParent, "system-temp-alias")
	if err := os.Symlink(canonicalRoot, aliasRoot); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	safePath := filepath.Join(aliasRoot, "job", "archive.db")
	canonicalSafe, err := canonicalizeUnderTrustedRoot(safePath, aliasRoot)
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(canonicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedRoot, "job", "archive.db"); canonicalSafe != want {
		t.Fatalf("canonical safe path = %q, want %q", canonicalSafe, want)
	}
	if err := rejectSymlinkComponents(filepath.Dir(canonicalSafe)); err != nil {
		t.Fatalf("trusted root alias was not removed before strict validation: %v", err)
	}

	redirectTarget := t.TempDir()
	redirect := filepath.Join(canonicalRoot, "redirect")
	if err := os.Symlink(redirectTarget, redirect); err != nil {
		t.Fatal(err)
	}
	hostilePath := filepath.Join(aliasRoot, "redirect", "must-not-be-created", "archive.db")
	canonicalHostile, err := canonicalizeUnderTrustedRoot(hostilePath, aliasRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinkComponents(filepath.Dir(canonicalHostile)); err == nil {
		t.Fatal("caller-controlled link below trusted root was accepted")
	}
}

func TestReadOnlyOpenEncodesSpecialFilename(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Space and fragment-marker characters exercise URI encoding while remaining
	// valid filename characters on every supported platform. A question mark is
	// not a legal Windows filename character.
	path := filepath.Join(t.TempDir(), "archive# evidence.db")
	created, err := Create(ctx, path, KindArchive)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteDSNUsesAbsoluteWindowsFileURI(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "case.db")
	dsn := sqliteDSN(path, "rw", false)
	if runtime.GOOS == "windows" && !strings.HasPrefix(dsn, "file:///"+filepath.VolumeName(path)+"/") {
		t.Fatalf("Windows SQLite DSN is not an absolute file URI: %q", dsn)
	}
}

func TestWritableOpenRestoresOwnerOnlyPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix owner-only permission bits")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "archive.db")
	created, err := Create(ctx, path, KindArchive)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Skipf("file permission changes are unavailable: %v", err)
	}
	opened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("writable archive mode = %o, want 600", got)
	}
}

func TestOpenRejectsUnexpectedOrSubstitutedSchema(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{name: "extra view", mutate: `CREATE VIEW attacker_view AS SELECT value FROM metadata`},
		{name: "extra trigger", mutate: `CREATE TRIGGER attacker_trigger AFTER INSERT ON metadata BEGIN SELECT 1; END`},
		{name: "substituted table", mutate: `DROP TABLE graph_projection_edges; CREATE TABLE graph_projection_edges (edge_id TEXT PRIMARY KEY) STRICT`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "archive.db")
			created, err := Create(ctx, path, KindArchive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := created.DB().ExecContext(ctx, test.mutate); err != nil {
				_ = created.Close()
				t.Fatal(err)
			}
			if err := created.Close(); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenReadOnly(ctx, path); err == nil {
				_ = opened.Close()
				t.Fatal("modified schema was accepted")
			} else if !strings.Contains(err.Error(), "schema") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOpenRejectsOversizeSparseStoreBeforeSQLite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "oversize.db")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxStoreBytes + 1); err != nil {
		_ = f.Close()
		t.Skipf("filesystem does not support sparse test file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(context.Background(), path); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversize open error = %v", err)
	}
}

func TestReadOnlyPathsRejectUntrustedSQLiteSidecars(t *testing.T) {
	ctx := context.Background()
	newArchive := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "archive.db")
		created, err := Create(ctx, path, KindArchive)
		if err != nil {
			t.Fatal(err)
		}
		if err := created.Finalize(ctx); err != nil {
			_ = created.Close()
			t.Fatal(err)
		}
		if err := created.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("finalized reader rejects any sidecar", func(t *testing.T) {
		path := newArchive(t)
		if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReadOnly(ctx, path); err == nil || !strings.Contains(err.Error(), "sidecars") {
			t.Fatalf("finalized reader sidecar error = %v", err)
		}
	})

	t.Run("WAL-aware reader rejects link", func(t *testing.T) {
		path := newArchive(t)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("not a WAL"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path+"-wal"); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := OpenReadOnlyWALAware(ctx, path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("WAL-aware symlink error = %v", err)
		}
	})

	t.Run("WAL-aware reader rejects rollback journal", func(t *testing.T) {
		path := newArchive(t)
		if err := os.WriteFile(path+"-journal", []byte("untrusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReadOnlyWALAware(ctx, path); err == nil || !strings.Contains(err.Error(), "rollback journal") {
			t.Fatalf("WAL-aware rollback-journal error = %v", err)
		}
	})
}

func TestGraphProjectionLookupPlansUseBoundedIndexes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := Create(ctx, filepath.Join(t.TempDir(), "case.db"), KindCase)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	queries := []struct {
		name  string
		query string
		index string
	}{
		{"source", `SELECT edge_id FROM graph_projection_edges WHERE analysis_id=? AND source_id=?`, "idx_graph_source"},
		{"target", `SELECT edge_id FROM graph_projection_edges WHERE analysis_id=? AND target_id=?`, "idx_graph_target"},
	}
	for _, test := range queries {
		t.Run(test.name, func(t *testing.T) {
			rows, err := database.DB().QueryContext(ctx, "EXPLAIN QUERY PLAN "+test.query, "analysis", "node")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(plan, " "), test.index) {
				t.Fatalf("query plan does not use %s: %v", test.index, plan)
			}
		})
	}
}
