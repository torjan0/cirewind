// Package store owns CIRewind's SQLite persistence boundary.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	SchemaVersion = 1
	ApplicationID = 0x43495257 // "CIRW"
	maxStoreBytes = int64(64 << 30)
)

// Kind identifies whether a database is an incident case or an incremental archive.
type Kind string

const (
	KindCase    Kind = "case"
	KindArchive Kind = "archive"
)

// Store is a single CIRewind SQLite database. Callers should use one writer.
type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
}

// Create creates a new owner-only database and applies all migrations.
func Create(ctx context.Context, path string, kind Kind) (*Store, error) {
	if kind != KindCase && kind != KindArchive {
		return nil, fmt.Errorf("invalid store kind %q", kind)
	}
	abs, err := secureNewFilePath(path)
	if err != nil {
		return nil, err
	}
	// Reject existing symlink ancestors before MkdirAll so creating a missing
	// parent cannot be redirected outside the requested store path. Recheck
	// after creation to narrow the remaining local filesystem race.
	if err := rejectSymlinkComponents(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create store parent: %w", err)
	}
	if err := rejectSymlinkComponents(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close new store: %w", err)
	}

	db, err := sql.Open("sqlite", sqliteDSN(abs, "rw", false))
	if err != nil {
		_ = os.Remove(abs)
		return nil, fmt.Errorf("open store: %w", err)
	}
	s := &Store{db: db, path: abs}
	if err := s.configure(ctx, true); err != nil {
		_ = db.Close()
		_ = os.Remove(abs)
		return nil, err
	}
	if err := s.migrate(ctx, kind); err != nil {
		_ = db.Close()
		_ = os.Remove(abs)
		return nil, err
	}
	return s, nil
}

// Open opens an existing CIRewind database for continued collection.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := existingRegularFile(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return nil, fmt.Errorf("protect writable store: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(abs, "rw", false))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	s := &Store{db: db, path: abs}
	if err := s.configure(ctx, true); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.validateHeader(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.validateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an imported database in query-only mode. It validates the
// CIRewind application and schema IDs before exposing it to replay.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	abs, err := existingRegularFile(path)
	if err != nil {
		return nil, err
	}
	if present, err := sqliteSidecarsPresent(abs); err != nil {
		return nil, err
	} else if present {
		return nil, errors.New("read-only database has SQLite sidecars; use the WAL-aware archive replay path or finalize the database")
	}
	return openReadOnly(ctx, abs, true)
}

// OpenReadOnlyWALAware opens an incremental archive without ignoring a
// committed WAL left by an interrupted collector. It is intentionally
// separate from OpenReadOnly: finalized case files must be self-contained and
// must never acquire meaning from an unmanifested sidecar.
func OpenReadOnlyWALAware(ctx context.Context, path string) (*Store, error) {
	abs, err := existingRegularFile(path)
	if err != nil {
		return nil, err
	}
	walPresent, err := validateReplaySidecars(abs)
	if err != nil {
		return nil, err
	}
	if !walPresent {
		return openReadOnly(ctx, abs, true)
	}
	return openReadOnly(ctx, abs, false)
}

func openReadOnly(ctx context.Context, abs string, immutable bool) (*Store, error) {
	dsn := sqliteDSN(abs, "ro", immutable)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open archive read-only: %w", err)
	}
	s := &Store{db: db, path: abs, readOnly: true}
	if err := s.configure(ctx, false); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `PRAGMA query_only=ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable query-only mode: %w", err)
	}
	if err := s.validateHeader(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.validateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.IntegrityCheck(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func sqliteSidecarsPresent(path string) (bool, error) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_, err := os.Lstat(path + suffix)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return false, fmt.Errorf("inspect SQLite sidecar: %w", err)
		}
	}
	return false, nil
}

// validateReplaySidecars accepts only the ordinary regular-file WAL set. A
// rollback journal is never part of a committed CIRewind archive, and links or
// special files are rejected before SQLite can follow them.
func validateReplaySidecars(path string) (bool, error) {
	if _, err := os.Lstat(path + "-journal"); err == nil {
		return false, errors.New("archive has an unexpected SQLite rollback journal")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect SQLite rollback journal: %w", err)
	}

	walPresent := false
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("inspect SQLite %s sidecar: %w", strings.TrimPrefix(suffix, "-"), err)
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("SQLite %s sidecar is not a regular file", strings.TrimPrefix(suffix, "-"))
		}
		if info.Size() > maxStoreBytes {
			return false, fmt.Errorf("SQLite %s sidecar exceeds the compiled %d-byte size limit", strings.TrimPrefix(suffix, "-"), maxStoreBytes)
		}
		if suffix == "-wal" && info.Size() > 0 {
			walPresent = true
		}
	}
	return walPresent, nil
}

func (s *Store) configure(ctx context.Context, writable bool) error {
	statements := []string{
		`PRAGMA foreign_keys=ON`,
		`PRAGMA trusted_schema=OFF`,
		`PRAGMA cell_size_check=ON`,
		`PRAGMA busy_timeout=5000`,
	}
	if writable {
		statements = append(statements, `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`)
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure SQLite: %w", err)
		}
	}
	s.db.SetMaxOpenConns(1)
	return nil
}

func (s *Store) validateHeader(ctx context.Context) error {
	var appID, version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&appID); err != nil {
		return fmt.Errorf("read application ID: %w", err)
	}
	if appID != ApplicationID {
		return fmt.Errorf("not a CIRewind database: application ID %d", appID)
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("unsupported CIRewind schema version %d", version)
	}
	return nil
}

// DB exposes the database only to repository implementations. Callers must use
// bound parameters for every hostile value.
func (s *Store) DB() *sql.DB { return s.db }

// Path returns the canonical database path.
func (s *Store) Path() string { return s.path }

// Kind returns the persisted store kind.
func (s *Store) Kind(ctx context.Context) (Kind, error) {
	var value string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='store_kind'`).Scan(&value); err != nil {
		return "", fmt.Errorf("read store kind: %w", err)
	}
	kind := Kind(value)
	if kind != KindCase && kind != KindArchive {
		return "", fmt.Errorf("invalid persisted store kind %q", value)
	}
	return kind, nil
}

// IntegrityCheck verifies foreign keys and SQLite's internal structure.
func (s *Store) IntegrityCheck(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("foreign key check: %w", err)
	}
	if rows.Next() {
		_ = rows.Close()
		return errors.New("foreign key integrity failure")
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close foreign key check: %w", err)
	}
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("SQLite integrity failure: %s", bounded(result, 256))
	}
	return nil
}

// Finalize checkpoints WAL and validates the database before case hashing.
// A finalized case is also converted out of WAL mode so ordinary read-only
// SQLite inspection cannot create unmanifested -wal or -shm sidecars. Archives
// remain in WAL mode because they are incremental writable stores.
func (s *Store) Finalize(ctx context.Context) error {
	if s.readOnly {
		return errors.New("cannot finalize a read-only store")
	}
	kind, err := s.Kind(ctx)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint store: %w", err)
	}
	if kind == KindCase {
		var journalMode string
		if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&journalMode); err != nil {
			return fmt.Errorf("seal case journal: %w", err)
		}
		if !strings.EqualFold(journalMode, "delete") {
			return fmt.Errorf("seal case journal: SQLite selected unexpected mode %q", bounded(journalMode, 32))
		}
	}
	if err := s.IntegrityCheck(ctx); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

func (s *Store) Close() error { return s.db.Close() }

func secureNewFilePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("store path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve store path: %w", err)
	}
	clean := filepath.Clean(abs)
	if clean == string(filepath.Separator) || filepath.Base(clean) == "." {
		return "", errors.New("store path must name a file")
	}
	if _, err := os.Lstat(clean); err == nil {
		return "", fmt.Errorf("store path already exists: %s", clean)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect store path: %w", err)
	}
	return clean, nil
}

func existingRegularFile(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve store path: %w", err)
	}
	if err := rejectSymlinkComponents(filepath.Dir(abs)); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("store is not a regular file")
	}
	if info.Size() > maxStoreBytes {
		return "", fmt.Errorf("store exceeds the compiled %d-byte size limit", maxStoreBytes)
	}
	return abs, nil
}

func sqliteDSN(path, mode string, immutable bool) string {
	slashPath := filepath.ToSlash(path)
	// A Windows absolute drive path such as C:/case.db must be encoded as
	// file:///C:/case.db. Without the leading slash, SQLite parses the drive
	// letter as a URI authority and rejects the database before opening it.
	// UNC paths already begin with // and retain their authority semantics.
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	target := &url.URL{Scheme: "file", Path: slashPath}
	query := url.Values{}
	if immutable {
		query.Set("immutable", "1")
	}
	query.Set("mode", mode)
	target.RawQuery = query.Encode()
	return target.String()
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path contains symlink component: %s", current)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect path component: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func bounded(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n]
}
