// Package archive persists the compact, structured source facts required for
// deterministic incident replay. It performs no network operations.
package archive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

const (
	metadataSnapshotSchema = "archive_snapshot_schema"
	metadataArchiveID      = "archive_id"
	metadataArchiveCreated = "archive_created_at"
)

type Archive struct {
	store    *store.Store
	metadata SnapshotMetadata
	readOnly bool
}

func Create(ctx context.Context, path string, options Options) (*Archive, error) {
	if options.CreatedAt.Time.IsZero() {
		options.CreatedAt = model.MustInstant(time.Now().UTC())
	}
	metadata, err := defaultMetadata(options)
	if err != nil {
		return nil, fmt.Errorf("archive metadata: %w", err)
	}
	database, err := store.Create(ctx, path, store.KindArchive)
	if err != nil {
		return nil, err
	}
	archive := &Archive{store: database, metadata: metadata}
	if err := archive.writeMetadata(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return archive, nil
}

func Open(ctx context.Context, path string) (*Archive, error) {
	database, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	archive, err := openWithStore(ctx, database, false)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return archive, nil
}

// OpenReplay opens an archive with SQLite query_only enabled. Replay callers
// cannot accidentally mutate source facts or advance collection checkpoints.
func OpenReplay(ctx context.Context, path string) (*Archive, error) {
	database, err := store.OpenReadOnlyWALAware(ctx, path)
	if err != nil {
		return nil, err
	}
	archive, err := openWithStore(ctx, database, true)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	return archive, nil
}

func openWithStore(ctx context.Context, database *store.Store, readOnly bool) (*Archive, error) {
	kind, err := database.Kind(ctx)
	if err != nil {
		return nil, err
	}
	if kind != store.KindArchive {
		return nil, errors.New("database is not a CIRewind archive")
	}
	metadata, err := readMetadata(ctx, database.DB())
	if err != nil {
		return nil, err
	}
	return &Archive{store: database, metadata: metadata, readOnly: readOnly}, nil
}

func (a *Archive) Close() error {
	if a.readOnly {
		return a.store.Close()
	}
	// A normal close makes every committed batch self-contained in the main
	// database. OpenReplay remains WAL-aware because a process interruption can
	// occur after SQLite commits a batch but before this checkpoint runs.
	finalizeErr := a.store.Finalize(context.Background())
	return errors.Join(finalizeErr, a.store.Close())
}

func (a *Archive) Metadata() SnapshotMetadata { return a.metadata }

func (a *Archive) writeMetadata(ctx context.Context) error {
	tx, err := a.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive metadata: %w", err)
	}
	defer tx.Rollback()
	values := [][2]string{
		{metadataSnapshotSchema, a.metadata.SchemaVersion},
		{metadataArchiveID, a.metadata.ArchiveID},
		{metadataArchiveCreated, formatInstant(a.metadata.CreatedAt)},
	}
	for _, value := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES(?,?)`, value[0], value[1]); err != nil {
			return fmt.Errorf("write archive metadata %s: %w", value[0], err)
		}
	}
	return tx.Commit()
}

func readMetadata(ctx context.Context, database *sql.DB) (SnapshotMetadata, error) {
	values := make(map[string]string, 3)
	rows, err := database.QueryContext(ctx, `SELECT key,value FROM metadata WHERE key IN (?,?,?) ORDER BY key`, metadataSnapshotSchema, metadataArchiveID, metadataArchiveCreated)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("read archive metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return SnapshotMetadata{}, err
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return SnapshotMetadata{}, err
	}
	createdAt, err := parseInstant(values[metadataArchiveCreated])
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("archive creation time: %w", err)
	}
	metadata := SnapshotMetadata{
		SchemaVersion:      values[metadataSnapshotSchema],
		StoreSchemaVersion: store.SchemaVersion,
		ArchiveID:          values[metadataArchiveID],
		CreatedAt:          createdAt,
	}
	if err := metadata.Validate(); err != nil {
		return SnapshotMetadata{}, err
	}
	return metadata, nil
}

// Append atomically completes a prepared batch. Repeating an identical batch
// is a no-op. A batch prepared before interruption is resumed by content ID.
func (a *Archive) Append(ctx context.Context, input Batch) error {
	if a.readOnly {
		return errors.New("cannot append to a read-only replay archive")
	}
	batch, err := NormalizeBatch(input)
	if err != nil {
		return err
	}
	if len(batch.Collections) == 0 {
		if len(batch.Payloads)+len(batch.Evidence)+len(batch.Facts)+len(batch.Capabilities)+len(batch.Checkpoints) == 0 {
			return nil
		}
		return errors.New("non-empty archive batch requires a collection session")
	}
	// A raw-retained evidence claim is committed only after its exact bytes have
	// been content-addressed in this archive's opt-in sidecar. An interrupted
	// preflight can leave deduplicable sidecar content, but never committed facts
	// that point at absent bytes.
	if err := a.verifyBatchRawPayloads(ctx, batch); err != nil {
		return err
	}
	state, err := a.prepareBatch(ctx, batch)
	if err != nil {
		return err
	}
	if state == "COMMITTED" {
		return nil
	}
	return a.commitBatch(ctx, batch)
}

// prepareBatch is deliberately separate so an interrupted PREPARED batch can
// be exercised deterministically by package tests. Checkpoints never advance
// in this phase.
func (a *Archive) prepareBatch(ctx context.Context, batch Batch) (string, error) {
	tx, err := a.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin archive batch preparation: %w", err)
	}
	defer tx.Rollback()
	for _, session := range batch.Collections {
		if err := insertCollection(ctx, tx, session); err != nil {
			return "", err
		}
	}
	primary := batch.Collections[0]
	contentHash := strings.TrimPrefix(batch.ID, "batch1:")
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO archive_batches(batch_id,primary_collection_id,content_sha256,state,prepared_at)
		VALUES(?,?,?,?,?) ON CONFLICT(batch_id) DO NOTHING`,
		batch.ID, primary.ID, contentHash, "PREPARED", formatInstant(primary.StartedAt)); err != nil {
		return "", fmt.Errorf("prepare archive batch: %w", err)
	}
	var persistedHash, state string
	if err := tx.QueryRowContext(ctx, `SELECT content_sha256,state FROM archive_batches WHERE batch_id=?`, batch.ID).Scan(&persistedHash, &state); err != nil {
		return "", fmt.Errorf("read prepared archive batch: %w", err)
	}
	if persistedHash != contentHash || (state != "PREPARED" && state != "COMMITTED") {
		return "", errors.New("archive batch identity collision or invalid persisted state")
	}
	for _, session := range batch.Collections {
		if _, err := tx.ExecContext(ctx, `INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?) ON CONFLICT DO NOTHING`, batch.ID, session.ID); err != nil {
			return "", fmt.Errorf("link archive batch collection: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit archive batch preparation: %w", err)
	}
	return state, nil
}

func insertCollection(ctx context.Context, tx *sql.Tx, session CollectionSession) error {
	scopeJSON, err := canonicalText(session.Scope)
	if err != nil {
		return err
	}
	limitsJSON, err := canonicalText(session.Limits)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO collection_sessions(collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(collection_id) DO NOTHING`,
		session.ID, session.Mode, nullableText(session.APIVersion), session.AuthKind,
		formatInstant(session.StartedAt), formatInstant(session.EndedAt), boolInt(session.RawRetention), scopeJSON, limitsJSON); err != nil {
		return fmt.Errorf("insert collection %s: %w", session.ID, err)
	}
	var mode, auth, start, end, scope, limits string
	var rawRetention int
	var api sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json FROM collection_sessions WHERE collection_id=?`, session.ID).
		Scan(&mode, &api, &auth, &start, &end, &rawRetention, &scope, &limits); err != nil {
		return err
	}
	if mode != session.Mode || api.String != session.APIVersion || auth != session.AuthKind || start != formatInstant(session.StartedAt) || end != formatInstant(session.EndedAt) || rawRetention != boolInt(session.RawRetention) || scope != scopeJSON || limits != limitsJSON {
		return fmt.Errorf("collection session %s conflicts with persisted content", session.ID)
	}
	return nil
}

func (a *Archive) commitBatch(ctx context.Context, batch Batch) error {
	tx, err := a.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive batch commit: %w", err)
	}
	defer tx.Rollback()

	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM archive_batches WHERE batch_id=?`, batch.ID).Scan(&state); err != nil {
		return fmt.Errorf("read archive batch state: %w", err)
	}
	if state == "COMMITTED" {
		return tx.Commit()
	}
	if state != "PREPARED" {
		return fmt.Errorf("archive batch has invalid state %q", state)
	}

	if err := insertHierarchyFacts(ctx, tx, batch); err != nil {
		return err
	}
	for _, payload := range batch.Payloads {
		if err := insertPayload(ctx, tx, payload); err != nil {
			return err
		}
	}
	for _, envelope := range batch.Evidence {
		if err := insertEnvelope(ctx, tx, envelope); err != nil {
			return err
		}
	}
	if err := insertEvidenceDerivations(ctx, tx, batch.Evidence); err != nil {
		return err
	}
	for _, fact := range batch.Facts {
		if err := insertFact(ctx, tx, batch.ID, fact); err != nil {
			return err
		}
	}
	for _, capability := range batch.Capabilities {
		if err := insertCapability(ctx, tx, capability); err != nil {
			return err
		}
	}
	for _, checkpoint := range batch.Checkpoints {
		if err := insertCheckpoint(ctx, tx, checkpoint); err != nil {
			return err
		}
	}
	committedAt := formatInstant(batch.Collections[0].EndedAt)
	if _, err := tx.ExecContext(ctx, `UPDATE archive_batches SET state='COMMITTED',committed_at=? WHERE batch_id=? AND state='PREPARED'`, committedAt, batch.ID); err != nil {
		return fmt.Errorf("commit archive batch state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive batch: %w", err)
	}
	return nil
}

func canonicalText(value any) (string, error) {
	data, err := evidence.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBool(value *bool) any {
	if value == nil {
		return nil
	}
	return boolInt(*value)
}

func nullableInt64[T ~int64](value *T) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func formatInstant(value model.Instant) string { return value.Format(time.RFC3339Nano) }

func parseInstant(value string) (model.Instant, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return model.Instant{}, err
	}
	return model.NewInstant(parsed)
}
