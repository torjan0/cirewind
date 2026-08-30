package archive

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

const maxSnapshotBytes = 256 << 20
const maxPersistedJSONCellBytes = 16 << 20

func (a *Archive) Snapshot(ctx context.Context) (Snapshot, error) {
	if err := validatePersistedSnapshotBudgets(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Metadata:     a.metadata,
		Collections:  []CollectionSession{},
		Payloads:     []Payload{},
		Evidence:     []evidence.Envelope{},
		Facts:        []Fact{},
		Capabilities: []Capability{},
		Checkpoints:  []Checkpoint{},
	}
	var err error
	if snapshot.Collections, err = readCollections(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Payloads, err = readPayloads(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Evidence, err = readEnvelopes(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Facts, err = readFacts(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Capabilities, err = readCapabilities(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	// Optional raw sidecars are checked for present-time availability without
	// turning their loss into loss of compact structured facts. Raw-dependent
	// copy or verification remains fail-closed via CopyRaw and VerifyRaw.
	if err := a.applyRawAvailability(ctx, &snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.Checkpoints, err = readCheckpoints(ctx, a.store.DB()); err != nil {
		return Snapshot{}, err
	}
	return normalizeRetainedSnapshot(snapshot)
}

func validatePersistedSnapshotBudgets(ctx context.Context, database *sql.DB) error {
	counts := []struct {
		label string
		query string
		limit int64
	}{
		{"compact payload", `SELECT count(*) FROM evidence_payloads WHERE payload IS NOT NULL`, maxSnapshotPayloads},
		{"evidence envelope", `SELECT count(*) FROM archive_evidence_envelopes`, maxSnapshotEvidence},
		{"archive fact", `SELECT count(*) FROM archive_facts`, maxSnapshotFacts},
		{"collection session", `SELECT count(*) FROM collection_sessions`, maxSnapshotEvidence},
		{"capability", `SELECT count(*) FROM archive_capabilities`, maxSnapshotEvidence},
	}
	for _, check := range counts {
		var count int64
		if err := database.QueryRowContext(ctx, check.query).Scan(&count); err != nil {
			return fmt.Errorf("inspect %s count: %w", check.label, err)
		}
		if count < 0 || count > check.limit {
			return fmt.Errorf("persisted %s count %d exceeds limit %d", check.label, count, check.limit)
		}
	}
	jsonBudgets := []struct {
		label string
		query string
	}{
		{"collection JSON", `SELECT coalesce(max(length(scope_json)+length(limits_json)),0),coalesce(sum(length(scope_json)+length(limits_json)),0) FROM collection_sessions`},
		{"evidence envelope JSON", `SELECT coalesce(max(length(envelope_json)),0),coalesce(sum(length(envelope_json)),0) FROM archive_evidence_envelopes`},
		{"archive fact JSON", `SELECT coalesce(max(length(event_time_json)+length(payload_json)),0),coalesce(sum(length(event_time_json)+length(payload_json)),0) FROM archive_facts`},
		{"capability JSON", `SELECT coalesce(max(length(detail_json)),0),coalesce(sum(length(detail_json)),0) FROM archive_capabilities`},
		{"compact payload", `SELECT coalesce(max(length(payload)),0),coalesce(sum(length(payload)),0) FROM evidence_payloads WHERE payload IS NOT NULL`},
	}
	var aggregate int64
	for _, check := range jsonBudgets {
		var maximum, total int64
		if err := database.QueryRowContext(ctx, check.query).Scan(&maximum, &total); err != nil {
			return fmt.Errorf("inspect %s budget: %w", check.label, err)
		}
		if maximum < 0 || maximum > maxPersistedJSONCellBytes {
			return fmt.Errorf("persisted %s cell length %d exceeds limit %d", check.label, maximum, maxPersistedJSONCellBytes)
		}
		if total < 0 || total > maxSnapshotBytes || aggregate > maxSnapshotBytes-total {
			return fmt.Errorf("persisted compact snapshot data exceeds %d bytes", maxSnapshotBytes)
		}
		aggregate += total
	}
	return nil
}

func (a *Archive) Export(ctx context.Context, writer io.Writer) error {
	snapshot, err := a.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshotHasRaw(snapshot) {
		return errors.New("raw-bearing archive cannot be exported as one JSON file; preserve the archive database and its .raw sidecar together")
	}
	encoded, err := evidence.CanonicalJSON(snapshot)
	if err != nil {
		return fmt.Errorf("encode archive snapshot: %w", err)
	}
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("write archive snapshot: %w", err)
	}
	return nil
}

func DecodeSnapshot(reader io.Reader) (Snapshot, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read archive snapshot: %w", err)
	}
	if len(data) > maxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("archive snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode archive snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Snapshot{}, errors.New("archive snapshot contains multiple JSON values")
		}
		return Snapshot{}, fmt.Errorf("decode archive snapshot suffix: %w", err)
	}
	return normalizeRetainedSnapshot(snapshot)
}

// Import creates an archive from a self-contained snapshot without network
// access. The returned archive remains open for incremental collection.
func Import(ctx context.Context, path string, input Snapshot) (*Archive, error) {
	snapshot, err := NormalizeSnapshot(input)
	if err != nil {
		return nil, err
	}
	if snapshotHasRaw(snapshot) {
		return nil, errors.New("raw-bearing snapshot import requires an archive bundle; single-file JSON import is disabled")
	}
	archive, err := Create(ctx, path, Options{ArchiveID: snapshot.Metadata.ArchiveID, CreatedAt: snapshot.Metadata.CreatedAt})
	if err != nil {
		return nil, err
	}
	if len(snapshot.Collections)+len(snapshot.Payloads)+len(snapshot.Evidence)+len(snapshot.Facts)+len(snapshot.Capabilities)+len(snapshot.Checkpoints) == 0 {
		return archive, nil
	}
	batch := Batch{
		Collections: snapshot.Collections, Payloads: snapshot.Payloads, Evidence: snapshot.Evidence,
		Facts: snapshot.Facts, Capabilities: snapshot.Capabilities, Checkpoints: snapshot.Checkpoints,
	}
	if snapshot.retainedLegacyCredentialBasis {
		err = archive.appendRetained(ctx, batch)
	} else {
		err = archive.Append(ctx, batch)
	}
	if err != nil {
		_ = archive.Close()
		return nil, err
	}
	return archive, nil
}

func readCollections(ctx context.Context, database *sql.DB) ([]CollectionSession, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT DISTINCT c.collection_id,c.mode,COALESCE(c.api_version,''),c.auth_kind,c.started_at,c.ended_at,c.raw_retention,c.scope_json,c.limits_json
		FROM collection_sessions c
		JOIN archive_batch_collections bc ON bc.collection_id=c.collection_id
		JOIN archive_batches b ON b.batch_id=bc.batch_id AND b.state='COMMITTED'
		ORDER BY c.collection_id`)
	if err != nil {
		return nil, fmt.Errorf("read archive collections: %w", err)
	}
	defer rows.Close()
	result := []CollectionSession{}
	for rows.Next() {
		var session CollectionSession
		var startedAt, endedAt, scopeJSON, limitsJSON string
		var rawRetention int
		if err := rows.Scan(&session.ID, &session.Mode, &session.APIVersion, &session.AuthKind, &startedAt, &endedAt, &rawRetention, &scopeJSON, &limitsJSON); err != nil {
			return nil, err
		}
		if rawRetention != 0 && rawRetention != 1 {
			return nil, errors.New("persisted collection has an invalid raw-retention flag")
		}
		session.RawRetention = rawRetention == 1
		var err error
		if session.StartedAt, err = parseInstant(startedAt); err != nil {
			return nil, err
		}
		if session.EndedAt, err = parseInstant(endedAt); err != nil {
			return nil, err
		}
		if err := decodePersistedJSON("collection scope", scopeJSON, &session.Scope); err != nil {
			return nil, fmt.Errorf("decode collection scope: %w", err)
		}
		if err := decodePersistedJSON("collection limits", limitsJSON, &session.Limits); err != nil {
			return nil, fmt.Errorf("decode collection limits: %w", err)
		}
		result = append(result, session)
	}
	return result, rows.Err()
}

func readPayloads(ctx context.Context, database *sql.DB) ([]Payload, error) {
	rows, err := database.QueryContext(ctx, `SELECT payload_sha256,media_type,payload FROM evidence_payloads WHERE payload IS NOT NULL ORDER BY payload_sha256`)
	if err != nil {
		return nil, fmt.Errorf("read archive payloads: %w", err)
	}
	defer rows.Close()
	result := []Payload{}
	for rows.Next() {
		var payload Payload
		if err := rows.Scan(&payload.SHA256, &payload.MediaType, &payload.Bytes); err != nil {
			return nil, err
		}
		result = append(result, payload)
	}
	return result, rows.Err()
}

func readEnvelopes(ctx context.Context, database *sql.DB) ([]evidence.Envelope, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT ae.envelope_json FROM archive_evidence_envelopes ae
		JOIN evidence_observations eo ON eo.observation_id=ae.observation_id
		JOIN archive_batch_collections bc ON bc.collection_id=eo.collection_id
		JOIN archive_batches b ON b.batch_id=bc.batch_id AND b.state='COMMITTED'
		GROUP BY ae.observation_id ORDER BY ae.observation_id`)
	if err != nil {
		return nil, fmt.Errorf("read archive evidence: %w", err)
	}
	defer rows.Close()
	result := []evidence.Envelope{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var envelope evidence.Envelope
		if err := decodePersistedJSON("evidence envelope", encoded, &envelope); err != nil {
			return nil, fmt.Errorf("decode persisted evidence envelope: %w", err)
		}
		result = append(result, envelope)
	}
	return result, rows.Err()
}

func readFacts(ctx context.Context, database *sql.DB) ([]Fact, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT f.fact_id,f.kind,f.repository_id,f.run_id,f.run_attempt,f.job_id,COALESCE(f.step_key,''),f.event_time_json,f.payload_json
		FROM archive_facts f
		JOIN archive_batch_facts bf ON bf.fact_id=f.fact_id
		JOIN archive_batches b ON b.batch_id=bf.batch_id AND b.state='COMMITTED'
		GROUP BY f.fact_id ORDER BY f.fact_id`)
	if err != nil {
		return nil, fmt.Errorf("read archive facts: %w", err)
	}
	result := []Fact{}
	for rows.Next() {
		var fact Fact
		var repositoryID, runID, attempt, jobID sql.NullInt64
		var eventJSON, payloadJSON string
		if err := rows.Scan(&fact.ID, &fact.Kind, &repositoryID, &runID, &attempt, &jobID, &fact.Subject.StepKey, &eventJSON, &payloadJSON); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if repositoryID.Valid {
			fact.Subject.RepositoryID = model.RepositoryID(repositoryID.Int64)
		}
		if runID.Valid {
			value := model.WorkflowRunID(runID.Int64)
			fact.Subject.RunID = &value
		}
		if attempt.Valid {
			value := model.RunAttempt(attempt.Int64)
			fact.Subject.RunAttempt = &value
		}
		if jobID.Valid {
			value := model.JobID(jobID.Int64)
			fact.Subject.JobID = &value
		}
		if err := decodePersistedJSON("fact event time", eventJSON, &fact.EventTime); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var payload factPayload
		if err := decodePersistedJSON("fact payload", payloadJSON, &payload); err != nil {
			_ = rows.Close()
			return nil, err
		}
		fact.Repository, fact.Run, fact.Attempt, fact.Job = payload.Repository, payload.Run, payload.Attempt, payload.Job
		fact.ActionOccurrence, fact.Dependency = payload.ActionOccurrence, payload.Dependency
		fact.Coverage, fact.CoverageGap, fact.Exposure = payload.Coverage, payload.CoverageGap, payload.Exposure
		fact.EvidenceIDs = []model.EvidenceID{}
		result = append(result, fact)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	evidenceRows, err := database.QueryContext(ctx, `
		SELECT fe.fact_id,fe.evidence_id FROM archive_fact_evidence fe
		JOIN archive_facts f ON f.fact_id=fe.fact_id ORDER BY fe.fact_id,fe.evidence_id`)
	if err != nil {
		return nil, err
	}
	defer evidenceRows.Close()
	factIndex := make(map[string]int, len(result))
	for index := range result {
		factIndex[result[index].ID] = index
	}
	for evidenceRows.Next() {
		var factID string
		var evidenceID model.EvidenceID
		if err := evidenceRows.Scan(&factID, &evidenceID); err != nil {
			return nil, err
		}
		if index, ok := factIndex[factID]; ok {
			result[index].EvidenceIDs = append(result[index].EvidenceIDs, evidenceID)
		}
	}
	return result, evidenceRows.Err()
}

func readCapabilities(ctx context.Context, database *sql.DB) ([]Capability, error) {
	rows, err := database.QueryContext(ctx, `SELECT capability,status,COALESCE(extractor_version,''),detail_json FROM archive_capabilities ORDER BY capability`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Capability{}
	for rows.Next() {
		var capability Capability
		var detailJSON string
		if err := rows.Scan(&capability.Name, &capability.Status, &capability.ExtractorVersion, &detailJSON); err != nil {
			return nil, err
		}
		if err := decodePersistedJSON("capability details", detailJSON, &capability.Details); err != nil {
			return nil, err
		}
		result = append(result, capability)
	}
	return result, rows.Err()
}

func decodePersistedJSON(label, encoded string, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxPersistedJSONCellBytes {
		return fmt.Errorf("%s JSON byte length %d is outside the compiled limit", label, len(encoded))
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%s JSON: %w", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%s JSON contains multiple values", label)
		}
		return fmt.Errorf("%s JSON suffix: %w", label, err)
	}
	return nil
}

func readCheckpoints(ctx context.Context, database *sql.DB) ([]Checkpoint, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT repository_id,discovery_watermark,overlap_seconds,watch_horizon_days,last_successful_collection_id
		FROM archive_checkpoints ORDER BY repository_id`)
	if err != nil {
		return nil, err
	}
	result := []Checkpoint{}
	for rows.Next() {
		var checkpoint Checkpoint
		var watermark sql.NullString
		if err := rows.Scan(&checkpoint.RepositoryID, &watermark, &checkpoint.OverlapSeconds, &checkpoint.WatchHorizonDays, &checkpoint.LastSuccessfulCollection); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if watermark.Valid {
			value, err := parseInstant(watermark.String)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
			checkpoint.DiscoveryWatermark = &value
		}
		checkpoint.WatchedParents = []WatchedParent{}
		result = append(result, checkpoint)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	parents, err := database.QueryContext(ctx, `SELECT repository_id,run_id,created_at,last_refreshed_at,final_refresh_complete FROM watched_parents ORDER BY repository_id,run_id`)
	if err != nil {
		return nil, err
	}
	defer parents.Close()
	index := make(map[model.RepositoryID]int, len(result))
	for i := range result {
		index[result[i].RepositoryID] = i
	}
	for parents.Next() {
		var repositoryID model.RepositoryID
		var parent WatchedParent
		var createdAt string
		var refreshed sql.NullString
		var complete int
		if err := parents.Scan(&repositoryID, &parent.RunID, &createdAt, &refreshed, &complete); err != nil {
			return nil, err
		}
		parent.CreatedAt, err = parseInstant(createdAt)
		if err != nil {
			return nil, err
		}
		if refreshed.Valid {
			value, err := parseInstant(refreshed.String)
			if err != nil {
				return nil, err
			}
			parent.LastRefreshedAt = &value
		}
		parent.FinalRefreshComplete = complete != 0
		if i, ok := index[repositoryID]; ok {
			result[i].WatchedParents = append(result[i].WatchedParents, parent)
		}
	}
	return result, parents.Err()
}
