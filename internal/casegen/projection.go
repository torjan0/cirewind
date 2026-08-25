package casegen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/store"
)

const (
	maxProjectionFacts     = 1_000_000
	maxProjectionJSONBytes = 16 << 20
	maxProjectionTotalJSON = 512 << 20
)

type persistedProjection struct {
	findings []report.Finding
	legacy   graph.Graph
	typed    graph.GraphV2
}

// reprojectCaseDatabase reopens the finalized relational source of truth,
// rehydrates typed facts and selected finding revisions, and independently
// projects both graph contracts. It also verifies the frozen v1 edge cache.
func reprojectCaseDatabase(ctx context.Context, path string, expected report.Case, pack *incident.ValidatedPack, allowRetainedLegacyBasis bool) (persistedProjection, error) {
	database, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		return persistedProjection{}, fmt.Errorf("reopen case database for graph projection: %w", err)
	}
	defer database.Close()
	db := database.DB()
	if err := verifyPersistedProjectionProvenance(ctx, db, expected, pack); err != nil {
		return persistedProjection{}, err
	}
	collections, err := loadPersistedCollections(ctx, db)
	if err != nil {
		return persistedProjection{}, err
	}
	facts, err := loadPersistedFacts(ctx, db, allowRetainedLegacyBasis)
	if err != nil {
		return persistedProjection{}, err
	}
	findings, err := loadPersistedFindings(ctx, db, "analysis:"+expected.Metadata.CaseID)
	if err != nil {
		return persistedProjection{}, err
	}
	normalized := expected
	normalized.Findings = findings
	if err := normalized.NormalizeAndValidate(); err != nil {
		return persistedProjection{}, fmt.Errorf("validate persisted finding selection: %w", err)
	}
	findings = normalized.Findings
	persistedSnapshot := archive.Snapshot{Collections: collections, Facts: facts}
	legacy, typed, err := analyze.ProjectGraphs(persistedSnapshot, findings, pack)
	if err != nil {
		return persistedProjection{}, fmt.Errorf("project persisted case facts: %w", err)
	}
	if err := equalCanonicalJSON("selected findings", findings, expected.Findings); err != nil {
		return persistedProjection{}, err
	}
	if err := equalCanonicalJSON("frozen graph", legacy, expected.Graph); err != nil {
		return persistedProjection{}, err
	}
	if err := equalCanonicalJSON("typed graph", typed, expected.GraphV2); err != nil {
		return persistedProjection{}, err
	}
	if err := verifyLegacyEdgeCache(ctx, db, "analysis:"+expected.Metadata.CaseID, legacy); err != nil {
		return persistedProjection{}, err
	}
	return persistedProjection{findings: findings, legacy: legacy, typed: typed}, nil
}

func loadPersistedCollections(ctx context.Context, db *sql.DB) ([]archive.CollectionSession, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT c.collection_id,c.mode,COALESCE(c.api_version,''),c.auth_kind,
		       c.started_at,c.ended_at,c.raw_retention,c.scope_json,c.limits_json
		FROM collection_sessions c
		JOIN archive_batch_collections bc ON bc.collection_id=c.collection_id
		JOIN archive_batches b ON b.batch_id=bc.batch_id AND b.state='COMMITTED'
		ORDER BY c.collection_id`)
	if err != nil {
		return nil, fmt.Errorf("query persisted collection provenance: %w", err)
	}
	defer rows.Close()
	collections := make([]archive.CollectionSession, 0)
	for rows.Next() {
		if len(collections) >= maxProjectionFacts {
			return nil, fmt.Errorf("persisted collection count exceeds %d", maxProjectionFacts)
		}
		var session archive.CollectionSession
		var startedAt, endedAt string
		var rawRetention int
		var scopeJSON, limitsJSON []byte
		if err := rows.Scan(&session.ID, &session.Mode, &session.APIVersion, &session.AuthKind,
			&startedAt, &endedAt, &rawRetention, &scopeJSON, &limitsJSON); err != nil {
			return nil, fmt.Errorf("scan persisted collection provenance: %w", err)
		}
		if rawRetention != 0 && rawRetention != 1 {
			return nil, fmt.Errorf("persisted collection %s has invalid raw-retention flag", session.ID)
		}
		session.RawRetention = rawRetention == 1
		var parseErr error
		if session.StartedAt, parseErr = parsePersistedInstant(startedAt); parseErr != nil {
			return nil, fmt.Errorf("persisted collection %s started_at: %w", session.ID, parseErr)
		}
		if session.EndedAt, parseErr = parsePersistedInstant(endedAt); parseErr != nil {
			return nil, fmt.Errorf("persisted collection %s ended_at: %w", session.ID, parseErr)
		}
		if len(scopeJSON) > maxProjectionJSONBytes || len(limitsJSON) > maxProjectionJSONBytes {
			return nil, fmt.Errorf("persisted collection %s JSON exceeds size limit", session.ID)
		}
		if err := decodeStrictJSON(scopeJSON, &session.Scope); err != nil {
			return nil, fmt.Errorf("decode persisted collection %s scope: %w", session.ID, err)
		}
		if err := decodeStrictJSON(limitsJSON, &session.Limits); err != nil {
			return nil, fmt.Errorf("decode persisted collection %s limits: %w", session.ID, err)
		}
		if err := session.Validate(); err != nil {
			return nil, fmt.Errorf("validate persisted collection %s: %w", session.ID, err)
		}
		collections = append(collections, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted collection provenance: %w", err)
	}
	var storedCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM collection_sessions`).Scan(&storedCount); err != nil {
		return nil, fmt.Errorf("count persisted collection provenance: %w", err)
	}
	if len(collections) == 0 || len(collections) != storedCount {
		return nil, fmt.Errorf("committed collection provenance count %d disagrees with stored count %d", len(collections), storedCount)
	}
	return collections, nil
}

func parsePersistedInstant(value string) (model.Instant, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return model.Instant{}, err
	}
	return model.NewInstant(parsed)
}

func verifyPersistedProjectionProvenance(ctx context.Context, db *sql.DB, expected report.Case, pack *incident.ValidatedPack) error {
	if pack == nil {
		return errors.New("validated incident pack is nil")
	}
	var canonicalHash, sourceHash string
	var canonicalJSON []byte
	err := db.QueryRowContext(ctx, `
		SELECT canonical_pack_sha256,source_pack_sha256,canonical_json
		FROM incident_packs WHERE canonical_pack_sha256=?`, pack.CanonicalSHA256).
		Scan(&canonicalHash, &sourceHash, &canonicalJSON)
	if err != nil {
		return fmt.Errorf("read persisted incident pack: %w", err)
	}
	if canonicalHash != pack.CanonicalSHA256 || sourceHash != pack.OriginalSHA256 || !bytes.Equal(canonicalJSON, pack.CanonicalJSON) {
		return errors.New("persisted incident pack provenance disagrees with validated input")
	}
	var mode, engineVersion, analyzedAt, analysisCanonical, analysisSource string
	err = db.QueryRowContext(ctx, `
		SELECT mode,engine_version,analyzed_at,canonical_pack_sha256,source_pack_sha256
		FROM analysis_sessions WHERE analysis_id=?`, "analysis:"+expected.Metadata.CaseID).
		Scan(&mode, &engineVersion, &analyzedAt, &analysisCanonical, &analysisSource)
	if err != nil {
		return fmt.Errorf("read persisted analysis provenance: %w", err)
	}
	if mode != expected.Metadata.Mode || engineVersion != expected.Metadata.EngineVersion || analyzedAt != expected.Metadata.AnalysisTime ||
		analysisCanonical != canonicalHash || analysisSource != sourceHash {
		return errors.New("persisted analysis provenance disagrees with case metadata")
	}
	var analysisCount, packCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM analysis_sessions`).Scan(&analysisCount); err != nil {
		return fmt.Errorf("count persisted analyses: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM incident_packs`).Scan(&packCount); err != nil {
		return fmt.Errorf("count persisted incident packs: %w", err)
	}
	if analysisCount != 1 || packCount != 1 {
		return fmt.Errorf("case database requires one analysis and one incident pack; got %d and %d", analysisCount, packCount)
	}
	for _, pair := range []struct{ key, want string }{
		{"case_id", expected.Metadata.CaseID},
		{"engine_version", expected.Metadata.EngineVersion},
		{"analysis_time", expected.Metadata.AnalysisTime},
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key=?`, pair.key).Scan(&got); err != nil {
			return fmt.Errorf("read persisted %s metadata: %w", pair.key, err)
		}
		if got != pair.want {
			return fmt.Errorf("persisted %s metadata disagrees with case", pair.key)
		}
	}
	return nil
}

func loadPersistedFacts(ctx context.Context, db *sql.DB, allowRetainedLegacyBasis bool) ([]archive.Fact, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT f.fact_id,f.kind,f.repository_id,f.run_id,f.run_attempt,f.job_id,
		       COALESCE(f.step_key,''),f.event_time_json,f.payload_json,f.first_batch_id
		FROM archive_facts f
		JOIN archive_batches b ON b.batch_id=f.first_batch_id AND b.state='COMMITTED'
		JOIN archive_batch_facts bf ON bf.batch_id=f.first_batch_id AND bf.fact_id=f.fact_id
		ORDER BY f.fact_id`)
	if err != nil {
		return nil, fmt.Errorf("query persisted facts: %w", err)
	}
	defer rows.Close()
	facts := make([]archive.Fact, 0)
	totalJSON := 0
	for rows.Next() {
		if len(facts) >= maxProjectionFacts {
			return nil, fmt.Errorf("persisted fact count exceeds %d", maxProjectionFacts)
		}
		var raw, eventRaw []byte
		var storedID, storedKind, stepKey, firstBatchID string
		var repositoryID, runID, attempt, jobID sql.NullInt64
		if err := rows.Scan(&storedID, &storedKind, &repositoryID, &runID, &attempt, &jobID,
			&stepKey, &eventRaw, &raw, &firstBatchID); err != nil {
			return nil, fmt.Errorf("scan persisted fact: %w", err)
		}
		if len(raw) > maxProjectionJSONBytes || len(eventRaw) > maxProjectionJSONBytes {
			return nil, fmt.Errorf("persisted fact exceeds %d bytes", maxProjectionJSONBytes)
		}
		totalJSON += len(raw) + len(eventRaw)
		if totalJSON > maxProjectionTotalJSON {
			return nil, fmt.Errorf("persisted fact JSON exceeds %d aggregate bytes", maxProjectionTotalJSON)
		}
		var fact archive.Fact
		if err := decodeStrictJSON(raw, &fact); err != nil {
			return nil, fmt.Errorf("decode persisted fact: %w", err)
		}
		if string(fact.ID) != storedID || string(fact.Kind) != storedKind || firstBatchID == "" {
			return nil, fmt.Errorf("persisted fact %s identity columns disagree with payload", storedID)
		}
		storedSubject := archive.FactSubject{StepKey: stepKey}
		if repositoryID.Valid {
			storedSubject.RepositoryID = model.RepositoryID(repositoryID.Int64)
		}
		if runID.Valid {
			value := model.WorkflowRunID(runID.Int64)
			storedSubject.RunID = &value
		}
		if attempt.Valid {
			value := model.RunAttempt(attempt.Int64)
			storedSubject.RunAttempt = &value
		}
		if jobID.Valid {
			value := model.JobID(jobID.Int64)
			storedSubject.JobID = &value
		}
		if !reflect.DeepEqual(fact.Subject, storedSubject) {
			return nil, fmt.Errorf("persisted fact %s subject columns disagree with payload", storedID)
		}
		var storedEvent model.EventInterval
		if err := decodeStrictJSON(eventRaw, &storedEvent); err != nil {
			return nil, fmt.Errorf("decode persisted fact %s event time: %w", storedID, err)
		}
		if !reflect.DeepEqual(fact.EventTime, storedEvent) {
			return nil, fmt.Errorf("persisted fact %s event-time column disagrees with payload", storedID)
		}
		var normalized archive.Fact
		var normalizeErr error
		if allowRetainedLegacyBasis {
			normalized, normalizeErr = archive.NormalizeRetainedV1Fact(fact)
		} else {
			normalized, normalizeErr = archive.NormalizeFact(fact)
		}
		if normalizeErr != nil {
			return nil, fmt.Errorf("validate persisted fact: %w", normalizeErr)
		}
		if err := equalCanonicalJSON("fact "+storedID, normalized, fact); err != nil {
			return nil, err
		}
		fact = normalized
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted facts: %w", err)
	}
	var storedCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM archive_facts`).Scan(&storedCount); err != nil {
		return nil, fmt.Errorf("count persisted facts: %w", err)
	}
	if len(facts) != storedCount {
		return nil, fmt.Errorf("committed fact count %d disagrees with stored count %d", len(facts), storedCount)
	}
	if err := crossCheckPersistedFactEvidence(ctx, db, facts); err != nil {
		return nil, err
	}
	if err := crossCheckPersistedCoverage(ctx, db, facts); err != nil {
		return nil, err
	}
	if err := crossCheckPersistedBatch(ctx, db, facts); err != nil {
		return nil, err
	}
	return facts, nil
}

func crossCheckPersistedFactEvidence(ctx context.Context, db *sql.DB, facts []archive.Fact) error {
	wanted := make(map[string][]string, len(facts))
	for _, fact := range facts {
		ids := make([]string, len(fact.EvidenceIDs))
		for i, id := range fact.EvidenceIDs {
			ids[i] = string(id)
		}
		sort.Strings(ids)
		wanted[fact.ID] = ids
	}
	actual := make(map[string][]string, len(facts))
	rows, err := db.QueryContext(ctx, `SELECT fact_id,evidence_id FROM archive_fact_evidence ORDER BY fact_id,evidence_id`)
	if err != nil {
		return fmt.Errorf("query persisted fact evidence links: %w", err)
	}
	for rows.Next() {
		var factID, evidenceID string
		if err := rows.Scan(&factID, &evidenceID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan persisted fact evidence link: %w", err)
		}
		if _, ok := wanted[factID]; !ok {
			_ = rows.Close()
			return fmt.Errorf("persisted evidence link references unprojected fact %s", factID)
		}
		actual[factID] = append(actual[factID], evidenceID)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close persisted fact evidence links: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate persisted fact evidence links: %w", err)
	}
	keys := make([]string, 0, len(wanted))
	for factID := range wanted {
		keys = append(keys, factID)
	}
	sort.Strings(keys)
	for _, factID := range keys {
		if !stringSlicesEqual(wanted[factID], actual[factID]) {
			return fmt.Errorf("persisted fact %s evidence links disagree with payload", factID)
		}
	}
	return nil
}

type persistedCoverageRow struct {
	collectionID, kind, logicalScope, status string
	repositoryID, runID, attempt, jobID      sql.NullInt64
	expected, collected, notApplicable, gaps int
	reason                                   sql.NullString
	material, retryable                      int
	evidenceID                               sql.NullString
}

func crossCheckPersistedCoverage(ctx context.Context, db *sql.DB, facts []archive.Fact) error {
	wanted := make(map[string]archive.Fact)
	for _, fact := range facts {
		if fact.Coverage != nil {
			wanted[string(fact.Coverage.Assessment.ID)] = fact
		}
		if fact.CoverageGap != nil {
			wanted[string(fact.CoverageGap.Assessment.ID)] = fact
		}
	}
	rows, err := db.QueryContext(ctx, `
		SELECT coverage_id,collection_id,kind,logical_scope,repository_id,run_id,run_attempt,job_id,
		       expected,collected,not_applicable,gaps,status,reason_code,material,retryable,evidence_id
		FROM coverage_units ORDER BY coverage_id`)
	if err != nil {
		return fmt.Errorf("query persisted coverage rows: %w", err)
	}
	seen := make(map[string]struct{}, len(wanted))
	for rows.Next() {
		var id string
		var row persistedCoverageRow
		if err := rows.Scan(&id, &row.collectionID, &row.kind, &row.logicalScope,
			&row.repositoryID, &row.runID, &row.attempt, &row.jobID,
			&row.expected, &row.collected, &row.notApplicable, &row.gaps,
			&row.status, &row.reason, &row.material, &row.retryable, &row.evidenceID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan persisted coverage row: %w", err)
		}
		fact, ok := wanted[id]
		if !ok {
			_ = rows.Close()
			return fmt.Errorf("persisted coverage row %s has no typed coverage fact", id)
		}
		if _, duplicate := seen[id]; duplicate {
			_ = rows.Close()
			return fmt.Errorf("persisted coverage row %s is duplicated", id)
		}
		seen[id] = struct{}{}
		if err := comparePersistedCoverageRow(id, row, fact); err != nil {
			_ = rows.Close()
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close persisted coverage rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate persisted coverage rows: %w", err)
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("persisted coverage row count %d disagrees with typed fact count %d", len(seen), len(wanted))
	}
	return nil
}

func comparePersistedCoverageRow(id string, row persistedCoverageRow, fact archive.Fact) error {
	var unit model.CoverageUnit
	var assessment model.CoverageAssessment
	if fact.Coverage != nil {
		unit, assessment = fact.Coverage.Unit, fact.Coverage.Assessment
	} else if fact.CoverageGap != nil {
		unit, assessment = fact.CoverageGap.Unit, fact.CoverageGap.Assessment
	} else {
		return fmt.Errorf("coverage row %s has no typed payload", id)
	}
	wantStatus, collected, notApplicable, gaps := "", 0, 0, 0
	wantReason, material, retryable := "", 0, 0
	switch assessment.Status {
	case model.CoverageCollected:
		wantStatus, collected = "collected", 1
	case model.CoverageNotApplicable:
		wantStatus, notApplicable = "not_applicable", 1
	case model.CoverageGap:
		wantStatus, gaps = "gap", 1
		if assessment.Gap == nil {
			return fmt.Errorf("coverage row %s has gap status without detail", id)
		}
		wantReason = string(assessment.Gap.Reason)
		material, retryable = boolToInt(assessment.Gap.Material), boolToInt(assessment.Gap.Retryable)
	default:
		return fmt.Errorf("coverage row %s has unsupported typed status %q", id, assessment.Status)
	}
	wantEvidence := ""
	if len(fact.EvidenceIDs) > 0 {
		wantEvidence = string(fact.EvidenceIDs[0])
	}
	if row.collectionID == "" || row.kind != string(unit.Kind) || row.logicalScope != unit.LogicalKey ||
		row.expected != 1 || row.collected != collected || row.notApplicable != notApplicable || row.gaps != gaps ||
		row.status != wantStatus || nullStringValue(row.reason) != wantReason || row.material != material ||
		row.retryable != retryable || nullStringValue(row.evidenceID) != wantEvidence ||
		!sameNullableID(row.repositoryID, fact.Subject.RepositoryID) || !sameNullableRun(row.runID, fact.Subject.RunID) ||
		!sameNullableAttempt(row.attempt, fact.Subject.RunAttempt) || !sameNullableJob(row.jobID, fact.Subject.JobID) {
		return fmt.Errorf("persisted coverage row %s disagrees with typed coverage fact", id)
	}
	return nil
}

func crossCheckPersistedBatch(ctx context.Context, db *sql.DB, facts []archive.Fact) error {
	var batchID, contentHash, state string
	var count int
	rows, err := db.QueryContext(ctx, `SELECT batch_id,content_sha256,state FROM archive_batches ORDER BY batch_id`)
	if err != nil {
		return fmt.Errorf("query persisted fact batch: %w", err)
	}
	for rows.Next() {
		count++
		if err := rows.Scan(&batchID, &contentHash, &state); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan persisted fact batch: %w", err)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close persisted fact batch: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate persisted fact batch: %w", err)
	}
	if count != 1 || state != "COMMITTED" || batchID == "" {
		return fmt.Errorf("case database has %d fact batches; exactly one committed batch is required", count)
	}
	encoded, err := evidence.CanonicalJSON(facts)
	if err != nil {
		return fmt.Errorf("encode persisted fact batch: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if contentHash != hex.EncodeToString(digest[:]) {
		return errors.New("persisted fact batch content hash disagrees with rehydrated facts")
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullStringValue(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func sameNullableID(value sql.NullInt64, expected model.RepositoryID) bool {
	return value.Valid == (expected != 0) && (!value.Valid || value.Int64 == int64(expected))
}

func sameNullableRun(value sql.NullInt64, expected *model.WorkflowRunID) bool {
	return value.Valid == (expected != nil) && (!value.Valid || value.Int64 == int64(*expected))
}

func sameNullableAttempt(value sql.NullInt64, expected *model.RunAttempt) bool {
	return value.Valid == (expected != nil) && (!value.Valid || value.Int64 == int64(*expected))
}

func sameNullableJob(value sql.NullInt64, expected *model.JobID) bool {
	return value.Valid == (expected != nil) && (!value.Valid || value.Int64 == int64(*expected))
}

type persistedFinding struct {
	finding      report.Finding
	jsonCoverage []string
}

func loadPersistedFindings(ctx context.Context, db *sql.DB, analysisID string) ([]report.Finding, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT fr.finding_revision_id,f.finding_id,f.incident_id,f.indicator_id,
		       COALESCE(r.owner,''),COALESCE(r.name,''),COALESCE(f.workflow_path,''),
		       COALESCE(f.run_id,0),COALESCE(f.run_attempt,0),COALESCE(f.job_id,0),COALESCE(f.step_key,''),
		       fr.state,fr.provenance,fr.concise_conclusion,COALESCE(fr.event_time_json,''),
		       fr.assumptions_json,fr.gaps_json,fr.contradictions_json,
		       fr.credential_exposure_json,fr.resource_exposure_json,fr.remediation_json,
		       fr.collection_coverage_json,fr.rule_version
		FROM analysis_session_findings selected
		JOIN finding_revisions fr ON fr.finding_revision_id=selected.finding_revision_id
		JOIN findings f ON f.finding_id=fr.finding_id
		LEFT JOIN repositories r ON r.repository_id=f.repository_id
		WHERE selected.analysis_id=? AND selected.disposition IN ('EMITTED','REUSED')
		ORDER BY fr.finding_revision_id`, analysisID)
	if err != nil {
		return nil, fmt.Errorf("query persisted findings: %w", err)
	}
	var persisted []persistedFinding
	totalJSON := 0
	for rows.Next() {
		if len(persisted) >= maxProjectionFacts {
			_ = rows.Close()
			return nil, fmt.Errorf("persisted finding count exceeds %d", maxProjectionFacts)
		}
		var item persistedFinding
		var owner, name string
		var assumptions, gaps, contradictions, credentials, resources, remediation, coverage []byte
		f := &item.finding
		if err := rows.Scan(
			&f.FindingRevisionID, &f.FindingID, &f.IncidentID, &f.IndicatorID,
			&owner, &name, &f.Workflow, &f.RunID, &f.RunAttempt, &f.JobID, &f.StepIdentity,
			&f.State, &f.Provenance, &f.Conclusion, &f.EventTime,
			&assumptions, &gaps, &contradictions, &credentials, &resources, &remediation,
			&coverage, &f.DerivationRuleVersion,
		); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan persisted finding: %w", err)
		}
		if owner == "" || name == "" {
			_ = rows.Close()
			return nil, fmt.Errorf("persisted finding %s lacks repository identity", f.FindingRevisionID)
		}
		f.Repository = owner + "/" + name
		for _, value := range []struct {
			label string
			raw   []byte
			out   any
		}{
			{"assumptions", assumptions, &f.Assumptions},
			{"gaps", gaps, &f.EvidenceGaps},
			{"contradictions", contradictions, &f.ContradictoryEvidence},
			{"credential exposure", credentials, &f.CredentialExposure},
			{"resource exposure", resources, &f.ResourceExposure},
			{"remediation", remediation, &f.RemediationGuidance},
			{"coverage", coverage, &item.jsonCoverage},
		} {
			if len(value.raw) > maxProjectionJSONBytes {
				_ = rows.Close()
				return nil, fmt.Errorf("persisted finding %s %s exceeds size limit", f.FindingRevisionID, value.label)
			}
			totalJSON += len(value.raw)
			if totalJSON > maxProjectionTotalJSON {
				_ = rows.Close()
				return nil, fmt.Errorf("persisted finding JSON exceeds %d aggregate bytes", maxProjectionTotalJSON)
			}
			if err := decodeStrictJSON(value.raw, value.out); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("decode persisted finding %s %s: %w", f.FindingRevisionID, value.label, err)
			}
		}
		persisted = append(persisted, item)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close persisted findings: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted findings: %w", err)
	}
	result := make([]report.Finding, 0, len(persisted))
	for _, item := range persisted {
		f := item.finding
		evidenceIDs, err := queryStrings(ctx, db, `SELECT evidence_id FROM finding_revision_evidence WHERE finding_revision_id=? AND role='SUPPORTS' ORDER BY evidence_id`, f.FindingRevisionID)
		if err != nil {
			return nil, fmt.Errorf("read finding evidence %s: %w", f.FindingRevisionID, err)
		}
		coverageIDs, err := queryStrings(ctx, db, `SELECT coverage_id FROM finding_revision_coverage WHERE finding_revision_id=? ORDER BY coverage_id`, f.FindingRevisionID)
		if err != nil {
			return nil, fmt.Errorf("read finding coverage %s: %w", f.FindingRevisionID, err)
		}
		sort.Strings(item.jsonCoverage)
		if !stringSlicesEqual(coverageIDs, item.jsonCoverage) {
			return nil, fmt.Errorf("persisted finding %s coverage links disagree with revision JSON", f.FindingRevisionID)
		}
		f.EvidenceIDs = evidenceIDs
		f.CollectionCoverage = coverageIDs
		result = append(result, f)
	}
	return result, nil
}

func verifyLegacyEdgeCache(ctx context.Context, db *sql.DB, analysisID string, expected graph.Graph) error {
	encoded, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	wantHash := hex.EncodeToString(hash[:])
	wanted := make(map[string]graph.Edge, len(expected.Edges))
	for _, edge := range expected.Edges {
		wanted[edge.ID] = edge
	}
	rows, err := db.QueryContext(ctx, `
		SELECT edge_id,source_id,target_id,relation,COALESCE(event_time_json,''),
		       evidence_ids_json,COALESCE(derivation_rule,''),snapshot_sha256
		FROM graph_projection_edges WHERE analysis_id=? ORDER BY edge_id`, analysisID)
	if err != nil {
		return fmt.Errorf("query frozen graph edge cache: %w", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id, source, target, relation, eventTime, rule, storedHash string
		var evidenceJSON []byte
		if err := rows.Scan(&id, &source, &target, &relation, &eventTime, &evidenceJSON, &rule, &storedHash); err != nil {
			return fmt.Errorf("scan frozen graph edge cache: %w", err)
		}
		edge, ok := wanted[id]
		if !ok {
			return fmt.Errorf("frozen graph edge cache contains unexpected edge %s", id)
		}
		var evidenceIDs []string
		if err := decodeStrictJSON(evidenceJSON, &evidenceIDs); err != nil {
			return fmt.Errorf("decode frozen graph edge %s evidence: %w", id, err)
		}
		if source != edge.Source || target != edge.Target || relation != string(edge.Type) || eventTime != edge.EventTime || rule != edge.DerivationRule || storedHash != wantHash || !stringSlicesEqual(evidenceIDs, edge.EvidenceIDs) {
			return fmt.Errorf("frozen graph edge cache disagrees with reprojected edge %s", id)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate frozen graph edge cache: %w", err)
	}
	if seen != len(wanted) {
		return fmt.Errorf("frozen graph edge cache has %d edges, reprojected graph has %d", seen, len(wanted))
	}
	return nil
}

func queryStrings(ctx context.Context, db *sql.DB, query, value string) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		if len(result) >= maxProjectionFacts {
			return nil, fmt.Errorf("persisted relationship count exceeds %d", maxProjectionFacts)
		}
		var item string
		if err := rows.Scan(&item); err != nil {
			return nil, err
		}
		if len(item) == 0 || len(item) > maxProjectionJSONBytes {
			return nil, errors.New("persisted relationship identity is empty or unbounded")
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func equalCanonicalJSON(label string, actual, expected any) error {
	left, err := json.Marshal(actual)
	if err != nil {
		return fmt.Errorf("encode persisted %s: %w", label, err)
	}
	right, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("encode expected %s: %w", label, err)
	}
	if !bytes.Equal(left, right) {
		leftHash := sha256.Sum256(left)
		rightHash := sha256.Sum256(right)
		index := firstDifferentByte(left, right)
		return fmt.Errorf("persisted %s projection disagrees with pre-database expectation (actual %x, expected %x, first byte %d)", label, leftHash, rightHash, index)
	}
	return nil
}

func firstDifferentByte(left, right []byte) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
