package qualification

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/store"
)

type scaleProfile struct {
	Repositories int `json:"repositories"`
	Runs         int `json:"runs"`
	Executions   int `json:"attempts_jobs"`
}

var scaleProfiles = map[string]scaleProfile{
	"small":  {Repositories: 100, Runs: 10_000, Executions: 25_000},
	"medium": {Repositories: 1_000, Runs: 100_000, Executions: 300_000},
	"large":  {Repositories: 10_000, Runs: 1_000_000, Executions: 3_000_000},
}

// TestSyntheticStoreScaleQualification is an explicit release-qualification
// harness. It is skipped in the default offline suite because the medium and
// large profiles intentionally create substantial databases. The caller must
// provide a new path on a volume with adequate space.
func TestSyntheticStoreScaleQualification(t *testing.T) {
	profileName := os.Getenv("CIREWIND_SCALE_PROFILE")
	if profileName == "" {
		t.Skip("set CIREWIND_SCALE_PROFILE and CIREWIND_SCALE_DB for scale qualification")
	}
	profile, ok := scaleProfiles[profileName]
	if !ok {
		t.Fatalf("unknown CIREWIND_SCALE_PROFILE %q", profileName)
	}
	databasePath := os.Getenv("CIREWIND_SCALE_DB")
	if databasePath == "" || !filepath.IsAbs(databasePath) {
		t.Fatal("CIREWIND_SCALE_DB must be an absolute path to a new database")
	}
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(databasePath); err == nil {
		t.Fatalf("scale database already exists: %s", databasePath)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	started := time.Now()
	database, err := store.Create(ctx, databasePath, store.KindCase)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := populateScaleDatabase(ctx, database.DB(), profile); err != nil {
		t.Fatal(err)
	}
	insertElapsed := time.Since(started)
	queryMetrics, err := qualifyScaleQueries(ctx, database.DB(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var sqliteVersion string
	if err := database.DB().QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&sqliteVersion); err != nil {
		t.Fatal(err)
	}
	result := struct {
		Profile       string                 `json:"profile"`
		Seed          int                    `json:"seed"`
		Counts        scaleProfile           `json:"counts"`
		GoVersion     string                 `json:"go_version"`
		SQLiteVersion string                 `json:"sqlite_version"`
		DatabaseBytes int64                  `json:"database_bytes"`
		InsertMillis  int64                  `json:"insert_millis"`
		Queries       map[string]queryMetric `json:"queries"`
	}{profileName, 20260821, profile, runtime.Version(), sqliteVersion, info.Size(), insertElapsed.Milliseconds(), queryMetrics}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CIREWIND_SCALE_RESULT %s", encoded)
}

func populateScaleDatabase(ctx context.Context, database *sql.DB, profile scaleProfile) error {
	const (
		instant    = "2026-08-21T00:00:00Z"
		collection = "collection:scale"
		analysis   = "analysis:scale"
		packHash   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		batchID    = "batch1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		evidenceID = "ev1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		sourceID   = "src1:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	bootstrap := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO collection_sessions(collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json) VALUES(?,?,?,?,?,?,?,?,?)`, []any{collection, "fixture", "2026-03-10", "none", instant, instant, 0, `{}`, `{}`}},
		{`INSERT INTO incident_packs(canonical_pack_sha256,incident_id,api_version,pack_version,source_pack_sha256,canonical_json,validation_policy_version) VALUES(?,?,?,?,?,?,?)`, []any{packHash, "SYNTH-SCALE", "cirewind.dev/v1alpha1", "1.0.0", packHash, []byte(`{}`), "v1"}},
		{`INSERT INTO analysis_sessions(analysis_id,mode,engine_version,semantic_rule_version,canonical_pack_sha256,source_pack_sha256,policy_sha256,analyzed_at) VALUES(?,?,?,?,?,?,?,?)`, []any{analysis, "fixture", "scale", "v1", packHash, packHash, packHash, instant}},
		{`INSERT INTO archive_batches(batch_id,primary_collection_id,content_sha256,state,prepared_at,committed_at) VALUES(?,?,?,?,?,?)`, []any{batchID, collection, packHash, "COMMITTED", instant, instant}},
		{`INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?)`, []any{batchID, collection}},
		{`INSERT INTO source_requests(request_id,collection_id,method,route_template,parameters_json,http_status,media_type,byte_length,source_sha256,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, []any{"request:scale", collection, "GET", "offline-scale", `{}`, 200, "application/json", 2, packHash, instant, instant}},
		{`INSERT INTO logical_sources(logical_source_id,kind,canonical_id,selector_json) VALUES(?,?,?,?)`, []any{sourceID, "derived_projection", "synthetic-scale", `{}`}},
		{`INSERT INTO evidence_objects(evidence_id,logical_source_id,schema_version,provider,source_sha256,source_byte_length,complete,media_type,raw_retained,redaction_status,redaction_policy_version,extractor_name,extractor_version,ruleset_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, []any{evidenceID, sourceID, "cirewind.evidence/v1alpha1", "synthetic", packHash, 2, 1, "application/json", 0, "structured_allowlist", "scale-v1", "scale", "v1", packHash}},
	}
	for _, statement := range bootstrap {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}

	if err := withTransaction(ctx, database, func(tx *sql.Tx) error {
		statement, err := tx.PrepareContext(ctx, `INSERT INTO repositories(repository_id,owner,name,visibility,is_private,is_fork,is_archived,is_disabled,default_branch) VALUES(?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer statement.Close()
		for repository := 1; repository <= profile.Repositories; repository++ {
			if _, err := statement.ExecContext(ctx, repository, "synthetic", fmt.Sprintf("repository-%05d", repository), "private", 1, 0, 0, 0, "main"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	const chunk = 10_000
	for start := 0; start < profile.Runs; start += chunk {
		end := min(start+chunk, profile.Runs)
		if err := withTransaction(ctx, database, func(tx *sql.Tx) error {
			statement, err := tx.PrepareContext(ctx, `INSERT INTO workflow_runs(repository_id,run_id,workflow_path,event_type,status,conclusion,created_at) VALUES(?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer statement.Close()
			for index := start; index < end; index++ {
				repositoryID, runID := index%profile.Repositories+1, index+1
				if _, err := statement.ExecContext(ctx, repositoryID, runID, ".github/workflows/scale.yml", "push", "completed", "success", instant); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}

	for start := 0; start < profile.Executions; start += chunk {
		end := min(start+chunk, profile.Executions)
		if err := withTransaction(ctx, database, func(tx *sql.Tx) error {
			attempt, err := tx.PrepareContext(ctx, `INSERT INTO run_attempts(repository_id,run_id,run_attempt,status,conclusion,started_at) VALUES(?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer attempt.Close()
			job, err := tx.PrepareContext(ctx, `INSERT INTO jobs(repository_id,run_id,run_attempt,job_id,display_name,status,conclusion,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer job.Close()
			fact, err := tx.PrepareContext(ctx, `INSERT INTO archive_facts(fact_id,kind,repository_id,run_id,run_attempt,job_id,event_time_json,payload_json,first_batch_id) VALUES(?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer fact.Close()
			batchFact, err := tx.PrepareContext(ctx, `INSERT INTO archive_batch_facts(batch_id,fact_id) VALUES(?,?)`)
			if err != nil {
				return err
			}
			defer batchFact.Close()
			for index := start; index < end; index++ {
				runIndex := index % profile.Runs
				repositoryID, runID := runIndex%profile.Repositories+1, runIndex+1
				runAttempt, jobID := index/profile.Runs+1, int64(index+1)
				if _, err := attempt.ExecContext(ctx, repositoryID, runID, runAttempt, "completed", "success", instant); err != nil {
					return err
				}
				if _, err := job.ExecContext(ctx, repositoryID, runID, runAttempt, jobID, "synthetic-job", "completed", "success", instant, instant); err != nil {
					return err
				}
				factID := syntheticID("fact1", index+1)
				if _, err := fact.ExecContext(ctx, factID, "job", repositoryID, runID, runAttempt, jobID, `{}`, `{"job":{"display_name":"synthetic-job"}}`, batchID); err != nil {
					return err
				}
				if _, err := batchFact.ExecContext(ctx, batchID, factID); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// Ten percent of executions are incident findings. This keeps the
	// finding/evidence graph realistically sparse while scaling every query
	// family required by the release contract.
	for start := 0; start < profile.Executions; start += chunk {
		end := min(start+chunk, profile.Executions)
		if err := withTransaction(ctx, database, func(tx *sql.Tx) error {
			coverage, err := tx.PrepareContext(ctx, `INSERT INTO coverage_units(coverage_id,collection_id,kind,logical_scope,repository_id,run_id,run_attempt,job_id,expected,collected,not_applicable,gaps,status,material,retryable) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer coverage.Close()
			finding, err := tx.PrepareContext(ctx, `INSERT INTO findings(finding_id,incident_id,indicator_id,repository_id,workflow_path,run_id,run_attempt,job_id,step_key,proposition_kind,subject_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer finding.Close()
			revision, err := tx.PrepareContext(ctx, `INSERT INTO finding_revisions(finding_revision_id,finding_id,canonical_pack_sha256,state,provenance,proposition_json,concise_conclusion,event_time_json,assumptions_json,gaps_json,contradictions_json,credential_exposure_json,resource_exposure_json,remediation_json,collection_coverage_json,rule_id,rule_version,first_produced_analysis_id,first_produced_engine_version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer revision.Close()
			selection, err := tx.PrepareContext(ctx, `INSERT INTO analysis_session_findings(analysis_id,finding_revision_id,disposition) VALUES(?,?,'EMITTED')`)
			if err != nil {
				return err
			}
			defer selection.Close()
			revCoverage, err := tx.PrepareContext(ctx, `INSERT INTO finding_revision_coverage(finding_revision_id,coverage_id) VALUES(?,?)`)
			if err != nil {
				return err
			}
			defer revCoverage.Close()
			graphEdge, err := tx.PrepareContext(ctx, `INSERT INTO graph_projection_edges(edge_id,analysis_id,source_id,target_id,relation,evidence_ids_json,snapshot_sha256) VALUES(?,?,?,?,?,?,?)`)
			if err != nil {
				return err
			}
			defer graphEdge.Close()
			revEvidence, err := tx.PrepareContext(ctx, `INSERT INTO finding_revision_evidence(finding_revision_id,evidence_id,role) VALUES(?,?,'SUPPORTS')`)
			if err != nil {
				return err
			}
			defer revEvidence.Close()
			for index := start; index < end; index++ {
				if index%10 != 0 {
					continue
				}
				runIndex := index % profile.Runs
				repositoryID, runID := runIndex%profile.Repositories+1, runIndex+1
				runAttempt, jobID := index/profile.Runs+1, int64(index+1)
				coverageID, findingID, revisionID := syntheticID("cova1", index+1), syntheticID("find1", index+1), syntheticID("frev1", index+1)
				if _, err := coverage.ExecContext(ctx, coverageID, collection, "job_logs", fmt.Sprintf("%d:%d:%d:%d", repositoryID, runID, runAttempt, jobID), repositoryID, runID, runAttempt, jobID, 1, 0, 0, 1, "gap", 1, 0); err != nil {
					return err
				}
				if _, err := finding.ExecContext(ctx, findingID, "SYNTH-SCALE", "indicator", repositoryID, ".github/workflows/scale.yml", runID, runAttempt, jobID, "step:1:main:1", "execution", `{}`); err != nil {
					return err
				}
				if _, err := revision.ExecContext(ctx, revisionID, findingID, packHash, "UNKNOWN_EVIDENCE_GAP", "L0_UNKNOWN", `{}`, "synthetic scale gap", `{}`, `[]`, `["logs missing"]`, `[]`, `[]`, `[]`, `[]`, fmt.Sprintf(`["%s"]`, coverageID), "scale", "v1", analysis, "scale", instant); err != nil {
					return err
				}
				if _, err := selection.ExecContext(ctx, analysis, revisionID); err != nil {
					return err
				}
				if _, err := revCoverage.ExecContext(ctx, revisionID, coverageID); err != nil {
					return err
				}
				if _, err := revEvidence.ExecContext(ctx, revisionID, evidenceID); err != nil {
					return err
				}
				if _, err := graphEdge.ExecContext(ctx, syntheticID("edge", index+1), analysis, revisionID, syntheticID("job", index+1), "FINDING_ABOUT", fmt.Sprintf(`["%s"]`, evidenceID), packHash); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func withTransaction(ctx context.Context, database *sql.DB, body func(*sql.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := body(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type queryMetric struct {
	Plan         []string `json:"plan"`
	Iterations   int      `json:"iterations"`
	ElapsedNanos int64    `json:"elapsed_nanos"`
}

func qualifyScaleQueries(ctx context.Context, database *sql.DB, profile scaleProfile) (map[string]queryMetric, error) {
	executionIndex := (profile.Executions / 20) * 10
	runIndex := executionIndex % profile.Runs
	repositoryID, runID := runIndex%profile.Repositories+1, runIndex+1
	runAttempt, jobID := executionIndex/profile.Runs+1, int64(executionIndex+1)
	findingID, revisionID := syntheticID("find1", executionIndex+1), syntheticID("frev1", executionIndex+1)
	queries := []struct {
		name       string
		query      string
		args       []any
		forbidScan string
	}{
		{"attempt_findings", `SELECT finding_id FROM findings WHERE repository_id=? AND run_id=? AND run_attempt=? AND job_id=?`, []any{repositoryID, runID, runAttempt, jobID}, "findings"},
		{"finding_revisions", `SELECT finding_revision_id FROM finding_revisions WHERE finding_id=? ORDER BY created_at`, []any{findingID}, "finding_revisions"},
		{"evidence_trace", `SELECT evidence_id FROM finding_revision_evidence WHERE finding_revision_id=? ORDER BY evidence_id`, []any{revisionID}, "finding_revision_evidence"},
		{"coverage_trace", `SELECT cu.status FROM finding_revision_coverage frc JOIN coverage_units cu ON cu.coverage_id=frc.coverage_id WHERE frc.finding_revision_id=?`, []any{revisionID}, "coverage_units"},
		{"graph_source", `SELECT edge_id FROM graph_projection_edges WHERE analysis_id=? AND source_id=?`, []any{"analysis:scale", revisionID}, "graph_projection_edges"},
		{"graph_target", `SELECT edge_id FROM graph_projection_edges WHERE analysis_id=? AND target_id=?`, []any{"analysis:scale", syntheticID("job", executionIndex+1)}, "graph_projection_edges"},
		{"archive_subject", `SELECT fact_id FROM archive_facts WHERE repository_id=? AND run_id=? AND run_attempt=? AND job_id=? AND kind='job'`, []any{repositoryID, runID, runAttempt, jobID}, "archive_facts"},
	}
	result := make(map[string]queryMetric, len(queries))
	for _, query := range queries {
		plan, err := explainPlan(ctx, database, query.query, query.args...)
		if err != nil {
			return nil, err
		}
		for _, detail := range plan {
			if strings.Contains(strings.ToUpper(detail), "SCAN "+strings.ToUpper(query.forbidScan)) {
				return nil, fmt.Errorf("%s performs a full table scan: %v", query.name, plan)
			}
		}
		started := time.Now()
		const iterations = 100
		for iteration := 0; iteration < iterations; iteration++ {
			rows, err := database.QueryContext(ctx, query.query, query.args...)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var ignored string
				if err := rows.Scan(&ignored); err != nil {
					rows.Close()
					return nil, err
				}
			}
			if err := rows.Close(); err != nil {
				return nil, err
			}
		}
		result[query.name] = queryMetric{Plan: plan, Iterations: iterations, ElapsedNanos: time.Since(started).Nanoseconds()}
	}
	return result, nil
}

func explainPlan(ctx context.Context, database *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := database.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			return nil, err
		}
		result = append(result, detail)
	}
	return result, rows.Err()
}

func syntheticID(prefix string, value int) string {
	return fmt.Sprintf("%s:%064x", prefix, value)
}

// TestAggregateLogParserQualification streams a caller-selected aggregate
// byte count through the bounded parser without materializing a giant corpus.
// Every chunk is setup evidence, so any lifecycle observation is a forensic
// promotion failure.
func TestAggregateLogParserQualification(t *testing.T) {
	configured := os.Getenv("CIREWIND_LOG_SCALE_BYTES")
	if configured == "" {
		t.Skip("set CIREWIND_LOG_SCALE_BYTES for aggregate parser qualification")
	}
	total, err := strconv.ParseInt(configured, 10, 64)
	if err != nil || total <= 0 {
		t.Fatalf("invalid CIREWIND_LOG_SCALE_BYTES %q", configured)
	}
	const chunkBytes = 1 << 20
	prefix := "2026-08-21T00:00:00Z Download action repository 'synthetic/harmless@v1' (SHA:" + strings.Repeat("1", 40) + ")\n"
	fillerLine := "2026-08-21T00:00:00Z synthetic bounded filler " + strings.Repeat("x", 4000) + "\n"
	var builder strings.Builder
	builder.Grow(chunkBytes)
	builder.WriteString(prefix)
	for builder.Len()+len(fillerLine) <= chunkBytes {
		builder.WriteString(fillerLine)
	}
	for builder.Len() < chunkBytes {
		builder.WriteByte('\n')
	}
	chunk := builder.String()
	started := time.Now()
	var processed int64
	for processed < total {
		length := min(int64(len(chunk)), total-processed)
		result, err := logparse.Parse(context.Background(), strings.NewReader(chunk[:length]), logparse.SourceContext{
			Scope: logparse.ExecutionScope{RepositoryID: 1, RunID: 1, RunAttempt: 1, JobID: 1, StepKey: "setup"},
			Role:  logparse.RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, observation := range result.Observations {
			if observation.Kind == logparse.ObservationLifecycleStarted || observation.Kind == logparse.ObservationLifecycleCompleted {
				t.Fatal("setup-log scale fixture produced lifecycle evidence")
			}
		}
		processed += length
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("CIREWIND_LOG_SCALE_RESULT bytes=%d elapsed_ms=%d heap_alloc=%d heap_sys=%d total_alloc=%d", processed, time.Since(started).Milliseconds(), memory.HeapAlloc, memory.HeapSys, memory.TotalAlloc)
}
