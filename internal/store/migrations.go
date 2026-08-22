package store

import (
	"context"
	"fmt"
)

func (s *Store) migrate(ctx context.Context, kind Kind) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, schemaV1); err != nil {
		return fmt.Errorf("apply schema v1: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('store_kind', ?), ('schema_version', '1')`, string(kind)); err != nil {
		return fmt.Errorf("write schema metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA application_id=%d`, ApplicationID)); err != nil {
		return fmt.Errorf("write application ID: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version=%d`, SchemaVersion)); err != nil {
		return fmt.Errorf("write schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}

const schemaV1 = `
CREATE TABLE metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE collection_sessions (
  collection_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('investigate','archive','fixture')),
  api_version TEXT,
  auth_kind TEXT NOT NULL DEFAULT 'none',
  started_at TEXT NOT NULL,
  ended_at TEXT,
  raw_retention INTEGER NOT NULL CHECK(raw_retention IN (0,1)),
  scope_json TEXT NOT NULL,
  limits_json TEXT NOT NULL,
  CHECK(instr(lower(scope_json), 'authorization') = 0)
) STRICT;

CREATE TABLE analysis_sessions (
  analysis_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('investigate','replay','fixture')),
  engine_version TEXT NOT NULL,
  semantic_rule_version TEXT NOT NULL,
  canonical_pack_sha256 TEXT NOT NULL CHECK(length(canonical_pack_sha256)=64),
  source_pack_sha256 TEXT NOT NULL CHECK(length(source_pack_sha256)=64),
  policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
  analyzed_at TEXT NOT NULL
) STRICT;

CREATE TABLE repositories (
  repository_id INTEGER PRIMARY KEY CHECK(repository_id > 0),
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  node_id TEXT,
  visibility TEXT,
  is_private INTEGER CHECK(is_private IN (0,1)),
  is_fork INTEGER CHECK(is_fork IN (0,1)),
  is_archived INTEGER CHECK(is_archived IN (0,1)),
  is_disabled INTEGER CHECK(is_disabled IN (0,1)),
  default_branch TEXT
) STRICT;

CREATE TABLE repository_name_observations (
  observation_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(repository_id),
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  collected_at TEXT NOT NULL
) STRICT;

CREATE TABLE source_requests (
  request_id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES collection_sessions(collection_id),
  method TEXT NOT NULL CHECK(method='GET'),
  route_template TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  http_status INTEGER,
  github_request_id TEXT,
  media_type TEXT,
  byte_length INTEGER CHECK(byte_length IS NULL OR byte_length >= 0),
  source_sha256 TEXT CHECK(source_sha256 IS NULL OR length(source_sha256)=64),
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  sanitized_error TEXT,
  CHECK(instr(lower(parameters_json), 'token') = 0),
  CHECK(instr(lower(parameters_json), 'authorization') = 0)
) STRICT;

CREATE TABLE logical_sources (
  logical_source_id TEXT PRIMARY KEY CHECK(logical_source_id GLOB 'src1:*'),
  kind TEXT NOT NULL,
  canonical_id TEXT NOT NULL,
  repository_id INTEGER REFERENCES repositories(repository_id),
  run_id INTEGER,
  run_attempt INTEGER CHECK(run_attempt IS NULL OR run_attempt > 0),
  job_id INTEGER,
  selector_json TEXT NOT NULL
) STRICT;

CREATE TABLE evidence_payloads (
  payload_sha256 TEXT PRIMARY KEY CHECK(length(payload_sha256)=64),
  media_type TEXT NOT NULL,
  byte_length INTEGER NOT NULL CHECK(byte_length >= 0),
  payload BLOB,
  retained_path TEXT,
  CHECK((payload IS NULL) != (retained_path IS NULL))
) STRICT;

CREATE TABLE evidence_objects (
  evidence_id TEXT PRIMARY KEY CHECK(evidence_id GLOB 'ev1:*'),
  logical_source_id TEXT NOT NULL REFERENCES logical_sources(logical_source_id),
  schema_version TEXT NOT NULL,
  provider TEXT NOT NULL,
  source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),
  source_byte_length INTEGER NOT NULL CHECK(source_byte_length >= 0),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  media_type TEXT NOT NULL,
  retained_payload_sha256 TEXT REFERENCES evidence_payloads(payload_sha256),
  raw_retained INTEGER NOT NULL CHECK(raw_retained IN (0,1)),
  redaction_status TEXT NOT NULL CHECK(redaction_status IN ('not_applicable','not_inspected','structured_allowlist','redacted')),
  redaction_policy_version TEXT NOT NULL,
  extractor_name TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  ruleset_sha256 TEXT NOT NULL CHECK(length(ruleset_sha256)=64),
  UNIQUE(logical_source_id, source_sha256, retained_payload_sha256, raw_retained, redaction_status, redaction_policy_version)
) STRICT;

CREATE TABLE evidence_observations (
  observation_id TEXT PRIMARY KEY CHECK(observation_id GLOB 'obs1:*'),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  collection_id TEXT NOT NULL REFERENCES collection_sessions(collection_id),
  request_id TEXT REFERENCES source_requests(request_id),
  request_attempt INTEGER NOT NULL CHECK(request_attempt > 0),
  event_time_start TEXT,
  event_time_end TEXT,
  event_time_bounds TEXT CHECK(event_time_bounds IS NULL OR event_time_bounds IN ('[)','[]','()','(]')),
  event_precision TEXT NOT NULL CHECK(event_precision IN ('second','minute','hour','day','unknown')),
  event_approximation TEXT NOT NULL CHECK(event_approximation IN ('exact','source-rounded','conservative-expanded','unknown')),
  event_basis TEXT NOT NULL,
  collection_started_at TEXT NOT NULL,
  collection_ended_at TEXT NOT NULL
) STRICT;

CREATE TABLE evidence_errors (
  error_id TEXT PRIMARY KEY,
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  observation_id TEXT REFERENCES evidence_observations(observation_id),
  phase TEXT NOT NULL CHECK(phase IN ('collect','decode','extract','derive','store','report')),
  code TEXT NOT NULL,
  http_status INTEGER,
  retryable INTEGER NOT NULL CHECK(retryable IN (0,1)),
  permission_related INTEGER CHECK(permission_related IS NULL OR permission_related IN (0,1)),
  sanitized_message TEXT,
  raw_message_sha256 TEXT CHECK(raw_message_sha256 IS NULL OR length(raw_message_sha256)=64),
  CHECK(evidence_id IS NOT NULL OR observation_id IS NOT NULL)
) STRICT;

CREATE TABLE evidence_derivations (
  child_evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  parent_evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  parameters_sha256 TEXT NOT NULL CHECK(length(parameters_sha256)=64),
  PRIMARY KEY(child_evidence_id, parent_evidence_id, rule_id, rule_version, parameters_sha256),
  CHECK(child_evidence_id <> parent_evidence_id)
) STRICT;

CREATE TABLE coverage_units (
  coverage_id TEXT PRIMARY KEY,
  collection_id TEXT NOT NULL REFERENCES collection_sessions(collection_id),
  kind TEXT NOT NULL,
  logical_scope TEXT NOT NULL,
  repository_id INTEGER REFERENCES repositories(repository_id),
  run_id INTEGER,
  run_attempt INTEGER CHECK(run_attempt IS NULL OR run_attempt > 0),
  job_id INTEGER,
  expected INTEGER NOT NULL CHECK(expected >= 0),
  collected INTEGER NOT NULL CHECK(collected >= 0),
  not_applicable INTEGER NOT NULL CHECK(not_applicable >= 0),
  gaps INTEGER NOT NULL CHECK(gaps >= 0),
  status TEXT NOT NULL CHECK(status IN ('open','collected','not_applicable','gap')),
  reason_code TEXT,
  material INTEGER NOT NULL CHECK(material IN (0,1)),
  retryable INTEGER NOT NULL CHECK(retryable IN (0,1)),
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  CHECK(expected = collected + not_applicable + gaps)
) STRICT;

CREATE TABLE workflow_runs (
  repository_id INTEGER NOT NULL REFERENCES repositories(repository_id),
  run_id INTEGER NOT NULL,
  workflow_id INTEGER,
  workflow_path TEXT,
  run_number INTEGER,
  event_type TEXT NOT NULL,
  status TEXT,
  conclusion TEXT,
  trigger_oid_algorithm TEXT,
  trigger_oid_value TEXT,
  head_ref TEXT,
  actor_id INTEGER,
  actor_login TEXT,
  created_at TEXT,
  run_started_at TEXT,
  updated_at TEXT,
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  PRIMARY KEY(repository_id, run_id)
) STRICT;

CREATE TABLE run_attempts (
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL CHECK(run_attempt > 0),
  status TEXT,
  conclusion TEXT,
  actor_id INTEGER,
  actor_login TEXT,
  triggering_actor_id INTEGER,
  triggering_actor_login TEXT,
  started_at TEXT,
  updated_at TEXT,
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  PRIMARY KEY(repository_id, run_id, run_attempt),
  FOREIGN KEY(repository_id, run_id) REFERENCES workflow_runs(repository_id, run_id)
) STRICT;

CREATE TABLE jobs (
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT,
  conclusion TEXT,
  started_at TEXT,
  completed_at TEXT,
  runner_id INTEGER,
  runner_name TEXT,
  runner_group_id INTEGER,
  runner_group_name TEXT,
  environment_name TEXT,
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  PRIMARY KEY(repository_id, run_id, run_attempt, job_id),
  FOREIGN KEY(repository_id, run_id, run_attempt) REFERENCES run_attempts(repository_id, run_id, run_attempt)
) STRICT;

CREATE TABLE steps (
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  step_number INTEGER NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('pre','main','post','run','setup','unknown')),
  occurrence INTEGER NOT NULL DEFAULT 1 CHECK(occurrence > 0),
  timeline_record_id TEXT,
  ast_ordinal INTEGER,
  display_name TEXT NOT NULL,
  status TEXT,
  conclusion TEXT,
  started_at TEXT,
  completed_at TEXT,
  evidence_id TEXT REFERENCES evidence_objects(evidence_id),
  PRIMARY KEY(repository_id, run_id, run_attempt, job_id, step_number, phase, occurrence),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id)
) STRICT;

CREATE TABLE synchronization_edges (
  edge_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  from_step_key TEXT NOT NULL,
  to_step_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('wait','cancel','parallel_join','timestamp_order')),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id)
) STRICT;

CREATE TABLE workflow_definitions (
  definition_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(repository_id),
  path TEXT NOT NULL,
  commit_oid_algorithm TEXT NOT NULL,
  commit_oid_value TEXT NOT NULL,
  content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
  kind TEXT NOT NULL CHECK(kind IN ('caller','reusable','current')),
  exactness_basis TEXT NOT NULL,
  parse_status TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  UNIQUE(repository_id, path, commit_oid_algorithm, commit_oid_value, content_sha256)
) STRICT;

CREATE TABLE workflow_calls (
  call_id TEXT PRIMARY KEY,
  caller_definition_id TEXT NOT NULL REFERENCES workflow_definitions(definition_id),
  caller_job_ordinal INTEGER NOT NULL,
  declared_target TEXT NOT NULL,
  declared_ref TEXT,
  depth INTEGER NOT NULL CHECK(depth >= 1 AND depth <= 10),
  secret_boundary_json TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id)
) STRICT;

CREATE TABLE workflow_call_resolutions (
  resolution_id TEXT PRIMARY KEY,
  call_id TEXT NOT NULL REFERENCES workflow_calls(call_id),
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER,
  called_oid_algorithm TEXT NOT NULL,
  called_oid_value TEXT NOT NULL,
  called_definition_id TEXT REFERENCES workflow_definitions(definition_id),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt) REFERENCES run_attempts(repository_id, run_id, run_attempt)
) STRICT;

CREATE TABLE action_references (
  action_ref_id TEXT PRIMARY KEY,
  definition_id TEXT REFERENCES workflow_definitions(definition_id),
  parent_action_definition_id TEXT,
  yaml_pointer TEXT NOT NULL,
  syntax_kind TEXT NOT NULL CHECK(syntax_kind IN ('repository','local-workspace','self-repository','docker','dynamic')),
  owner TEXT,
  repository TEXT,
  subpath TEXT,
  declared_ref TEXT,
  condition_text TEXT,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id)
) STRICT;

CREATE TABLE action_commits (
  action_commit_id TEXT PRIMARY KEY,
  repository_id INTEGER REFERENCES repositories(repository_id),
  owner TEXT NOT NULL COLLATE NOCASE,
  repository TEXT NOT NULL COLLATE NOCASE,
  subpath TEXT NOT NULL,
  oid_algorithm TEXT NOT NULL,
  oid_value TEXT NOT NULL,
  UNIQUE(owner, repository, subpath, oid_algorithm, oid_value)
) STRICT;

CREATE TABLE action_packages (
  action_package_id TEXT PRIMARY KEY,
  action_commit_id TEXT REFERENCES action_commits(action_commit_id),
  version TEXT,
  digest_subject TEXT NOT NULL,
  digest_algorithm TEXT NOT NULL,
  digest_value TEXT NOT NULL,
  UNIQUE(digest_subject, digest_algorithm, digest_value)
) STRICT;

CREATE TABLE action_definitions (
  action_definition_id TEXT PRIMARY KEY,
  action_commit_id TEXT NOT NULL REFERENCES action_commits(action_commit_id),
  metadata_path TEXT NOT NULL,
  content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
  kind TEXT NOT NULL CHECK(kind IN ('javascript','docker','composite','unknown')),
  metadata_json TEXT NOT NULL,
  parse_status TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  UNIQUE(action_commit_id, metadata_path, content_sha256)
) STRICT;

CREATE TABLE runtime_action_observations (
  runtime_observation_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  step_key TEXT,
  action_ref_id TEXT REFERENCES action_references(action_ref_id),
  action_commit_id TEXT REFERENCES action_commits(action_commit_id),
  action_package_id TEXT REFERENCES action_packages(action_package_id),
  kind TEXT NOT NULL CHECK(kind IN ('DECLARED','RESOLUTION_OBSERVED','DOWNLOAD_ANNOUNCED','PREPARATION_COMPLETED','PREPARATION_FAILED','CONDITION_SKIPPED','LIFECYCLE_STARTED','LIFECYCLE_COMPLETED','RUNTIME_IOC_OBSERVED')),
  lifecycle_phase TEXT CHECK(lifecycle_phase IS NULL OR lifecycle_phase IN ('pre','main','post')),
  event_time_start TEXT,
  event_time_end TEXT,
  parser_version TEXT NOT NULL,
  source_span_json TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id),
  CHECK(action_commit_id IS NOT NULL OR action_package_id IS NOT NULL OR kind IN ('DECLARED','CONDITION_SKIPPED'))
) STRICT;

CREATE TABLE token_permissions (
  permission_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  permission TEXT NOT NULL,
  access_level TEXT NOT NULL CHECK(access_level IN ('read','write','none','unknown')),
  basis TEXT NOT NULL CHECK(basis IN ('runtime-observed','static-inferred')),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id),
  UNIQUE(repository_id, run_id, run_attempt, job_id, permission, basis, evidence_id)
) STRICT;

CREATE TABLE secret_metadata_observations (
  secret_observation_id TEXT PRIMARY KEY,
  repository_id INTEGER REFERENCES repositories(repository_id),
  secret_name TEXT NOT NULL,
  scope TEXT NOT NULL CHECK(scope IN ('organization','repository','environment')),
  environment_name TEXT,
  visibility TEXT,
  selected_repositories_json TEXT,
  event_time TEXT,
  collected_at TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id)
) STRICT;

CREATE TABLE secret_flows (
  secret_flow_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER,
  step_key TEXT,
  secret_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('SECRET_EXISTS_METADATA','SECRET_REFERENCED_BY_JOB','SECRET_PASSED_TO_STEP','REUSABLE_SECRET_MAPPED','REUSABLE_SECRET_INHERITED','ENVIRONMENT_SECRET_ELIGIBLE')),
  source_scope TEXT,
  destination TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt) REFERENCES run_attempts(repository_id, run_id, run_attempt)
) STRICT;

CREATE TABLE environment_observations (
  environment_observation_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  environment_name TEXT NOT NULL,
  gate_state TEXT NOT NULL CHECK(gate_state IN ('targeted','waiting','approved','rejected','bypassed','crossed','unknown')),
  job_started INTEGER NOT NULL CHECK(job_started IN (0,1)),
  event_time TEXT,
  collected_at TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id)
) STRICT;

CREATE TABLE runner_observations (
  runner_observation_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  classification TEXT NOT NULL CHECK(classification IN ('github-hosted','self-hosted','unknown')),
  runner_id INTEGER,
  runner_name TEXT,
  runner_group_id INTEGER,
  runner_group_name TEXT,
  labels_json TEXT NOT NULL,
  version TEXT,
  os TEXT,
  architecture TEXT,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id)
) STRICT;

CREATE TABLE oidc_capabilities (
  capability_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(kind='OIDC_MINTING_CAPABILITY'),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt, job_id) REFERENCES jobs(repository_id, run_id, run_attempt, job_id)
) STRICT;

CREATE TABLE resources (
  resource_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(repository_id),
  kind TEXT NOT NULL CHECK(kind IN ('artifact','package','release','deployment','repository-write','pull-request-change')),
  provider_id TEXT,
  name TEXT,
  event_time TEXT,
  metadata_json TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id)
) STRICT;

CREATE TABLE resource_correlations (
  correlation_id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  run_attempt INTEGER NOT NULL,
  job_id INTEGER,
  resource_id TEXT NOT NULL REFERENCES resources(resource_id),
  relation TEXT NOT NULL CHECK(relation IN ('DIRECT_RUN_ATTRIBUTION','DIRECT_JOB_ATTRIBUTION','DIRECT_STEP_ATTRIBUTION','OBSERVED_AFTER')),
  rationale TEXT NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  FOREIGN KEY(repository_id, run_id, run_attempt) REFERENCES run_attempts(repository_id, run_id, run_attempt)
) STRICT;

CREATE TABLE incident_packs (
  canonical_pack_sha256 TEXT PRIMARY KEY CHECK(length(canonical_pack_sha256)=64),
  incident_id TEXT NOT NULL,
  api_version TEXT NOT NULL,
  pack_version TEXT NOT NULL,
  source_pack_sha256 TEXT NOT NULL CHECK(length(source_pack_sha256)=64),
  canonical_json BLOB NOT NULL,
  validation_policy_version TEXT NOT NULL
) STRICT;

CREATE TABLE indicators (
  canonical_pack_sha256 TEXT NOT NULL REFERENCES incident_packs(canonical_pack_sha256),
  indicator_id TEXT NOT NULL,
  component_id TEXT,
  kind TEXT NOT NULL,
  canonical_json TEXT NOT NULL,
  PRIMARY KEY(canonical_pack_sha256, indicator_id)
) STRICT;

CREATE TABLE indicator_matches (
  match_id TEXT PRIMARY KEY,
  canonical_pack_sha256 TEXT NOT NULL,
  indicator_id TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  matched_fields_json TEXT NOT NULL,
  event_time_json TEXT,
  evidence_ids_json TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  FOREIGN KEY(canonical_pack_sha256, indicator_id) REFERENCES indicators(canonical_pack_sha256, indicator_id)
) STRICT;

CREATE TABLE findings (
  finding_id TEXT PRIMARY KEY CHECK(finding_id GLOB 'find1:*'),
  incident_id TEXT NOT NULL,
  indicator_id TEXT NOT NULL,
  repository_id INTEGER REFERENCES repositories(repository_id),
  workflow_path TEXT,
  run_id INTEGER,
  run_attempt INTEGER CHECK(run_attempt IS NULL OR run_attempt > 0),
  job_id INTEGER,
  step_key TEXT,
  proposition_kind TEXT NOT NULL,
  subject_json TEXT NOT NULL
) STRICT;

CREATE TABLE finding_revisions (
  finding_revision_id TEXT PRIMARY KEY CHECK(finding_revision_id GLOB 'frev1:*'),
  finding_id TEXT NOT NULL REFERENCES findings(finding_id),
  canonical_pack_sha256 TEXT NOT NULL REFERENCES incident_packs(canonical_pack_sha256),
  state TEXT NOT NULL CHECK(state IN ('CONFIRMED_EXECUTED','CONFIRMED_DOWNLOADED','CONFIRMED_CALLED_WORKFLOW','DECLARED_AT_RUN_SHA','RUN_IN_WINDOW_MUTABLE_REF','POTENTIAL_TRANSITIVE','CURRENT_REFERENCE_ONLY','NO_MATCH_CONFIRMED','UNKNOWN_EVIDENCE_GAP','CONTRADICTORY_EVIDENCE')),
  provenance TEXT NOT NULL CHECK(provenance IN ('L4_CERTAIN','L3_STRONG','L2_PROBABLE','L1_POSSIBLE','L0_UNKNOWN')),
  proposition_json TEXT NOT NULL,
  concise_conclusion TEXT NOT NULL,
  event_time_json TEXT,
  assumptions_json TEXT NOT NULL,
  gaps_json TEXT NOT NULL,
  contradictions_json TEXT NOT NULL,
  credential_exposure_json TEXT NOT NULL,
  resource_exposure_json TEXT NOT NULL,
  remediation_json TEXT NOT NULL,
  collection_coverage_json TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  first_produced_analysis_id TEXT NOT NULL REFERENCES analysis_sessions(analysis_id),
  first_produced_engine_version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  supersedes_revision_id TEXT REFERENCES finding_revisions(finding_revision_id)
) STRICT;

CREATE TABLE finding_revision_evidence (
  finding_revision_id TEXT NOT NULL REFERENCES finding_revisions(finding_revision_id),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  role TEXT NOT NULL CHECK(role IN ('SUPPORTS','CONTRADICTS','COVERAGE_GAP')),
  PRIMARY KEY(finding_revision_id, evidence_id, role)
) STRICT;

CREATE TABLE finding_revision_coverage (
  finding_revision_id TEXT NOT NULL REFERENCES finding_revisions(finding_revision_id),
  coverage_id TEXT NOT NULL REFERENCES coverage_units(coverage_id),
  PRIMARY KEY(finding_revision_id, coverage_id)
) STRICT;

CREATE TABLE analysis_session_findings (
  analysis_id TEXT NOT NULL REFERENCES analysis_sessions(analysis_id),
  finding_revision_id TEXT NOT NULL REFERENCES finding_revisions(finding_revision_id),
  disposition TEXT NOT NULL CHECK(disposition IN ('EMITTED','REUSED')),
  PRIMARY KEY(analysis_id, finding_revision_id)
) STRICT;

CREATE TABLE contradiction_groups (
  contradiction_id TEXT PRIMARY KEY,
  subject_key TEXT NOT NULL,
  comparison_rule TEXT NOT NULL,
  fields_json TEXT NOT NULL
) STRICT;

CREATE TABLE contradiction_evidence (
  contradiction_id TEXT NOT NULL REFERENCES contradiction_groups(contradiction_id),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  proposition_role TEXT NOT NULL,
  PRIMARY KEY(contradiction_id, evidence_id, proposition_role)
) STRICT;

CREATE TABLE graph_projection_edges (
  edge_id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL REFERENCES analysis_sessions(analysis_id),
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  event_time_json TEXT,
  evidence_ids_json TEXT NOT NULL,
  derivation_rule TEXT,
  snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256)=64)
) STRICT;

CREATE TABLE archive_capabilities (
  capability TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('retained','structured-only','hash-only','not-collected','gap')),
  extractor_version TEXT,
  detail_json TEXT NOT NULL
) STRICT;

CREATE TABLE archive_checkpoints (
  repository_id INTEGER PRIMARY KEY REFERENCES repositories(repository_id),
  discovery_watermark TEXT,
  overlap_seconds INTEGER NOT NULL CHECK(overlap_seconds >= 0),
  watch_horizon_days INTEGER NOT NULL CHECK(watch_horizon_days >= 35),
  last_successful_collection_id TEXT REFERENCES collection_sessions(collection_id)
) STRICT;

CREATE TABLE watched_parents (
  repository_id INTEGER NOT NULL,
  run_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  last_refreshed_at TEXT,
  final_refresh_complete INTEGER NOT NULL CHECK(final_refresh_complete IN (0,1)),
  PRIMARY KEY(repository_id, run_id),
  FOREIGN KEY(repository_id, run_id) REFERENCES workflow_runs(repository_id, run_id)
) STRICT;

-- Compact archive facts are a closed, typed replay ledger. They coexist with
-- the case-oriented normalized tables above and never contain raw log bodies or
-- credential values.
CREATE TABLE archive_batches (
  batch_id TEXT PRIMARY KEY CHECK(batch_id GLOB 'batch1:*'),
  primary_collection_id TEXT NOT NULL REFERENCES collection_sessions(collection_id),
  content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
  state TEXT NOT NULL CHECK(state IN ('PREPARED','COMMITTED')),
  prepared_at TEXT NOT NULL,
  committed_at TEXT
) STRICT;

CREATE TABLE archive_batch_collections (
  batch_id TEXT NOT NULL REFERENCES archive_batches(batch_id),
  collection_id TEXT NOT NULL REFERENCES collection_sessions(collection_id),
  PRIMARY KEY(batch_id, collection_id)
) STRICT;

CREATE TABLE archive_facts (
  fact_id TEXT PRIMARY KEY CHECK(fact_id GLOB 'fact1:*'),
  kind TEXT NOT NULL CHECK(kind IN ('repository','run','attempt','job','action-occurrence','dependency','coverage-assessment','coverage-gap','exposure')),
  repository_id INTEGER REFERENCES repositories(repository_id),
  run_id INTEGER,
  run_attempt INTEGER CHECK(run_attempt IS NULL OR run_attempt > 0),
  job_id INTEGER,
  step_key TEXT,
  event_time_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  first_batch_id TEXT NOT NULL REFERENCES archive_batches(batch_id),
  CHECK(run_attempt IS NULL OR run_id IS NOT NULL),
  CHECK(job_id IS NULL OR run_attempt IS NOT NULL),
  CHECK(step_key IS NULL OR job_id IS NOT NULL)
) STRICT;

CREATE TABLE archive_batch_facts (
  batch_id TEXT NOT NULL REFERENCES archive_batches(batch_id),
  fact_id TEXT NOT NULL REFERENCES archive_facts(fact_id),
  PRIMARY KEY(batch_id, fact_id)
) STRICT;

CREATE TABLE archive_fact_evidence (
  fact_id TEXT NOT NULL REFERENCES archive_facts(fact_id),
  evidence_id TEXT NOT NULL REFERENCES evidence_objects(evidence_id),
  PRIMARY KEY(fact_id, evidence_id)
) STRICT;

-- The canonical structured envelope preserves fields not projected into the
-- relational evidence indexes. It is bounded archive data, never a raw log.
CREATE TABLE archive_evidence_envelopes (
  observation_id TEXT PRIMARY KEY REFERENCES evidence_observations(observation_id),
  envelope_json TEXT NOT NULL
) STRICT;

CREATE INDEX idx_runs_created ON workflow_runs(repository_id, created_at, run_id);
CREATE INDEX idx_attempts_status ON run_attempts(repository_id, run_id, run_attempt, status);
CREATE INDEX idx_jobs_times ON jobs(repository_id, run_id, run_attempt, started_at, completed_at);
CREATE INDEX idx_evidence_source ON evidence_objects(logical_source_id, source_sha256);
CREATE INDEX idx_observations_collection ON evidence_observations(collection_id, collection_ended_at);
CREATE INDEX idx_runtime_job ON runtime_action_observations(repository_id, run_id, run_attempt, job_id, kind);
CREATE INDEX idx_findings_subject ON findings(repository_id, run_id, run_attempt, job_id);
CREATE INDEX idx_revisions_finding ON finding_revisions(finding_id, created_at);
CREATE INDEX idx_graph_source ON graph_projection_edges(analysis_id, source_id);
CREATE INDEX idx_graph_target ON graph_projection_edges(analysis_id, target_id);
CREATE INDEX idx_archive_facts_subject ON archive_facts(repository_id, run_id, run_attempt, job_id, kind);
`
