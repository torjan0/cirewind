package archive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

func insertHierarchyFacts(ctx context.Context, tx *sql.Tx, batch Batch) error {
	for _, fact := range batch.Facts {
		if fact.Repository == nil {
			continue
		}
		repository := fact.Repository.Repository
		parts := strings.SplitN(string(repository.Name), "/", 2)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO repositories(repository_id,owner,name,visibility,is_private,is_fork,is_archived,is_disabled,default_branch)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(repository_id) DO UPDATE SET owner=excluded.owner,name=excluded.name,
			visibility=excluded.visibility,is_private=excluded.is_private,is_fork=excluded.is_fork,
			is_archived=excluded.is_archived,is_disabled=excluded.is_disabled,default_branch=excluded.default_branch`,
			repository.ID, parts[0], parts[1], nullableText(fact.Repository.Visibility), nullableBool(fact.Repository.Private),
			nullableBool(fact.Repository.Fork), nullableBool(fact.Repository.Archived), nullableBool(fact.Repository.Disabled),
			nullableText(fact.Repository.DefaultBranch)); err != nil {
			return fmt.Errorf("persist repository fact %s: %w", fact.ID, err)
		}
	}
	for _, fact := range batch.Facts {
		if fact.Run == nil {
			continue
		}
		run := fact.Run
		var workflowPath any
		if run.WorkflowPath != nil {
			workflowPath = string(*run.WorkflowPath)
		}
		var algorithm, value any
		if run.TriggerObject != nil {
			oid := model.GitObjectID(*run.TriggerObject)
			algorithm, value = string(oid.Algorithm), oid.Value
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO workflow_runs(repository_id,run_id,workflow_path,event_type,status,conclusion,trigger_oid_algorithm,trigger_oid_value,head_ref,actor_id,actor_login,created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,run_id) DO NOTHING`,
			run.RepositoryID, run.RunID, workflowPath, run.EventType, nullableText(run.Status), nullableText(run.Conclusion),
			algorithm, value, nullableText(run.TriggerRef), nullableInt64(run.Actor.ID), nullableText(run.Actor.Login), intervalStart(run.EventTime)); err != nil {
			return fmt.Errorf("persist run fact %s: %w", fact.ID, err)
		}
	}
	for _, fact := range batch.Facts {
		if fact.Attempt == nil {
			continue
		}
		attempt := fact.Attempt
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO run_attempts(repository_id,run_id,run_attempt,status,conclusion,actor_id,actor_login,triggering_actor_id,triggering_actor_login,started_at)
			VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,run_id,run_attempt) DO NOTHING`,
			attempt.RepositoryID, attempt.RunID, attempt.RunAttempt, nullableText(attempt.Status), nullableText(attempt.Conclusion),
			nullableInt64(attempt.Actor.ID), nullableText(attempt.Actor.Login), nullableInt64(attempt.TriggeringActor.ID),
			nullableText(attempt.TriggeringActor.Login), intervalStart(attempt.EventTime)); err != nil {
			return fmt.Errorf("persist attempt fact %s: %w", fact.ID, err)
		}
	}
	for _, fact := range batch.Facts {
		if fact.Job == nil {
			continue
		}
		job := fact.Job
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO jobs(repository_id,run_id,run_attempt,job_id,display_name,status,conclusion,started_at,completed_at)
			VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,run_id,run_attempt,job_id) DO NOTHING`,
			job.Execution.RepositoryID, job.Execution.RunID, job.Execution.RunAttempt, job.Execution.JobID,
			job.DisplayName, nullableText(job.Status), nullableText(job.Conclusion), intervalStart(job.EventTime), intervalEnd(job.EventTime)); err != nil {
			return fmt.Errorf("persist job fact %s: %w", fact.ID, err)
		}
	}
	return nil
}

func insertPayload(ctx context.Context, tx *sql.Tx, payload Payload) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO evidence_payloads(payload_sha256,media_type,byte_length,payload,retained_path)
		VALUES(?,?,?,?,NULL) ON CONFLICT(payload_sha256) DO NOTHING`,
		payload.SHA256, payload.MediaType, len(payload.Bytes), payload.Bytes); err != nil {
		return fmt.Errorf("insert compact payload %s: %w", payload.SHA256, err)
	}
	var mediaType string
	var byteLength int
	var retained []byte
	if err := tx.QueryRowContext(ctx, `SELECT media_type,byte_length,payload FROM evidence_payloads WHERE payload_sha256=?`, payload.SHA256).Scan(&mediaType, &byteLength, &retained); err != nil {
		return err
	}
	if mediaType != payload.MediaType || byteLength != len(payload.Bytes) || string(retained) != string(payload.Bytes) {
		return errors.New("compact payload hash collision or persisted descriptor conflict")
	}
	return nil
}

func insertEnvelope(ctx context.Context, tx *sql.Tx, envelope evidence.Envelope) error {
	object := envelope.Evidence
	observation := envelope.Observation
	requestParameters, err := canonicalText(object.Source.RequestParameters)
	if err != nil {
		return err
	}
	sanitizedError := ""
	for _, evidenceError := range object.Errors {
		if evidenceError.Phase == evidence.ErrorCollect && evidenceError.SanitizedMessage != "" {
			sanitizedError = evidenceError.SanitizedMessage
			break
		}
	}
	route := object.Source.EndpointTemplate
	if route == "" {
		route = "offline-derived"
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO source_requests(request_id,collection_id,method,route_template,parameters_json,http_status,media_type,byte_length,source_sha256,started_at,ended_at,sanitized_error)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(request_id) DO NOTHING`,
		observation.RequestID, observation.CollectionSessionID, "GET", route, requestParameters, object.Source.HTTPStatus,
		object.Content.MediaType, object.Content.ByteLength, object.Content.SourceSHA256,
		formatInstant(observation.CollectionTime.StartedAt), formatInstant(observation.CollectionTime.EndedAt), nullableText(sanitizedError)); err != nil {
		return fmt.Errorf("insert source request %s: %w", observation.RequestID, err)
	}
	var persistedCollection, persistedRoute, persistedParameters, persistedStarted, persistedEnded string
	if err := tx.QueryRowContext(ctx, `
		SELECT collection_id,route_template,parameters_json,started_at,ended_at FROM source_requests WHERE request_id=?`,
		observation.RequestID).Scan(&persistedCollection, &persistedRoute, &persistedParameters, &persistedStarted, &persistedEnded); err != nil {
		return fmt.Errorf("verify source request %s: %w", observation.RequestID, err)
	}
	if persistedCollection != string(observation.CollectionSessionID) || persistedRoute != route || persistedParameters != requestParameters ||
		persistedStarted != formatInstant(observation.CollectionTime.StartedAt) || persistedEnded != formatInstant(observation.CollectionTime.EndedAt) {
		return fmt.Errorf("source request %s conflicts with persisted identity", observation.RequestID)
	}

	selector, err := canonicalText(struct {
		CanonicalID       string                     `json:"canonical_id"`
		RequestParameters evidence.RequestParameters `json:"request_parameters"`
	}{object.LogicalSource.CanonicalID, object.LogicalSource.RequestParameters})
	if err != nil {
		return err
	}
	scope := object.Scope
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO logical_sources(logical_source_id,kind,canonical_id,repository_id,run_id,run_attempt,job_id,selector_json)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(logical_source_id) DO NOTHING`,
		object.LogicalSource.ID, object.LogicalSource.Kind, object.LogicalSource.CanonicalID,
		nullableInt64(scope.RepositoryID), nullableInt64(scope.RunID), nullableUint32(scope.RunAttempt), nullableInt64(scope.JobID), selector); err != nil {
		return fmt.Errorf("insert logical source %s: %w", object.LogicalSource.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO evidence_objects(evidence_id,logical_source_id,schema_version,provider,source_sha256,source_byte_length,complete,media_type,retained_payload_sha256,raw_retained,redaction_status,redaction_policy_version,extractor_name,extractor_version,ruleset_sha256)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(evidence_id) DO NOTHING`,
		object.ID, object.LogicalSource.ID, object.SchemaVersion, object.Source.Provider, object.Content.SourceSHA256,
		object.Content.ByteLength, boolInt(object.Content.Complete), object.Content.MediaType, object.Content.RetainedPayloadSHA256,
		boolInt(object.Content.RawRetained), object.Redaction.Status, object.Redaction.PolicyVersion, object.Extractor.Name, object.Extractor.Version, object.Extractor.RulesetSHA256); err != nil {
		return fmt.Errorf("insert evidence %s: %w", object.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO evidence_observations(observation_id,evidence_id,collection_id,request_id,request_attempt,event_time_start,event_time_end,event_time_bounds,event_precision,event_approximation,event_basis,collection_started_at,collection_ended_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(observation_id) DO NOTHING`,
		observation.ID, object.ID, observation.CollectionSessionID, observation.RequestID, observation.RequestAttempt,
		intervalStart(object.EventTime), intervalEnd(object.EventTime), intervalBounds(object.EventTime), object.EventTime.Precision,
		object.EventTime.Approximation, object.EventTime.Basis, formatInstant(observation.CollectionTime.StartedAt), formatInstant(observation.CollectionTime.EndedAt)); err != nil {
		return fmt.Errorf("insert evidence observation %s: %w", observation.ID, err)
	}
	for index, evidenceError := range object.Errors {
		errorHash, err := evidence.CanonicalSHA256(struct {
			EvidenceID    model.EvidenceID              `json:"evidence_id"`
			ObservationID model.CollectionObservationID `json:"observation_id"`
			Index         int                           `json:"index"`
			Error         evidence.EvidenceError        `json:"error"`
		}{object.ID, observation.ID, index, evidenceError})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO evidence_errors(error_id,evidence_id,observation_id,phase,code,http_status,retryable,permission_related,sanitized_message,raw_message_sha256)
			VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(error_id) DO NOTHING`,
			"err1:"+errorHash, object.ID, observation.ID, evidenceError.Phase, evidenceError.Code, evidenceError.HTTPStatus,
			boolInt(evidenceError.Retryable), nullableBool(evidenceError.PermissionRelated), nullableText(evidenceError.SanitizedMessage), evidenceError.RawMessageSHA256); err != nil {
			return fmt.Errorf("insert evidence error: %w", err)
		}
	}
	envelopeJSON, err := canonicalText(envelope)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO archive_evidence_envelopes(observation_id,envelope_json) VALUES(?,?) ON CONFLICT(observation_id) DO NOTHING`, observation.ID, envelopeJSON); err != nil {
		return fmt.Errorf("store canonical evidence envelope: %w", err)
	}
	var persisted string
	if err := tx.QueryRowContext(ctx, `SELECT envelope_json FROM archive_evidence_envelopes WHERE observation_id=?`, observation.ID).Scan(&persisted); err != nil {
		return err
	}
	if persisted != envelopeJSON {
		return errors.New("evidence observation identity collision")
	}
	return nil
}

func insertEvidenceDerivations(ctx context.Context, tx *sql.Tx, envelopes []evidence.Envelope) error {
	emptyParameters, err := evidence.CanonicalSHA256(struct{}{})
	if err != nil {
		return err
	}
	for _, envelope := range envelopes {
		derivation := envelope.Evidence.Derivation
		parameters := emptyParameters
		if derivation.ParametersSHA256 != nil {
			parameters = *derivation.ParametersSHA256
		}
		for _, parent := range derivation.ParentEvidenceIDs {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO evidence_derivations(child_evidence_id,parent_evidence_id,rule_id,rule_version,parameters_sha256)
				VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING`, envelope.Evidence.ID, parent, derivation.RuleID, derivation.RuleVersion, parameters); err != nil {
				return fmt.Errorf("insert evidence derivation: %w", err)
			}
		}
	}
	return nil
}

type factPayload struct {
	Repository       *RepositoryFact       `json:"repository,omitempty"`
	Run              *RunFact              `json:"run,omitempty"`
	Attempt          *AttemptFact          `json:"attempt,omitempty"`
	Job              *JobFact              `json:"job,omitempty"`
	ActionOccurrence *ActionOccurrenceFact `json:"action_occurrence,omitempty"`
	Dependency       *DependencyFact       `json:"dependency,omitempty"`
	Coverage         *CoverageFact         `json:"coverage,omitempty"`
	CoverageGap      *CoverageGapFact      `json:"coverage_gap,omitempty"`
	Exposure         *ExposureFact         `json:"exposure,omitempty"`
}

func insertFact(ctx context.Context, tx *sql.Tx, batchID string, fact Fact) error {
	eventJSON, err := canonicalText(fact.EventTime)
	if err != nil {
		return err
	}
	payloadJSON, err := canonicalText(factPayload{
		Repository: fact.Repository, Run: fact.Run, Attempt: fact.Attempt, Job: fact.Job,
		ActionOccurrence: fact.ActionOccurrence, Dependency: fact.Dependency,
		Coverage: fact.Coverage, CoverageGap: fact.CoverageGap, Exposure: fact.Exposure,
	})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO archive_facts(fact_id,kind,repository_id,run_id,run_attempt,job_id,step_key,event_time_json,payload_json,first_batch_id)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fact_id) DO NOTHING`,
		fact.ID, fact.Kind, nullableRepositoryID(fact.Subject.RepositoryID), fact.Subject.RunID, fact.Subject.RunAttempt, fact.Subject.JobID,
		nullableText(fact.Subject.StepKey), eventJSON, payloadJSON, batchID); err != nil {
		return fmt.Errorf("insert archive fact %s: %w", fact.ID, err)
	}
	var kind, persistedEvent, persistedPayload string
	if err := tx.QueryRowContext(ctx, `SELECT kind,event_time_json,payload_json FROM archive_facts WHERE fact_id=?`, fact.ID).Scan(&kind, &persistedEvent, &persistedPayload); err != nil {
		return err
	}
	if kind != string(fact.Kind) || persistedEvent != eventJSON || persistedPayload != payloadJSON {
		return errors.New("archive fact identity collision")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO archive_batch_facts(batch_id,fact_id) VALUES(?,?) ON CONFLICT DO NOTHING`, batchID, fact.ID); err != nil {
		return err
	}
	for _, evidenceID := range fact.EvidenceIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO archive_fact_evidence(fact_id,evidence_id) VALUES(?,?) ON CONFLICT DO NOTHING`, fact.ID, evidenceID); err != nil {
			return fmt.Errorf("link archive fact evidence: %w", err)
		}
	}
	return nil
}

func insertCapability(ctx context.Context, tx *sql.Tx, capability Capability) error {
	details, err := canonicalText(capability.Details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO archive_capabilities(capability,status,extractor_version,detail_json) VALUES(?,?,?,?)
		ON CONFLICT(capability) DO UPDATE SET status=excluded.status,extractor_version=excluded.extractor_version,detail_json=excluded.detail_json`,
		capability.Name, capability.Status, nullableText(capability.ExtractorVersion), details)
	if err != nil {
		return fmt.Errorf("persist archive capability: %w", err)
	}
	return nil
}

func insertCheckpoint(ctx context.Context, tx *sql.Tx, checkpoint Checkpoint) error {
	var existing sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT discovery_watermark FROM archive_checkpoints WHERE repository_id=?`, checkpoint.RepositoryID).Scan(&existing)
	advance := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		advance = true
	case err != nil:
		return fmt.Errorf("read archive checkpoint: %w", err)
	case checkpoint.DiscoveryWatermark == nil:
		advance = !existing.Valid
	case !existing.Valid:
		advance = true
	default:
		current, parseErr := parseInstant(existing.String)
		if parseErr != nil {
			return parseErr
		}
		advance = !checkpoint.DiscoveryWatermark.Before(current.Time)
	}
	if !advance {
		return nil
	}
	var watermark any
	if checkpoint.DiscoveryWatermark != nil {
		watermark = formatInstant(*checkpoint.DiscoveryWatermark)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO archive_checkpoints(repository_id,discovery_watermark,overlap_seconds,watch_horizon_days,last_successful_collection_id)
		VALUES(?,?,?,?,?) ON CONFLICT(repository_id) DO UPDATE SET discovery_watermark=excluded.discovery_watermark,
		overlap_seconds=excluded.overlap_seconds,watch_horizon_days=excluded.watch_horizon_days,last_successful_collection_id=excluded.last_successful_collection_id`,
		checkpoint.RepositoryID, watermark, checkpoint.OverlapSeconds, checkpoint.WatchHorizonDays, checkpoint.LastSuccessfulCollection); err != nil {
		return fmt.Errorf("write archive checkpoint: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM watched_parents WHERE repository_id=?`, checkpoint.RepositoryID); err != nil {
		return err
	}
	for _, parent := range checkpoint.WatchedParents {
		var refreshed any
		if parent.LastRefreshedAt != nil {
			refreshed = formatInstant(*parent.LastRefreshedAt)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO watched_parents(repository_id,run_id,created_at,last_refreshed_at,final_refresh_complete)
			VALUES(?,?,?,?,?)`, checkpoint.RepositoryID, parent.RunID, formatInstant(parent.CreatedAt), refreshed, boolInt(parent.FinalRefreshComplete)); err != nil {
			return fmt.Errorf("write watched parent: %w", err)
		}
	}
	return nil
}

func intervalStart(interval model.EventInterval) any {
	if interval.Start == nil {
		return nil
	}
	return formatInstant(*interval.Start)
}

func intervalEnd(interval model.EventInterval) any {
	if interval.End == nil {
		return nil
	}
	return formatInstant(*interval.End)
}

func intervalBounds(interval model.EventInterval) any {
	if interval.Bounds == nil {
		return nil
	}
	return string(*interval.Bounds)
}

func nullableUint32[T ~uint32](value *T) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func nullableRepositoryID(value model.RepositoryID) any {
	if value == 0 {
		return nil
	}
	return int64(value)
}
