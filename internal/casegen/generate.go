// Package casegen materializes a deterministic, offline CIRewind case bundle.
package casegen

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/ledger"
	"github.com/torjan0/cirewind/internal/match"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/store"
)

type Options struct {
	Output    string
	Raw       bool
	RawSource RawSource
	Snapshot  archive.Snapshot
	Pack      *incident.ValidatedPack
	Case      report.Case
}

// RawSource is the narrow offline boundary used to copy an already-retained
// content-addressed object into a case. archive.Archive implements it without
// network access.
type RawSource interface {
	CopyRaw(context.Context, string, io.Writer) error
}

const (
	// These materialization limits intentionally match the strict v0.2 case
	// verifier and the archive's per-object custody limit. Compact replay does
	// not apply them because it copies no raw bytes.
	maxCaseRawObjectBytes       = uint64(2 << 30)
	maxCaseRawMaterializedBytes = uint64(10 << 30)
	maxCaseRawObjectCount       = 100_000
)

// Generate creates every required case file in a private staging directory,
// verifies its SQLite integrity, writes the manifest, and atomically publishes
// the directory. Existing output directories are never overwritten.
func Generate(ctx context.Context, options Options) (err error) {
	return generate(ctx, options, generationHooks{})
}

// generationHooks is a per-call test seam for failures at boundaries that
// cannot be reached through public inputs. Production generation supplies no
// hooks.
type generationHooks struct {
	beforeFinalize func(context.Context, *casefile.Builder) error
}

func generate(ctx context.Context, options Options, hooks generationHooks) (err error) {
	if options.Pack == nil {
		return errors.New("validated incident pack is required")
	}
	normalizedSnapshot, err := archive.NormalizeSnapshot(options.Snapshot)
	if err != nil {
		return fmt.Errorf("normalize archive snapshot: %w", err)
	}
	options.Snapshot = normalizedSnapshot
	retainedLegacyCredentialBasis := archive.HasRetainedLegacyCredentialBasis(options.Snapshot)
	if options.Case.Metadata.SchemaVersion == report.MetadataSchemaV2 {
		rawMaterialized := options.Raw
		options.Case.Metadata.RawMaterialized = &rawMaterialized
	}
	if err := options.Case.NormalizeAndValidate(); err != nil {
		return fmt.Errorf("normalize case report: %w", err)
	}
	var builder *casefile.Builder
	if options.Case.Metadata.SchemaVersion == report.MetadataSchemaV2 {
		builder, err = casefile.NewBuilderV2(options.Output, options.Raw)
	} else {
		builder, err = casefile.NewBuilder(options.Output, options.Raw)
	}
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cleanupErr := abortStagedCase(builder); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			err = protectPrivateStagingDiagnostic(err)
		}
	}()
	if err = writeRawEvidence(ctx, builder, options); err != nil {
		return err
	}

	if err = writeCaseDatabase(ctx, builder, options); err != nil {
		return err
	}
	var graphSVG []byte
	if options.Case.Metadata.SchemaVersion == report.MetadataSchemaV2 {
		databasePath, pathErr := builder.Path("case.db")
		if pathErr != nil {
			return pathErr
		}
		projected, projectionErr := reprojectCaseDatabase(ctx, databasePath, options.Case, options.Pack, retainedLegacyCredentialBasis)
		if projectionErr != nil {
			return projectionErr
		}
		options.Case.Findings = projected.findings
		options.Case.Graph = projected.legacy
		options.Case.GraphV2 = projected.typed
		var path graph.TemporalEvidencePath
		path, graphSVG, err = graph.RenderGraphSVG(ctx, options.Case.GraphV2, graph.PathOptions{})
		if err != nil {
			return fmt.Errorf("render temporal evidence path: %w", err)
		}
		options.Case.TemporalPath = path
	}
	if err = writeEvidenceLedger(builder, options); err != nil {
		return err
	}
	writers := []struct {
		name string
		fn   func(io.Writer) error
	}{
		{"findings.json", func(w io.Writer) error { return report.WriteFindingsJSON(w, options.Case) }},
		{"affected-runs.csv", func(w io.Writer) error { return report.WriteAffectedRunsCSV(w, options.Case) }},
		{"collection-metadata.json", func(w io.Writer) error { return report.WriteMetadataJSON(w, options.Case.Metadata) }},
		{"graph.json", func(w io.Writer) error {
			if options.Case.Metadata.SchemaVersion == report.MetadataSchemaV2 {
				return report.WriteGraphV2JSON(w, options.Case.GraphV2)
			}
			return report.WriteGraphJSON(w, options.Case.Graph)
		}},
		{"report.html", func(w io.Writer) error { return report.WriteHTMLContext(ctx, w, options.Case) }},
		{"summary.md", func(w io.Writer) error { return report.WriteSummaryMarkdown(w, options.Case) }},
	}
	if options.Case.Metadata.SchemaVersion == report.MetadataSchemaV2 {
		writers = append(writers, struct {
			name string
			fn   func(io.Writer) error
		}{"graph.svg", func(w io.Writer) error {
			_, err := w.Write(graphSVG)
			return err
		}})
	}
	sort.Slice(writers, func(i, j int) bool { return writers[i].name < writers[j].name })
	for _, output := range writers {
		if err = writeFile(builder, output.name, output.fn); err != nil {
			return err
		}
	}
	if hooks.beforeFinalize != nil {
		if err = hooks.beforeFinalize(ctx, builder); err != nil {
			return err
		}
	}
	if err = builder.Finalize(ctx); err != nil {
		return err
	}
	return nil
}

type rawDescriptor struct {
	digest     string
	mediaType  string
	byteLength uint64
	path       string
}

func rawDescriptors(snapshot archive.Snapshot) ([]rawDescriptor, error) {
	byDigest := make(map[string]rawDescriptor)
	for _, envelope := range snapshot.Evidence {
		content := envelope.Evidence.Content
		if !content.RawRetained {
			continue
		}
		descriptor := rawDescriptor{digest: content.SourceSHA256, mediaType: content.MediaType, byteLength: content.ByteLength, path: content.RetainedPath}
		expectedPath, err := archive.RawRelativePath(descriptor.digest)
		if err != nil || descriptor.path != expectedPath || content.RetainedPayloadSHA256 == nil || *content.RetainedPayloadSHA256 != descriptor.digest {
			return nil, fmt.Errorf("raw evidence %s has an invalid content-addressed descriptor", envelope.Evidence.ID)
		}
		if previous, ok := byDigest[descriptor.digest]; ok && (previous.mediaType != descriptor.mediaType || previous.byteLength != descriptor.byteLength || previous.path != descriptor.path) {
			return nil, errors.New("raw evidence hash has contradictory descriptors")
		}
		byDigest[descriptor.digest] = descriptor
	}
	result := make([]rawDescriptor, 0, len(byDigest))
	for _, descriptor := range byDigest {
		result = append(result, descriptor)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].digest < result[j].digest })
	return result, nil
}

func writeRawEvidence(ctx context.Context, builder *casefile.Builder, options Options) error {
	descriptors, err := rawDescriptors(options.Snapshot)
	if err != nil {
		return err
	}
	if !options.Raw {
		return nil
	}
	if err := preflightRawMaterialization(descriptors); err != nil {
		return err
	}
	if options.RawSource == nil {
		return errors.New("raw case retention requires an offline raw source")
	}
	for _, descriptor := range descriptors {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := builder.CreateRawFile(descriptor.digest)
		if err != nil {
			return err
		}
		hasher := sha256.New()
		counter := &rawCopyWriter{ctx: ctx, destination: io.MultiWriter(file, hasher), expected: descriptor.byteLength}
		copyErr := options.RawSource.CopyRaw(ctx, descriptor.digest, counter)
		copyErr = errors.Join(copyErr, counter.err)
		if contextErr := ctx.Err(); contextErr != nil {
			copyErr = errors.Join(copyErr, contextErr)
		}
		if copyErr == nil && (counter.written != descriptor.byteLength || hex.EncodeToString(hasher.Sum(nil)) != descriptor.digest) {
			copyErr = errors.New("copied raw evidence disagrees with its descriptor")
		}
		if copyErr == nil {
			copyErr = file.Sync()
		}
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("copy raw evidence %s: %w", descriptor.digest, errors.Join(copyErr, closeErr))
		}
	}
	return nil
}

func preflightRawMaterialization(descriptors []rawDescriptor) error {
	if len(descriptors) > maxCaseRawObjectCount {
		return fmt.Errorf("raw evidence materialization exceeds the %d-object limit", maxCaseRawObjectCount)
	}
	var aggregate uint64
	for _, descriptor := range descriptors {
		if descriptor.byteLength > maxCaseRawObjectBytes {
			return fmt.Errorf("raw evidence object %s exceeds the %d-byte limit", descriptor.digest, maxCaseRawObjectBytes)
		}
		if descriptor.byteLength > maxCaseRawMaterializedBytes || aggregate > maxCaseRawMaterializedBytes-descriptor.byteLength {
			return fmt.Errorf("raw evidence materialization exceeds the %d-byte aggregate limit", maxCaseRawMaterializedBytes)
		}
		aggregate += descriptor.byteLength
	}
	return nil
}

// rawCopyWriter is a fail-closed boundary around a RawSource implementation.
// It never writes bytes beyond the authenticated descriptor, remembers a
// violation even if the source ignores the returned error, and observes
// cancellation between writes.
type rawCopyWriter struct {
	ctx         context.Context
	destination io.Writer
	expected    uint64
	written     uint64
	err         error
}

func (w *rawCopyWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return 0, err
	}
	if w.written > w.expected || uint64(len(data)) > w.expected-w.written {
		w.err = errors.New("raw evidence source exceeds its declared byte length")
		return 0, w.err
	}
	written, err := w.destination.Write(data)
	if written < 0 || written > len(data) {
		w.err = errors.New("raw evidence destination returned an invalid write count")
		return 0, w.err
	}
	w.written += uint64(written)
	if err != nil {
		w.err = err
		return written, err
	}
	if written != len(data) {
		w.err = io.ErrShortWrite
		return written, w.err
	}
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return written, err
	}
	return written, nil
}

type caseAborter interface {
	Abort() error
}

type stagedCaseCleanupError struct {
	cause error
}

func (e *stagedCaseCleanupError) Error() string {
	return "clean up staged case: staging directory removal failed"
}

func (e *stagedCaseCleanupError) Unwrap() error {
	return e.cause
}

type stagedCaseOperationError struct {
	cause error
}

func (e *stagedCaseOperationError) Error() string {
	return "materialize case in private staging: operation failed; private path withheld"
}

func (e *stagedCaseOperationError) Unwrap() error {
	return e.cause
}

func protectPrivateStagingDiagnostic(err error) error {
	if err == nil || !strings.Contains(err.Error(), ".cirewind-case-") {
		return err
	}
	// OS and SQLite errors can carry the randomized private staging path.
	// Preserve errors.Is/errors.As causality without exposing that path through
	// the ordinary CLI diagnostic returned by Error.
	return &stagedCaseOperationError{cause: err}
}

func abortStagedCase(builder caseAborter) error {
	if err := builder.Abort(); err != nil {
		// Builder cleanup errors can contain the randomized private staging
		// path. Keep errors.Is/As support without placing that path in normal
		// terminal or report output.
		return &stagedCaseCleanupError{cause: err}
	}
	return nil
}

func writeFile(builder *casefile.Builder, name string, write func(io.Writer) error) error {
	f, err := builder.CreateFile(name)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}

func writeEvidenceLedger(builder *casefile.Builder, options Options) error {
	path, err := builder.Path("evidence.jsonl")
	if err != nil {
		return err
	}
	session := "analysis:" + options.Case.Metadata.CaseID
	w, err := ledger.Create(path, session)
	if err != nil {
		return err
	}
	for _, envelope := range options.Snapshot.Evidence {
		if _, err := w.Append("evidence_observation", envelope); err != nil {
			_ = w.Close()
			return err
		}
	}
	for _, finding := range options.Case.Findings {
		if _, err := w.Append("finding_revision", finding); err != nil {
			_ = w.Close()
			return err
		}
	}
	return w.Close()
}

func writeCaseDatabase(ctx context.Context, builder *casefile.Builder, options Options) error {
	path, err := builder.Path("case.db")
	if err != nil {
		return err
	}
	db, err := store.Create(ctx, path, store.KindCase)
	if err != nil {
		return err
	}
	closeWith := func(cause error) error { return errors.Join(cause, db.Close()) }
	if err := persistCase(ctx, db, options); err != nil {
		return closeWith(err)
	}
	if err := db.Finalize(ctx); err != nil {
		return closeWith(err)
	}
	if err := db.Close(); err != nil {
		return err
	}
	return nil
}

func persistCase(ctx context.Context, destination *store.Store, options Options) error {
	db := destination.DB()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	metadataPairs := [][2]string{{"case_id", options.Case.Metadata.CaseID}, {"engine_version", options.Case.Metadata.EngineVersion}, {"analysis_time", options.Case.Metadata.AnalysisTime}, {"case_raw_materialized", fmt.Sprint(options.Raw)}}
	for _, pair := range metadataPairs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES(?,?)`, pair[0], pair[1]); err != nil {
			return fmt.Errorf("persist case metadata: %w", err)
		}
	}
	for _, session := range options.Snapshot.Collections {
		scope, _ := json.Marshal(session.Scope)
		limits, _ := json.Marshal(session.Limits)
		if _, err := tx.ExecContext(ctx, `INSERT INTO collection_sessions(collection_id,mode,api_version,auth_kind,started_at,ended_at,raw_retention,scope_json,limits_json) VALUES(?,?,?,?,?,?,?,?,?)`,
			session.ID, session.Mode, session.APIVersion, session.AuthKind, session.StartedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), session.EndedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), boolInt(session.RawRetention), string(scope), string(limits)); err != nil {
			return fmt.Errorf("persist collection session: %w", err)
		}
	}
	for _, fact := range options.Snapshot.Facts {
		if fact.Repository == nil {
			continue
		}
		repo := fact.Repository
		owner, name := splitRepository(string(repo.Repository.Name))
		if _, err := tx.ExecContext(ctx, `INSERT INTO repositories(repository_id,owner,name,visibility,is_private,is_fork,is_archived,is_disabled,default_branch) VALUES(?,?,?,?,?,?,?,?,?)`,
			repo.Repository.ID, owner, name, nullable(repo.Visibility), boolPointer(repo.Private), boolPointer(repo.Fork), boolPointer(repo.Archived), boolPointer(repo.Disabled), nullable(repo.DefaultBranch)); err != nil {
			return fmt.Errorf("persist repository: %w", err)
		}
	}
	for _, payload := range options.Snapshot.Payloads {
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_payloads(payload_sha256,media_type,byte_length,payload,retained_path) VALUES(?,?,?,?,NULL) ON CONFLICT(payload_sha256) DO NOTHING`, payload.SHA256, payload.MediaType, len(payload.Bytes), payload.Bytes); err != nil {
			return fmt.Errorf("persist compact evidence payload: %w", err)
		}
	}
	rawPayloads, err := rawDescriptors(options.Snapshot)
	if err != nil {
		return err
	}
	for _, raw := range rawPayloads {
		retainedPath := "not-retained-in-case"
		if options.Raw {
			retainedPath = raw.path
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_payloads(payload_sha256,media_type,byte_length,payload,retained_path) VALUES(?,?,?,NULL,?) ON CONFLICT(payload_sha256) DO NOTHING`, raw.digest, raw.mediaType, raw.byteLength, retainedPath); err != nil {
			return fmt.Errorf("persist raw evidence descriptor: %w", err)
		}
	}
	for _, envelope := range options.Snapshot.Evidence {
		if err := persistEvidence(ctx, tx, envelope); err != nil {
			return err
		}
	}
	for _, envelope := range options.Snapshot.Evidence {
		e := envelope.Evidence
		for _, parent := range e.Derivation.ParentEvidenceIDs {
			parameters := strings.Repeat("0", 64)
			if e.Derivation.ParametersSHA256 != nil {
				parameters = *e.Derivation.ParametersSHA256
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_derivations(child_evidence_id,parent_evidence_id,rule_id,rule_version,parameters_sha256) VALUES(?,?,?,?,?)`, e.ID, parent, e.Derivation.RuleID, e.Derivation.RuleVersion, parameters); err != nil {
				return fmt.Errorf("persist evidence derivation: %w", err)
			}
		}
	}
	if err := persistFacts(ctx, tx, options.Snapshot); err != nil {
		return err
	}
	canonicalPack := options.Pack.CanonicalJSON
	if _, err := tx.ExecContext(ctx, `INSERT INTO incident_packs(canonical_pack_sha256,incident_id,api_version,pack_version,source_pack_sha256,canonical_json,validation_policy_version) VALUES(?,?,?,?,?,?,?)`,
		options.Pack.CanonicalSHA256, options.Pack.Pack.Metadata.ID, options.Pack.Pack.APIVersion, options.Pack.Pack.Metadata.PackVersion, options.Pack.OriginalSHA256, canonicalPack, options.Pack.ValidatorPolicy); err != nil {
		return fmt.Errorf("persist incident pack: %w", err)
	}
	for _, indicator := range options.Pack.Pack.Spec.Indicators {
		encoded, _ := json.Marshal(indicator)
		if _, err := tx.ExecContext(ctx, `INSERT INTO indicators(canonical_pack_sha256,indicator_id,component_id,kind,canonical_json) VALUES(?,?,?,?,?)`, options.Pack.CanonicalSHA256, indicator.ID, nullable(indicator.ComponentID), indicator.Kind, string(encoded)); err != nil {
			return fmt.Errorf("persist incident indicator: %w", err)
		}
	}
	analysisID := "analysis:" + options.Case.Metadata.CaseID
	policyHash := sha256.Sum256([]byte(options.Case.Metadata.LimitPolicy))
	if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_sessions(analysis_id,mode,engine_version,semantic_rule_version,canonical_pack_sha256,source_pack_sha256,policy_sha256,analyzed_at) VALUES(?,?,?,?,?,?,?,?)`,
		analysisID, options.Case.Metadata.Mode, options.Case.Metadata.EngineVersion, match.RuleVersion, options.Pack.CanonicalSHA256, options.Pack.OriginalSHA256, hex.EncodeToString(policyHash[:]), options.Case.Metadata.AnalysisTime); err != nil {
		return fmt.Errorf("persist analysis session: %w", err)
	}
	indicatorKinds := make(map[string]string, len(options.Pack.Pack.Spec.Indicators))
	for _, indicator := range options.Pack.Pack.Spec.Indicators {
		indicatorKinds[indicator.ID] = indicator.Kind
	}
	for _, finding := range options.Case.Findings {
		indicatorKind, ok := indicatorKinds[finding.IndicatorID]
		if !ok {
			return fmt.Errorf("finding %s references indicator %q absent from validated pack", finding.FindingID, finding.IndicatorID)
		}
		proposition, err := analyze.PropositionForIndicatorKind(indicatorKind)
		if err != nil {
			return err
		}
		ruleVersion := finding.DerivationRuleVersion
		if ruleVersion == "" {
			ruleVersion = analyze.FindingRuleVersion(indicatorKind)
		}
		if err := persistFinding(ctx, tx, analysisID, options.Pack.CanonicalSHA256, options.Case.Metadata, finding, proposition, ruleVersion); err != nil {
			return err
		}
	}
	graphJSON, _ := json.Marshal(options.Case.Graph)
	graphHash := sha256.Sum256(graphJSON)
	for _, edge := range options.Case.Graph.Edges {
		evidenceJSON, _ := json.Marshal(edge.EvidenceIDs)
		if _, err := tx.ExecContext(ctx, `INSERT INTO graph_projection_edges(edge_id,analysis_id,source_id,target_id,relation,event_time_json,evidence_ids_json,derivation_rule,snapshot_sha256) VALUES(?,?,?,?,?,?,?,?,?)`, edge.ID, analysisID, edge.Source, edge.Target, edge.Type, nullable(edge.EventTime), string(evidenceJSON), nullable(edge.DerivationRule), hex.EncodeToString(graphHash[:])); err != nil {
			return fmt.Errorf("persist graph edge: %w", err)
		}
	}
	return tx.Commit()
}

func persistEvidence(ctx context.Context, tx *sql.Tx, envelope evidence.Envelope) error {
	e := envelope.Evidence
	scope := e.Scope
	selector, _ := json.Marshal(e.LogicalSource.RequestParameters)
	if _, err := tx.ExecContext(ctx, `INSERT INTO logical_sources(logical_source_id,kind,canonical_id,repository_id,run_id,run_attempt,job_id,selector_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(logical_source_id) DO NOTHING`,
		e.LogicalSource.ID, e.LogicalSource.Kind, e.LogicalSource.CanonicalID, ptrInt64(scope.RepositoryID), ptrInt64(scope.RunID), ptrInt64(scope.RunAttempt), ptrInt64(scope.JobID), string(selector)); err != nil {
		return fmt.Errorf("persist logical source: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_objects(evidence_id,logical_source_id,schema_version,provider,source_sha256,source_byte_length,complete,media_type,retained_payload_sha256,raw_retained,redaction_status,redaction_policy_version,extractor_name,extractor_version,ruleset_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(evidence_id) DO NOTHING`,
		e.ID, e.LogicalSource.ID, e.SchemaVersion, e.Source.Provider, e.Content.SourceSHA256, e.Content.ByteLength, boolInt(e.Content.Complete), e.Content.MediaType, nullableStringPointer(e.Content.RetainedPayloadSHA256), boolInt(e.Content.RawRetained), e.Redaction.Status, e.Redaction.PolicyVersion, e.Extractor.Name, e.Extractor.Version, e.Extractor.RulesetSHA256); err != nil {
		return fmt.Errorf("persist evidence object: %w", err)
	}
	event := e.EventTime
	o := envelope.Observation
	if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_observations(observation_id,evidence_id,collection_id,request_id,request_attempt,event_time_start,event_time_end,event_time_bounds,event_precision,event_approximation,event_basis,collection_started_at,collection_ended_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		o.ID, e.ID, o.CollectionSessionID, nil, o.RequestAttempt, instantText(event.Start), instantText(event.End), intervalBounds(event.Bounds), event.Precision, event.Approximation, event.Basis, instantText(&o.CollectionTime.StartedAt), instantText(&o.CollectionTime.EndedAt)); err != nil {
		return fmt.Errorf("persist evidence observation: %w", err)
	}
	for index, evidenceError := range e.Errors {
		errorID := deterministicHashID("error1", string(e.ID), fmt.Sprint(index), evidenceError.Code)
		if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_errors(error_id,evidence_id,observation_id,phase,code,http_status,retryable,permission_related,sanitized_message,raw_message_sha256) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			errorID, e.ID, o.ID, evidenceError.Phase, evidenceError.Code, intPointer(evidenceError.HTTPStatus), boolInt(evidenceError.Retryable), boolPointer(evidenceError.PermissionRelated), nullable(evidenceError.SanitizedMessage), nullableStringPointer(evidenceError.RawMessageSHA256)); err != nil {
			return fmt.Errorf("persist evidence error: %w", err)
		}
	}
	return nil
}

func persistFacts(ctx context.Context, tx *sql.Tx, snapshot archive.Snapshot) error {
	if len(snapshot.Collections) == 0 {
		return errors.New("case snapshot has no collection session")
	}
	encoded, err := evidence.CanonicalJSON(snapshot.Facts)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	batchID := "batch1:" + hex.EncodeToString(sum[:])
	committedAt := snapshot.Metadata.CreatedAt.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO archive_batches(batch_id,primary_collection_id,content_sha256,state,prepared_at,committed_at) VALUES(?,?,?,?,?,?)`, batchID, snapshot.Collections[0].ID, hex.EncodeToString(sum[:]), "COMMITTED", committedAt, committedAt); err != nil {
		return fmt.Errorf("persist case fact batch: %w", err)
	}
	for _, session := range snapshot.Collections {
		if _, err := tx.ExecContext(ctx, `INSERT INTO archive_batch_collections(batch_id,collection_id) VALUES(?,?)`, batchID, session.ID); err != nil {
			return fmt.Errorf("persist case batch collection provenance: %w", err)
		}
	}
	for _, fact := range snapshot.Facts {
		eventJSON, _ := json.Marshal(fact.EventTime)
		payloadJSON, _ := json.Marshal(fact)
		if _, err := tx.ExecContext(ctx, `INSERT INTO archive_facts(fact_id,kind,repository_id,run_id,run_attempt,job_id,step_key,event_time_json,payload_json,first_batch_id) VALUES(?,?,?,?,?,?,?,?,?,?)`, fact.ID, fact.Kind, nullableRepositoryID(fact.Subject.RepositoryID), ptrInt64(fact.Subject.RunID), ptrInt64(fact.Subject.RunAttempt), ptrInt64(fact.Subject.JobID), nullable(fact.Subject.StepKey), string(eventJSON), string(payloadJSON), batchID); err != nil {
			return fmt.Errorf("persist normalized fact: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO archive_batch_facts(batch_id,fact_id) VALUES(?,?)`, batchID, fact.ID); err != nil {
			return err
		}
		for _, evidenceID := range fact.EvidenceIDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO archive_fact_evidence(fact_id,evidence_id) VALUES(?,?)`, fact.ID, evidenceID); err != nil {
				return fmt.Errorf("persist fact evidence link: %w", err)
			}
		}
		if fact.Coverage != nil || fact.CoverageGap != nil {
			if err := persistCoverageFact(ctx, tx, snapshot.Collections[0].ID, fact); err != nil {
				return err
			}
		}
	}
	return nil
}

func persistCoverageFact(ctx context.Context, tx *sql.Tx, collectionID model.CollectionSessionID, fact archive.Fact) error {
	var unit model.CoverageUnit
	var assessment model.CoverageAssessment
	switch {
	case fact.Coverage != nil:
		unit, assessment = fact.Coverage.Unit, fact.Coverage.Assessment
	case fact.CoverageGap != nil:
		unit, assessment = fact.CoverageGap.Unit, fact.CoverageGap.Assessment
	default:
		return errors.New("persist coverage fact requires a coverage payload")
	}
	status := ""
	collected, notApplicable, gaps := 0, 0, 0
	reason, material, retryable := "", 0, 0
	switch assessment.Status {
	case model.CoverageCollected:
		status, collected = "collected", 1
	case model.CoverageNotApplicable:
		status, notApplicable = "not_applicable", 1
	case model.CoverageGap:
		status, gaps = "gap", 1
		if assessment.Gap == nil {
			return errors.New("persist coverage gap requires gap detail")
		}
		reason = string(assessment.Gap.Reason)
		material, retryable = boolInt(assessment.Gap.Material), boolInt(assessment.Gap.Retryable)
	default:
		return fmt.Errorf("persist terminal coverage has unsupported status %q", assessment.Status)
	}
	var evidenceID any
	if len(fact.EvidenceIDs) > 0 {
		evidenceID = fact.EvidenceIDs[0]
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO coverage_units(
			coverage_id,collection_id,kind,logical_scope,repository_id,run_id,run_attempt,job_id,
			expected,collected,not_applicable,gaps,status,reason_code,material,retryable,evidence_id
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(coverage_id) DO NOTHING`,
		assessment.ID, collectionID, unit.Kind, unit.LogicalKey, nullableRepositoryID(fact.Subject.RepositoryID),
		ptrInt64(fact.Subject.RunID), ptrInt64(fact.Subject.RunAttempt), ptrInt64(fact.Subject.JobID),
		1, collected, notApplicable, gaps, status, nullable(reason), material, retryable, evidenceID); err != nil {
		return fmt.Errorf("persist coverage assessment: %w", err)
	}
	var persistedCollection, persistedKind, persistedScope, persistedStatus string
	var persistedExpected, persistedCollected, persistedNotApplicable, persistedGaps, persistedMaterial, persistedRetryable int
	if err := tx.QueryRowContext(ctx, `
		SELECT collection_id,kind,logical_scope,status,expected,collected,not_applicable,gaps,material,retryable
		FROM coverage_units WHERE coverage_id=?`, assessment.ID).Scan(
		&persistedCollection, &persistedKind, &persistedScope, &persistedStatus, &persistedExpected,
		&persistedCollected, &persistedNotApplicable, &persistedGaps, &persistedMaterial, &persistedRetryable,
	); err != nil {
		return fmt.Errorf("verify persisted coverage assessment: %w", err)
	}
	if persistedCollection != string(collectionID) || persistedKind != string(unit.Kind) || persistedScope != unit.LogicalKey ||
		persistedStatus != status || persistedExpected != 1 || persistedCollected != collected ||
		persistedNotApplicable != notApplicable || persistedGaps != gaps || persistedMaterial != material || persistedRetryable != retryable {
		return errors.New("coverage assessment identity conflicts with persisted content")
	}
	return nil
}

func persistFinding(ctx context.Context, tx *sql.Tx, analysisID, canonicalPack string, metadata report.Metadata, finding report.Finding, proposition model.Proposition, ruleVersion string) error {
	subject := map[string]any{"repository": finding.Repository, "workflow": finding.Workflow, "run_id": finding.RunID, "run_attempt": finding.RunAttempt, "job_id": finding.JobID, "step": finding.StepIdentity}
	subjectJSON, _ := json.Marshal(subject)
	if _, err := tx.ExecContext(ctx, `INSERT INTO findings(finding_id,incident_id,indicator_id,repository_id,workflow_path,run_id,run_attempt,job_id,step_key,proposition_kind,subject_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		finding.FindingID, finding.IncidentID, finding.IndicatorID, repositoryIDForFinding(tx, finding.Repository), nullable(finding.Workflow), positiveOrNil(finding.RunID), positiveOrNil(int64(finding.RunAttempt)), positiveOrNil(finding.JobID), nullable(finding.StepIdentity), proposition.Kind, string(subjectJSON)); err != nil {
		return fmt.Errorf("persist finding: %w", err)
	}
	propositionJSON, err := evidence.CanonicalJSON(proposition)
	if err != nil {
		return fmt.Errorf("encode finding proposition: %w", err)
	}
	assumptions, _ := json.Marshal(finding.Assumptions)
	gaps, _ := json.Marshal(finding.EvidenceGaps)
	contradictions, _ := json.Marshal(finding.ContradictoryEvidence)
	credentials, _ := json.Marshal(finding.CredentialExposure)
	resources, _ := json.Marshal(finding.ResourceExposure)
	remediation, _ := json.Marshal(finding.RemediationGuidance)
	coverage, _ := json.Marshal(finding.CollectionCoverage)
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_revisions(finding_revision_id,finding_id,canonical_pack_sha256,state,provenance,proposition_json,concise_conclusion,event_time_json,assumptions_json,gaps_json,contradictions_json,credential_exposure_json,resource_exposure_json,remediation_json,collection_coverage_json,rule_id,rule_version,first_produced_analysis_id,first_produced_engine_version,created_at,supersedes_revision_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
		finding.FindingRevisionID, finding.FindingID, canonicalPack, finding.State, finding.Provenance, string(propositionJSON), finding.Conclusion, nullable(finding.EventTime), string(assumptions), string(gaps), string(contradictions), string(credentials), string(resources), string(remediation), string(coverage), "finding-state", ruleVersion, analysisID, metadata.EngineVersion, metadata.AnalysisTime); err != nil {
		return fmt.Errorf("persist finding revision: %w", err)
	}
	for _, evidenceID := range finding.EvidenceIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_revision_evidence(finding_revision_id,evidence_id,role) VALUES(?,?,'SUPPORTS')`, finding.FindingRevisionID, evidenceID); err != nil {
			return fmt.Errorf("persist finding support: %w", err)
		}
	}
	for _, coverageID := range finding.CollectionCoverage {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO finding_revision_coverage(finding_revision_id,coverage_id) VALUES(?,?)`, finding.FindingRevisionID, coverageID); err != nil {
			return fmt.Errorf("persist finding coverage: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO analysis_session_findings(analysis_id,finding_revision_id,disposition) VALUES(?,?,'EMITTED')`, analysisID, finding.FindingRevisionID); err != nil {
		return fmt.Errorf("persist analysis finding selection: %w", err)
	}
	return nil
}

func repositoryIDForFinding(tx *sql.Tx, repository string) any {
	owner, name := splitRepository(repository)
	var id int64
	if err := tx.QueryRow(`SELECT repository_id FROM repositories WHERE lower(owner)=lower(?) AND lower(name)=lower(?)`, owner, name).Scan(&id); err != nil {
		return nil
	}
	return id
}

func splitRepository(value string) (string, string) {
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 {
		return value, "unknown"
	}
	return parts[0], parts[1]
}

func ptrInt64[T ~int64 | ~uint32](value *T) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func intPointer(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableStringPointer(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func boolPointer(value *bool) any {
	if value == nil {
		return nil
	}
	return boolInt(*value)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func positiveOrNil(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullableRepositoryID(value model.RepositoryID) any {
	if value == 0 {
		return nil
	}
	return int64(value)
}

func instantText(value *model.Instant) any {
	if value == nil {
		return nil
	}
	return value.Format(time.RFC3339Nano)
}

func intervalBounds(value *model.IntervalBounds) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func deterministicHashID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return prefix + ":" + hex.EncodeToString(h.Sum(nil))
}
