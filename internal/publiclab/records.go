package publiclab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/torjan0/cirewind/internal/model"
)

const (
	RecordRun              RecordKind = "run-record"
	RecordPackInput        RecordKind = "pack-input-record"
	RecordTagMove          RecordKind = "tag-move-record"
	RecordReproduction     RecordKind = "reproduction-record"
	RecordReproductionsIdx RecordKind = "reproductions-index"
	RecordExpectedSeed     RecordKind = "expected-findings-seed"

	maxRecordBytes = 10 << 20
	maxSchemaBytes = 1 << 20
	maxJSONDepth   = 64
)

const recordSchemaBase = "https://schemas.invalid/cirewind/public-lab/"

var recordSchemaFiles = []string{
	"record-common.schema.json",
	"run-record.schema.json",
	"tag-move-record.schema.json",
	"pack-input-record.schema.json",
	"reproduction-record.schema.json",
	"expected-findings-seed.schema.json",
	"reproductions-index.schema.json",
}

// RecordKind is a closed choice of reviewed public-lab record contracts.
type RecordKind string

func (kind RecordKind) schemaFilename() (string, bool) {
	switch kind {
	case RecordRun:
		return "run-record.schema.json", true
	case RecordPackInput:
		return "pack-input-record.schema.json", true
	case RecordTagMove:
		return "tag-move-record.schema.json", true
	case RecordReproduction:
		return "reproduction-record.schema.json", true
	case RecordReproductionsIdx:
		return "reproductions-index.schema.json", true
	case RecordExpectedSeed:
		return "expected-findings-seed.schema.json", true
	default:
		return "", false
	}
}

// ValidateRecord validates one bounded JSON record against reviewed local
// schemas and then applies cross-field semantics JSON Schema cannot express.
// Schema references are pre-registered local resources; the compiler has no
// URL loader and cannot fetch a reference from the network.
func ValidateRecord(ctx context.Context, schemaDir string, kind RecordKind, data []byte) error {
	schemas, err := loadRecordSchemas(ctx, schemaDir)
	if err != nil {
		return err
	}
	return validateRecordWithSchemas(ctx, schemas, kind, data)
}

func loadRecordSchemas(ctx context.Context, schemaDir string) (map[string][]byte, error) {
	schemas := make(map[string][]byte, len(recordSchemaFiles))
	for _, name := range recordSchemaFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := readBoundedRegular(filepath.Join(schemaDir, name), maxSchemaBytes)
		if err != nil {
			return nil, fmt.Errorf("read reviewed schema %s: %w", name, err)
		}
		schemas[name] = raw
	}
	return schemas, nil
}

func validateRecordWithSchemas(ctx context.Context, schemas map[string][]byte, kind RecordKind, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	filename, ok := kind.schemaFilename()
	if !ok {
		return errors.New("unsupported public-lab record kind")
	}
	if len(data) == 0 || len(data) > maxRecordBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("public-lab record is empty, oversized, or not valid UTF-8 JSON")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return fmt.Errorf("validate public-lab JSON: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	for _, name := range recordSchemaFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, ok := schemas[name]
		if !ok || len(raw) == 0 || len(raw) > maxSchemaBytes {
			return fmt.Errorf("reviewed schema %s is absent or oversized", name)
		}
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return fmt.Errorf("reviewed schema %s is not strict JSON: %w", name, err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("decode reviewed schema %s: %w", name, err)
		}
		if err := compiler.AddResource(recordSchemaBase+name, document); err != nil {
			return fmt.Errorf("register reviewed schema %s: %w", name, err)
		}
	}
	schema, err := compiler.Compile(recordSchemaBase + filename)
	if err != nil {
		return fmt.Errorf("compile reviewed schema %s: %w", filename, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return errors.New("decode public-lab record: invalid JSON")
	}
	// Scan both object names and values before schema validation. Schema error
	// paths can contain attacker-controlled property names, so credential-like
	// material must be rejected before a diagnostic is constructed.
	if err := scanPublicRecordStrings(instance); err != nil {
		return err
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("public-lab record violates reviewed %s schema", filename)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	switch kind {
	case RecordRun:
		var record labRunRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("decode run record: %w", err)
		}
		return validateRunRecordSemantics(record)
	case RecordPackInput:
		var record labPackInputRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("decode pack-input record: %w", err)
		}
		return validatePackInputSemantics(record)
	case RecordTagMove:
		var record tagMoveRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("decode tag-move record: %w", err)
		}
		return validateTagMoveRecordSemantics(record)
	case RecordReproduction:
		var record labReproductionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("decode reproduction record: %w", err)
		}
		return validateReproductionSemantics(record)
	case RecordReproductionsIdx:
		var record labReproductionsIndex
		if err := json.Unmarshal(data, &record); err != nil {
			return fmt.Errorf("decode reproductions index: %w", err)
		}
		return validateIndexSemantics(record)
	case RecordExpectedSeed:
		return nil
	default:
		panic("unreachable record kind")
	}
}

func loadArtifactBoundProtocolFiles(ctx context.Context, sourceRoot, schemaDir string, artifact Artifact) (map[string][]byte, error) {
	if err := verifyArtifactValue(ctx, sourceRoot, artifact); err != nil {
		return nil, fmt.Errorf("verify reviewed public-lab artifact: %w", err)
	}
	expectedDir := filepath.Join(sourceRoot, "import", "protocol")
	expectedInfo, err := os.Lstat(expectedDir)
	if err != nil || !expectedInfo.IsDir() || expectedInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("reviewed protocol directory is unavailable or unsafe")
	}
	suppliedInfo, err := os.Lstat(schemaDir)
	if err != nil || !suppliedInfo.IsDir() || suppliedInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expectedInfo, suppliedInfo) {
		return nil, errors.New("schema directory is not the reviewed artifact-bound protocol directory")
	}

	files := make(map[string][]byte, len(recordSchemaFiles)+1)
	names := append(append([]string(nil), recordSchemaFiles...), "expected-findings.seed.json")
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		limit := int64(maxSchemaBytes)
		if name == "expected-findings.seed.json" {
			limit = maxRecordBytes
		}
		raw, err := readBoundedRegular(filepath.Join(expectedDir, name), limit)
		if err != nil {
			return nil, fmt.Errorf("read artifact-bound protocol file %s: %w", name, err)
		}
		descriptor, ok := importFileDescriptor(artifact.Model, "protocol/"+name)
		if !ok {
			return nil, fmt.Errorf("artifact manifest omits protocol file %s", name)
		}
		digest := sha256.Sum256(raw)
		if descriptor.ByteLength != len(raw) || descriptor.SHA256 != hex.EncodeToString(digest[:]) || descriptor.BlobObject != objectID("blob", raw) {
			return nil, fmt.Errorf("protocol file %s differs from the reviewed artifact manifest", name)
		}
		files[name] = raw
	}
	return files, nil
}

func importFileDescriptor(manifest ObjectManifest, path string) (ImportFile, bool) {
	index := sort.Search(len(manifest.ImportFiles), func(index int) bool {
		return manifest.ImportFiles[index].Path >= path
	})
	if index >= len(manifest.ImportFiles) || manifest.ImportFiles[index].Path != path {
		return ImportFile{}, false
	}
	return manifest.ImportFiles[index], true
}

// ReadAndValidateRecord accepts only a bounded regular file, never a symlink.
func ReadAndValidateRecord(ctx context.Context, schemaDir string, kind RecordKind, path string) ([]byte, error) {
	data, err := readBoundedRegular(path, maxRecordBytes)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(ctx, schemaDir, kind, data); err != nil {
		return nil, err
	}
	return data, nil
}

// ValidateRecordAgainstArtifact adds immutable source and scenario-oracle
// bindings. The artifact is first regenerated from the reviewed source, so an
// arbitrary self-consistent manifest cannot qualify itself.
func ValidateRecordAgainstArtifact(ctx context.Context, sourceRoot, schemaDir string, kind RecordKind, data []byte, artifact Artifact) error {
	protocolFiles, err := loadArtifactBoundProtocolFiles(ctx, sourceRoot, schemaDir, artifact)
	if err != nil {
		return err
	}
	if err := validateRecordWithSchemas(ctx, protocolFiles, kind, data); err != nil {
		return err
	}
	switch kind {
	case RecordRun:
		var record labRunRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		if err := bindRunRecordToManifest(record, artifact); err != nil {
			return err
		}
		return validateQualifiedScenarioSet(record, artifact.Model)
	case RecordPackInput:
		var record labPackInputRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		return bindCoreToManifest(record.LabRepository, record.Protocol, record.FixtureObjects, artifact)
	case RecordTagMove:
		var record tagMoveRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		return bindTagMoveToArtifact(record, artifact)
	case RecordReproduction:
		var record labReproductionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		return bindReproductionToManifest(record, artifact)
	default:
		return nil
	}
}

// ValidateRunRecordAgainstPackInput qualifies a collected run record against
// both the exact pack input and the full reviewed scenario oracle.
func ValidateRunRecordAgainstPackInput(ctx context.Context, sourceRoot, schemaDir string, runJSON, packInputJSON []byte, artifact Artifact) error {
	if err := validateRunRecordCoreAgainstPackInput(ctx, sourceRoot, schemaDir, runJSON, packInputJSON, artifact); err != nil {
		return err
	}
	var run labRunRecord
	if err := json.Unmarshal(runJSON, &run); err != nil {
		return errors.New("decode exact run record")
	}
	return validateQualifiedScenarioSet(run, artifact.Model)
}

// validateRunRecordCoreAgainstPackInput preserves a failed reproduction as a
// valid mismatch while still enforcing immutable artifact identity, exact pack
// provenance, and the operator-asserted/later-observed repository ID equality.
func validateRunRecordCoreAgainstPackInput(ctx context.Context, sourceRoot, schemaDir string, runJSON, packInputJSON []byte, artifact Artifact) error {
	protocolFiles, err := loadArtifactBoundProtocolFiles(ctx, sourceRoot, schemaDir, artifact)
	if err != nil {
		return err
	}
	if err := validateRecordWithSchemas(ctx, protocolFiles, RecordPackInput, packInputJSON); err != nil {
		return fmt.Errorf("validate pack-input record: %w", err)
	}
	if err := validateRecordWithSchemas(ctx, protocolFiles, RecordRun, runJSON); err != nil {
		return fmt.Errorf("validate run record: %w", err)
	}
	var packInput labPackInputRecord
	if err := json.Unmarshal(packInputJSON, &packInput); err != nil {
		return errors.New("decode exact pack-input record")
	}
	var run labRunRecord
	if err := json.Unmarshal(runJSON, &run); err != nil {
		return errors.New("decode exact run record")
	}
	if err := bindCoreToManifest(packInput.LabRepository, packInput.Protocol, packInput.FixtureObjects, artifact); err != nil {
		return fmt.Errorf("bind exact pack-input record: %w", err)
	}
	if err := bindRunRecordToManifest(run, artifact); err != nil {
		return fmt.Errorf("bind exact run record: %w", err)
	}
	if run.LabRepository != packInput.LabRepository || run.Protocol != packInput.Protocol ||
		run.FixtureObjects != packInput.FixtureObjects || run.MutableTag != packInput.MutableTag {
		return errors.New("run record repository identity or A-to-B-to-A observations differ from the exact pack input")
	}
	createdAt, err := parseRecordTime(packInput.CreatedAt)
	if err != nil {
		return err
	}
	collectedAt, err := parseRecordTime(run.Collection.CollectedAt)
	if err != nil || collectedAt.Before(createdAt) {
		return errors.New("run-record collection precedes the bound pack-input record")
	}
	return nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	if path == "" || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("input path must be nonempty and clean")
	}
	data, _, err := readRegularFileOnce(path, limit)
	return data, err
}

type recordGitObject struct {
	Algorithm string `json:"algorithm"`
	ObjectID  string `json:"objectId"`
}

type recordObservation struct {
	ObservedAt      string `json:"observedAt"`
	EventSource     string `json:"eventSource"`
	SourcePrecision string `json:"sourcePrecision"`
	Approximation   string `json:"approximation"`
}

type recordTagObservation struct {
	Target      recordGitObject   `json:"target_commit"`
	Observation recordObservation `json:"observation"`
}

type labRepositoryBinding struct {
	DatabaseID int64  `json:"database_id"`
	FullName   string `json:"full_name"`
	PublicURL  string `json:"public_url"`
}

type labProtocolBinding struct {
	Version              string          `json:"version"`
	SourceCommit         recordGitObject `json:"source_commit"`
	SourceManifestSHA256 string          `json:"source_manifest_sha256"`
}

type labAnnotatedTagBinding struct {
	Ref          string          `json:"ref"`
	TagObject    recordGitObject `json:"tag_object"`
	PeeledCommit recordGitObject `json:"peeled_commit"`
}

type labFixtureObjects struct {
	MarkerA recordGitObject        `json:"marker_a_commit"`
	MarkerB recordGitObject        `json:"marker_b_commit"`
	TagA    labAnnotatedTagBinding `json:"fixture_a_tag"`
	TagB    labAnnotatedTagBinding `json:"fixture_b_tag"`
}

type labMutableTag struct {
	Ref    string               `json:"ref"`
	Before recordTagObservation `json:"before"`
	During recordTagObservation `json:"during"`
	After  recordTagObservation `json:"after"`
}

type labPackInputRecord struct {
	SchemaVersion     string               `json:"schema_version"`
	RecordID          string               `json:"record_id"`
	LabRepository     labRepositoryBinding `json:"lab_repository"`
	RepositoryIDBasis string               `json:"repository_database_id_basis"`
	Protocol          labProtocolBinding   `json:"protocol"`
	FixtureObjects    labFixtureObjects    `json:"fixture_objects"`
	MutableTag        labMutableTag        `json:"mutable_tag"`
	DerivationInputs  []struct {
		RecordID string `json:"record_id"`
		SHA256   string `json:"sha256"`
	} `json:"derivation_inputs"`
	CreatedAt string `json:"created_at"`
}

type labRunRecord struct {
	SchemaVersion  string               `json:"schema_version"`
	RecordID       string               `json:"record_id"`
	LabRepository  labRepositoryBinding `json:"lab_repository"`
	Protocol       labProtocolBinding   `json:"protocol"`
	FixtureObjects labFixtureObjects    `json:"fixture_objects"`
	MutableTag     labMutableTag        `json:"mutable_tag"`
	WorkflowRuns   []labWorkflowRun     `json:"workflow_runs"`
	RerunRequests  []struct {
		OriginalRunID      int64             `json:"original_run_id"`
		Kind               string            `json:"kind"`
		JobID              *int64            `json:"job_id"`
		OperatorActionTime recordObservation `json:"operator_action_time"`
	} `json:"rerun_requests"`
	Collector  labCollectorIdentity `json:"collector"`
	Collection struct {
		WindowStart          string                  `json:"window_start"`
		WindowEnd            string                  `json:"window_end"`
		CollectedAt          string                  `json:"collected_at"`
		CaseManifestSHA256   string                  `json:"case_manifest_sha256"`
		CaseManifestVerified bool                    `json:"case_manifest_verified"`
		Coverage             labCollectionCoverage   `json:"coverage"`
		Issues               []recordStructuredIssue `json:"issues"`
	} `json:"collection"`
}

type labCollectionCoverage struct {
	RepositoriesRequested        int64 `json:"repositories_requested"`
	RepositoriesAccessible       int64 `json:"repositories_accessible"`
	RepositoriesDenied           int64 `json:"repositories_denied"`
	Runs                         int64 `json:"runs_enumerated"`
	Attempts                     int64 `json:"attempts_enumerated"`
	Jobs                         int64 `json:"jobs_enumerated"`
	LogsRetrieved                int64 `json:"logs_retrieved"`
	LogsMissing                  int64 `json:"logs_missing"`
	WorkflowDefinitionsRetrieved int64 `json:"workflow_definitions_retrieved"`
	ActionDefinitionsRetrieved   int64 `json:"action_definitions_retrieved"`
	OptionalCapabilitiesDenied   int64 `json:"optional_capabilities_denied"`
	TruncatedEvidenceObjects     int64 `json:"truncated_evidence_objects"`
}

type labCollectorIdentity struct {
	Version        string          `json:"version"`
	SourceRevision recordGitObject `json:"source_revision"`
	BinarySHA256   string          `json:"binary_sha256"`
}

type recordStructuredIssue struct {
	Code    string `json:"code"`
	Scope   string `json:"scope"`
	Summary string `json:"summary"`
}

type labWorkflowRun struct {
	ScenarioID               string            `json:"scenario_id"`
	WorkflowPath             string            `json:"workflow_path"`
	WorkflowDefinitionCommit recordGitObject   `json:"workflow_definition_commit"`
	EventTime                recordObservation `json:"event_time"`
	RunID                    int64             `json:"run_id"`
	RunURL                   string            `json:"run_url"`
	Attempts                 []labRunAttempt   `json:"attempts"`
}

type labRunAttempt struct {
	Number int64    `json:"run_attempt"`
	Jobs   []labJob `json:"jobs"`
}

type labJob struct {
	JobID              int64                   `json:"job_id"`
	RerunOfJobID       *int64                  `json:"rerun_of_job_id"`
	Conclusion         string                  `json:"conclusion"`
	ActionObservations []labActionObservation  `json:"action_observations"`
	CalledWorkflows    []labCalledWorkflow     `json:"called_workflow_observations"`
	DependencyChain    []labDependencyLink     `json:"dependency_chain"`
	Findings           []labFindingObservation `json:"findings"`
}

type labCalledWorkflow struct {
	Repository   string          `json:"repository"`
	WorkflowPath string          `json:"workflow_path"`
	Commit       recordGitObject `json:"called_workflow_commit"`
	EvidenceIDs  []string        `json:"evidence_ids"`
}

type labActionObservation struct {
	Repository   string                       `json:"action_repository"`
	Path         string                       `json:"action_path"`
	DeclaredRef  string                       `json:"declared_ref"`
	SourceCommit recordGitObject              `json:"source_commit"`
	Lifecycle    model.RuntimeObservationKind `json:"lifecycle"`
	Step         string                       `json:"step_identity"`
	EvidenceIDs  []string                     `json:"evidence_ids"`
}

type labDependencyEndpoint struct {
	Kind       string          `json:"kind"`
	Repository string          `json:"repository"`
	Path       string          `json:"path"`
	Commit     recordGitObject `json:"commit"`
}

type labDependencyLink struct {
	Relationship string                `json:"relationship"`
	From         labDependencyEndpoint `json:"from"`
	To           labDependencyEndpoint `json:"to"`
	EvidenceIDs  []string              `json:"evidence_ids"`
}

type labFindingObservation struct {
	FindingID            string                `json:"finding_id"`
	FindingRevisionID    string                `json:"finding_revision_id"`
	IndicatorID          string                `json:"indicator_id"`
	Step                 *string               `json:"step_identity"`
	State                model.FindingState    `json:"state"`
	Provenance           model.ProvenanceLevel `json:"provenance"`
	Conclusion           string                `json:"conclusion"`
	EvidenceIDs          []string              `json:"evidence_ids"`
	CoverageAssessmentID []string              `json:"coverage_assessment_ids"`
	EvidenceGapCodes     []string              `json:"evidence_gap_codes"`
}

func validateRunRecordSemantics(record labRunRecord) error {
	before, _, after, err := validateCoreRecordSemantics(record.LabRepository, record.FixtureObjects, record.MutableTag)
	if err != nil {
		return err
	}
	windowStart, err := parseRecordTime(record.Collection.WindowStart)
	if err != nil {
		return err
	}
	windowEnd, err := parseRecordTime(record.Collection.WindowEnd)
	if err != nil {
		return err
	}
	collectedAt, err := parseRecordTime(record.Collection.CollectedAt)
	if err != nil {
		return err
	}
	if !windowStart.Before(windowEnd) || collectedAt.Before(windowEnd) || before.Before(windowStart) || after.After(windowEnd) {
		return errors.New("collection times do not contain the ordered tag observations")
	}

	seenRuns := make(map[int64]struct{}, len(record.WorkflowRuns))
	seenJobs := make(map[int64]struct{})
	seenFindingIDs := make(map[string]struct{})
	seenFindingRevisionIDs := make(map[string]struct{})
	totalAttempts := int64(0)
	totalJobs := int64(0)
	lastRunKey := ""
	for _, run := range record.WorkflowRuns {
		key := run.ScenarioID + "\x00" + fmt.Sprintf("%020d", run.RunID) + "\x00" + run.WorkflowPath
		if lastRunKey != "" && key <= lastRunKey {
			return errors.New("workflow runs must be strictly sorted by scenario, run ID, and path")
		}
		lastRunKey = key
		if _, duplicate := seenRuns[run.RunID]; duplicate {
			return errors.New("duplicate workflow run ID")
		}
		seenRuns[run.RunID] = struct{}{}
		if !runURLMatches(run.RunURL, record.LabRepository.FullName, run.RunID) {
			return errors.New("workflow run URL does not bind its repository and run ID")
		}
		if run.WorkflowDefinitionCommit != record.Protocol.SourceCommit {
			return errors.New("workflow definition commit differs from the reviewed import commit")
		}
		eventAt, timeErr := parseRecordTime(run.EventTime.ObservedAt)
		if timeErr != nil || eventAt.Before(windowStart) || eventAt.After(windowEnd) {
			return errors.New("workflow event time is invalid or outside the collection window")
		}
		priorAttemptJobs := make(map[int64]struct{})
		for attemptIndex, attempt := range run.Attempts {
			totalAttempts++
			if attempt.Number != int64(attemptIndex+1) {
				return errors.New("run attempts must be contiguous and begin at one")
			}
			lastJob := int64(0)
			currentAttemptJobs := make(map[int64]struct{}, len(attempt.Jobs))
			for _, job := range attempt.Jobs {
				totalJobs++
				if job.JobID <= lastJob {
					return errors.New("job IDs must be strictly increasing within each run attempt")
				}
				lastJob = job.JobID
				if _, duplicate := seenJobs[job.JobID]; duplicate {
					return errors.New("job ID is reused across material run-attempt identities")
				}
				seenJobs[job.JobID] = struct{}{}
				currentAttemptJobs[job.JobID] = struct{}{}
				if attemptIndex == 0 && job.RerunOfJobID != nil {
					return errors.New("original run attempt cannot claim rerun job lineage")
				}
				if attemptIndex > 0 {
					if job.RerunOfJobID == nil {
						return errors.New("rerun-attempt job omits its immediately prior selected job identity")
					}
					if _, ok := priorAttemptJobs[*job.RerunOfJobID]; !ok {
						return errors.New("rerun-attempt job does not bind an immediately prior attempt job")
					}
				}
				if err := validateJobFindingSupport(record.LabRepository.FullName, record.FixtureObjects.MarkerB, job, seenFindingIDs, seenFindingRevisionIDs); err != nil {
					return fmt.Errorf("run %d attempt %d job %d: %w", run.RunID, attempt.Number, job.JobID, err)
				}
			}
			priorAttemptJobs = currentAttemptJobs
		}
	}
	coverage := record.Collection.Coverage
	if coverage.RepositoriesRequested != 1 || coverage.RepositoriesAccessible != 1 || coverage.RepositoriesDenied != 0 {
		return errors.New("public-lab run coverage must identify exactly one requested and accessible repository with none denied")
	}
	if coverage.Runs != int64(len(record.WorkflowRuns)) || coverage.Attempts != totalAttempts || coverage.Jobs != totalJobs {
		return errors.New("coverage identity totals differ from the exact runs, attempts, or jobs retained in the run record")
	}
	if coverage.LogsRetrieved+coverage.LogsMissing != totalJobs {
		return errors.New("retrieved and missing log coverage does not equal the exact retained job count")
	}
	lastRerunAt := time.Time{}
	for _, rerun := range record.RerunRequests {
		if _, ok := seenRuns[rerun.OriginalRunID]; !ok {
			return errors.New("rerun request refers to an unknown original run")
		}
		actionAt, timeErr := parseRecordTime(rerun.OperatorActionTime.ObservedAt)
		if timeErr != nil || actionAt.Before(windowStart) || actionAt.After(windowEnd) {
			return errors.New("rerun request time is invalid or outside the collection window")
		}
		if !actionAt.After(after) {
			return errors.New("rerun request does not follow the restored-A observation")
		}
		if !lastRerunAt.IsZero() && !actionAt.After(lastRerunAt) {
			return errors.New("rerun request times must be strictly increasing")
		}
		lastRerunAt = actionAt
	}
	return nil
}

func validatePackInputSemantics(record labPackInputRecord) error {
	if record.RepositoryIDBasis != repositoryDatabaseIDBasis {
		return errors.New("pack-input repository database ID basis is not the required operator assertion")
	}
	_, _, after, err := validateCoreRecordSemantics(record.LabRepository, record.FixtureObjects, record.MutableTag)
	if err != nil {
		return err
	}
	createdAt, err := parseRecordTime(record.CreatedAt)
	if err != nil || createdAt.Before(after) {
		return errors.New("pack-input creation time precedes restored-A observation")
	}
	if len(record.DerivationInputs) != 2 || record.DerivationInputs[0].RecordID == record.DerivationInputs[1].RecordID || record.DerivationInputs[0].SHA256 == record.DerivationInputs[1].SHA256 {
		return errors.New("pack-input must retain distinct install and restore derivation identities")
	}
	if record.RecordID == "" || record.RecordID != packInputRecordID(record) {
		return errors.New("pack-input record ID does not bind its canonical content")
	}
	return nil
}

func validateCoreRecordSemantics(repository labRepositoryBinding, fixtures labFixtureObjects, mutable labMutableTag) (time.Time, time.Time, time.Time, error) {
	if repository.PublicURL != "https://github.com/"+repository.FullName {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("public lab repository URL does not bind the declared owner/name")
	}
	if fixtures.MarkerA != fixtures.TagA.PeeledCommit || fixtures.MarkerB != fixtures.TagB.PeeledCommit {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("fixture annotated-tag peeled commits do not equal marker A/B commits")
	}
	if fixtures.MarkerA == fixtures.MarkerB || fixtures.TagA.TagObject == fixtures.TagB.TagObject {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("marker and fixture-tag identities must be distinct")
	}
	if mutable.Before.Target != fixtures.MarkerA || mutable.During.Target != fixtures.MarkerB || mutable.After.Target != fixtures.MarkerA {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("mutable v1 observations are not the exact reviewed A-to-B-to-A sequence")
	}
	observations := []recordObservation{mutable.Before.Observation, mutable.During.Observation, mutable.After.Observation}
	for _, observation := range observations {
		if observation.EventSource != "git-ls-remote" {
			return time.Time{}, time.Time{}, time.Time{}, errors.New("mutable v1 target must be observed by git-ls-remote")
		}
	}
	before, err := parseRecordTime(mutable.Before.Observation.ObservedAt)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	during, err := parseRecordTime(mutable.During.Observation.ObservedAt)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	after, err := parseRecordTime(mutable.After.Observation.ObservedAt)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	if !before.Before(during) || !during.Before(after) {
		return time.Time{}, time.Time{}, time.Time{}, errors.New("mutable v1 observation times are not strictly A-before-B-before-A")
	}
	return before, during, after, nil
}

func validateJobFindingSupport(actionRepository string, markerB recordGitObject, job labJob, seenFindingIDs, seenFindingRevisionIDs map[string]struct{}) error {
	observationEvidence := make(map[string]struct{})
	actionEvidence := make(map[string][]labActionObservation)
	calledWorkflowEvidence := make(map[string][]labCalledWorkflow)
	for _, action := range job.ActionObservations {
		for _, evidenceID := range action.EvidenceIDs {
			observationEvidence[evidenceID] = struct{}{}
			actionEvidence[evidenceID] = append(actionEvidence[evidenceID], action)
		}
	}
	for _, called := range job.CalledWorkflows {
		for _, evidenceID := range called.EvidenceIDs {
			observationEvidence[evidenceID] = struct{}{}
			calledWorkflowEvidence[evidenceID] = append(calledWorkflowEvidence[evidenceID], called)
		}
	}
	for index, link := range job.DependencyChain {
		if link.From.Repository != actionRepository || link.To.Repository != actionRepository {
			return errors.New("dependency chain leaves the bound public-lab repository")
		}
		if index > 0 && job.DependencyChain[index-1].To != link.From {
			return errors.New("dependency chain is not endpoint-contiguous")
		}
		if !validDependencyRelationship(link) {
			return errors.New("dependency-chain relationship conflicts with endpoint kinds")
		}
		for _, evidenceID := range link.EvidenceIDs {
			if !dependencyEvidenceSupports(link, evidenceID, actionEvidence, calledWorkflowEvidence) {
				return errors.New("dependency-chain evidence does not support the edge's exact destination repository, path, and commit")
			}
		}
	}
	for _, finding := range job.Findings {
		if _, duplicate := seenFindingIDs[finding.FindingID]; duplicate {
			return errors.New("finding ID is reused across material job identities")
		}
		seenFindingIDs[finding.FindingID] = struct{}{}
		if _, duplicate := seenFindingRevisionIDs[finding.FindingRevisionID]; duplicate {
			return errors.New("finding revision ID is reused across material job identities")
		}
		seenFindingRevisionIDs[finding.FindingRevisionID] = struct{}{}
		if finding.IndicatorID != syntheticMarkerBIndicatorID {
			return errors.New("finding does not identify the synthetic marker-B indicator")
		}
		wantConclusion, ok := canonicalSyntheticFindingConclusion(finding.State)
		if !ok || finding.Conclusion != wantConclusion {
			return errors.New("finding conclusion is not the canonical conservative synthetic conclusion for its state")
		}
		for _, evidenceID := range finding.EvidenceIDs {
			if _, ok := observationEvidence[evidenceID]; !ok {
				return errors.New("finding evidence is not closed over same-job observations")
			}
		}
		if finding.State == model.NoMatchConfirmed {
			if finding.Provenance != model.L4Certain {
				return errors.New("exact covered NO_MATCH_CONFIRMED must use L4_CERTAIN provenance")
			}
			for _, action := range job.ActionObservations {
				if action.Repository == actionRepository && action.SourceCommit == markerB {
					return errors.New("NO_MATCH_CONFIRMED contradicts an exact marker-B Action observation")
				}
			}
		}
		if finding.State != model.ConfirmedExecuted && finding.State != model.ConfirmedDownloaded {
			continue
		}
		if finding.Provenance != model.L4Certain {
			return errors.New("exact runtime Action finding must use L4_CERTAIN provenance")
		}
		if finding.Step == nil {
			return errors.New("runtime Action finding omits step identity")
		}
		var citedDownloaded, citedStarted, anyStarted bool
		for _, action := range job.ActionObservations {
			if action.Repository != actionRepository || action.SourceCommit != markerB || action.Step != *finding.Step {
				continue
			}
			anyStarted = anyStarted || action.Lifecycle.SupportsExecuted()
			if !hasStringIntersection(action.EvidenceIDs, finding.EvidenceIDs) {
				continue
			}
			citedDownloaded = citedDownloaded || action.Lifecycle.SupportsDownloaded()
			citedStarted = citedStarted || action.Lifecycle.SupportsExecuted()
		}
		if finding.State == model.ConfirmedExecuted && !citedStarted {
			return errors.New("CONFIRMED_EXECUTED lacks a same-step lifecycle start or completion")
		}
		if finding.State == model.ConfirmedDownloaded && (!citedDownloaded || anyStarted) {
			return errors.New("CONFIRMED_DOWNLOADED lacks completed preparation or contradicts a lifecycle start")
		}
	}
	return nil
}

func dependencyEvidenceSupports(link labDependencyLink, evidenceID string, actionEvidence map[string][]labActionObservation, calledWorkflowEvidence map[string][]labCalledWorkflow) bool {
	switch link.Relationship {
	case "WORKFLOW_CALLED_WORKFLOW":
		for _, called := range calledWorkflowEvidence[evidenceID] {
			if called.Repository == link.To.Repository && called.WorkflowPath == link.To.Path && called.Commit == link.To.Commit {
				return true
			}
		}
	case "WORKFLOW_DECLARED_ACTION", "ACTION_CONTAINS_ACTION":
		for _, action := range actionEvidence[evidenceID] {
			if action.Repository == link.To.Repository && action.Path == link.To.Path && action.SourceCommit == link.To.Commit {
				return true
			}
		}
	}
	return false
}

func canonicalSyntheticFindingConclusion(state model.FindingState) (string, bool) {
	switch state {
	case model.ConfirmedExecuted:
		return "Exact harmless synthetic marker B began its lifecycle in this job attempt.", true
	case model.ConfirmedDownloaded:
		return "Exact harmless synthetic marker B completed preparation, but no lifecycle start was observed.", true
	case model.ConfirmedCalledWorkflow:
		return "GitHub recorded an exact synthetic reusable-workflow commit for this job attempt.", true
	case model.DeclaredAtRunSHA:
		return "The historical workflow definition declared the exact harmless synthetic marker B commit.", true
	case model.RunInWindowMutableRef:
		return "The historical workflow used mutable v1 during the synthetic marker-B interval; exact runtime resolution was unavailable.", true
	case model.PotentialTransitive:
		return "Harmless synthetic marker B was transitively reachable, but exact runtime resolution was unavailable.", true
	case model.CurrentReferenceOnly:
		return "Only present-day synthetic configuration referenced marker B.", true
	case model.NoMatchConfirmed:
		return "Exact reviewed marker A began after v1 restoration; complete retained evidence contains no marker B observation for this job attempt.", true
	case model.UnknownEvidenceGap:
		return "Required retained synthetic laboratory evidence was unavailable; no responsible match or no-match conclusion was possible.", true
	case model.ContradictoryEvidence:
		return "Synthetic static and runtime evidence materially disagreed; neither source was silently preferred.", true
	default:
		return "", false
	}
}

func validDependencyRelationship(link labDependencyLink) bool {
	switch link.Relationship {
	case "WORKFLOW_DECLARED_ACTION":
		return (link.From.Kind == "WORKFLOW_DEFINITION" || link.From.Kind == "REUSABLE_WORKFLOW_DEFINITION") && link.To.Kind == "ACTION_DEFINITION"
	case "WORKFLOW_CALLED_WORKFLOW":
		return link.From.Kind == "WORKFLOW_DEFINITION" && link.To.Kind == "REUSABLE_WORKFLOW_DEFINITION"
	case "ACTION_CONTAINS_ACTION":
		return link.From.Kind == "ACTION_DEFINITION" && link.To.Kind == "ACTION_DEFINITION"
	default:
		return false
	}
}

func hasStringIntersection(left, right []string) bool {
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := seen[value]; ok {
			return true
		}
	}
	return false
}

type labReproductionRecord struct {
	ClaimedResult string `json:"claimed_result"`
	LabBinding    struct {
		Repository           string               `json:"repository"`
		RepositoryDatabaseID int64                `json:"repository_database_id"`
		PublicURL            string               `json:"public_url"`
		SourceCommit         recordGitObject      `json:"source_commit"`
		SourceManifestSHA256 string               `json:"source_manifest_sha256"`
		MarkerA              recordGitObject      `json:"marker_a_commit"`
		MarkerB              recordGitObject      `json:"marker_b_commit"`
		FixtureATagObject    recordGitObject      `json:"fixture_a_tag_object"`
		FixtureAPeeledCommit recordGitObject      `json:"fixture_a_peeled_commit"`
		FixtureBTagObject    recordGitObject      `json:"fixture_b_tag_object"`
		FixtureBPeeledCommit recordGitObject      `json:"fixture_b_peeled_commit"`
		V1Before             recordTagObservation `json:"v1_before"`
		V1During             recordTagObservation `json:"v1_during"`
		V1After              recordTagObservation `json:"v1_after"`
	} `json:"lab_binding"`
	QualifiedBinary struct {
		Version        string          `json:"version"`
		SourceRevision recordGitObject `json:"source_revision"`
		BinarySHA256   string          `json:"binary_sha256"`
		Acquisition    struct {
			Kind           string          `json:"kind"`
			SourceURL      string          `json:"source_url"`
			SourceCommit   recordGitObject `json:"source_commit"`
			WorkflowRunURL string          `json:"workflow_run_url"`
			WorkflowRunID  int64           `json:"workflow_run_id"`
			ArtifactSHA256 string          `json:"artifact_sha256"`
			ReleaseURL     string          `json:"release_url"`
			AssetSHA256    string          `json:"asset_sha256"`
			AccessedAt     string          `json:"accessed_at"`
		} `json:"acquisition"`
	} `json:"qualified_binary"`
	RunRecord struct {
		RecordID   string `json:"record_id"`
		PublicURL  string `json:"public_url"`
		SHA256     string `json:"sha256"`
		ByteLength int64  `json:"byte_length"`
	} `json:"run_record"`
	PublicRuns []struct {
		ScenarioID string `json:"scenario_id"`
		RunID      int64  `json:"run_id"`
		RunURL     string `json:"run_url"`
		Attempts   []struct {
			Number int64   `json:"run_attempt"`
			JobIDs []int64 `json:"job_ids"`
		} `json:"attempts"`
	} `json:"public_runs"`
	CaseArchive struct {
		CaseManifestSHA256 string `json:"case_manifest_sha256"`
	} `json:"case_archive"`
	FindingCounts    map[string]int64  `json:"finding_counts"`
	ScenarioChecks   labScenarioChecks `json:"scenario_checks"`
	OracleComparison struct {
		OracleSHA256 string   `json:"oracle_sha256"`
		Result       string   `json:"result"`
		Deviations   []string `json:"deviations"`
	} `json:"oracle_comparison"`
	CoverageIssues []recordStructuredIssue `json:"coverage_issues"`
	SubmittedAt    string                  `json:"submitted_at"`
}

type labScenarioChecks struct {
	DirectBExecuted                    bool `json:"direct_b_executed"`
	CompositeBExecuted                 bool `json:"composite_b_executed"`
	ReusableBExecuted                  bool `json:"reusable_b_executed"`
	SkippedBNotExecuted                bool `json:"skipped_b_not_executed"`
	MatrixJobsKeptDistinct             bool `json:"matrix_jobs_kept_distinct"`
	RerunAttemptsKeptDistinct          bool `json:"rerun_attempts_kept_distinct"`
	PresentTagDidNotRewriteHistory     bool `json:"present_tag_did_not_rewrite_history"`
	CalledWorkflowIdentityKeptSeparate bool `json:"called_workflow_identity_kept_separate"`
}

func (checks labScenarioChecks) allSatisfied() bool {
	return checks.DirectBExecuted && checks.CompositeBExecuted && checks.ReusableBExecuted && checks.SkippedBNotExecuted &&
		checks.MatrixJobsKeptDistinct && checks.RerunAttemptsKeptDistinct && checks.PresentTagDidNotRewriteHistory &&
		checks.CalledWorkflowIdentityKeptSeparate
}

// ValidateReproductionAgainstRunRecord closes the reproduction's public run
// tuples and content claims over the exact run-record bytes and the separately
// validated reviewed artifact. It performs no network access and does not treat
// the reproducer's matching claim as maintainer acceptance.
func ValidateReproductionAgainstRunRecord(ctx context.Context, sourceRoot, schemaDir string, reproductionJSON, runJSON, packInputJSON []byte, artifact Artifact) error {
	if err := ValidateRecordAgainstArtifact(ctx, sourceRoot, schemaDir, RecordReproduction, reproductionJSON, artifact); err != nil {
		return fmt.Errorf("validate reproduction record: %w", err)
	}
	if err := validateRunRecordCoreAgainstPackInput(ctx, sourceRoot, schemaDir, runJSON, packInputJSON, artifact); err != nil {
		return fmt.Errorf("validate referenced qualified run record: %w", err)
	}
	var reproduction labReproductionRecord
	if err := json.Unmarshal(reproductionJSON, &reproduction); err != nil {
		return err
	}
	var run labRunRecord
	if err := json.Unmarshal(runJSON, &run); err != nil {
		return err
	}
	if err := bindRunRecordToManifest(run, artifact); err != nil {
		return fmt.Errorf("bind referenced run record to reviewed artifact: %w", err)
	}
	digest := sha256.Sum256(runJSON)
	if reproduction.RunRecord.RecordID != run.RecordID || reproduction.RunRecord.SHA256 != hex.EncodeToString(digest[:]) || reproduction.RunRecord.ByteLength != int64(len(runJSON)) {
		return errors.New("reproduction run-record identity, length, or SHA-256 does not match the supplied bytes")
	}
	if reproduction.LabBinding.Repository != run.LabRepository.FullName || reproduction.LabBinding.RepositoryDatabaseID != run.LabRepository.DatabaseID ||
		reproduction.LabBinding.PublicURL != run.LabRepository.PublicURL || reproduction.LabBinding.SourceCommit != run.Protocol.SourceCommit ||
		reproduction.LabBinding.SourceManifestSHA256 != run.Protocol.SourceManifestSHA256 || reproduction.LabBinding.MarkerA != run.FixtureObjects.MarkerA ||
		reproduction.LabBinding.MarkerB != run.FixtureObjects.MarkerB || reproduction.LabBinding.FixtureATagObject != run.FixtureObjects.TagA.TagObject ||
		reproduction.LabBinding.FixtureAPeeledCommit != run.FixtureObjects.TagA.PeeledCommit || reproduction.LabBinding.FixtureBTagObject != run.FixtureObjects.TagB.TagObject ||
		reproduction.LabBinding.FixtureBPeeledCommit != run.FixtureObjects.TagB.PeeledCommit || reproduction.LabBinding.V1Before != run.MutableTag.Before ||
		reproduction.LabBinding.V1During != run.MutableTag.During || reproduction.LabBinding.V1After != run.MutableTag.After {
		return errors.New("reproduction lab binding differs from the supplied run record")
	}
	if len(reproduction.PublicRuns) != len(run.WorkflowRuns) {
		return errors.New("reproduction public-run set differs from the supplied run record")
	}
	for index := range run.WorkflowRuns {
		want := run.WorkflowRuns[index]
		got := reproduction.PublicRuns[index]
		if got.ScenarioID != want.ScenarioID || got.RunID != want.RunID || got.RunURL != want.RunURL || len(got.Attempts) != len(want.Attempts) {
			return errors.New("reproduction public-run identity differs from the supplied run record")
		}
		for attemptIndex := range want.Attempts {
			wantAttempt := want.Attempts[attemptIndex]
			gotAttempt := got.Attempts[attemptIndex]
			if gotAttempt.Number != wantAttempt.Number || len(gotAttempt.JobIDs) != len(wantAttempt.Jobs) {
				return errors.New("reproduction attempt topology differs from the supplied run record")
			}
			for jobIndex := range wantAttempt.Jobs {
				if gotAttempt.JobIDs[jobIndex] != wantAttempt.Jobs[jobIndex].JobID {
					return errors.New("reproduction job identity differs from the supplied run record")
				}
			}
		}
	}
	if reproduction.QualifiedBinary.Version != run.Collector.Version ||
		reproduction.QualifiedBinary.SourceRevision != run.Collector.SourceRevision ||
		reproduction.QualifiedBinary.BinarySHA256 != run.Collector.BinarySHA256 {
		return errors.New("reproduction qualified-binary identity differs from the run-record collector")
	}
	submittedAt, err := parseRecordTime(reproduction.SubmittedAt)
	if err != nil {
		return err
	}
	const projectRepository = "torjan0/cirewind"
	switch reproduction.QualifiedBinary.Acquisition.Kind {
	case "independent-reproducible-source-build":
		wantSourceURL := "https://github.com/" + projectRepository + "/tree/" + reproduction.QualifiedBinary.SourceRevision.ObjectID
		if reproduction.QualifiedBinary.Acquisition.SourceCommit != reproduction.QualifiedBinary.SourceRevision || reproduction.QualifiedBinary.Acquisition.SourceURL != wantSourceURL {
			return errors.New("reproduction source-build acquisition does not bind the qualified source revision")
		}
	case "immutable-ci-artifact":
		accessedAt, accessErr := parseRecordTime(reproduction.QualifiedBinary.Acquisition.AccessedAt)
		if reproduction.QualifiedBinary.Acquisition.SourceCommit != reproduction.QualifiedBinary.SourceRevision ||
			reproduction.QualifiedBinary.Acquisition.ArtifactSHA256 != reproduction.QualifiedBinary.BinarySHA256 ||
			!runURLMatches(reproduction.QualifiedBinary.Acquisition.WorkflowRunURL, projectRepository, reproduction.QualifiedBinary.Acquisition.WorkflowRunID) ||
			accessErr != nil || accessedAt.After(submittedAt) {
			return errors.New("reproduction CI-artifact acquisition does not bind the official run, source revision, access time, and qualified binary")
		}
	case "published-release-recheck":
		accessedAt, accessErr := parseRecordTime(reproduction.QualifiedBinary.Acquisition.AccessedAt)
		wantReleaseURL := "https://github.com/" + projectRepository + "/releases/tag/v" + reproduction.QualifiedBinary.Version
		if reproduction.QualifiedBinary.Acquisition.SourceCommit != reproduction.QualifiedBinary.SourceRevision ||
			reproduction.QualifiedBinary.Acquisition.AssetSHA256 != reproduction.QualifiedBinary.BinarySHA256 ||
			reproduction.QualifiedBinary.Acquisition.ReleaseURL != wantReleaseURL || accessErr != nil || accessedAt.After(submittedAt) {
			return errors.New("reproduction release acquisition does not bind the official release, source revision, access time, and qualified binary")
		}
	}
	if reproduction.CaseArchive.CaseManifestSHA256 != run.Collection.CaseManifestSHA256 {
		return errors.New("reproduction case-manifest SHA-256 differs from the verified run-record collection")
	}
	collectedAt, err := parseRecordTime(run.Collection.CollectedAt)
	if err != nil || submittedAt.Before(collectedAt) {
		return errors.New("reproduction submission precedes the supplied run-record collection")
	}
	if !equalCollectionIssues(reproduction.CoverageIssues, run.Collection.Issues) {
		return errors.New("reproduction coverage issues differ from the supplied run record")
	}
	wantCounts := deriveFindingCounts(run)
	if !equalFindingCounts(reproduction.FindingCounts, wantCounts) {
		return errors.New("reproduction finding counts differ from the supplied run record")
	}
	wantChecks := deriveScenarioChecks(run)
	if reproduction.ScenarioChecks != wantChecks {
		return errors.New("reproduction scenario checks differ from the supplied run record")
	}
	protocolFiles, err := loadArtifactBoundProtocolFiles(ctx, sourceRoot, schemaDir, artifact)
	if err != nil {
		return err
	}
	seed := protocolFiles["expected-findings.seed.json"]
	if err := validateRecordWithSchemas(ctx, protocolFiles, RecordExpectedSeed, seed); err != nil {
		return fmt.Errorf("validate expected-findings seed: %w", err)
	}
	seedDigest := sha256.Sum256(seed)
	if reproduction.OracleComparison.OracleSHA256 != hex.EncodeToString(seedDigest[:]) {
		return errors.New("reproduction oracle SHA-256 does not identify the exact expected-findings seed bytes")
	}
	wantDeviations := qualificationOracleDeviations(run, wantChecks, artifact.Model)
	wantOracleResult := "mismatch"
	wantClaimedResult := "does-not-match-qualified-oracle"
	if len(wantDeviations) == 0 {
		wantOracleResult = "match"
		wantClaimedResult = "matches-qualified-oracle"
	}
	if reproduction.OracleComparison.Result != wantOracleResult || reproduction.ClaimedResult != wantClaimedResult || !equalStrings(reproduction.OracleComparison.Deviations, wantDeviations) {
		return errors.New("reproduction oracle result, claimed result, or deterministic deviations differ from the supplied run record")
	}
	return nil
}

func deriveFindingCounts(run labRunRecord) map[string]int64 {
	counts := make(map[string]int64, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		counts[string(state)] = 0
	}
	for _, workflowRun := range run.WorkflowRuns {
		for _, attempt := range workflowRun.Attempts {
			for _, job := range attempt.Jobs {
				for _, finding := range job.Findings {
					counts[string(finding.State)]++
				}
			}
		}
	}
	return counts
}

func equalFindingCounts(got, want map[string]int64) bool {
	if len(got) != len(want) {
		return false
	}
	for state, count := range want {
		if got[state] != count {
			return false
		}
	}
	return true
}

func deriveScenarioChecks(record labRunRecord) labScenarioChecks {
	runs := make(map[string]labWorkflowRun, len(record.WorkflowRuns))
	for _, run := range record.WorkflowRuns {
		runs[run.ScenarioID] = run
	}
	repository := record.LabRepository.FullName
	markerA := record.FixtureObjects.MarkerA
	markerB := record.FixtureObjects.MarkerB
	direct := runs["PUBLIC-DIRECT"]
	composite := runs["PUBLIC-COMPOSITE"]
	reusable := runs["PUBLIC-REUSABLE"]
	skipped := runs["PUBLIC-SKIPPED"]
	matrix := runs["PUBLIC-MATRIX"]
	full := runs["PUBLIC-RERUN-FULL"]
	jobRerun := runs["PUBLIC-RERUN-JOB"]

	calledWorkflowSeparate := false
	for _, attempt := range reusable.Attempts {
		for _, job := range attempt.Jobs {
			for _, called := range job.CalledWorkflows {
				if called.Repository == repository && called.Commit != markerB && len(called.EvidenceIDs) > 0 {
					calledWorkflowSeparate = true
				}
			}
		}
	}

	fullDistinct := runHasCardinality(full, []int{2, 2}) && lineageMapsAllJobs(full.Attempts[0], full.Attempts[1]) &&
		countAttemptStartedSource(full.Attempts[0], repository, markerB) == 2 && countAttemptStartedSource(full.Attempts[0], repository, markerA) == 0 &&
		countAttemptStartedSource(full.Attempts[1], repository, markerA) == 2 && countAttemptStartedSource(full.Attempts[1], repository, markerB) == 0
	jobDistinct := runHasCardinality(jobRerun, []int{2, 1, 1}) &&
		countAttemptStartedSource(jobRerun.Attempts[0], repository, markerB) == 2 && countAttemptStartedSource(jobRerun.Attempts[0], repository, markerA) == 0 &&
		countAttemptStartedSource(jobRerun.Attempts[1], repository, markerA) == 1 && countAttemptStartedSource(jobRerun.Attempts[1], repository, markerB) == 0 &&
		countAttemptStartedSource(jobRerun.Attempts[2], repository, markerA) == 1 && countAttemptStartedSource(jobRerun.Attempts[2], repository, markerB) == 0
	if jobDistinct {
		jobDistinct = jobRerun.Attempts[1].Jobs[0].RerunOfJobID != nil && jobRerun.Attempts[2].Jobs[0].RerunOfJobID != nil &&
			*jobRerun.Attempts[2].Jobs[0].RerunOfJobID == jobRerun.Attempts[1].Jobs[0].JobID
	}

	return labScenarioChecks{
		DirectBExecuted:           countJobsWithFinding(direct, repository, model.ConfirmedExecuted, markerB) >= 1,
		CompositeBExecuted:        countJobsWithFinding(composite, repository, model.ConfirmedExecuted, markerB) >= 1,
		ReusableBExecuted:         countJobsWithFinding(reusable, repository, model.ConfirmedExecuted, markerB) >= 1,
		SkippedBNotExecuted:       countJobsWithFinding(skipped, repository, model.ConfirmedDownloaded, markerB) >= 1 && countJobsWithFinding(skipped, repository, model.ConfirmedExecuted, markerB) == 0 && !anyRunStartedSource(skipped, repository, markerB),
		MatrixJobsKeptDistinct:    runHasCardinality(matrix, []int{4}) && countJobsWithFinding(matrix, repository, model.ConfirmedExecuted, markerB) == 4,
		RerunAttemptsKeptDistinct: fullDistinct && jobDistinct,
		PresentTagDidNotRewriteHistory: record.MutableTag.After.Target == markerA &&
			countJobsWithFinding(full, repository, model.ConfirmedExecuted, markerB)+countJobsWithFinding(jobRerun, repository, model.ConfirmedExecuted, markerB) > 0 &&
			countJobsWithFinding(full, repository, model.NoMatchConfirmed, markerA)+countJobsWithFinding(jobRerun, repository, model.NoMatchConfirmed, markerA) > 0,
		CalledWorkflowIdentityKeptSeparate: calledWorkflowSeparate,
	}
}

func anyRunStartedSource(run labWorkflowRun, repository string, source recordGitObject) bool {
	for _, attempt := range run.Attempts {
		if attemptHasStartedSource(attempt, repository, source) {
			return true
		}
	}
	return false
}

func qualificationOracleDeviations(record labRunRecord, checks labScenarioChecks, manifest ObjectManifest) []string {
	deviations := qualificationCoverageDeviations(record)
	if err := validateQualifiedScenarioSet(record, manifest); err != nil {
		// Do not serialize validator diagnostics: they can contain hostile record
		// fields. This fixed deviation still prevents coarse counts/checks from
		// qualifying a substituted dependency topology.
		deviations = append(deviations, "qualified scenario set differs from reviewed artifact")
	}
	checkResults := []struct {
		name string
		ok   bool
	}{
		{"called_workflow_identity_kept_separate", checks.CalledWorkflowIdentityKeptSeparate},
		{"composite_b_executed", checks.CompositeBExecuted},
		{"direct_b_executed", checks.DirectBExecuted},
		{"matrix_jobs_kept_distinct", checks.MatrixJobsKeptDistinct},
		{"present_tag_did_not_rewrite_history", checks.PresentTagDidNotRewriteHistory},
		{"rerun_attempts_kept_distinct", checks.RerunAttemptsKeptDistinct},
		{"reusable_b_executed", checks.ReusableBExecuted},
		{"skipped_b_not_executed", checks.SkippedBNotExecuted},
	}
	for _, check := range checkResults {
		if !check.ok {
			deviations = append(deviations, "scenario check failed: "+check.name)
		}
	}
	sort.Strings(deviations)
	return deviations
}

func equalStrings(left, right []string) bool {
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

func equalCollectionIssues(got, want []recordStructuredIssue) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func validateReproductionSemantics(record labReproductionRecord) error {
	if record.LabBinding.RepositoryDatabaseID <= 0 {
		return errors.New("reproduction lab repository database ID must be positive")
	}
	if record.LabBinding.PublicURL != "https://github.com/"+record.LabBinding.Repository {
		return errors.New("reproduction lab repository URL does not bind the declared owner/name")
	}
	if record.LabBinding.MarkerA != record.LabBinding.FixtureAPeeledCommit || record.LabBinding.MarkerB != record.LabBinding.FixtureBPeeledCommit {
		return errors.New("reproduction fixture tag peel bindings differ from marker A/B")
	}
	if record.LabBinding.V1Before.Target != record.LabBinding.MarkerA || record.LabBinding.V1During.Target != record.LabBinding.MarkerB || record.LabBinding.V1After.Target != record.LabBinding.MarkerA {
		return errors.New("reproduction mutable tag binding is not A-to-B-to-A")
	}
	before, err := parseRecordTime(record.LabBinding.V1Before.Observation.ObservedAt)
	if err != nil {
		return err
	}
	during, err := parseRecordTime(record.LabBinding.V1During.Observation.ObservedAt)
	if err != nil {
		return err
	}
	after, err := parseRecordTime(record.LabBinding.V1After.Observation.ObservedAt)
	if err != nil || !before.Before(during) || !during.Before(after) {
		return errors.New("reproduction mutable tag observation order is invalid")
	}
	for _, observation := range []recordObservation{
		record.LabBinding.V1Before.Observation,
		record.LabBinding.V1During.Observation,
		record.LabBinding.V1After.Observation,
	} {
		if observation.EventSource != "git-ls-remote" {
			return errors.New("reproduction mutable v1 target must be observed by git-ls-remote")
		}
	}
	submittedAt, err := parseRecordTime(record.SubmittedAt)
	if err != nil || submittedAt.Before(after) {
		return errors.New("reproduction submission precedes its restored-A observation")
	}
	if !immutableBlobURL(record.RunRecord.PublicURL, record.LabBinding.Repository, "reproductions/"+record.RunRecord.RecordID+".json", "") {
		return errors.New("run-record URL is not an immutable declared-lab blob URL")
	}
	lastRunKey := ""
	seenScenarios := make(map[string][]int, len(record.PublicRuns))
	seenJobs := make(map[int64]struct{})
	for _, run := range record.PublicRuns {
		key := run.ScenarioID + "\x00" + fmt.Sprintf("%020d", run.RunID)
		if lastRunKey != "" && key <= lastRunKey || !runURLMatches(run.RunURL, record.LabBinding.Repository, run.RunID) {
			return errors.New("public runs must be strictly sorted by scenario and run ID and URL-bound")
		}
		lastRunKey = key
		if _, duplicate := seenScenarios[run.ScenarioID]; duplicate {
			return errors.New("public reproduction repeats a scenario")
		}
		cardinality := make([]int, 0, len(run.Attempts))
		for attemptIndex, attempt := range run.Attempts {
			if attempt.Number != int64(attemptIndex+1) || !sort.SliceIsSorted(attempt.JobIDs, func(i, j int) bool { return attempt.JobIDs[i] < attempt.JobIDs[j] }) {
				return errors.New("public run attempts must be contiguous from one and job IDs strictly sorted")
			}
			cardinality = append(cardinality, len(attempt.JobIDs))
			for index := 1; index < len(attempt.JobIDs); index++ {
				if attempt.JobIDs[index-1] == attempt.JobIDs[index] {
					return errors.New("duplicate public job ID within an attempt")
				}
			}
			for _, jobID := range attempt.JobIDs {
				if _, duplicate := seenJobs[jobID]; duplicate {
					return errors.New("public job ID is reused across material run-attempt identities")
				}
				seenJobs[jobID] = struct{}{}
			}
		}
		seenScenarios[run.ScenarioID] = cardinality
	}
	if record.ClaimedResult == "matches-qualified-oracle" {
		want := map[string][]int{
			"PUBLIC-COMPOSITE":  {1},
			"PUBLIC-DIRECT":     {1},
			"PUBLIC-MATRIX":     {4},
			"PUBLIC-RERUN-FULL": {2, 2},
			"PUBLIC-RERUN-JOB":  {2, 1, 1},
			"PUBLIC-REUSABLE":   {1},
			"PUBLIC-SKIPPED":    {1},
		}
		if len(seenScenarios) != len(want) {
			return errors.New("matching reproduction omits a qualified public scenario")
		}
		for scenario, wantCardinality := range want {
			if got, ok := seenScenarios[scenario]; !ok || !equalIntSlices(got, wantCardinality) {
				return fmt.Errorf("matching reproduction %s attempt/job topology differs from the qualified oracle", scenario)
			}
		}
	}
	return nil
}

func equalIntSlices(left, right []int) bool {
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

type labReproductionsIndex struct {
	Status  string `json:"status"`
	Records []struct {
		ReproductionID string          `json:"reproduction_id"`
		RecordCommit   recordGitObject `json:"record_commit"`
		RecordURL      string          `json:"record_url"`
	} `json:"records"`
}

func validateIndexSemantics(index labReproductionsIndex) error {
	if index.Status == "awaiting-independent-reproduction" && len(index.Records) != 0 {
		return errors.New("awaiting index cannot contain accepted records")
	}
	last := ""
	for _, record := range index.Records {
		if last != "" && record.ReproductionID <= last {
			return errors.New("accepted reproduction records must be strictly sorted by reproduction ID")
		}
		last = record.ReproductionID
		if !immutableBlobURL(record.RecordURL, RepositoryName, "reproductions/"+record.ReproductionID+".json", record.RecordCommit.ObjectID) {
			return errors.New("accepted reproduction URL is not bound to its record commit and ID")
		}
	}
	return nil
}

func bindRunRecordToManifest(record labRunRecord, artifact Artifact) error {
	return bindCoreToManifest(record.LabRepository, record.Protocol, record.FixtureObjects, artifact)
}

func bindCoreToManifest(repository labRepositoryBinding, protocol labProtocolBinding, fixtures labFixtureObjects, artifact Artifact) error {
	if err := verifyArtifactModel(artifact); err != nil {
		return err
	}
	manifest := artifact.Model
	if repository.FullName != manifest.Repository || repository.PublicURL != "https://github.com/"+manifest.Repository {
		return errors.New("record repository differs from the reviewed artifact repository")
	}
	if protocol.SourceCommit != gitObjectFor(manifest.Commits[5].ObjectID) || protocol.SourceManifestSHA256 != manifestSHA256(artifact.Manifest) {
		return errors.New("record does not bind the reviewed import commit and object-manifest hash")
	}
	tags := manifestTagsByName(manifest)
	if fixtures.MarkerA != gitObjectFor(manifest.Commits[1].ObjectID) || fixtures.MarkerB != gitObjectFor(manifest.Commits[2].ObjectID) ||
		fixtures.TagA.TagObject != gitObjectFor(tags["fixture-a"].ObjectID) || fixtures.TagA.PeeledCommit != gitObjectFor(tags["fixture-a"].PeeledCommitID) ||
		fixtures.TagB.TagObject != gitObjectFor(tags["fixture-b"].ObjectID) || fixtures.TagB.PeeledCommit != gitObjectFor(tags["fixture-b"].PeeledCommitID) {
		return errors.New("record A/B or annotated fixture-tag identities differ from the reviewed object manifest")
	}
	return nil
}

func bindReproductionToManifest(record labReproductionRecord, artifact Artifact) error {
	if err := verifyArtifactModel(artifact); err != nil {
		return err
	}
	manifest := artifact.Model
	tags := manifestTagsByName(manifest)
	if record.LabBinding.Repository != manifest.Repository || record.LabBinding.PublicURL != "https://github.com/"+manifest.Repository ||
		record.LabBinding.SourceCommit != gitObjectFor(manifest.Commits[5].ObjectID) || record.LabBinding.SourceManifestSHA256 != manifestSHA256(artifact.Manifest) ||
		record.LabBinding.MarkerA != gitObjectFor(manifest.Commits[1].ObjectID) || record.LabBinding.MarkerB != gitObjectFor(manifest.Commits[2].ObjectID) ||
		record.LabBinding.FixtureATagObject != gitObjectFor(tags["fixture-a"].ObjectID) || record.LabBinding.FixtureAPeeledCommit != gitObjectFor(tags["fixture-a"].PeeledCommitID) ||
		record.LabBinding.FixtureBTagObject != gitObjectFor(tags["fixture-b"].ObjectID) || record.LabBinding.FixtureBPeeledCommit != gitObjectFor(tags["fixture-b"].PeeledCommitID) {
		return errors.New("reproduction record does not bind the reviewed object manifest")
	}
	expectedSeedSHA256, ok := importFileSHA256(manifest, "protocol/expected-findings.seed.json")
	if !ok || record.OracleComparison.OracleSHA256 != expectedSeedSHA256 {
		return errors.New("reproduction oracle SHA-256 differs from the expected-findings seed in the reviewed object manifest")
	}
	return nil
}

func manifestTagsByName(manifest ObjectManifest) map[string]TagDescriptor {
	result := make(map[string]TagDescriptor, len(manifest.Tags))
	for _, tag := range manifest.Tags {
		result[tag.Name] = tag
	}
	return result
}

func gitObjectFor(value string) recordGitObject {
	return recordGitObject{Algorithm: "sha1", ObjectID: value}
}

func qualificationCoverageDeviations(record labRunRecord) []string {
	coverage := record.Collection.Coverage
	want := labCollectionCoverage{
		RepositoriesRequested:        1,
		RepositoriesAccessible:       1,
		RepositoriesDenied:           0,
		Runs:                         7,
		Attempts:                     10,
		Jobs:                         16,
		LogsRetrieved:                16,
		LogsMissing:                  0,
		WorkflowDefinitionsRetrieved: 7,
		ActionDefinitionsRetrieved:   2,
		OptionalCapabilitiesDenied:   0,
		TruncatedEvidenceObjects:     0,
	}
	fields := []struct {
		name      string
		got, want int64
	}{
		{"action_definitions_retrieved", coverage.ActionDefinitionsRetrieved, want.ActionDefinitionsRetrieved},
		{"attempts_enumerated", coverage.Attempts, want.Attempts},
		{"jobs_enumerated", coverage.Jobs, want.Jobs},
		{"logs_missing", coverage.LogsMissing, want.LogsMissing},
		{"logs_retrieved", coverage.LogsRetrieved, want.LogsRetrieved},
		{"optional_capabilities_denied", coverage.OptionalCapabilitiesDenied, want.OptionalCapabilitiesDenied},
		{"repositories_accessible", coverage.RepositoriesAccessible, want.RepositoriesAccessible},
		{"repositories_denied", coverage.RepositoriesDenied, want.RepositoriesDenied},
		{"repositories_requested", coverage.RepositoriesRequested, want.RepositoriesRequested},
		{"runs_enumerated", coverage.Runs, want.Runs},
		{"truncated_evidence_objects", coverage.TruncatedEvidenceObjects, want.TruncatedEvidenceObjects},
		{"workflow_definitions_retrieved", coverage.WorkflowDefinitionsRetrieved, want.WorkflowDefinitionsRetrieved},
	}
	deviations := make([]string, 0, len(fields)+len(record.Collection.Issues))
	for _, field := range fields {
		if field.got != field.want {
			deviations = append(deviations, fmt.Sprintf("coverage %s expected %d observed %d", field.name, field.want, field.got))
		}
	}
	for _, issue := range record.Collection.Issues {
		deviations = append(deviations, "collection issue blocks qualification: "+issue.Code+" at "+issue.Scope)
	}
	sort.Strings(deviations)
	return deviations
}

func validateQualifiedScenarioSet(record labRunRecord, manifest ObjectManifest) error {
	if deviations := qualificationCoverageDeviations(record); len(deviations) != 0 {
		return fmt.Errorf("qualified run record has incomplete or inconsistent collection coverage: %s", strings.Join(deviations, "; "))
	}
	wantPaths := map[string]string{
		"PUBLIC-COMPOSITE":  ".github/workflows/composite.yml",
		"PUBLIC-DIRECT":     ".github/workflows/direct.yml",
		"PUBLIC-MATRIX":     ".github/workflows/matrix.yml",
		"PUBLIC-RERUN-FULL": ".github/workflows/rerun.yml",
		"PUBLIC-RERUN-JOB":  ".github/workflows/rerun.yml",
		"PUBLIC-REUSABLE":   ".github/workflows/reusable-caller.yml",
		"PUBLIC-SKIPPED":    ".github/workflows/skipped.yml",
	}
	if len(record.WorkflowRuns) != len(wantPaths) {
		return errors.New("qualified run record must contain exactly all seven public scenarios")
	}
	runs := make(map[string]labWorkflowRun, len(record.WorkflowRuns))
	for _, run := range record.WorkflowRuns {
		wantPath, ok := wantPaths[run.ScenarioID]
		if !ok || run.WorkflowPath != wantPath {
			return errors.New("qualified run record has an unknown scenario or wrong workflow path")
		}
		if _, duplicate := runs[run.ScenarioID]; duplicate {
			return errors.New("qualified run record repeats a scenario")
		}
		runs[run.ScenarioID] = run
	}
	markerA := gitObjectFor(manifest.Commits[1].ObjectID)
	markerB := gitObjectFor(manifest.Commits[2].ObjectID)
	wrapper := gitObjectFor(manifest.Commits[3].ObjectID)
	reusable := gitObjectFor(manifest.Commits[4].ObjectID)
	workflow := gitObjectFor(manifest.Commits[5].ObjectID)
	wantCardinalities := map[string][]int{
		"PUBLIC-COMPOSITE":  {1},
		"PUBLIC-DIRECT":     {1},
		"PUBLIC-MATRIX":     {4},
		"PUBLIC-RERUN-FULL": {2, 2},
		"PUBLIC-RERUN-JOB":  {2, 1, 1},
		"PUBLIC-REUSABLE":   {1},
		"PUBLIC-SKIPPED":    {1},
	}
	for scenario, want := range wantCardinalities {
		if !runHasCardinality(runs[scenario], want) {
			return fmt.Errorf("%s attempt/job topology differs from the qualified protocol", scenario)
		}
	}
	wantFindingCounts := make(map[string]int64, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		wantFindingCounts[string(state)] = 0
	}
	wantFindingCounts[string(model.ConfirmedExecuted)] = 11
	wantFindingCounts[string(model.ConfirmedDownloaded)] = 1
	wantFindingCounts[string(model.NoMatchConfirmed)] = 4
	if !equalFindingCounts(deriveFindingCounts(record), wantFindingCounts) {
		return errors.New("qualified run record finding-state totals differ from the exact reviewed oracle")
	}
	if err := validateQualifiedObservationSets(runs, manifest.Repository, markerA, markerB, wrapper, reusable); err != nil {
		return err
	}
	_, tagDuring, tagAfter, err := validateCoreRecordSemantics(record.LabRepository, record.FixtureObjects, record.MutableTag)
	if err != nil {
		return err
	}
	for _, run := range runs {
		eventAt, err := parseRecordTime(run.EventTime.ObservedAt)
		if err != nil || eventAt.Before(tagDuring) || !eventAt.Before(tagAfter) {
			return errors.New("qualified original workflow event does not fall within the observed B interval")
		}
	}
	for _, scenario := range []string{"PUBLIC-DIRECT", "PUBLIC-COMPOSITE", "PUBLIC-REUSABLE"} {
		if countJobsWithFinding(runs[scenario], manifest.Repository, model.ConfirmedExecuted, markerB) != 1 {
			return fmt.Errorf("%s lacks exactly one exact-B CONFIRMED_EXECUTED job", scenario)
		}
		if countAttemptStartedSource(runs[scenario].Attempts[0], manifest.Repository, markerA) != 0 {
			return fmt.Errorf("%s contains an unexpected marker-A execution observation during the B interval", scenario)
		}
	}
	matrix := runs["PUBLIC-MATRIX"]
	if countJobsWithFinding(matrix, manifest.Repository, model.ConfirmedExecuted, markerB) != 4 || countAttemptStartedSource(matrix.Attempts[0], manifest.Repository, markerA) != 0 {
		return errors.New("PUBLIC-MATRIX does not retain four distinct exact-B job executions")
	}
	skipped := runs["PUBLIC-SKIPPED"]
	if countJobsWithFinding(skipped, manifest.Repository, model.ConfirmedDownloaded, markerB) != 1 || countJobsWithFinding(skipped, manifest.Repository, model.ConfirmedExecuted, markerB) != 0 {
		return errors.New("PUBLIC-SKIPPED does not preserve exact-B download without execution")
	}
	if countAttemptStartedSource(skipped.Attempts[0], manifest.Repository, markerB) != 0 || countAttemptStartedSource(skipped.Attempts[0], manifest.Repository, markerA) != 0 {
		return errors.New("PUBLIC-SKIPPED contains a marker lifecycle start despite its downloaded-only oracle")
	}
	if !hasCalledWorkflow(runs["PUBLIC-REUSABLE"], manifest.Repository, gitObjectFor(manifest.Commits[4].ObjectID)) {
		return errors.New("PUBLIC-REUSABLE lacks the exact called-workflow identity")
	}
	full := runs["PUBLIC-RERUN-FULL"]
	if countAttemptStartedSource(full.Attempts[0], manifest.Repository, markerB) != 2 || countAttemptStartedSource(full.Attempts[0], manifest.Repository, markerA) != 0 ||
		countAttemptStartedSource(full.Attempts[1], manifest.Repository, markerA) != 2 || countAttemptStartedSource(full.Attempts[1], manifest.Repository, markerB) != 0 {
		return errors.New("PUBLIC-RERUN-FULL does not retain two exact-B originals and two separate restored-A jobs")
	}
	if countJobsWithFinding(full, manifest.Repository, model.ConfirmedExecuted, markerB) != 2 || countJobsWithFinding(full, manifest.Repository, model.NoMatchConfirmed, markerA) != 2 {
		return errors.New("PUBLIC-RERUN-FULL findings do not distinguish the two exact-B originals from two covered restored-A jobs")
	}
	if !lineageMapsAllJobs(full.Attempts[0], full.Attempts[1]) {
		return errors.New("PUBLIC-RERUN-FULL rerun jobs do not bind one-to-one to original jobs")
	}
	jobRerun := runs["PUBLIC-RERUN-JOB"]
	if countAttemptStartedSource(jobRerun.Attempts[0], manifest.Repository, markerB) != 2 || countAttemptStartedSource(jobRerun.Attempts[0], manifest.Repository, markerA) != 0 ||
		countAttemptStartedSource(jobRerun.Attempts[1], manifest.Repository, markerA) != 1 || countAttemptStartedSource(jobRerun.Attempts[1], manifest.Repository, markerB) != 0 ||
		countAttemptStartedSource(jobRerun.Attempts[2], manifest.Repository, markerA) != 1 || countAttemptStartedSource(jobRerun.Attempts[2], manifest.Repository, markerB) != 0 {
		return errors.New("PUBLIC-RERUN-JOB does not retain exact original, failed-job, and single-job attempts")
	}
	if countJobsWithFinding(jobRerun, manifest.Repository, model.ConfirmedExecuted, markerB) != 2 || countJobsWithFinding(jobRerun, manifest.Repository, model.NoMatchConfirmed, markerA) != 2 {
		return errors.New("PUBLIC-RERUN-JOB findings do not distinguish exact-B originals from covered restored-A reruns")
	}
	failureJobID, ok := uniqueJobWithConclusion(jobRerun.Attempts[0], "failure")
	if !ok || countJobsWithConclusion(jobRerun.Attempts[0], "success") != 1 || jobRerun.Attempts[1].Jobs[0].RerunOfJobID == nil || *jobRerun.Attempts[1].Jobs[0].RerunOfJobID != failureJobID {
		return errors.New("PUBLIC-RERUN-JOB failed-jobs attempt does not bind only the original failed job")
	}
	wantReruns := []struct {
		kind     string
		scenario string
	}{
		{"full-workflow", "PUBLIC-RERUN-FULL"},
		{"failed-jobs", "PUBLIC-RERUN-JOB"},
		{"single-job", "PUBLIC-RERUN-JOB"},
	}
	if len(record.RerunRequests) != len(wantReruns) {
		return errors.New("qualified run record must retain full, failed-jobs, and single-job rerun requests")
	}
	for index, want := range wantReruns {
		request := record.RerunRequests[index]
		if request.Kind != want.kind || request.OriginalRunID != runs[want.scenario].RunID ||
			want.kind != "single-job" && request.JobID != nil || want.kind == "single-job" && request.JobID == nil {
			return errors.New("rerun request sequence or run binding differs from the qualified protocol")
		}
	}
	singleRequest := record.RerunRequests[2]
	selectedJob := jobRerun.Attempts[1].Jobs[0].JobID
	if *singleRequest.JobID != selectedJob || jobRerun.Attempts[2].Jobs[0].RerunOfJobID == nil || *jobRerun.Attempts[2].Jobs[0].RerunOfJobID != selectedJob {
		return errors.New("PUBLIC-RERUN-JOB single-job request and result do not bind the exact selected prior-attempt job")
	}

	directShape := func(path string, source recordGitObject) []labDependencyLink {
		return []labDependencyLink{{
			Relationship: "WORKFLOW_DECLARED_ACTION",
			From:         dependencyEndpoint("WORKFLOW_DEFINITION", manifest.Repository, path, workflow),
			To:           dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/marker/action.yml", source),
		}}
	}
	for _, pair := range []struct {
		run    labWorkflowRun
		source recordGitObject
	}{
		{runs["PUBLIC-DIRECT"], markerB},
		{runs["PUBLIC-MATRIX"], markerB},
		{runs["PUBLIC-SKIPPED"], markerB},
	} {
		for _, job := range pair.run.Attempts[0].Jobs {
			if !dependencyChainMatches(job.DependencyChain, directShape(pair.run.WorkflowPath, pair.source)) {
				return fmt.Errorf("%s job lacks its exact direct historical dependency chain", pair.run.ScenarioID)
			}
		}
	}
	for attemptIndex, attempt := range full.Attempts {
		source := markerB
		if attemptIndex > 0 {
			source = markerA
		}
		for _, job := range attempt.Jobs {
			if !dependencyChainMatches(job.DependencyChain, directShape(full.WorkflowPath, source)) {
				return errors.New("PUBLIC-RERUN-FULL job lacks its attempt-specific historical dependency chain")
			}
		}
	}
	for attemptIndex, attempt := range jobRerun.Attempts {
		source := markerB
		if attemptIndex > 0 {
			source = markerA
		}
		for _, job := range attempt.Jobs {
			if !dependencyChainMatches(job.DependencyChain, directShape(jobRerun.WorkflowPath, source)) {
				return errors.New("PUBLIC-RERUN-JOB job lacks its attempt-specific historical dependency chain")
			}
		}
	}
	compositeChain := []labDependencyLink{
		{Relationship: "WORKFLOW_DECLARED_ACTION", From: dependencyEndpoint("WORKFLOW_DEFINITION", manifest.Repository, runs["PUBLIC-COMPOSITE"].WorkflowPath, workflow), To: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/wrapper/action.yml", wrapper)},
		{Relationship: "ACTION_CONTAINS_ACTION", From: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/wrapper/action.yml", wrapper), To: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/marker/action.yml", markerB)},
	}
	if !dependencyChainMatches(runs["PUBLIC-COMPOSITE"].Attempts[0].Jobs[0].DependencyChain, compositeChain) {
		return errors.New("PUBLIC-COMPOSITE lacks exact wrapper-to-marker transitive dependency evidence")
	}
	reusableChain := []labDependencyLink{
		{Relationship: "WORKFLOW_CALLED_WORKFLOW", From: dependencyEndpoint("WORKFLOW_DEFINITION", manifest.Repository, runs["PUBLIC-REUSABLE"].WorkflowPath, workflow), To: dependencyEndpoint("REUSABLE_WORKFLOW_DEFINITION", manifest.Repository, ".github/workflows/reusable.yml", reusable)},
		{Relationship: "WORKFLOW_DECLARED_ACTION", From: dependencyEndpoint("REUSABLE_WORKFLOW_DEFINITION", manifest.Repository, ".github/workflows/reusable.yml", reusable), To: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/wrapper/action.yml", wrapper)},
		{Relationship: "ACTION_CONTAINS_ACTION", From: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/wrapper/action.yml", wrapper), To: dependencyEndpoint("ACTION_DEFINITION", manifest.Repository, "actions/marker/action.yml", markerB)},
	}
	if !dependencyChainMatches(runs["PUBLIC-REUSABLE"].Attempts[0].Jobs[0].DependencyChain, reusableChain) {
		return errors.New("PUBLIC-REUSABLE lacks exact called-workflow and wrapper transitive dependency evidence")
	}
	return nil
}

type expectedActionObservation struct {
	Repository  string
	Path        string
	DeclaredRef string
	Source      recordGitObject
	Lifecycle   model.RuntimeObservationKind
	Step        string
}

func validateQualifiedObservationSets(runs map[string]labWorkflowRun, repository string, markerA, markerB, wrapper, reusable recordGitObject) error {
	marker := func(source recordGitObject, lifecycle model.RuntimeObservationKind) expectedActionObservation {
		return expectedActionObservation{Repository: repository, Path: "actions/marker/action.yml", DeclaredRef: "v1", Source: source, Lifecycle: lifecycle, Step: "step:marker"}
	}
	wrapperObservation := expectedActionObservation{Repository: repository, Path: "actions/wrapper/action.yml", DeclaredRef: wrapper.ObjectID, Source: wrapper, Lifecycle: model.ObservationLifecycleStarted, Step: "step:wrapper"}

	for scenario, run := range runs {
		for attemptIndex, attempt := range run.Attempts {
			for _, job := range attempt.Jobs {
				source := markerB
				if (scenario == "PUBLIC-RERUN-FULL" || scenario == "PUBLIC-RERUN-JOB") && attemptIndex > 0 {
					source = markerA
				}
				wantActions := []expectedActionObservation{marker(source, model.ObservationLifecycleStarted)}
				switch scenario {
				case "PUBLIC-COMPOSITE", "PUBLIC-REUSABLE":
					wantActions = append(wantActions, wrapperObservation)
				case "PUBLIC-SKIPPED":
					wantActions = []expectedActionObservation{
						marker(markerB, model.ObservationPreparationComplete),
						marker(markerB, model.ObservationConditionSkipped),
					}
				}
				if !actionObservationSetMatches(job.ActionObservations, wantActions) {
					return fmt.Errorf("%s attempt %d job %d Action observations differ from the exact qualified set", scenario, attempt.Number, job.JobID)
				}
				if scenario == "PUBLIC-REUSABLE" {
					if len(job.CalledWorkflows) != 1 || job.CalledWorkflows[0].Repository != repository || job.CalledWorkflows[0].WorkflowPath != ".github/workflows/reusable.yml" || job.CalledWorkflows[0].Commit != reusable || len(job.CalledWorkflows[0].EvidenceIDs) == 0 {
						return errors.New("PUBLIC-REUSABLE called-workflow observations differ from the exact qualified set")
					}
				} else if len(job.CalledWorkflows) != 0 {
					return fmt.Errorf("%s contains an unexpected called-workflow observation", scenario)
				}
			}
		}
	}
	return nil
}

func actionObservationSetMatches(got []labActionObservation, want []expectedActionObservation) bool {
	if len(got) != len(want) {
		return false
	}
	remaining := append([]expectedActionObservation(nil), want...)
	for _, observation := range got {
		match := -1
		for index, expected := range remaining {
			if observation.Repository == expected.Repository && observation.Path == expected.Path && observation.DeclaredRef == expected.DeclaredRef && observation.SourceCommit == expected.Source && observation.Lifecycle == expected.Lifecycle && observation.Step == expected.Step && len(observation.EvidenceIDs) > 0 {
				match = index
				break
			}
		}
		if match < 0 {
			return false
		}
		remaining = append(remaining[:match], remaining[match+1:]...)
	}
	return len(remaining) == 0
}

func runHasCardinality(run labWorkflowRun, want []int) bool {
	if len(run.Attempts) != len(want) {
		return false
	}
	for index, count := range want {
		if len(run.Attempts[index].Jobs) != count {
			return false
		}
	}
	return true
}

func countAttemptStartedSource(attempt labRunAttempt, repository string, source recordGitObject) int {
	count := 0
	for _, job := range attempt.Jobs {
		if attemptHasStartedSource(labRunAttempt{Jobs: []labJob{job}}, repository, source) {
			count++
		}
	}
	return count
}

func lineageMapsAllJobs(prior, next labRunAttempt) bool {
	if len(prior.Jobs) != len(next.Jobs) {
		return false
	}
	want := make(map[int64]struct{}, len(prior.Jobs))
	for _, job := range prior.Jobs {
		want[job.JobID] = struct{}{}
	}
	for _, job := range next.Jobs {
		if job.RerunOfJobID == nil {
			return false
		}
		if _, ok := want[*job.RerunOfJobID]; !ok {
			return false
		}
		delete(want, *job.RerunOfJobID)
	}
	return len(want) == 0
}

func uniqueJobWithConclusion(attempt labRunAttempt, conclusion string) (int64, bool) {
	var result int64
	count := 0
	for _, job := range attempt.Jobs {
		if job.Conclusion == conclusion {
			result = job.JobID
			count++
		}
	}
	return result, count == 1
}

func countJobsWithConclusion(attempt labRunAttempt, conclusion string) int {
	count := 0
	for _, job := range attempt.Jobs {
		if job.Conclusion == conclusion {
			count++
		}
	}
	return count
}

func dependencyEndpoint(kind, repository, path string, commit recordGitObject) labDependencyEndpoint {
	return labDependencyEndpoint{Kind: kind, Repository: repository, Path: path, Commit: commit}
}

func dependencyChainMatches(got, want []labDependencyLink) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index].Relationship != want[index].Relationship || got[index].From != want[index].From || got[index].To != want[index].To || len(got[index].EvidenceIDs) == 0 {
			return false
		}
	}
	return true
}

func countJobsWithFinding(run labWorkflowRun, repository string, state model.FindingState, source recordGitObject) int {
	count := 0
	for _, attempt := range run.Attempts {
		for _, job := range attempt.Jobs {
			matched := false
			for _, finding := range job.Findings {
				if finding.IndicatorID != syntheticMarkerBIndicatorID || finding.State != state || finding.Step == nil {
					continue
				}
				for _, observation := range job.ActionObservations {
					if observation.Repository == repository && observation.SourceCommit == source && observation.Step == *finding.Step && hasStringIntersection(observation.EvidenceIDs, finding.EvidenceIDs) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
				count++
			}
		}
	}
	return count
}

func hasCalledWorkflow(run labWorkflowRun, repository string, commit recordGitObject) bool {
	for _, attempt := range run.Attempts {
		for _, job := range attempt.Jobs {
			for _, called := range job.CalledWorkflows {
				if called.Repository == repository && called.WorkflowPath == ".github/workflows/reusable.yml" && called.Commit == commit && len(called.EvidenceIDs) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func attemptHasStartedSource(attempt labRunAttempt, repository string, source recordGitObject) bool {
	for _, job := range attempt.Jobs {
		for _, observation := range job.ActionObservations {
			if observation.Repository == repository && observation.SourceCommit == source && observation.Lifecycle.SupportsExecuted() {
				return true
			}
		}
	}
	return false
}

func parseRecordTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value == "" || !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("record time is not a canonical UTC timestamp")
	}
	return parsed, nil
}

func runURLMatches(value, repository string, runID int64) bool {
	return value == "https://github.com/"+repository+"/actions/runs/"+strconv.FormatInt(runID, 10)
}

func immutableBlobURL(value, repository, expectedPath, expectedCommit string) bool {
	prefix := "https://github.com/" + repository + "/blob/"
	if !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, "?#") {
		return false
	}
	remainder := strings.TrimPrefix(value, prefix)
	parts := strings.Split(remainder, "/")
	if len(parts) < 2 || !isSHA1(parts[0]) || expectedCommit != "" && parts[0] != expectedCommit {
		return false
	}
	return strings.Join(parts[1:], "/") == expectedPath
}

var forbiddenRecordText = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])gh[pousrc]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`(?:^|[^A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`(?:^|[^A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?:[^A-Za-z0-9_-]|$)`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])sk_live_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])npm_[A-Za-z0-9]{36}(?:[^A-Za-z0-9]|$)`),
	regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:[^A-Za-z0-9_-]|$)`),
	regexp.MustCompile(`(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:[^A-Z0-9]|$)`),
	regexp.MustCompile(`(?i)(?:authorization|proxy-authorization)[[:space:]]*:[[:space:]]*(?:bearer|basic)[[:space:]]+\S+`),
	regexp.MustCompile(`(?i)(?:^|[[:space:]])(?:set-cookie|cookie)[[:space:]]*:[^\r\n]+`),
	regexp.MustCompile(`(?i)x-amz-(?:signature|credential)[[:space:]=:]+[A-Za-z0-9%/_+-]+`),
	regexp.MustCompile(`(?i)x-goog-(?:signature|credential)[[:space:]=:]+[A-Za-z0-9%/_+-]+`),
	regexp.MustCompile(`(?i)(?:^|[?&[:space:]])sig=[A-Za-z0-9%/_+.-]{16,}(?:[&[:space:]]|$)`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])/(?:home|users|root)/[A-Za-z0-9._-]+(?:/[^\s<>]*)?`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])/(?:tmp|private/var|var/folders)/(?:[^\s<>]+)`),
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])[A-Z]:\\Users\\[^\s<>]+`),
	regexp.MustCompile(`(?:^|[^\\])\\\\[^\\\s<>]+\\[^\s<>]+`),
}

func scanPublicRecordStrings(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if err := scanPublicRecordStrings(key); err != nil {
				return err
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := scanPublicRecordStrings(typed[key]); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := scanPublicRecordStrings(item); err != nil {
				return err
			}
		}
	case string:
		for _, pattern := range forbiddenRecordText {
			if pattern.FindStringIndex(typed) != nil {
				return errors.New("public-lab record contains credential-like material or an exact private local path")
			}
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := consumeJSONToken(decoder, first, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON has trailing data")
		}
		return err
	}
	return nil
}

func consumeJSONToken(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting exceeds the accepted depth")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSONToken(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSONToken(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func manifestSHA256(manifest []byte) string {
	digest := sha256.Sum256(manifest)
	return hex.EncodeToString(digest[:])
}
