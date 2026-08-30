package casefile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/ledger"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

const (
	metadataV1Schema       = "cirewind.collection-metadata/v1alpha1"
	metadataV2Schema       = "cirewind.collection-metadata/v1alpha2"
	maxManifestBytes       = int64(16 << 20)
	maxMetadataBytes       = int64(4 << 20)
	maxLedgerBytes         = int64(8 << 30)
	maxLedgerLineBytes     = 16 << 20
	maxRawObjectBytes      = uint64(2 << 30)
	maxRawMaterializedByte = uint64(10 << 30)
	maxRawObjectCount      = 100_000
	maxJSONDepth           = 64

	// LegacyExtraStatus deliberately avoids implying that an unknown legacy
	// extra satisfies any v0.2 content-security or semantic contract.
	LegacyExtraStatus = "integrity-checked unknown legacy extra; not parsed or v2 safety-validated"
)

// VerifiedExtra reports a safe, manifested regular file accepted solely for
// v0.1 verification compatibility.
type VerifiedExtra struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

// VerificationResult identifies the manifest-selected case contract and any
// non-consumed legacy extras. A nil error means integrity verification passed;
// it is not an authenticity or factual-correctness assertion.
type VerificationResult struct {
	Contract     CaseContract    `json:"contract"`
	LegacyExtras []VerifiedExtra `json:"legacyExtras"`
}

// VerifyCase verifies every manifested byte before collection metadata is
// parsed. Metadata then selects either the compatible v0.1 contract or the
// strict v0.2 contract; engine-version strings never select a contract.
func VerifyCase(ctx context.Context, dir string) (VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return VerificationResult{}, err
	}
	expected, err := verifyManifestIntegrity(ctx, dir)
	if err != nil {
		return VerificationResult{}, err
	}
	for _, name := range requiredFiles {
		if _, present := expected[name]; !present {
			return VerificationResult{}, fmt.Errorf("manifest omits required case file %s", name)
		}
	}

	metadataBytes, err := readBoundedRegular(filepath.Join(dir, "collection-metadata.json"), maxMetadataBytes)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("read verified collection metadata: %w", err)
	}
	metadataDigest := sha256Hex(metadataBytes)
	if metadataDigest != expected["collection-metadata.json"] {
		return VerificationResult{}, errors.New("collection metadata changed after manifest verification")
	}
	if err := rejectDuplicateJSONKeys(metadataBytes, maxJSONDepth); err != nil {
		return VerificationResult{}, fmt.Errorf("collection metadata: %w", err)
	}
	var selector struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(metadataBytes, &selector); err != nil {
		return VerificationResult{}, fmt.Errorf("decode collection metadata selector: %w", err)
	}
	switch selector.SchemaVersion {
	case metadataV1Schema:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(metadataBytes, &fields); err != nil {
			return VerificationResult{}, fmt.Errorf("decode legacy collection metadata: %w", err)
		}
		if _, hasContract := fields["caseContractVersion"]; hasContract {
			return VerificationResult{}, errors.New("legacy collection metadata must not declare a case contract")
		}
		return verifyLegacyContract(expected), nil
	case metadataV2Schema:
		return verifyV2Contract(ctx, dir, expected, metadataBytes)
	default:
		return VerificationResult{}, fmt.Errorf("unsupported collection metadata schema %q", selector.SchemaVersion)
	}
}

func verifyLegacyContract(files map[string]string) VerificationResult {
	base := stringSet(requiredFiles)
	var paths []string
	for name := range files {
		if _, known := base[name]; !known {
			paths = append(paths, name)
		}
	}
	sort.Strings(paths)
	result := VerificationResult{Contract: ContractV1Alpha1, LegacyExtras: []VerifiedExtra{}}
	for _, name := range paths {
		result.LegacyExtras = append(result.LegacyExtras, VerifiedExtra{Path: name, Status: LegacyExtraStatus})
	}
	return result
}

type strictMetadataV2 struct {
	SchemaVersion       string            `json:"schemaVersion"`
	CaseContractVersion string            `json:"caseContractVersion"`
	CaseKind            string            `json:"caseKind"`
	RawMaterialized     *bool             `json:"rawMaterialized"`
	CaseID              string            `json:"caseId"`
	Mode                string            `json:"mode"`
	IncidentID          string            `json:"incidentId"`
	IncidentPackVersion string            `json:"incidentPackVersion"`
	CanonicalPackSHA256 string            `json:"canonicalPackSha256"`
	SourcePackSHA256    string            `json:"sourcePackSha256"`
	EngineVersion       string            `json:"engineVersion"`
	AnalysisTime        string            `json:"analysisTime"`
	GitHubAPIVersion    string            `json:"githubApiVersion,omitempty"`
	RawLogsRetained     *bool             `json:"rawLogsRetained"`
	WatchHorizonDays    int               `json:"watchHorizonDays,omitempty"`
	Coverage            *strictCoverageV2 `json:"coverage"`
	LimitPolicy         string            `json:"limitPolicy"`
	Warnings            []string          `json:"warnings,omitempty"`
}

type strictCoverageV2 struct {
	Partial                      *bool    `json:"partial"`
	RepositoriesRequested        *int     `json:"repositoriesRequested"`
	RepositoriesAccessible       *int     `json:"repositoriesAccessible"`
	RepositoriesDenied           *int     `json:"repositoriesDenied"`
	RunsEnumerated               *int     `json:"runsEnumerated"`
	AttemptsEnumerated           *int     `json:"attemptsEnumerated"`
	JobsEnumerated               *int     `json:"jobsEnumerated"`
	LogsRetrieved                *int     `json:"logsRetrieved"`
	LogsMissing                  *int     `json:"logsMissing"`
	WorkflowDefinitionsRetrieved *int     `json:"workflowDefinitionsRetrieved"`
	ActionDefinitionsRetrieved   *int     `json:"actionDefinitionsRetrieved"`
	OptionalCapabilitiesDenied   []string `json:"optionalCapabilitiesDenied,omitempty"`
	IncompleteEvidence           []string `json:"incompleteEvidence,omitempty"`
}

func verifyV2Contract(ctx context.Context, dir string, files map[string]string, raw []byte) (VerificationResult, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var metadata strictMetadataV2
	if err := decoder.Decode(&metadata); err != nil {
		return VerificationResult{}, fmt.Errorf("strict v0.2 collection metadata: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return VerificationResult{}, fmt.Errorf("strict v0.2 collection metadata: %w", err)
	}
	if err := rejectV2OptionalNulls(raw); err != nil {
		return VerificationResult{}, err
	}
	if metadata.SchemaVersion != metadataV2Schema || metadata.CaseContractVersion != string(ContractV1Alpha2) {
		return VerificationResult{}, errors.New("collection metadata schema and case contract do not form the v0.2 pair")
	}
	switch metadata.CaseKind {
	case "synthetic", "collected", "mixed", "unknown":
	default:
		return VerificationResult{}, fmt.Errorf("collection metadata has invalid caseKind %q", metadata.CaseKind)
	}
	if metadata.RawMaterialized == nil {
		return VerificationResult{}, errors.New("collection metadata omits required rawMaterialized")
	}
	if err := validateV2RequiredMetadata(metadata); err != nil {
		return VerificationResult{}, err
	}
	for _, name := range requiredFilesV2 {
		if _, present := files[name]; !present {
			return VerificationResult{}, fmt.Errorf("manifest omits required v0.2 case file %s", name)
		}
	}

	database, err := store.OpenReadOnly(ctx, filepath.Join(dir, "case.db"))
	if err != nil {
		return VerificationResult{}, fmt.Errorf("validate v0.2 case database: %w", err)
	}
	queryErr := verifyV2DatabaseContract(ctx, database, metadata)
	closeErr := database.Close()
	if queryErr != nil {
		return VerificationResult{}, fmt.Errorf("validate v0.2 case database contract: %w", errors.Join(queryErr, closeErr))
	}
	if closeErr != nil {
		return VerificationResult{}, fmt.Errorf("close verified case database: %w", closeErr)
	}
	databaseDigest, err := hashFile(ctx, filepath.Join(dir, "case.db"))
	if err != nil {
		return VerificationResult{}, err
	}
	if databaseDigest != files["case.db"] {
		return VerificationResult{}, errors.New("case database changed during contract verification")
	}
	if err := verifyV2Files(ctx, dir, files, *metadata.RawMaterialized); err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{Contract: ContractV1Alpha2, LegacyExtras: []VerifiedExtra{}}, nil
}

func verifyV2DatabaseContract(ctx context.Context, database *store.Store, metadata strictMetadataV2) error {
	kind, err := database.Kind(ctx)
	if err != nil {
		return err
	}
	if kind != store.KindCase {
		return fmt.Errorf("database store kind is %q, want %q", kind, store.KindCase)
	}
	db := database.DB()
	for _, field := range []struct {
		key  string
		want string
	}{
		{key: "case_id", want: metadata.CaseID},
		{key: "engine_version", want: metadata.EngineVersion},
		{key: "analysis_time", want: metadata.AnalysisTime},
		{key: "case_raw_materialized", want: strconv.FormatBool(*metadata.RawMaterialized)},
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key=?`, field.key).Scan(&got); err != nil {
			return fmt.Errorf("read database metadata %s: %w", field.key, err)
		}
		if got != field.want {
			return fmt.Errorf("collection metadata %s disagrees with case database", field.key)
		}
	}

	var analysisCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM analysis_sessions`).Scan(&analysisCount); err != nil {
		return fmt.Errorf("count case analyses: %w", err)
	}
	if analysisCount != 1 {
		return fmt.Errorf("case database contains %d analysis sessions, want 1", analysisCount)
	}
	var mode, engineVersion, canonicalPack, sourcePack, analyzedAt string
	if err := db.QueryRowContext(ctx, `
		SELECT mode,engine_version,canonical_pack_sha256,source_pack_sha256,analyzed_at
		FROM analysis_sessions WHERE analysis_id=?`, "analysis:"+metadata.CaseID).
		Scan(&mode, &engineVersion, &canonicalPack, &sourcePack, &analyzedAt); err != nil {
		return fmt.Errorf("read case analysis provenance: %w", err)
	}
	if mode != metadata.Mode || engineVersion != metadata.EngineVersion || canonicalPack != metadata.CanonicalPackSHA256 ||
		sourcePack != metadata.SourcePackSHA256 || analyzedAt != metadata.AnalysisTime {
		return errors.New("collection metadata disagrees with case analysis provenance")
	}

	var packCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM incident_packs`).Scan(&packCount); err != nil {
		return fmt.Errorf("count case incident packs: %w", err)
	}
	if packCount != 1 {
		return fmt.Errorf("case database contains %d incident packs, want 1", packCount)
	}
	var incidentID, packVersion, sourceHash string
	if err := db.QueryRowContext(ctx, `
		SELECT incident_id,pack_version,source_pack_sha256
		FROM incident_packs WHERE canonical_pack_sha256=?`, metadata.CanonicalPackSHA256).
		Scan(&incidentID, &packVersion, &sourceHash); err != nil {
		return fmt.Errorf("read case incident-pack provenance: %w", err)
	}
	if incidentID != metadata.IncidentID || packVersion != metadata.IncidentPackVersion || sourceHash != metadata.SourcePackSHA256 {
		return errors.New("collection metadata disagrees with case incident-pack provenance")
	}
	persistedCaseKind, err := derivePersistedCaseKind(ctx, db)
	if err != nil {
		return err
	}
	if persistedCaseKind != metadata.CaseKind {
		return fmt.Errorf("collection metadata caseKind %q disagrees with persisted collection provenance %q", metadata.CaseKind, persistedCaseKind)
	}
	return nil
}

// derivePersistedCaseKind mirrors the analyzer's closed collection-mode
// classification. Labels and report fields are deliberately excluded: only
// persisted collection session modes may classify a strict v0.2 case.
func derivePersistedCaseKind(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT c.collection_id,c.mode
		FROM collection_sessions c
		JOIN archive_batch_collections bc ON bc.collection_id=c.collection_id
		JOIN archive_batches b ON b.batch_id=bc.batch_id AND b.state='COMMITTED'
		ORDER BY c.collection_id`)
	if err != nil {
		return "", fmt.Errorf("read committed persisted collection modes: %w", err)
	}
	var synthetic, collected, unknown bool
	linkedCount := 0
	for rows.Next() {
		if linkedCount >= 100_000 {
			_ = rows.Close()
			return "", errors.New("persisted collection mode count exceeds 100000")
		}
		var collectionID, mode string
		if err := rows.Scan(&collectionID, &mode); err != nil {
			_ = rows.Close()
			return "", fmt.Errorf("scan persisted collection mode: %w", err)
		}
		linkedCount++
		switch mode {
		case "fixture":
			synthetic = true
		case "archive", "investigate":
			collected = true
		default:
			unknown = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return "", fmt.Errorf("iterate persisted collection modes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return "", fmt.Errorf("close persisted collection modes: %w", err)
	}
	var storedCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM collection_sessions`).Scan(&storedCount); err != nil {
		return "", fmt.Errorf("count persisted collection modes: %w", err)
	}
	if linkedCount == 0 || linkedCount != storedCount {
		return "", fmt.Errorf("committed collection provenance count %d disagrees with stored count %d", linkedCount, storedCount)
	}
	if unknown {
		return "unknown", nil
	}
	switch {
	case synthetic && collected:
		return "mixed", nil
	case synthetic:
		return "synthetic", nil
	case collected:
		return "collected", nil
	default:
		return "unknown", nil
	}
}

func rejectV2OptionalNulls(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return err
	}
	for _, name := range []string{"githubApiVersion", "watchHorizonDays", "warnings"} {
		if value, present := top[name]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("v0.2 collection metadata %s cannot be null", name)
		}
	}
	coverageRaw, present := top["coverage"]
	if !present || bytes.Equal(bytes.TrimSpace(coverageRaw), []byte("null")) {
		return errors.New("v0.2 collection metadata coverage cannot be null")
	}
	var coverage map[string]json.RawMessage
	if err := json.Unmarshal(coverageRaw, &coverage); err != nil {
		return fmt.Errorf("decode v0.2 collection metadata coverage: %w", err)
	}
	for _, name := range []string{"optionalCapabilitiesDenied", "incompleteEvidence"} {
		if value, present := coverage[name]; present && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("v0.2 collection metadata coverage.%s cannot be null", name)
		}
	}
	return nil
}

func validateV2RequiredMetadata(metadata strictMetadataV2) error {
	if !validVersionedSHA256ID(metadata.CaseID, "case1:") {
		return errors.New("v0.2 collection metadata caseId is not a canonical case1 identifier")
	}
	if metadata.Mode != "investigate" && metadata.Mode != "replay" {
		return fmt.Errorf("v0.2 collection metadata has invalid mode %q", metadata.Mode)
	}
	if err := boundedRequiredText(metadata.IncidentID, 256, "incidentId"); err != nil {
		return err
	}
	if err := boundedRequiredText(metadata.IncidentPackVersion, 128, "incidentPackVersion"); err != nil {
		return err
	}
	if err := boundedRequiredText(metadata.EngineVersion, 128, "engineVersion"); err != nil {
		return err
	}
	if len(metadata.GitHubAPIVersion) > 128 || !utf8.ValidString(metadata.GitHubAPIVersion) {
		return errors.New("v0.2 collection metadata githubApiVersion exceeds its limit")
	}
	if err := boundedRequiredText(metadata.LimitPolicy, 4096, "limitPolicy"); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, metadata.AnalysisTime); err != nil {
		return fmt.Errorf("v0.2 collection metadata analysisTime is not RFC3339: %w", err)
	}
	if metadata.RawLogsRetained == nil {
		return errors.New("v0.2 collection metadata omits required rawLogsRetained")
	}
	if metadata.WatchHorizonDays < 0 || metadata.WatchHorizonDays > 3650 {
		return errors.New("v0.2 collection metadata watchHorizonDays is outside 0..3650")
	}
	if metadata.Coverage == nil {
		return errors.New("v0.2 collection metadata omits required coverage")
	}
	if err := validateStrictCoverage(*metadata.Coverage); err != nil {
		return err
	}
	if err := validateBoundedStringSet(metadata.Warnings, 1024, 4096, "warnings"); err != nil {
		return err
	}
	for _, field := range []struct{ label, digest string }{
		{"canonicalPackSha256", metadata.CanonicalPackSHA256},
		{"sourcePackSha256", metadata.SourcePackSHA256},
	} {
		if !validLowerSHA256(field.digest) {
			return fmt.Errorf("v0.2 collection metadata %s is not a lowercase SHA-256", field.label)
		}
	}
	return nil
}

func validVersionedSHA256ID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 && validLowerSHA256(strings.TrimPrefix(value, prefix))
}

func boundedRequiredText(value string, maximum int, label string) error {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return fmt.Errorf("v0.2 collection metadata %s is empty or exceeds %d bytes", label, maximum)
	}
	return nil
}

func validateStrictCoverage(coverage strictCoverageV2) error {
	if coverage.Partial == nil {
		return errors.New("v0.2 collection metadata coverage omits partial")
	}
	counts := []struct {
		label string
		value *int
	}{
		{"repositoriesRequested", coverage.RepositoriesRequested},
		{"repositoriesAccessible", coverage.RepositoriesAccessible},
		{"repositoriesDenied", coverage.RepositoriesDenied},
		{"runsEnumerated", coverage.RunsEnumerated},
		{"attemptsEnumerated", coverage.AttemptsEnumerated},
		{"jobsEnumerated", coverage.JobsEnumerated},
		{"logsRetrieved", coverage.LogsRetrieved},
		{"logsMissing", coverage.LogsMissing},
		{"workflowDefinitionsRetrieved", coverage.WorkflowDefinitionsRetrieved},
		{"actionDefinitionsRetrieved", coverage.ActionDefinitionsRetrieved},
	}
	for _, count := range counts {
		if count.value == nil {
			return fmt.Errorf("v0.2 collection metadata coverage omits %s", count.label)
		}
		if *count.value < 0 {
			return fmt.Errorf("v0.2 collection metadata coverage %s is negative", count.label)
		}
	}
	if err := validateBoundedStringSet(coverage.OptionalCapabilitiesDenied, 100_000, 4096, "coverage.optionalCapabilitiesDenied"); err != nil {
		return err
	}
	return validateBoundedStringSet(coverage.IncompleteEvidence, 100_000, 4096, "coverage.incompleteEvidence")
}

func validateBoundedStringSet(values []string, maximumItems, maximumBytes int, label string) error {
	if len(values) > maximumItems {
		return fmt.Errorf("v0.2 collection metadata %s exceeds %d items", label, maximumItems)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) {
			return fmt.Errorf("v0.2 collection metadata %s contains an empty or oversized value", label)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("v0.2 collection metadata %s contains duplicate value %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func verifyV2Files(ctx context.Context, dir string, files map[string]string, rawMaterialized bool) error {
	base := stringSet(requiredFilesV2)
	descriptors, err := rawDescriptorsFromLedger(ctx, filepath.Join(dir, "evidence.jsonl"), files["evidence.jsonl"], rawMaterialized)
	if err != nil {
		return err
	}
	rawDirectory := filepath.Join(dir, "raw")
	rawInfo, rawErr := os.Lstat(rawDirectory)
	if rawMaterialized {
		if rawErr != nil {
			return fmt.Errorf("rawMaterialized case requires exactly one raw directory: %w", rawErr)
		}
		if !rawInfo.IsDir() || rawInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("raw path is not a regular directory")
		}
	} else if rawErr == nil {
		return errors.New("raw-disabled v0.2 case contains a raw directory")
	} else if !errors.Is(rawErr, os.ErrNotExist) {
		return fmt.Errorf("inspect raw directory: %w", rawErr)
	}

	actualRaw := make(map[string]string)
	fileNames := make([]string, 0, len(files))
	for name := range files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		digest := files[name]
		if _, known := base[name]; known {
			continue
		}
		if !rawMaterialized || !validRawPath(name) {
			return fmt.Errorf("strict v0.2 case has unsupported extra file %q", name)
		}
		actualRaw[name] = digest
	}
	if rawMaterialized && len(actualRaw) != len(descriptors) {
		return fmt.Errorf("raw materialized file set differs from evidence descriptors: files=%d descriptors=%d", len(actualRaw), len(descriptors))
	}
	descriptorPaths := make([]string, 0, len(descriptors))
	for path := range descriptors {
		descriptorPaths = append(descriptorPaths, path)
	}
	sort.Strings(descriptorPaths)
	for _, path := range descriptorPaths {
		descriptor := descriptors[path]
		if !rawMaterialized {
			break
		}
		digest, present := actualRaw[path]
		if !present {
			return fmt.Errorf("raw evidence descriptor %q has no materialized file", path)
		}
		if digest != descriptor.digest {
			return fmt.Errorf("raw evidence file %q hash disagrees with its descriptor", path)
		}
		rawPath := filepath.Join(dir, filepath.FromSlash(path))
		info, err := os.Lstat(rawPath)
		if err != nil {
			return fmt.Errorf("inspect raw evidence file %q: %w", path, err)
		}
		if !info.Mode().IsRegular() || uint64(info.Size()) != descriptor.length {
			return fmt.Errorf("raw evidence file %q length or type disagrees with its descriptor", path)
		}
		observedDigest, observedLength, err := hashAndCountFile(ctx, rawPath)
		if err != nil {
			return err
		}
		if observedDigest != descriptor.digest || observedLength != descriptor.length {
			return fmt.Errorf("raw evidence file %q changed during contract verification", path)
		}
	}
	return validateV2TreeAndHardlinks(ctx, dir, rawMaterialized)
}

type rawDescriptor struct {
	digest string
	length uint64
}

func rawDescriptorsFromLedger(ctx context.Context, path, expectedDigest string, materialize bool) (map[string]rawDescriptor, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect evidence ledger: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxLedgerBytes {
		return nil, errors.New("evidence ledger is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence ledger: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hasher))
	scanner.Buffer(make([]byte, 64*1024), maxLedgerLineBytes)
	descriptors := make(map[string]rawDescriptor)
	observations := make(map[model.CollectionObservationID]struct{})
	var total uint64
	var sessionID string
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, fmt.Errorf("evidence ledger line %d is blank", lineNumber)
		}
		if err := rejectDuplicateJSONKeys(line, maxJSONDepth); err != nil {
			return nil, fmt.Errorf("evidence ledger line %d: %w", lineNumber, err)
		}
		var record ledger.Record
		if err := decodeStrictJSON(line, &record); err != nil {
			return nil, fmt.Errorf("decode evidence ledger line %d: %w", lineNumber, err)
		}
		if record.LedgerVersion != ledger.Version {
			return nil, fmt.Errorf("evidence ledger line %d has unsupported ledgerVersion %q", lineNumber, record.LedgerVersion)
		}
		if record.Sequence != uint64(lineNumber) {
			return nil, fmt.Errorf("evidence ledger line %d has noncontiguous sequence %d", lineNumber, record.Sequence)
		}
		if !validLedgerSessionID(record.SessionID) {
			return nil, fmt.Errorf("evidence ledger line %d has an invalid sessionId", lineNumber)
		}
		if sessionID == "" {
			sessionID = record.SessionID
		} else if record.SessionID != sessionID {
			return nil, fmt.Errorf("evidence ledger line %d changes sessionId", lineNumber)
		}
		switch record.RecordType {
		case "finding_revision":
			if err := validateFindingRevisionPayload(record.Payload); err != nil {
				return nil, fmt.Errorf("decode finding revision on ledger line %d: %w", lineNumber, err)
			}
			continue
		case "evidence_observation":
		default:
			return nil, fmt.Errorf("evidence ledger line %d has unsupported recordType %q", lineNumber, record.RecordType)
		}
		var envelope evidence.Envelope
		if err := decodeStrictJSON(record.Payload, &envelope); err != nil {
			return nil, fmt.Errorf("decode evidence envelope on ledger line %d: %w", lineNumber, err)
		}
		if err := envelope.Validate(); err != nil {
			return nil, fmt.Errorf("validate evidence envelope on ledger line %d: %w", lineNumber, err)
		}
		if _, duplicate := observations[envelope.Observation.ID]; duplicate {
			return nil, fmt.Errorf("evidence ledger line %d duplicates observation %s", lineNumber, envelope.Observation.ID)
		}
		observations[envelope.Observation.ID] = struct{}{}
		content := envelope.Evidence.Content
		if !content.RawRetained {
			continue
		}
		if content.RetainedPayloadSHA256 == nil || !validLowerSHA256(*content.RetainedPayloadSHA256) ||
			*content.RetainedPayloadSHA256 != content.SourceSHA256 {
			return nil, fmt.Errorf("raw evidence descriptor on line %d is incomplete", lineNumber)
		}
		digest := *content.RetainedPayloadSHA256
		expectedPath := "raw/" + digest + ".bin"
		if content.RetainedPath != expectedPath || content.ByteLength > maxRawObjectBytes {
			if content.RetainedPath != expectedPath || materialize {
				return nil, fmt.Errorf("raw evidence descriptor on line %d has an unsafe path or materialized length", lineNumber)
			}
		}
		if !materialize {
			continue
		}
		descriptor := rawDescriptor{digest: digest, length: content.ByteLength}
		if previous, exists := descriptors[expectedPath]; exists {
			if previous != descriptor {
				return nil, fmt.Errorf("raw evidence path %q has contradictory descriptors", expectedPath)
			}
			continue
		}
		if len(descriptors) >= maxRawObjectCount || total > maxRawMaterializedByte-descriptor.length {
			return nil, errors.New("raw evidence descriptors exceed the compiled case limit")
		}
		total += descriptor.length
		descriptors[expectedPath] = descriptor
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read evidence ledger: %w", err)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		return nil, errors.New("evidence ledger changed after manifest verification")
	}
	return descriptors, nil
}

// ledgerFindingRevision is the closed presentation envelope emitted by the
// case writer. The verifier only needs the structural contract here; finding
// semantics are independently bound by findings.json and case.db.
type ledgerFindingRevision struct {
	FindingID             string                `json:"findingId"`
	FindingRevisionID     string                `json:"findingRevisionId"`
	IncidentID            string                `json:"incidentId"`
	IndicatorID           string                `json:"indicatorId"`
	Repository            string                `json:"repository"`
	Workflow              string                `json:"workflow,omitempty"`
	RunID                 int64                 `json:"runId,omitempty"`
	RunAttempt            int                   `json:"runAttempt,omitempty"`
	JobID                 int64                 `json:"jobId,omitempty"`
	StepIdentity          string                `json:"stepIdentity,omitempty"`
	State                 model.FindingState    `json:"state"`
	Provenance            model.ProvenanceLevel `json:"provenance"`
	Conclusion            string                `json:"conclusion"`
	EventTime             string                `json:"eventTime,omitempty"`
	EvidenceIDs           []model.EvidenceID    `json:"evidenceIds"`
	Assumptions           []string              `json:"assumptions"`
	EvidenceGaps          []string              `json:"evidenceGaps"`
	ContradictoryEvidence []string              `json:"contradictoryEvidence"`
	CredentialExposure    []ledgerExposure      `json:"potentialCredentialExposure"`
	ResourceExposure      []ledgerExposure      `json:"potentialResourceExposure"`
	RemediationGuidance   []string              `json:"remediationGuidance"`
	CollectionCoverage    []string              `json:"collectionCoverage"`
}

type ledgerExposure struct {
	Kind        string             `json:"kind"`
	Name        string             `json:"name,omitempty"`
	Capability  string             `json:"capability,omitempty"`
	Basis       string             `json:"basis"`
	Conclusion  string             `json:"conclusion"`
	EvidenceIDs []model.EvidenceID `json:"evidenceIds"`
}

func validateFindingRevisionPayload(raw []byte) error {
	var finding ledgerFindingRevision
	if err := decodeStrictJSON(raw, &finding); err != nil {
		return err
	}
	if err := model.FindingID(finding.FindingID).Validate(); err != nil {
		return err
	}
	if err := model.FindingRevisionID(finding.FindingRevisionID).Validate(); err != nil {
		return err
	}
	if !finding.State.Valid() || !finding.Provenance.Valid() || finding.IncidentID == "" || finding.IndicatorID == "" || finding.Repository == "" || finding.Conclusion == "" {
		return errors.New("finding revision has invalid required fields")
	}
	if finding.EvidenceIDs == nil || finding.Assumptions == nil || finding.EvidenceGaps == nil || finding.ContradictoryEvidence == nil ||
		finding.CredentialExposure == nil || finding.ResourceExposure == nil || finding.RemediationGuidance == nil || finding.CollectionCoverage == nil {
		return errors.New("finding revision omits an explicit array")
	}
	for _, id := range finding.EvidenceIDs {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validLedgerSessionID(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateV2TreeAndHardlinks(ctx context.Context, dir string, rawMaterialized bool) error {
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("strict v0.2 case contains symlink %q", relative)
		}
		if entry.IsDir() {
			if relative != "raw" || !rawMaterialized {
				return fmt.Errorf("strict v0.2 case contains unsupported directory %q", relative)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("strict v0.2 case contains non-regular file %q", relative)
		}
		if err := requireSingleLink(path, info); err != nil {
			return err
		}
		return nil
	})
}

func verifyManifestIntegrity(ctx context.Context, dir string) (map[string]string, error) {
	manifestBytes, err := readBoundedRegular(filepath.Join(dir, "manifest.sha256"), maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	expected, err := parseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	actualBytes, err := BuildManifest(ctx, dir)
	if err != nil {
		return nil, err
	}
	actual, err := parseManifest(actualBytes)
	if err != nil {
		return nil, fmt.Errorf("parse generated manifest: %w", err)
	}
	if len(actual) != len(expected) {
		return nil, fmt.Errorf("manifest file set differs: expected %d files, found %d", len(expected), len(actual))
	}
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		digest := expected[name]
		if actual[name] != digest {
			return nil, fmt.Errorf("manifest verification failed for %s", name)
		}
	}
	return expected, nil
}

func parseManifest(data []byte) (map[string]string, error) {
	expected := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return nil, errors.New("malformed manifest line")
		}
		digest, name := line[:64], line[66:]
		if _, err := hex.DecodeString(digest); err != nil || !validRelative(name) || name == "manifest.sha256" {
			return nil, errors.New("malformed manifest entry")
		}
		if _, duplicate := expected[name]; duplicate {
			return nil, fmt.Errorf("duplicate manifest entry %q", name)
		}
		expected[name] = strings.ToLower(digest)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return expected, nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("file is not regular or exceeds %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func rejectDuplicateJSONKeys(data []byte, maxDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := consumeJSONValue(decoder, first, 0, maxDepth); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains multiple values")
		}
		return fmt.Errorf("decode JSON trailer: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token, depth, maxDepth int) error {
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	if depth >= maxDepth {
		return errors.New("JSON nesting limit reached")
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON object has duplicate key %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object value: %w", err)
			}
			if err := consumeJSONValue(decoder, value, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON array value: %w", err)
			}
			if err := consumeJSONValue(decoder, value, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validRawPath(path string) bool {
	if !strings.HasPrefix(path, "raw/") || strings.Count(path, "/") != 1 || !strings.HasSuffix(path, ".bin") {
		return false
	}
	return validLowerSHA256(strings.TrimSuffix(strings.TrimPrefix(path, "raw/"), ".bin"))
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashAndCountFile(ctx context.Context, path string) (string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open raw evidence for verification: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, 128*1024)
	var count uint64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			count += uint64(n)
			_, _ = hasher.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, fmt.Errorf("read raw evidence for verification: %w", readErr)
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), count, nil
}
