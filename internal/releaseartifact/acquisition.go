package releaseartifact

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/evidence"
)

// AcquisitionRecordSchema names the bounded release-candidate identity record
// that a local freeze produces and that an authorized hosted qualification
// may later complete with immutable artifact fields.
const AcquisitionRecordSchema = "cirewind.rc-acquisition/v1alpha1"

// AcquisitionPublicationStatement is the only publication status a locally
// frozen record may carry.
const AcquisitionPublicationStatement = "not-published; no tag, release, artifact, or attestation exists for this candidate"

const (
	maxSuiteLedgerBytes = 1 << 20
	maxSuites           = 64
	maxSubjects         = 64
	maxRecordFileBytes  = 64 << 20
)

var (
	plainVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	gitObjectPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	suiteNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	hostNamePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	recordFileName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
)

// AcquisitionRecord binds one locally frozen release candidate to its intended
// final metadata, toolchain, reproducible build command, subject and binary
// digests, final formula and README bytes, the recorded old default-branch
// tip, and the local qualification ledger. It never states publication,
// authentication, or human approval.
type AcquisitionRecord struct {
	SchemaVersion      string             `json:"schemaVersion"`
	IntendedVersion    string             `json:"intendedVersion"`
	SourceCommit       string             `json:"sourceCommit"`
	ExpectedDefaultTip string             `json:"expectedDefaultTip"`
	SourceDateEpoch    int64              `json:"sourceDateEpoch"`
	BuildDate          string             `json:"buildDate"`
	Toolchain          AcquisitionTool    `json:"toolchain"`
	BuildCommand       string             `json:"buildCommand"`
	ReleaseSubjects    []FileRecord       `json:"releaseSubjects"`
	Binaries           []BinaryRecord     `json:"binaries"`
	Formula            FileRecord         `json:"formula"`
	Readme             FileRecord         `json:"readme"`
	ImmutableArtifact  *ImmutableArtifact `json:"immutableArtifact"`
	Qualification      Qualification      `json:"qualification"`
	Publication        string             `json:"publication"`
}

// AcquisitionTool records the exact toolchain identity a reproducer must use.
type AcquisitionTool struct {
	GoVersion  string `json:"goVersion"`
	HostOS     string `json:"hostOS"`
	HostArch   string `json:"hostArch"`
	CGOEnabled bool   `json:"cgoEnabled"`
	Trimpath   bool   `json:"trimpath"`
	BuildVCS   bool   `json:"buildVCS"`
}

// BinaryRecord is the digest of one executable inside its release archive.
type BinaryRecord struct {
	Target  string `json:"target"`
	Archive string `json:"archive"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
}

// ImmutableArtifact holds the fields only an authorized hosted qualification
// may supply; a local freeze leaves it null.
type ImmutableArtifact struct {
	Workflow       string `json:"workflow"`
	RunID          int64  `json:"runID"`
	RunAttempt     int64  `json:"runAttempt"`
	ArtifactID     int64  `json:"artifactID"`
	ArtifactSHA256 string `json:"artifactSHA256"`
	SourceCommit   string `json:"sourceCommit"`
	AccessTime     string `json:"accessTime"`
}

// Qualification is the ledger of local gates the freeze ran. Complete is true
// only when every gate passed; a skipped gate keeps the freeze incomplete.
type Qualification struct {
	Suites   []SuiteResult `json:"suites"`
	Complete bool          `json:"complete"`
}

// SuiteResult is one local gate outcome.
type SuiteResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Command    string `json:"command"`
	DurationMs int64  `json:"durationMs"`
	Reason     string `json:"reason"`
}

// AcquisitionInput carries the caller-fixed identity a record binds.
type AcquisitionInput struct {
	IntendedVersion    string
	SourceCommit       string
	ExpectedDefaultTip string
	SourceDateEpoch    int64
	HostOS             string
	HostArch           string
	Formula            FileRecord
	Readme             FileRecord
	Suites             []SuiteResult
}

// BuildAcquisitionRecord composes a record from verified distribution
// metadata and the caller-fixed identity, rejecting every disagreement
// between them. Release subjects must be supplied by the directory-based
// caller; this function fills the metadata-derived subjects (archives and
// SBOMs) and the binaries.
func BuildAcquisitionRecord(metadata DistributionMetadata, input AcquisitionInput, subjects []FileRecord) (AcquisitionRecord, error) {
	if !plainVersionPattern.MatchString(input.IntendedVersion) {
		return AcquisitionRecord{}, fmt.Errorf("intended version %q must be a plain MAJOR.MINOR.PATCH value without a v prefix or pre-release suffix", input.IntendedVersion)
	}
	if !gitObjectPattern.MatchString(input.SourceCommit) {
		return AcquisitionRecord{}, errors.New("source commit must be a full lowercase SHA-1 object ID")
	}
	if !gitObjectPattern.MatchString(input.ExpectedDefaultTip) {
		return AcquisitionRecord{}, errors.New("expected default tip must be a full lowercase SHA-1 object ID")
	}
	if !hostNamePattern.MatchString(input.HostOS) || !hostNamePattern.MatchString(input.HostArch) {
		return AcquisitionRecord{}, errors.New("host OS and architecture must be short lowercase identifiers")
	}
	build := metadata.Build
	if build.Version != input.IntendedVersion {
		return AcquisitionRecord{}, fmt.Errorf("distribution was built as version %q, not the intended %q", build.Version, input.IntendedVersion)
	}
	if build.Commit != input.SourceCommit {
		return AcquisitionRecord{}, fmt.Errorf("distribution was built from commit %s, not %s", build.Commit, input.SourceCommit)
	}
	if build.SourceDateEpoch != input.SourceDateEpoch {
		return AcquisitionRecord{}, fmt.Errorf("distribution source date epoch %d differs from the fixed %d", build.SourceDateEpoch, input.SourceDateEpoch)
	}
	if build.CGOEnabled || !build.Trimpath || build.BuildVCS {
		return AcquisitionRecord{}, errors.New("distribution build controls are not the reproducible cgo-off, trimpath, no-VCS set")
	}
	if len(metadata.Artifacts) == 0 {
		return AcquisitionRecord{}, errors.New("distribution lists no artifacts")
	}
	for _, record := range []struct {
		label string
		file  FileRecord
	}{{"formula", input.Formula}, {"readme", input.Readme}} {
		if err := validateFileRecord(record.file); err != nil {
			return AcquisitionRecord{}, fmt.Errorf("%s: %w", record.label, err)
		}
	}
	ordered := append([]FileRecord{}, subjects...)
	seen := make(map[string]FileRecord)
	for _, subject := range ordered {
		if err := validateFileRecord(subject); err != nil {
			return AcquisitionRecord{}, fmt.Errorf("release subject: %w", err)
		}
		if _, dup := seen[subject.Name]; dup {
			return AcquisitionRecord{}, fmt.Errorf("release subject %s is listed twice", subject.Name)
		}
		seen[subject.Name] = subject
	}
	if len(ordered) == 0 || len(ordered) > maxSubjects {
		return AcquisitionRecord{}, fmt.Errorf("release subjects must number between 1 and %d", maxSubjects)
	}
	binaries := make([]BinaryRecord, 0, len(metadata.Artifacts))
	for _, artifact := range metadata.Artifacts {
		for _, want := range []FileRecord{artifact.Archive, artifact.SBOM} {
			got, ok := seen[want.Name]
			if !ok {
				return AcquisitionRecord{}, fmt.Errorf("release subject %s named by the distribution metadata is absent", want.Name)
			}
			if got.SHA256 != want.SHA256 || got.Bytes != want.Bytes {
				return AcquisitionRecord{}, fmt.Errorf("release subject %s differs from the distribution metadata", want.Name)
			}
		}
		if err := validateFileRecord(artifact.Binary); err != nil {
			return AcquisitionRecord{}, fmt.Errorf("binary for %s: %w", artifact.Target, err)
		}
		binaries = append(binaries, BinaryRecord{Target: artifact.Target.String(), Archive: artifact.Archive.Name, Name: artifact.Binary.Name, SHA256: artifact.Binary.SHA256, Bytes: artifact.Binary.Bytes})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	sort.Slice(binaries, func(i, j int) bool { return binaries[i].Target < binaries[j].Target })
	suites, complete, err := normalizeSuites(input.Suites)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	record := AcquisitionRecord{
		SchemaVersion: AcquisitionRecordSchema, IntendedVersion: input.IntendedVersion, SourceCommit: input.SourceCommit,
		ExpectedDefaultTip: input.ExpectedDefaultTip, SourceDateEpoch: input.SourceDateEpoch, BuildDate: build.BuildDate,
		Toolchain:       AcquisitionTool{GoVersion: build.GoVersion, HostOS: input.HostOS, HostArch: input.HostArch, CGOEnabled: false, Trimpath: true, BuildVCS: false},
		BuildCommand:    fmt.Sprintf("sh scripts/build-release.sh %s %s %d OUTPUT_DIR", input.IntendedVersion, input.SourceCommit, input.SourceDateEpoch),
		ReleaseSubjects: ordered, Binaries: binaries, Formula: input.Formula, Readme: input.Readme, ImmutableArtifact: nil,
		Qualification: Qualification{Suites: suites, Complete: complete}, Publication: AcquisitionPublicationStatement,
	}
	return record, nil
}

// AcquisitionRecordFromDistribution verifies a distribution directory, hashes
// every root subject, and composes the record.
func AcquisitionRecordFromDistribution(directory string, input AcquisitionInput) (AcquisitionRecord, error) {
	if err := VerifyDistribution(directory); err != nil {
		return AcquisitionRecord{}, fmt.Errorf("verify release subjects: %w", err)
	}
	metadata, err := LoadDistributionMetadata(directory)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	subjects, err := hashRootSubjects(directory)
	if err != nil {
		return AcquisitionRecord{}, err
	}
	return BuildAcquisitionRecord(metadata, input, subjects)
}

// HashFileRecord returns the bounded digest record of one regular file.
func HashFileRecord(path string) (FileRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileRecord{}, err
	}
	if !info.Mode().IsRegular() {
		return FileRecord{}, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if info.Size() > maxRecordFileBytes {
		return FileRecord{}, fmt.Errorf("%s exceeds the %d byte record limit", filepath.Base(path), maxRecordFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FileRecord{}, err
	}
	sum := sha256.Sum256(data)
	return FileRecord{Name: filepath.Base(path), SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}, nil
}

func hashRootSubjects(directory string) ([]FileRecord, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	subjects := make([]FileRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("release directory contains a subdirectory %s", entry.Name())
		}
		record, err := HashFileRecord(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		subjects = append(subjects, record)
	}
	return subjects, nil
}

// ParseSuiteLedger reads the tab-separated gate ledger a freeze driver writes:
// name, status, duration in milliseconds, command, and reason per line.
func ParseSuiteLedger(data []byte) ([]SuiteResult, error) {
	if len(data) > maxSuiteLedgerBytes {
		return nil, errors.New("suite ledger exceeds the size limit")
	}
	var suites []SuiteResult
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 5 {
			return nil, fmt.Errorf("suite ledger line %d must carry five tab-separated fields", line)
		}
		duration, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || duration < 0 {
			return nil, fmt.Errorf("suite ledger line %d has an invalid duration", line)
		}
		suites = append(suites, SuiteResult{Name: fields[0], Status: fields[1], DurationMs: duration, Command: fields[3], Reason: fields[4]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return suites, nil
}

func normalizeSuites(suites []SuiteResult) ([]SuiteResult, bool, error) {
	if len(suites) > maxSuites {
		return nil, false, fmt.Errorf("more than %d suites", maxSuites)
	}
	seen := make(map[string]struct{})
	complete := len(suites) > 0
	ordered := append([]SuiteResult{}, suites...)
	for _, suite := range ordered {
		if !suiteNamePattern.MatchString(suite.Name) {
			return nil, false, fmt.Errorf("suite name %q is not a short lowercase identifier", suite.Name)
		}
		if _, dup := seen[suite.Name]; dup {
			return nil, false, fmt.Errorf("suite %s is recorded twice", suite.Name)
		}
		seen[suite.Name] = struct{}{}
		switch suite.Status {
		case "pass":
		case "fail", "skipped":
			complete = false
			if suite.Reason == "" {
				return nil, false, fmt.Errorf("suite %s is %s without a reason", suite.Name, suite.Status)
			}
		default:
			return nil, false, fmt.Errorf("suite %s has unsupported status %q", suite.Name, suite.Status)
		}
		if suite.Command == "" || len(suite.Command) > 512 || len(suite.Reason) > 512 || strings.ContainsAny(suite.Command+suite.Reason, "<>\n") {
			return nil, false, fmt.Errorf("suite %s carries an unsafe or oversize command or reason", suite.Name)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	return ordered, complete, nil
}

func validateFileRecord(record FileRecord) error {
	if !recordFileName.MatchString(record.Name) {
		return fmt.Errorf("file name %q is not a plain file name", record.Name)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(record.SHA256) {
		return fmt.Errorf("%s digest is not 64 lowercase hex characters", record.Name)
	}
	if record.Bytes < 0 {
		return fmt.Errorf("%s has a negative length", record.Name)
	}
	return nil
}

// EncodeAcquisitionRecord renders the record as RFC 8785 canonical JSON plus
// one line feed, the byte form the freeze writes and later verification hashes.
func EncodeAcquisitionRecord(record AcquisitionRecord) ([]byte, error) {
	data, err := evidence.CanonicalJSON(record)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// VerifyAcquisitionRecord recomputes every release subject digest of a
// distribution directory and reports the first disagreement with the record.
func VerifyAcquisitionRecord(record AcquisitionRecord, directory string) error {
	if record.SchemaVersion != AcquisitionRecordSchema || record.Publication != AcquisitionPublicationStatement {
		return errors.New("record schema or publication statement is not the local freeze form")
	}
	subjects, err := hashRootSubjects(directory)
	if err != nil {
		return err
	}
	byName := make(map[string]FileRecord, len(subjects))
	for _, subject := range subjects {
		byName[subject.Name] = subject
	}
	if len(byName) != len(record.ReleaseSubjects) {
		return fmt.Errorf("directory holds %d subjects, record lists %d", len(byName), len(record.ReleaseSubjects))
	}
	for _, want := range record.ReleaseSubjects {
		got, ok := byName[want.Name]
		if !ok || got != want {
			return fmt.Errorf("release subject %s differs from the record", want.Name)
		}
	}
	metadata, err := LoadDistributionMetadata(directory)
	if err != nil {
		return err
	}
	if metadata.Build.Version != record.IntendedVersion || metadata.Build.Commit != record.SourceCommit || metadata.Build.SourceDateEpoch != record.SourceDateEpoch {
		return errors.New("distribution build metadata differs from the record identity")
	}
	return nil
}
