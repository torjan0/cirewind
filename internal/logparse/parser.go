package logparse

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	GrammarVersion  = "github-runner-control/v1alpha1"
	MaxLogLineBytes = 1 << 20
)

type EntryRole string

const (
	RoleSetup      EntryRole = "setup"
	RoleActionStep EntryRole = "action-step"
	RoleRunStep    EntryRole = "run-step"
	RoleUnknown    EntryRole = "unknown"
)

type LifecyclePhase string

const (
	PhasePre  LifecyclePhase = "pre"
	PhaseMain LifecyclePhase = "main"
	PhasePost LifecyclePhase = "post"
)

type ObservationKind string

const (
	ObservationResolution          ObservationKind = "RESOLUTION_OBSERVED"
	ObservationDownloadAnnounced   ObservationKind = "DOWNLOAD_ANNOUNCED"
	ObservationPreparationComplete ObservationKind = "PREPARATION_COMPLETED"
	ObservationPreparationFailed   ObservationKind = "PREPARATION_FAILED"
	ObservationConditionSkipped    ObservationKind = "CONDITION_SKIPPED"
	ObservationLifecycleStarted    ObservationKind = "LIFECYCLE_STARTED"
	ObservationLifecycleCompleted  ObservationKind = "LIFECYCLE_COMPLETED"
	ObservationTokenPermission     ObservationKind = "TOKEN_PERMISSION"
	ObservationRunnerMetadata      ObservationKind = "RUNNER_METADATA"
)

type ExecutionScope struct {
	RepositoryID int64  `json:"repositoryId"`
	RunID        int64  `json:"runId"`
	RunAttempt   int    `json:"runAttempt"`
	JobID        int64  `json:"jobId"`
	StepKey      string `json:"stepKey,omitempty"`
}

type SourceContext struct {
	Scope              ExecutionScope
	Role               EntryRole
	LifecyclePhase     LifecyclePhase
	ExpectedAction     string
	GitObjectAlgorithm string
	APIStatus          string
	APIConclusion      string
	RunnerVersion      string
	// Grammar identifies the structural grammar selected by the collector.
	// The empty value selects GrammarVersion for legacy split log entries.
	Grammar string
	// LineOffset preserves source line numbers when Parse receives a framed
	// region from a larger consolidated job log.
	LineOffset int
	// GrammarValidated is set only after the collector selected a pinned,
	// structurally recognized runner grammar for this source. Unknown formats
	// remain evidence gaps instead of falling back to substring matching.
	GrammarValidated bool
}

type GitObject struct {
	// Algorithm is empty when the runner log supplied a full hexadecimal
	// source value but no independently verified target-repository object
	// format was available at the parser boundary. Width alone never assigns
	// an algorithm.
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type Digest struct {
	Subject   string `json:"subject"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type Action struct {
	Owner      string    `json:"owner"`
	Repository string    `json:"repository"`
	Subpath    string    `json:"subpath,omitempty"`
	Ref        string    `json:"ref"`
	Source     GitObject `json:"source,omitempty"`
	Version    string    `json:"version,omitempty"`
	Digest     Digest    `json:"digest,omitempty"`
}

type Observation struct {
	Kind       ObservationKind `json:"kind"`
	Scope      ExecutionScope  `json:"scope"`
	Action     *Action         `json:"action,omitempty"`
	Phase      LifecyclePhase  `json:"phase,omitempty"`
	Permission string          `json:"permission,omitempty"`
	Access     string          `json:"access,omitempty"`
	Attribute  string          `json:"attribute,omitempty"`
	Value      string          `json:"value,omitempty"`
	EventTime  *time.Time      `json:"eventTime,omitempty"`
	LineStart  int             `json:"lineStart"`
	LineEnd    int             `json:"lineEnd"`
	Grammar    string          `json:"grammar"`
	Derived    bool            `json:"derived,omitempty"`
	Inputs     []int           `json:"inputObservationIndexes,omitempty"`
}

type ParseDiagnostic struct {
	Code  string `json:"code"`
	Line  int    `json:"line,omitempty"`
	Error string `json:"error,omitempty"`
}

type ParseResult struct {
	Observations  []Observation     `json:"observations"`
	Diagnostics   []ParseDiagnostic `json:"diagnostics,omitempty"`
	Complete      bool              `json:"complete"`
	ContentSHA256 string            `json:"contentSha256"`
	ByteLength    int64             `json:"byteLength"`
}

type lineRecord struct {
	number int
	time   *time.Time
	text   string
}

var (
	downloadPattern   = regexp.MustCompile(`^(?:##\[group\])?Download action repository '([^']+)' \(SHA:([0-9A-Fa-f]+)\)$`)
	immutablePattern  = regexp.MustCompile(`^(?:##\[group\])?Download immutable action package '([^']+)'$`)
	runPattern        = regexp.MustCompile(`^##\[group\]Run ([^[:space:]]+)$`)
	versionPattern    = regexp.MustCompile(`^Version:\s*(.+)$`)
	sourcePattern     = regexp.MustCompile(`^Source commit SHA:\s*([0-9A-Fa-f]+)$`)
	digestPattern     = regexp.MustCompile(`^Digest:\s*([a-z0-9-]+):([0-9A-Fa-f]+)$`)
	permissionPattern = regexp.MustCompile(`^([A-Za-z0-9_-]+):\s*(read|write|none)$`)
)

// Parse accepts bytes only after the collector has established their
// repository/run/attempt/job and structural entry role. It never infers scope
// from a hostile filename or display name.
func Parse(ctx context.Context, reader io.Reader, source SourceContext) (ParseResult, error) {
	result := ParseResult{Complete: true}
	if source.Scope.RepositoryID <= 0 || source.Scope.RunID <= 0 || source.Scope.RunAttempt <= 0 || source.Scope.JobID <= 0 {
		return result, errors.New("complete execution scope is required")
	}
	if source.LineOffset < 0 {
		return result, errors.New("source line offset cannot be negative")
	}
	hasher := sha256.New()
	counting := &byteCounter{reader: io.TeeReader(reader, hasher)}
	scanner := bufio.NewScanner(counting)
	scanner.Buffer(make([]byte, 64*1024), MaxLogLineBytes)

	var lines []lineRecord
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		line := scanner.Text()
		if len(lines) == 0 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		when, text := splitTimestamp(line)
		lines = append(lines, lineRecord{number: source.LineOffset + len(lines) + 1, time: when, text: text})
	}
	if err := scanner.Err(); err != nil {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "TRUNCATED_OR_OVERSIZE_LOG", Error: err.Error()})
	}
	result.ByteLength = counting.bytes
	result.ContentSHA256 = hex.EncodeToString(hasher.Sum(nil))
	if !source.GrammarValidated && (source.Role == RoleSetup || source.Role == RoleActionStep) {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Error: "runner grammar was not validated"})
		return result, nil
	}

	switch source.Role {
	case RoleSetup:
		parseSetup(lines, source, &result)
	case RoleActionStep:
		parseActionStep(lines, source, &result)
	case RoleRunStep, RoleUnknown:
		// Workflow output is not runner control evidence. Intentionally do not
		// recognize download/permission lookalikes here.
	default:
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Error: "unknown structural entry role"})
	}
	return result, nil
}

func parseSetup(lines []lineRecord, source SourceContext, result *ParseResult) {
	var announced []int
	failed := false
	permissionGroup := false
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		text := strings.TrimSpace(line.text)
		if strings.HasPrefix(text, "##[error]") {
			failed = true
		}
		if text == "##[group]GITHUB_TOKEN Permissions" {
			permissionGroup = true
			continue
		}
		if permissionGroup {
			if text == "##[endgroup]" {
				permissionGroup = false
				continue
			}
			if match := permissionPattern.FindStringSubmatch(text); match != nil {
				result.Observations = append(result.Observations, baseObservation(ObservationTokenPermission, source, line, nil, "", strings.ToLower(match[1]), match[2]))
			}
			continue
		}
		if source.Grammar == ConsolidatedGrammarVersion && strings.HasPrefix(text, "Uses: ") {
			// Reusable-workflow inputs are application-controlled even though the
			// runner emits them during setup. The consolidated framer validates
			// the bounded tail and exact completion record; the setup parser stops
			// here so input newlines can never forge Action or permission facts.
			break
		}
		if match := downloadPattern.FindStringSubmatch(text); match != nil {
			action, err := parseResolvedAction(match[1], match[2], source.GitObjectAlgorithm)
			if err != nil {
				result.Complete = false
				result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "MALFORMED_ACTION_RESOLUTION", Line: line.number, Error: err.Error()})
				continue
			}
			result.Observations = append(result.Observations,
				baseObservation(ObservationResolution, source, line, &action, "", "", ""),
				baseObservation(ObservationDownloadAnnounced, source, line, &action, "", "", ""),
			)
			announced = append(announced, len(result.Observations)-1)
			continue
		}
		if match := immutablePattern.FindStringSubmatch(text); match != nil {
			action, consumed, err := parseImmutable(lines[index:], match[1], source.GitObjectAlgorithm)
			if err != nil {
				result.Complete = false
				result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "INCOMPLETE_IMMUTABLE_PACKAGE_GROUP", Line: line.number, Error: err.Error()})
				continue
			}
			end := lines[index+consumed-1]
			observation := baseObservation(ObservationResolution, source, line, &action, "", "", "")
			observation.LineEnd = end.number
			result.Observations = append(result.Observations, observation)
			announcement := observation
			announcement.Kind = ObservationDownloadAnnounced
			result.Observations = append(result.Observations, announcement)
			announced = append(announced, len(result.Observations)-1)
			index += consumed - 1
			continue
		}
		parseRunnerMetadata(text, line, source, result)
	}

	success := result.Complete && !failed && strings.EqualFold(source.APIConclusion, "success")
	for _, announcedIndex := range announced {
		input := result.Observations[announcedIndex]
		kind := ObservationPreparationComplete
		if !success {
			kind = ObservationPreparationFailed
		}
		derived := input
		derived.Kind = kind
		derived.Derived = true
		derived.Inputs = []int{announcedIndex}
		if len(lines) > 0 {
			derived.LineEnd = lines[len(lines)-1].number
		}
		result.Observations = append(result.Observations, derived)
	}
	if len(announced) > 0 && !success {
		result.Complete = false
		result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "PREPARATION_COMPLETION_NOT_PROVEN"})
	}
}

func parseActionStep(lines []lineRecord, source SourceContext, result *ParseResult) {
	if strings.EqualFold(source.APIConclusion, "skipped") {
		line := lineRecord{number: 0}
		result.Observations = append(result.Observations, baseObservation(ObservationConditionSkipped, source, line, nil, source.LifecyclePhase, "", ""))
		return
	}
	for index, line := range lines {
		if strings.TrimSpace(line.text) == "" {
			continue
		}
		text := line.text
		if line.time == nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "Action lifecycle frame is not timestamped"})
			return
		}
		match := runPattern.FindStringSubmatch(text)
		if match == nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "first runner control record is not an Action lifecycle frame"})
			return
		}
		action, err := parseDeclaredAction(match[1])
		if err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "MALFORMED_ACTION_LIFECYCLE", Line: line.number, Error: err.Error()})
			return
		}
		groupEnd, diagnostic := validateRepositoryActionDetailsGroup(lines, index)
		if diagnostic != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, *diagnostic)
			return
		}
		if source.ExpectedAction == "" || !sameActionDeclaration(source.ExpectedAction, match[1]) {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "AMBIGUOUS_CORRELATION", Line: line.number, Error: "lifecycle frame does not match trusted step declaration"})
			return
		}
		started := baseObservation(ObservationLifecycleStarted, source, line, &action, source.LifecyclePhase, "", "")
		result.Observations = append(result.Observations, started)
		if source.APIConclusion != "" && !strings.EqualFold(source.APIStatus, "in_progress") {
			completed := started
			completed.Kind = ObservationLifecycleCompleted
			completed.Derived = true
			completed.Inputs = []int{len(result.Observations) - 1}
			completed.LineEnd = lines[groupEnd].number
			result.Observations = append(result.Observations, completed)
		}
		return
	}
	result.Complete = false
	result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{Code: "MISSING_LIFECYCLE_FRAME"})
}

// validateRepositoryActionDetailsGroup recognizes only the frame emitted by
// Handler.PrintActionDetails for a repository Action. ScriptHandler can emit
// the same first "Run owner/repository@ref" group line for a hostile `run:`
// script, but it must then emit ANSI-colored script text and a top-level
// "shell:" line. Requiring the complete, pinned group grammar prevents that
// lookalike from becoming lifecycle evidence.
func validateRepositoryActionDetailsGroup(lines []lineRecord, start int) (int, *ParseDiagnostic) {
	section := ""
	seenWith, seenEnv := false, false
	for index := start + 1; index < len(lines); index++ {
		line := lines[index]
		if line.time == nil {
			return 0, &ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "Action details record is not timestamped"}
		}
		text := line.text
		if text == "##[endgroup]" {
			return index, nil
		}
		if strings.ContainsRune(text, '\x1b') || hasStructuralControl(text) {
			return 0, &ParseDiagnostic{Code: "SHELL_STEP_LOOKALIKE", Line: line.number, Error: "Action details group contains script-control output"}
		}
		switch text {
		case "with:":
			if seenWith || seenEnv {
				return 0, &ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "Action details sections are duplicated or out of order"}
			}
			seenWith, section = true, "with"
			continue
		case "env:":
			if seenEnv {
				return 0, &ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "Action details env section is duplicated"}
			}
			seenEnv, section = true, "env"
			continue
		}
		if strings.HasPrefix(text, "shell:") {
			return 0, &ParseDiagnostic{Code: "SHELL_STEP_LOOKALIKE", Line: line.number, Error: "ScriptHandler shell record is not repository Action lifecycle evidence"}
		}
		if section == "" || !validActionDetailValue(text) {
			return 0, &ParseDiagnostic{Code: "UNSUPPORTED_LOG_GRAMMAR", Line: line.number, Error: "record is outside the pinned repository Action details grammar"}
		}
	}
	line := 0
	if start >= 0 && start < len(lines) {
		line = lines[start].number
	}
	return 0, &ParseDiagnostic{Code: "TRUNCATED_ACTION_DETAILS_GROUP", Line: line, Error: "repository Action details group has no closing runner record"}
}

func validActionDetailValue(text string) bool {
	if !strings.HasPrefix(text, "  ") || len(text) <= 2 || !utf8.ValidString(text) {
		return false
	}
	rest := text[2:]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return false
	}
	for _, char := range rest[:colon] {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func hasStructuralControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func parseImmutable(lines []lineRecord, declared, algorithm string) (Action, int, error) {
	action, err := parseDeclaredAction(declared)
	if err != nil {
		return Action{}, 0, err
	}
	var version, sourceValue, digestAlgorithm, digestValue string
	consumed := 1
	for consumed < len(lines) && consumed <= 8 {
		text := strings.TrimSpace(lines[consumed].text)
		if match := versionPattern.FindStringSubmatch(text); match != nil {
			version = strings.TrimSpace(match[1])
		}
		if match := sourcePattern.FindStringSubmatch(text); match != nil {
			sourceValue = strings.ToLower(match[1])
		}
		if match := digestPattern.FindStringSubmatch(text); match != nil {
			digestAlgorithm, digestValue = strings.ToLower(match[1]), strings.ToLower(match[2])
		}
		consumed++
		if version != "" && sourceValue != "" && digestValue != "" {
			break
		}
	}
	if version == "" || sourceValue == "" || digestAlgorithm != "sha256" || len(digestValue) != 64 {
		return Action{}, 0, errors.New("immutable package fields are missing or malformed")
	}
	if err := validateOID(algorithm, sourceValue); err != nil {
		return Action{}, 0, err
	}
	action.Source = GitObject{Algorithm: algorithm, Value: sourceValue}
	action.Version = version
	action.Digest = Digest{Subject: "github-action-package", Algorithm: digestAlgorithm, Value: digestValue}
	return action, consumed, nil
}

func parseResolvedAction(declared, oid, algorithm string) (Action, error) {
	action, err := parseDeclaredAction(declared)
	if err != nil {
		return Action{}, err
	}
	oid = strings.ToLower(oid)
	if err := validateOID(algorithm, oid); err != nil {
		return Action{}, err
	}
	action.Source = GitObject{Algorithm: algorithm, Value: oid}
	return action, nil
}

func validateOID(algorithm, value string) error {
	if algorithm == "" {
		if len(value) != 40 && len(value) != 64 {
			return fmt.Errorf("untyped Git object length %d is not a full SHA-1 or SHA-256 value", len(value))
		}
		if _, err := hex.DecodeString(value); err != nil {
			return errors.New("Git object is not hexadecimal")
		}
		return nil
	}
	want := 0
	switch algorithm {
	case "sha1":
		want = 40
	case "sha256":
		want = 64
	default:
		return errors.New("repository Git object algorithm is unknown")
	}
	if len(value) != want {
		return fmt.Errorf("Git object length %d does not match %s", len(value), algorithm)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("Git object is not hexadecimal")
	}
	return nil
}

func parseDeclaredAction(value string) (Action, error) {
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return Action{}, errors.New("Action declaration must contain repository and ref")
	}
	pathPart, ref := value[:at], value[at+1:]
	segments := strings.Split(pathPart, "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" || strings.ContainsAny(ref, "\x00\r\n") {
		return Action{}, errors.New("malformed repository Action declaration")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\\\x00") || !utf8.ValidString(segment) {
			return Action{}, errors.New("unsafe Action repository path")
		}
	}
	return Action{Owner: strings.ToLower(segments[0]), Repository: strings.ToLower(segments[1]), Subpath: strings.Join(segments[2:], "/"), Ref: ref}, nil
}

func sameActionDeclaration(left, right string) bool {
	a, errA := parseDeclaredAction(left)
	b, errB := parseDeclaredAction(right)
	return errA == nil && errB == nil && a.Owner == b.Owner && a.Repository == b.Repository && a.Subpath == b.Subpath && a.Ref == b.Ref
}

func parseRunnerMetadata(text string, line lineRecord, source SourceContext, result *ParseResult) {
	for _, prefix := range []struct{ label, value string }{
		{"runner-version", "Current runner version:"},
		{"runner-image", "Image:"},
		{"runner-os", "Operating System:"},
	} {
		if strings.HasPrefix(text, prefix.value) {
			value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(text, prefix.value)), "'")
			if value != "" {
				result.Observations = append(result.Observations, baseObservation(ObservationRunnerMetadata, source, line, nil, "", prefix.label, value))
			}
		}
	}
}

func baseObservation(kind ObservationKind, source SourceContext, line lineRecord, action *Action, phase LifecyclePhase, attribute, value string) Observation {
	grammar := source.Grammar
	if grammar == "" {
		grammar = GrammarVersion
	}
	return Observation{Kind: kind, Scope: source.Scope, Action: action, Phase: phase, Permission: attribute, Access: value, Attribute: attribute, Value: value, EventTime: line.time, LineStart: line.number, LineEnd: line.number, Grammar: grammar}
}

func splitTimestamp(line string) (*time.Time, string) {
	space := strings.IndexByte(line, ' ')
	if space <= 0 {
		return nil, line
	}
	parsed, err := parseRunnerTimestamp(line[:space])
	if err != nil {
		return nil, line
	}
	parsed = parsed.UTC()
	return &parsed, line[space+1:]
}

// parseRunnerTimestamp accepts RFC3339 timestamps while conservatively
// normalizing runner fractions that exceed Go's nanosecond precision. Current
// GitHub.com logs have been observed with ten fractional digits. Discarded
// digits cannot affect ordering at CIRewind's supported precision.
func parseRunnerTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, nil
	}
	dot := strings.IndexByte(value, '.')
	if dot < 0 {
		return time.Time{}, err
	}
	end := dot + 1
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end-(dot+1) <= 9 || end == len(value) {
		return time.Time{}, err
	}
	zone := value[end:]
	if zone != "Z" && !(len(zone) == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':') {
		return time.Time{}, err
	}
	normalized := value[:dot+1+9] + zone
	return time.Parse(time.RFC3339Nano, normalized)
}

type byteCounter struct {
	reader io.Reader
	bytes  int64
}

func (r *byteCounter) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	return n, err
}

// SortObservations provides deterministic output independent of parser worker order.
func SortObservations(observations []Observation) {
	sort.SliceStable(observations, func(i, j int) bool {
		a, b := observations[i], observations[j]
		if a.Scope.RepositoryID != b.Scope.RepositoryID {
			return a.Scope.RepositoryID < b.Scope.RepositoryID
		}
		if a.Scope.RunID != b.Scope.RunID {
			return a.Scope.RunID < b.Scope.RunID
		}
		if a.Scope.RunAttempt != b.Scope.RunAttempt {
			return a.Scope.RunAttempt < b.Scope.RunAttempt
		}
		if a.Scope.JobID != b.Scope.JobID {
			return a.Scope.JobID < b.Scope.JobID
		}
		if a.Scope.StepKey != b.Scope.StepKey {
			return a.Scope.StepKey < b.Scope.StepKey
		}
		if a.LineStart != b.LineStart {
			return a.LineStart < b.LineStart
		}
		return a.Kind < b.Kind
	})
}
