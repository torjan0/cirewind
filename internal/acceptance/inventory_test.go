package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/workflow"
)

type fixtureInventory struct {
	APIVersion         string             `json:"apiVersion"`
	Kind               string             `json:"kind"`
	SyntheticOnly      bool               `json:"syntheticOnly"`
	Repository         fixtureRepository  `json:"repository"`
	NormalizedMetadata string             `json:"normalizedMetadata"`
	LogContextDefaults logContextDefaults `json:"logContextDefaults"`
	Identifiers        fixtureIdentifiers `json:"identifiers"`
	Scenarios          []scenario         `json:"scenarios"`
	Supplemental       []scenario         `json:"supplementalFixtures"`
	LogEntries         []logEntry         `json:"logEntries"`
	GlobalAssertions   globalAssertions   `json:"globalAssertions"`
}

type fixtureRepository struct {
	ID            int64  `json:"id"`
	NameWithOwner string `json:"nameWithOwner"`
}

type logContextDefaults struct {
	RepositoryID int64  `json:"repositoryID"`
	Grammar      string `json:"grammar"`
}

type fixtureIdentifiers struct {
	SafeActionSHA          string `json:"safeActionSHA"`
	AffectedActionSHA      string `json:"affectedActionSHA"`
	CalledWorkflowSHA      string `json:"calledWorkflowSHA"`
	WrapperActionSHA       string `json:"wrapperActionSHA"`
	MovedCalledWorkflowSHA string `json:"movedCalledWorkflowSHA"`
	HistoricalWorkflowSHA  string `json:"historicalWorkflowSHA"`
	CurrentWorkflowSHA     string `json:"currentWorkflowSHA"`
	ImmutableDigest        string `json:"immutablePackageDigest"`
}

type scenario struct {
	ID                              string               `json:"id"`
	Title                           string               `json:"title"`
	Workflow                        string               `json:"workflow"`
	CurrentWorkflow                 string               `json:"currentWorkflow"`
	ReusableWorkflow                string               `json:"reusableWorkflow"`
	ActionDefinitions               []string             `json:"actionDefinitions"`
	ExecutionKeys                   []string             `json:"executionKeys"`
	ExpectedFindings                []expectedFinding    `json:"expectedFindings"`
	ForbiddenStates                 []string             `json:"forbiddenStates"`
	ExpectedCredentials             []expectedCredential `json:"expectedCredentialRelationships"`
	ForbiddenCredentials            []string             `json:"forbiddenCredentialRelationships"`
	CalledWorkflowSHAByAttempt      map[string]string    `json:"calledWorkflowSHAByAttempt"`
	JobConclusionByAttempt          map[string]string    `json:"jobConclusionByAttempt"`
	MutableCalledWorkflowAfterFirst string               `json:"mutableCalledWorkflowTagAfterAttemptOne"`
	MissingEvidence                 []string             `json:"missingEvidence"`
	Runner                          *fixtureRunner       `json:"runner"`
	Event                           string               `json:"event"`
	SynchronizationEvidence         []string             `json:"synchronizationEvidence"`
	ForbiddenConclusions            []string             `json:"forbiddenConclusions"`
	ExpectedRuntimeObservationCount *int                 `json:"expectedRuntimeObservationCount"`
	ExpectedEvidenceGap             string               `json:"expectedEvidenceGap"`
	WorkflowDefinitionCommit        string               `json:"workflowDefinitionCommit"`
	CurrentDefaultCommit            string               `json:"currentDefaultCommit"`
	DeclaredSHA                     string               `json:"declaredSHA"`
	RuntimeSHA                      string               `json:"runtimeSHA"`
	AttemptsMustRemainSeparate      bool                 `json:"attemptsMustRemainSeparate"`
	MatrixJobsMustRemainSeparate    bool                 `json:"matrixJobsMustRemainSeparate"`
	PresentDayMustNotOverride       bool                 `json:"presentDayDefinitionMustNotOverrideHistorical"`
	ContradictionPreservesBoth      bool                 `json:"contradictionMustPreserveBothValues"`
	TimeIntervalsOverlap            bool                 `json:"timeIntervalsOverlap"`
	UntrustedCheckoutPresent        *bool                `json:"untrustedCheckoutPresent"`
	JobStarted                      *bool                `json:"jobStarted"`
	EnvironmentGateCrossed          *bool                `json:"environmentGateCrossed"`
}

type expectedFinding struct {
	Attempt       int    `json:"attempt"`
	JobID         int64  `json:"jobID"`
	Component     string `json:"component"`
	State         string `json:"state"`
	Provenance    string `json:"provenance"`
	TransitiveVia string `json:"transitiveVia"`
	SourceSHA     string `json:"sourceSHA"`
	Digest        string `json:"digest"`
}

type expectedCredential struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	CallerName  string `json:"callerName"`
	CalleeName  string `json:"calleeName"`
	Eligible    bool   `json:"eligible"`
	MaximumHops int    `json:"maximumHops"`
}

type fixtureRunner struct {
	Classification string   `json:"classification"`
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	Labels         []string `json:"labels"`
}

type logEntry struct {
	Path                      string         `json:"path"`
	Role                      string         `json:"role"`
	Phase                     string         `json:"phase"`
	ExpectedAction            string         `json:"expectedAction"`
	Scope                     logScope       `json:"scope"`
	APIStatus                 string         `json:"apiStatus"`
	APIConclusion             string         `json:"apiConclusion"`
	GitObjectAlgorithm        string         `json:"gitObjectAlgorithm"`
	GrammarValidated          bool           `json:"grammarValidated"`
	ExpectedObservationCounts map[string]int `json:"expectedObservationCounts"`
	ExpectedDiagnostics       []string       `json:"expectedDiagnostics"`
}

type logScope struct {
	RunID      int64  `json:"runID"`
	RunAttempt int    `json:"runAttempt"`
	JobID      int64  `json:"jobID"`
	StepKey    string `json:"stepKey"`
}

type globalAssertions struct {
	DownloadedWithoutLifecycleNeverMeansExecuted bool     `json:"downloadedWithoutLifecycleNeverMeansExecuted"`
	SecretExistenceAloneNeverMeansExposed        bool     `json:"secretExistenceAloneNeverMeansExposed"`
	OIDCNeverMeansCloudRole                      bool     `json:"oidcCapabilityNeverMeansCloudRoleAssumed"`
	PresentDayNeverReplacesHistorical            bool     `json:"presentDayConfigurationNeverReplacesHistoricalDefinition"`
	MissingLogsNeverMeanNoMatch                  bool     `json:"missingLogsNeverMeanNoMatch"`
	TemporalFollowingNeverMeansCausation         bool     `json:"temporalFollowingNeverMeansCausation"`
	FixtureSecretNames                           []string `json:"fixtureSecretNamesOnly"`
}

type normalizedMetadata struct {
	APIVersion          string                       `json:"apiVersion"`
	SyntheticOnly       bool                         `json:"syntheticOnly"`
	ReferencedWorkflows []referencedWorkflowMetadata `json:"referencedWorkflows"`
	JobsWithoutLogs     []jobWithoutLogs             `json:"jobsWithoutLogs"`
	Runners             []runnerMetadata             `json:"runners"`
	SecretMetadata      []secretMetadata             `json:"secretMetadata"`
	MatrixJobs          []matrixJobMetadata          `json:"matrixJobs"`
}

type referencedWorkflowMetadata struct {
	Scenario          string `json:"scenario"`
	RunID             int64  `json:"runID"`
	RunAttempt        int    `json:"runAttempt"`
	CallerWorkflowSHA string `json:"callerWorkflowSHA"`
	CalledRepository  string `json:"calledRepository"`
	CalledPath        string `json:"calledPath"`
	CalledWorkflowSHA string `json:"calledWorkflowSHA"`
}

type jobWithoutLogs struct {
	Scenario               string  `json:"scenario"`
	RunID                  int64   `json:"runID"`
	RunAttempt             int     `json:"runAttempt"`
	JobID                  int64   `json:"jobID"`
	Status                 string  `json:"status"`
	Conclusion             *string `json:"conclusion"`
	Environment            string  `json:"environment"`
	EnvironmentGateCrossed bool    `json:"environmentGateCrossed"`
	JobStarted             bool    `json:"jobStarted"`
	LogAvailability        string  `json:"logAvailability"`
	NormalizedError        string  `json:"normalizedError"`
	HTTPStatus             *int    `json:"httpStatus"`
	HTTPStatusReason       string  `json:"httpStatusReason"`
}

type runnerMetadata struct {
	Scenario       string   `json:"scenario"`
	JobID          int64    `json:"jobID"`
	Classification string   `json:"classification"`
	RunnerID       *int64   `json:"runnerID"`
	RunnerName     string   `json:"runnerName"`
	RunnerGroup    string   `json:"runnerGroup"`
	Labels         []string `json:"labels"`
}

type secretMetadata struct {
	Name                   string   `json:"name"`
	Scope                  string   `json:"scope"`
	Relationships          []string `json:"relationships"`
	EnvironmentGateCrossed *bool    `json:"environmentGateCrossed"`
}

type matrixJobMetadata struct {
	Scenario   string            `json:"scenario"`
	RunID      int64             `json:"runID"`
	RunAttempt int               `json:"runAttempt"`
	JobID      int64             `json:"jobID"`
	Matrix     map[string]string `json:"matrix"`
}

type parsedLog struct {
	Entry  logEntry
	Bytes  []byte
	Result logparse.ParseResult
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate acceptance test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readRepositoryFile(t testing.TB, name string) []byte {
	t.Helper()
	// Fixture inventory paths are repository-relative slash paths regardless of
	// the host OS. filepath.Clean would rewrite every slash on Windows and reject
	// valid checked-in paths before FromSlash can translate them.
	if !isPortableRepositorySlashPath(name) {
		t.Fatalf("unsafe fixture path %q", name)
	}
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func isPortableRepositorySlashPath(name string) bool {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "\\") ||
		pathpkg.IsAbs(name) || pathpkg.Clean(name) != name || strings.HasPrefix(name, "../") {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || strings.ContainsAny(segment, `<>:"|?*`) ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") ||
			isWindowsReservedPathSegment(segment) {
			return false
		}
		for _, value := range segment {
			if value < 0x20 || value == 0x7f {
				return false
			}
		}
	}
	return true
}

func isWindowsReservedPathSegment(segment string) bool {
	base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

func TestRepositoryFixturePathsUsePortableSlashSemantics(t *testing.T) {
	for _, name := range []string{
		"testdata/fixture-inventory.json",
		".github/actions-pins.json",
		"third_party/licenses/modernc.org/sqlite/v1.57.0/LICENSE-SQLITE",
	} {
		if !isPortableRepositorySlashPath(name) {
			t.Errorf("portable repository path %q was rejected", name)
		}
	}

	for _, name := range []string{
		"", ".", "..", "../outside", "testdata/../outside", "/absolute", `C:/absolute`,
		`testdata\fixture.json`, "testdata//fixture.json", "testdata/fixture?.json", "testdata/NUL.txt",
		"testdata/trailing.", "testdata/trailing ", "testdata/control\x1b.json",
	} {
		if isPortableRepositorySlashPath(name) {
			t.Errorf("non-portable repository path %q was accepted", name)
		}
	}
}

func decodeStrict[T any](t testing.TB, path string) T {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(readRepositoryFile(t, path)))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			t.Fatalf("%s contains multiple JSON values", path)
		}
		t.Fatalf("decode trailing data in %s: %v", path, err)
	}
	return value
}

func loadInventory(t testing.TB) (fixtureInventory, normalizedMetadata) {
	t.Helper()
	inventory := decodeStrict[fixtureInventory](t, "testdata/fixture-inventory.json")
	metadata := decodeStrict[normalizedMetadata](t, inventory.NormalizedMetadata)
	if inventory.APIVersion != "cirewind.dev/fixture-inventory/v1alpha1" || inventory.Kind != "CIRewindSyntheticFixtureInventory" || !inventory.SyntheticOnly {
		t.Fatalf("fixture inventory identity is invalid: %q %q synthetic=%t", inventory.APIVersion, inventory.Kind, inventory.SyntheticOnly)
	}
	if metadata.APIVersion != "cirewind.dev/normalized-github-fixture/v1alpha1" || !metadata.SyntheticOnly {
		t.Fatalf("normalized metadata identity is invalid: %q synthetic=%t", metadata.APIVersion, metadata.SyntheticOnly)
	}
	if inventory.Repository.ID != inventory.LogContextDefaults.RepositoryID || inventory.LogContextDefaults.Grammar != logparse.GrammarVersion {
		t.Fatal("fixture inventory repository or grammar defaults drifted")
	}
	return inventory, metadata
}

func parseInventoryLogs(t testing.TB, inventory fixtureInventory) []parsedLog {
	t.Helper()
	results := make([]parsedLog, 0, len(inventory.LogEntries))
	for _, entry := range inventory.LogEntries {
		data := readRepositoryFile(t, entry.Path)
		role := logparse.EntryRole(entry.Role)
		phase := logparse.LifecyclePhase(entry.Phase)
		result, err := logparse.Parse(context.Background(), bytes.NewReader(data), logparse.SourceContext{
			Scope: logparse.ExecutionScope{
				RepositoryID: inventory.LogContextDefaults.RepositoryID,
				RunID:        entry.Scope.RunID,
				RunAttempt:   entry.Scope.RunAttempt,
				JobID:        entry.Scope.JobID,
				StepKey:      entry.Scope.StepKey,
			},
			Role: role, LifecyclePhase: phase, ExpectedAction: entry.ExpectedAction,
			GitObjectAlgorithm: entry.GitObjectAlgorithm, APIStatus: entry.APIStatus,
			APIConclusion: entry.APIConclusion, GrammarValidated: entry.GrammarValidated,
		})
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Path, err)
		}
		results = append(results, parsedLog{Entry: entry, Bytes: data, Result: result})
	}
	return results
}

func TestFixtureLogInventoryRunsThroughRealParser(t *testing.T) {
	inventory, _ := loadInventory(t)
	parsed := parseInventoryLogs(t, inventory)
	if len(parsed) != len(inventory.LogEntries) || len(parsed) == 0 {
		t.Fatalf("parsed %d of %d fixture log entries", len(parsed), len(inventory.LogEntries))
	}
	for _, value := range parsed {
		t.Run(value.Entry.Path, func(t *testing.T) {
			counts := make(map[string]int)
			for _, observation := range value.Result.Observations {
				counts[string(observation.Kind)]++
				if observation.Scope.RunID != value.Entry.Scope.RunID || observation.Scope.RunAttempt != value.Entry.Scope.RunAttempt || observation.Scope.JobID != value.Entry.Scope.JobID {
					t.Fatalf("observation escaped trusted execution scope: %+v", observation.Scope)
				}
			}
			if !reflect.DeepEqual(counts, value.Entry.ExpectedObservationCounts) {
				t.Fatalf("observation counts = %v, want %v; diagnostics=%+v", counts, value.Entry.ExpectedObservationCounts, value.Result.Diagnostics)
			}
			gotDiagnostics := make([]string, 0, len(value.Result.Diagnostics))
			for _, diagnostic := range value.Result.Diagnostics {
				gotDiagnostics = append(gotDiagnostics, diagnostic.Code)
			}
			sort.Strings(gotDiagnostics)
			wantDiagnostics := append([]string(nil), value.Entry.ExpectedDiagnostics...)
			sort.Strings(wantDiagnostics)
			if strings.Join(gotDiagnostics, "\x00") != strings.Join(wantDiagnostics, "\x00") {
				t.Fatalf("diagnostics = %v, want %v", gotDiagnostics, wantDiagnostics)
			}
			if len(wantDiagnostics) == 0 && !value.Result.Complete {
				t.Fatal("fixture unexpectedly parsed as incomplete")
			}
			if len(wantDiagnostics) != 0 && value.Result.Complete {
				t.Fatal("fixture with expected parser gap was marked complete")
			}
		})
	}
}

func TestIncompleteActionDetailsGroupCannotBecomeExecution(t *testing.T) {
	input := "2026-08-20T06:00:00Z ##[group]Run cirewind-fixtures/harmless@v1\n"
	result, err := logparse.Parse(context.Background(), strings.NewReader(input), logparse.SourceContext{
		Scope: logparse.ExecutionScope{RepositoryID: 900001, RunID: 919999, RunAttempt: 1, JobID: 929999, StepKey: "affected:main"},
		Role:  logparse.RoleActionStep, LifecyclePhase: logparse.PhaseMain,
		ExpectedAction: "cirewind-fixtures/harmless@v1", APIStatus: "completed", APIConclusion: "success", GrammarValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range result.Observations {
		if observation.Kind == logparse.ObservationLifecycleStarted || observation.Kind == logparse.ObservationLifecycleCompleted {
			t.Fatalf("incomplete runner group produced lifecycle evidence: %+v", observation)
		}
	}
	if result.Complete || !hasDiagnostic(result.Diagnostics, "TRUNCATED_ACTION_DETAILS_GROUP") {
		t.Fatalf("incomplete group result = %+v", result)
	}
}

func TestWorkflowInventoryRunsThroughRealParsers(t *testing.T) {
	inventory, _ := loadInventory(t)
	all := append(append([]scenario(nil), inventory.Scenarios...), inventory.Supplemental...)
	seen := make(map[string]bool)
	for _, item := range all {
		for _, path := range []string{item.Workflow, item.CurrentWorkflow, item.ReusableWorkflow} {
			if path == "" || seen[path] {
				continue
			}
			seen[path] = true
			parsed, diagnostics, err := workflow.ParseWorkflow(readRepositoryFile(t, path), workflow.DefaultLimits())
			if err != nil || len(diagnostics) != 0 {
				t.Fatalf("parse workflow %s: err=%v diagnostics=%+v", path, err, diagnostics)
			}
			if len(parsed.Jobs) == 0 {
				t.Fatalf("workflow %s contains no parsed jobs", path)
			}
		}
		for _, path := range item.ActionDefinitions {
			parsed, diagnostics, err := workflow.ParseAction(readRepositoryFile(t, path), workflow.DefaultLimits())
			if err != nil || len(diagnostics) != 0 {
				t.Fatalf("parse Action metadata %s: err=%v diagnostics=%+v", path, err, diagnostics)
			}
			if parsed.IsLeaf || parsed.Using != "composite" || len(parsed.Steps) == 0 {
				t.Fatalf("Action fixture %s did not parse as a non-empty composite: %+v", path, parsed)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("fixture inventory referenced no workflow definitions")
	}
}

func hasDiagnostic(diagnostics []logparse.ParseDiagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func executionKey(runID int64, attempt int, jobID int64) string {
	return fmt.Sprintf("%d:%d:%d", runID, attempt, jobID)
}
