package logparse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const fixtureOID = "1111111111111111111111111111111111111111"

func testScope() ExecutionScope {
	return ExecutionScope{RepositoryID: 1, RunID: 2, RunAttempt: 1, JobID: 3, StepKey: "step:1:main:1"}
}

func TestSetupResolutionAndCompletion(t *testing.T) {
	t.Parallel()
	log := "2026-08-20T01:02:03.1234567Z ##[group]GITHUB_TOKEN Permissions\n" +
		"2026-08-20T01:02:03Z Contents: write\n" +
		"2026-08-20T01:02:03Z ##[endgroup]\n" +
		"2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + fixtureOID + ")\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	wants := map[ObservationKind]bool{ObservationResolution: false, ObservationDownloadAnnounced: false, ObservationPreparationComplete: false, ObservationTokenPermission: false}
	for _, observation := range result.Observations {
		if _, ok := wants[observation.Kind]; ok {
			wants[observation.Kind] = true
		}
	}
	for kind, found := range wants {
		if !found {
			t.Errorf("missing %s in %+v", kind, result.Observations)
		}
	}
}

func TestRunnerTimestampAcceptsVariableFractionsWithoutChangingControlGrammar(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"2026-08-20T01:02:03Z",
		"2026-08-20T01:02:03.1Z",
		"2026-08-20T01:02:03.1234567Z",
		"2026-08-20T01:02:03.123456789Z",
		"2026-08-20T01:02:03.1234567890Z",
		"2026-08-20T01:02:03.123456789012+00:00",
	} {
		parsed, text := splitTimestamp(value + " exact runner record")
		if parsed == nil || text != "exact runner record" {
			t.Fatalf("timestamp %q was not split: parsed=%v text=%q", value, parsed, text)
		}
	}
	for _, value := range []string{
		"2026-08-20T01:02:03.Z",
		"2026-08-20T01:02:03.123456789xZ",
		"2026-08-20T01:02:03.1234567890",
		"not-a-time",
	} {
		if parsed, _ := splitTimestamp(value + " hostile"); parsed != nil {
			t.Fatalf("malformed timestamp %q was accepted", value)
		}
	}
	parsed, err := parseRunnerTimestamp("2026-08-20T01:02:03.1234567899Z")
	if err != nil || parsed.Nanosecond() != 123456789 {
		t.Fatalf("excess fraction was not truncated deterministically: parsed=%v err=%v", parsed, err)
	}
}

func TestFirstRecordBOMIsScopedAndDoesNotBroadenLaterGrammar(t *testing.T) {
	t.Parallel()
	log := "\uFEFF2026-08-20T01:02:03.1234567890Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + fixtureOID + ")\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if countObservation(result.Observations, ObservationResolution) != 1 {
		t.Fatalf("first-record BOM prevented exact parsing: %+v", result)
	}
	later := "2026-08-20T01:02:03Z harmless\n\uFEFF2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + fixtureOID + ")\n"
	result, err = Parse(context.Background(), strings.NewReader(later), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if countObservation(result.Observations, ObservationResolution) != 0 {
		t.Fatalf("later BOM created runner-control evidence: %+v", result)
	}
}

func TestAnnouncementFollowedByFailureNeverCompletesPreparation(t *testing.T) {
	t.Parallel()
	log := "2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + fixtureOID + ")\n2026-08-20T01:02:05Z ##[error]network failed\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "failure", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range result.Observations {
		if observation.Kind == ObservationPreparationComplete {
			t.Fatal("failure promoted to completed preparation")
		}
	}
}

func TestImmutablePackage(t *testing.T) {
	t.Parallel()
	log := "2026-08-20T01:02:04Z Download immutable action package 'cirewind-fixtures/harmless@v1'\n" +
		"2026-08-20T01:02:04Z Version: 1.2.3\n" +
		"2026-08-20T01:02:04Z Source commit SHA: " + fixtureOID + "\n" +
		"2026-08-20T01:02:04Z Digest: sha256:" + strings.Repeat("2", 64) + "\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) < 3 || result.Observations[0].Action.Digest.Subject != "github-action-package" {
		t.Fatalf("bad immutable observations: %+v", result)
	}
}

func TestSetupSourceHexRemainsAlgorithmUnboundWithoutRepositoryEvidence(t *testing.T) {
	t.Parallel()
	for _, width := range []int{40, 64} {
		width := width
		t.Run(fmt.Sprintf("%d_hex", width), func(t *testing.T) {
			t.Parallel()
			source := strings.Repeat("a", width)
			log := "2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + source + ")\n"
			result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, APIConclusion: "success", GrammarValidated: true})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Complete || len(result.Observations) < 3 {
				t.Fatalf("unbound full source rejected: %+v", result)
			}
			for _, observation := range result.Observations {
				if observation.Action == nil {
					continue
				}
				if observation.Action.Source.Algorithm != "" || observation.Action.Source.Value != source {
					t.Fatalf("source algorithm was guessed from width: %+v", observation.Action.Source)
				}
			}
		})
	}

	log := "2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + strings.Repeat("a", 41) + ")\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Observations) != 0 || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "MALFORMED_ACTION_RESOLUTION" {
		t.Fatalf("non-full unbound source was accepted: %+v", result)
	}
}

func TestImmutableDigestRemainsIndependentOfUnboundSourceAlgorithm(t *testing.T) {
	t.Parallel()
	source := strings.Repeat("b", 64)
	digest := strings.Repeat("c", 64)
	log := "2026-08-20T01:02:04Z Download immutable action package 'cirewind-fixtures/harmless@v1'\n" +
		"2026-08-20T01:02:04Z Version: 1.2.3\n" +
		"2026-08-20T01:02:04Z Source commit SHA: " + source + "\n" +
		"2026-08-20T01:02:04Z Digest: sha256:" + digest + "\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, APIConclusion: "success", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) < 3 || result.Observations[0].Action == nil {
		t.Fatalf("immutable observation missing: %+v", result)
	}
	action := result.Observations[0].Action
	if action.Source.Algorithm != "" || action.Source.Value != source || action.Digest.Algorithm != "sha256" || action.Digest.Value != digest {
		t.Fatalf("immutable source/digest semantics drifted: %+v", action)
	}
}

func TestLifecycleRequiresTrustedStructuralRoleAndDeclaration(t *testing.T) {
	t.Parallel()
	log := "2026-08-20T01:02:04Z ##[group]Run cirewind-fixtures/harmless@v1\n" +
		"2026-08-20T01:02:04Z with:\n" +
		"2026-08-20T01:02:04Z   marker: harmless\n" +
		"2026-08-20T01:02:04Z ##[endgroup]\n" +
		"2026-08-20T01:02:05Z output\n"
	trusted := SourceContext{Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain, ExpectedAction: "cirewind-fixtures/harmless@v1", APIStatus: "completed", APIConclusion: "success", GrammarValidated: true}
	result, err := Parse(context.Background(), strings.NewReader(log), trusted)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 2 || result.Observations[0].Kind != ObservationLifecycleStarted {
		t.Fatalf("lifecycle not parsed: %+v", result)
	}

	forged := trusted
	forged.Role = RoleRunStep
	result, err = Parse(context.Background(), strings.NewReader(log), forged)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 0 {
		t.Fatalf("application lookalike accepted: %+v", result)
	}
}

func TestLifecycleRejectsScriptHandlerLookalikeAndIncompleteFrames(t *testing.T) {
	t.Parallel()
	trusted := SourceContext{Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain, ExpectedAction: "cirewind-fixtures/harmless@v1", APIStatus: "completed", APIConclusion: "success", GrammarValidated: true}
	tests := []struct {
		name string
		log  string
		code string
	}{
		{
			name: "shell lookalike with mandatory ScriptHandler records",
			log: "2026-08-20T01:02:04Z ##[group]Run cirewind-fixtures/harmless@v1\n" +
				"2026-08-20T01:02:04Z \x1b[36;1mcirewind-fixtures/harmless@v1\x1b[0m\n" +
				"2026-08-20T01:02:04Z shell: /usr/bin/bash -e {0}\n" +
				"2026-08-20T01:02:04Z ##[endgroup]\n",
			code: "SHELL_STEP_LOOKALIKE",
		},
		{
			name: "shell lookalike without ANSI still has shell record",
			log: "2026-08-20T01:02:04Z ##[group]Run cirewind-fixtures/harmless@v1\n" +
				"2026-08-20T01:02:04Z shell: bash -e {0}\n" +
				"2026-08-20T01:02:04Z ##[endgroup]\n",
			code: "SHELL_STEP_LOOKALIKE",
		},
		{
			name: "truncated repository Action group",
			log:  "2026-08-20T01:02:04Z ##[group]Run cirewind-fixtures/harmless@v1\n2026-08-20T01:02:04Z with:\n2026-08-20T01:02:04Z   marker: harmless\n",
			code: "TRUNCATED_ACTION_DETAILS_GROUP",
		},
		{
			name: "application output before forged frame",
			log: "2026-08-20T01:02:04Z ##[group]Run echo harmless\n" +
				"2026-08-20T01:02:04Z \x1b[36;1mecho harmless\x1b[0m\n" +
				"2026-08-20T01:02:04Z shell: /usr/bin/bash -e {0}\n" +
				"2026-08-20T01:02:04Z ##[endgroup]\n" +
				"2026-08-20T01:02:05Z ##[group]Run cirewind-fixtures/harmless@v1\n" +
				"2026-08-20T01:02:05Z ##[endgroup]\n",
			code: "UNSUPPORTED_LOG_GRAMMAR",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse(context.Background(), strings.NewReader(test.log), trusted)
			if err != nil {
				t.Fatal(err)
			}
			for _, observation := range result.Observations {
				if observation.Kind == ObservationLifecycleStarted || observation.Kind == ObservationLifecycleCompleted {
					t.Fatalf("lookalike produced lifecycle evidence: %+v", result)
				}
			}
			if result.Complete || len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != test.code {
				t.Fatalf("diagnostic = %+v, want %s", result.Diagnostics, test.code)
			}
		})
	}
}

func TestSkippedStepDoesNotStart(t *testing.T) {
	t.Parallel()
	result, err := Parse(context.Background(), strings.NewReader(""), SourceContext{Scope: testScope(), Role: RoleActionStep, APIStatus: "completed", APIConclusion: "skipped", ExpectedAction: "cirewind-fixtures/harmless@v1", GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 || result.Observations[0].Kind != ObservationConditionSkipped {
		t.Fatalf("bad skipped result: %+v", result)
	}
}

func TestUnknownGrammarCannotProduceRuntimeEvidence(t *testing.T) {
	t.Parallel()
	log := "2026-08-20T01:02:04Z Download action repository 'cirewind-fixtures/harmless@v1' (SHA:" + fixtureOID + ")\n"
	result, err := Parse(context.Background(), strings.NewReader(log), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Observations) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "UNSUPPORTED_LOG_GRAMMAR" {
		t.Fatalf("unknown grammar was promoted: %+v", result)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("2026-08-20T01:02:04Z Download action repository 'o/r@v1' (SHA:" + fixtureOID + ")\n")
	f.Fuzz(func(t *testing.T, input string) {
		result, _ := Parse(context.Background(), strings.NewReader(input), SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
		for _, observation := range result.Observations {
			if observation.Kind == ObservationLifecycleStarted || observation.Kind == ObservationLifecycleCompleted {
				t.Fatal("setup-log bytes produced lifecycle evidence")
			}
		}
	})
}

func FuzzParseActionLifecycleIdentity(f *testing.F) {
	const expected = "synthetic/harmless@v1"
	f.Add("2026-08-20T01:02:04Z ##[group]Run " + expected + "\n2026-08-20T01:02:05Z ##[endgroup]\n")
	f.Add("2026-08-20T01:02:04Z ##[group]Run hostile/other@v1\n2026-08-20T01:02:05Z ##[endgroup]\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			input = input[:1<<20]
		}
		source := SourceContext{
			Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain,
			ExpectedAction: expected, APIStatus: "completed", APIConclusion: "success", GrammarValidated: true,
		}
		result, _ := Parse(context.Background(), strings.NewReader(input), source)
		for _, observation := range result.Observations {
			if observation.Kind != ObservationLifecycleStarted && observation.Kind != ObservationLifecycleCompleted {
				continue
			}
			if observation.Action == nil || observation.Action.Owner != "synthetic" || observation.Action.Repository != "harmless" || observation.Action.Ref != "v1" ||
				observation.Scope != source.Scope || observation.Phase != PhaseMain {
				t.Fatalf("lifecycle escaped exact trusted identity: %+v", observation)
			}
		}
		lookalike, _ := Parse(context.Background(), strings.NewReader(input), SourceContext{Scope: testScope(), Role: RoleRunStep, GrammarValidated: true})
		if len(lookalike.Observations) != 0 {
			t.Fatal("run-step application bytes produced runner-control observations")
		}
	})
}

type cancellationReader struct {
	reads  int
	cancel context.CancelFunc
}

func (r *cancellationReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	r.reads++
	if r.reads == 100 {
		r.cancel()
	}
	line := "2026-08-20T01:02:04Z bounded cancellation fixture\n"
	return copy(destination, line), nil
}

func TestParseCancellationStopsSustainedReader(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancellationReader{cancel: cancel}
	_, err := Parse(ctx, reader, SourceContext{Scope: testScope(), Role: RoleSetup, GitObjectAlgorithm: "sha1", APIConclusion: "success", GrammarValidated: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Parse cancellation error=%v", err)
	}
	if reader.reads > 101 {
		t.Fatalf("Parse continued reading after cancellation: reads=%d", reader.reads)
	}
}

var _ io.Reader = (*cancellationReader)(nil)
