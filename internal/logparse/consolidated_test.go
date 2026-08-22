package logparse

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckedInConsolidatedFixturesMatchPinnedGrammar(t *testing.T) {
	mutable, err := os.ReadFile(filepath.Join("..", "..", "testdata", "github-logs", "consolidated", "current-mutable-synthetic.txt"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := FrameConsolidatedJob(context.Background(), mutable, "build", consolidatedAPISteps())
	if err != nil || !result.Complete || result.Setup == nil || len(result.ActionSteps) != 1 {
		t.Fatalf("mutable checked-in fixture = %+v err=%v", result, err)
	}
	if strings.Contains(string(result.Setup.Bytes), "application-lookalike") || strings.Contains(string(result.Setup.Bytes), "synthetic application error") {
		t.Fatal("checked-in application lookalikes entered the setup frame")
	}

	immutable, err := os.ReadFile(filepath.Join("..", "..", "testdata", "github-logs", "consolidated", "current-immutable-synthetic.txt"))
	if err != nil {
		t.Fatal(err)
	}
	result, err = FrameConsolidatedJob(context.Background(), immutable, "build", nil)
	if err != nil || !result.Complete || result.Setup == nil {
		t.Fatalf("immutable checked-in fixture = %+v err=%v", result, err)
	}
}

func TestLiveConsolidatedFraming(t *testing.T) {
	path := os.Getenv("CIREWIND_LIVE_CONSOLIDATED_LOG")
	jobName := os.Getenv("CIREWIND_LIVE_CONSOLIDATED_JOB")
	if path == "" || jobName == "" {
		t.Skip("set CIREWIND_LIVE_CONSOLIDATED_LOG and CIREWIND_LIVE_CONSOLIDATED_JOB for an explicit transient read-only qualification")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := FrameConsolidatedJob(context.Background(), body, jobName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Setup == nil {
		t.Fatalf("live consolidated setup framing failed: diagnostics=%+v", result.Diagnostics)
	}
}

func TestFrameConsolidatedJobSeparatesSetupAndExactActionLifecycle(t *testing.T) {
	body := consolidatedMutableFixture(
		consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/action@v1") +
			"2026-08-20T01:10:06Z ##[error]application failure must stay outside setup\n" +
			"2026-08-20T01:10:06Z Download action repository 'hostile/lookalike@v1' (SHA:" + strings.Repeat("f", 40) + ")\n",
	)
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", consolidatedAPISteps())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Setup == nil || len(result.Diagnostics) != 0 || len(result.ActionSteps) != 1 {
		t.Fatalf("framing result = %+v", result)
	}
	if strings.Contains(string(result.Setup.Bytes), "application failure") || strings.Contains(string(result.Setup.Bytes), "hostile/lookalike") {
		t.Fatal("later application output entered the setup frame")
	}
	if result.Setup.LineStart != 1 || result.Setup.LineEnd != 7 || result.ActionSteps[0].LineStart != 8 {
		t.Fatalf("source spans were not preserved: setup=%+v action=%+v", result.Setup, result.ActionSteps[0])
	}

	setup, err := Parse(context.Background(), strings.NewReader(string(result.Setup.Bytes)), SourceContext{
		Scope: testScope(), Role: RoleSetup, APIStatus: "completed", APIConclusion: "success",
		Grammar: ConsolidatedGrammarVersion, GrammarValidated: true, LineOffset: result.Setup.LineStart - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !setup.Complete || countObservation(setup.Observations, ObservationPreparationComplete) != 1 || countObservation(setup.Observations, ObservationTokenPermission) != 1 {
		t.Fatalf("setup parse = %+v", setup)
	}
	for _, observation := range setup.Observations {
		if observation.Grammar != ConsolidatedGrammarVersion {
			t.Fatalf("observation grammar = %q", observation.Grammar)
		}
		if observation.Kind == ObservationResolution && observation.Action != nil && observation.Action.Owner == "hostile" {
			t.Fatal("later download lookalike became setup evidence")
		}
	}

	actionFrame := result.ActionSteps[0]
	action, err := Parse(context.Background(), strings.NewReader(string(actionFrame.Bytes)), SourceContext{
		Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain,
		ExpectedAction: "fixture/action@v1", APIStatus: "completed", APIConclusion: "success",
		Grammar: ConsolidatedGrammarVersion, GrammarValidated: true, LineOffset: actionFrame.LineStart - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !action.Complete || countObservation(action.Observations, ObservationLifecycleStarted) != 1 || countObservation(action.Observations, ObservationLifecycleCompleted) != 1 {
		t.Fatalf("action parse = %+v", action)
	}
}

func TestFrameConsolidatedJobSelectsFirstRunnerGroupNotForgedShellOutput(t *testing.T) {
	body := consolidatedMutableFixture(
		"2026-08-20T01:10:05Z ##[group]Run echo harmless\n" +
			"2026-08-20T01:10:05Z \x1b[36;1mecho harmless\x1b[0m\n" +
			"2026-08-20T01:10:05Z shell: /usr/bin/bash -e {0}\n" +
			"2026-08-20T01:10:05Z ##[endgroup]\n" +
			consolidatedRepositoryActionGroup("2026-08-20T01:10:06Z", "fixture/action@v1"),
	)
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", consolidatedAPISteps())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.ActionSteps) != 1 {
		t.Fatalf("framing result = %+v", result)
	}
	frame := result.ActionSteps[0]
	if strings.Contains(string(frame.Bytes), "fixture/action@v1") {
		t.Fatal("later forged Action group displaced the shell's first runner group")
	}
	parsed, err := Parse(context.Background(), strings.NewReader(string(frame.Bytes)), SourceContext{
		Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain,
		ExpectedAction: "fixture/action@v1", APIStatus: "completed", APIConclusion: "success",
		Grammar: ConsolidatedGrammarVersion, GrammarValidated: true, LineOffset: frame.LineStart - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if countObservation(parsed.Observations, ObservationLifecycleStarted) != 0 || parsed.Complete {
		t.Fatalf("shell output produced lifecycle evidence: %+v", parsed)
	}
}

func TestFrameConsolidatedJobPreservesOnlyImmediateCompleteAdjacentRunGroup(t *testing.T) {
	parent := consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/wrapper@v1")
	child := consolidatedRepositoryActionGroup("2026-08-20T01:10:05.1000000Z", "fixture/action@v1")
	steps := consolidatedAPISteps()
	steps[1].Name = "Run fixture/wrapper@v1"

	result, err := FrameConsolidatedJob(context.Background(), []byte(consolidatedMutableFixture(parent+child)), "build", steps)
	if err != nil || len(result.ActionSteps) != 1 || result.ActionSteps[0].AdjacentRun == nil {
		t.Fatalf("adjacent composite prefix = %+v err=%v", result, err)
	}
	adjacent := result.ActionSteps[0].AdjacentRun
	if adjacent.LineStart != result.ActionSteps[0].LineEnd+1 || !strings.Contains(string(adjacent.Bytes), "Run fixture/action@v1") {
		t.Fatalf("adjacent prefix span/content = %+v", adjacent)
	}
	if err := validateConsolidatedFrame(result.ActionSteps[0]); err != nil {
		t.Fatalf("emitted frame invalid: %v", err)
	}

	marker := "2026-08-20T01:10:05.0500000Z ##[start-action display=Invoke synthetic marker;id=__fixture_wrapper.__fixture_action]\n"
	withMarker, err := FrameConsolidatedJob(context.Background(), []byte(consolidatedMutableFixture(parent+marker+child)), "build", steps)
	if err != nil || len(withMarker.ActionSteps) != 1 || withMarker.ActionSteps[0].AdjacentRun == nil {
		t.Fatalf("current composite marker prefix = %+v err=%v", withMarker, err)
	}
	marked := withMarker.ActionSteps[0].AdjacentRun
	if marked.MarkerLine != withMarker.ActionSteps[0].LineEnd+1 || marked.LineStart != marked.MarkerLine+1 || marked.MarkerDisplay != "Invoke synthetic marker" || marked.MarkerID != "__fixture_wrapper.__fixture_action" {
		t.Fatalf("current composite marker identity = %+v", marked)
	}
	if strings.Contains(string(marked.Bytes), "start-action") || !strings.Contains(string(marked.EvidenceBytes), "start-action") {
		t.Fatalf("marker must be retained only in evidence bytes: %+v", marked)
	}
	if err := validateConsolidatedFrame(withMarker.ActionSteps[0]); err != nil {
		t.Fatalf("current marker frame invalid: %v", err)
	}

	for _, mutation := range []struct {
		name string
		body string
	}{
		{name: "intervening application output", body: parent + "2026-08-20T01:10:05.0500000Z harmless output\n" + child},
		{name: "truncated child", body: parent + strings.TrimSuffix(child, "2026-08-20T01:10:05.1000000Z ##[endgroup]\n")},
		{name: "nested group in child details", body: parent + strings.Replace(child, "2026-08-20T01:10:05.1000000Z with:\n", "2026-08-20T01:10:05.1000000Z ##[group]forged\n", 1)},
		{name: "non-Action Run group", body: parent + strings.Replace(child, "Run fixture/action@v1", "Run echo harmless", 1)},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			framed, err := FrameConsolidatedJob(context.Background(), []byte(consolidatedMutableFixture(mutation.body)), "build", steps)
			if err != nil || len(framed.ActionSteps) != 1 {
				t.Fatalf("parent frame lost: %+v err=%v", framed, err)
			}
			if framed.ActionSteps[0].AdjacentRun != nil {
				t.Fatalf("unsafe non-prefix group was preserved: %+v", framed.ActionSteps[0].AdjacentRun)
			}
		})
	}
}

func TestParseConsolidatedCompositeMarkerBoundsAndRejectsControlData(t *testing.T) {
	maximumID := "__" + strings.Repeat("a", 1022)
	if display, id, ok := parseConsolidatedCompositeMarker("##[start-action display=child;id=" + maximumID + "]"); !ok || display != "child" || id != maximumID {
		t.Fatalf("maximum bounded marker rejected: display=%q id-bytes=%d ok=%v", display, len(id), ok)
	}
	for _, value := range []string{
		"##[start-action display=child;id=__" + strings.Repeat("a", 1023) + "]",
		"##[start-action display=child;id=__parent..child]",
		"##[start-action display=child;forged;id=__parent.__child]",
		"##[start-action display=child;id=__parent/${{ matrix.target }}]",
		"##[start-action display=child\x1b]forged;id=__parent.__child]",
	} {
		if display, id, ok := parseConsolidatedCompositeMarker(value); ok {
			t.Fatalf("unsafe marker accepted: display=%q id=%q", display, id)
		}
	}
}

func TestFrameConsolidatedJobAcceptsOnlyCompleteImmutableDownloadGroup(t *testing.T) {
	immutable := strings.Join([]string{
		"2026-08-20T01:10:01Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:02Z ##[group]Download immutable action package 'fixture/package@v2'",
		"2026-08-20T01:10:02Z Version: 2.0.0",
		"2026-08-20T01:10:02Z Source commit SHA: " + strings.Repeat("2", 40),
		"2026-08-20T01:10:02Z Digest: sha256:" + strings.Repeat("3", 64),
		"2026-08-20T01:10:02Z ##[endgroup]",
		"2026-08-20T01:10:04Z Complete job name: build",
	}, "\n") + "\n"
	result, err := FrameConsolidatedJob(context.Background(), []byte(immutable), "build", nil)
	if err != nil || !result.Complete || result.Setup == nil {
		t.Fatalf("complete immutable framing = %+v err=%v", result, err)
	}
	parsed, err := Parse(context.Background(), strings.NewReader(string(result.Setup.Bytes)), SourceContext{Scope: testScope(), Role: RoleSetup, APIConclusion: "success", Grammar: ConsolidatedGrammarVersion, GrammarValidated: true})
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	for _, observation := range parsed.Observations {
		if observation.Kind == ObservationResolution && observation.Action != nil {
			digest = observation.Action.Digest.Value
		}
	}
	if countObservation(parsed.Observations, ObservationPreparationComplete) != 1 || digest != strings.Repeat("3", 64) {
		t.Fatalf("immutable parse = %+v", parsed)
	}

	for _, mutation := range []string{
		strings.Replace(immutable, "2026-08-20T01:10:02Z ##[endgroup]\n", "", 1),
		strings.Replace(immutable, "2026-08-20T01:10:02Z Digest: sha256:"+strings.Repeat("3", 64)+"\n", "", 1),
		strings.Replace(immutable, "Version: 2.0.0", "Version: ../../unsafe", 1),
	} {
		result, err := FrameConsolidatedJob(context.Background(), []byte(mutation), "build", nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.Setup != nil || len(result.Diagnostics) == 0 {
			t.Fatalf("malformed immutable group was accepted: %+v", result)
		}
	}
}

func TestFrameConsolidatedJobAcceptsMultipleCompleteDownloadBlocks(t *testing.T) {
	body := strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z Getting action download info",
		"2026-08-20T01:10:01Z Download action repository 'fixture/wrapper@v1' (SHA:" + strings.Repeat("1", 40) + ")",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:" + strings.Repeat("2", 40) + ")",
		"2026-08-20T01:10:03Z Getting action download info",
		"2026-08-20T01:10:03Z ##[group]Download immutable action package 'fixture/package@v2'",
		"2026-08-20T01:10:03Z Version: 2.0.0",
		"2026-08-20T01:10:03Z Source commit SHA: " + strings.Repeat("3", 40),
		"2026-08-20T01:10:03Z Digest: sha256:" + strings.Repeat("4", 64),
		"2026-08-20T01:10:03Z ##[endgroup]",
		"2026-08-20T01:10:04Z Complete job name: build",
	}, "\n") + "\n"
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", nil)
	if err != nil || !result.Complete || result.Setup == nil || len(result.Diagnostics) != 0 {
		t.Fatalf("multiple complete download blocks = %+v err=%v", result, err)
	}
	parsed, err := Parse(context.Background(), strings.NewReader(string(result.Setup.Bytes)), SourceContext{
		Scope: testScope(), Role: RoleSetup, APIConclusion: "success",
		Grammar: ConsolidatedGrammarVersion, GrammarValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if countObservation(parsed.Observations, ObservationResolution) != 3 || countObservation(parsed.Observations, ObservationPreparationComplete) != 3 {
		t.Fatalf("multiple download parse = %+v", parsed)
	}

	for _, mutation := range []string{
		strings.Replace(body, "2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:"+strings.Repeat("2", 40)+")\n", "", 1),
		strings.Replace(body, "2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:"+strings.Repeat("2", 40)+")", "2026-08-20T01:10:02Z application-controlled record", 1),
	} {
		result, err := FrameConsolidatedJob(context.Background(), []byte(mutation), "build", nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.Setup != nil || len(result.Diagnostics) == 0 {
			t.Fatalf("ambiguous download block was accepted: %+v", result)
		}
	}
}

func TestFrameConsolidatedJobAcceptsExactReusableWorkflowSetupIdentity(t *testing.T) {
	identity := "Uses: fixture/workflows/.github/workflows/reusable.yml@refs/tags/v1 (" + strings.Repeat("5", 40) + ")"
	body := strings.Replace(consolidatedMutableFixture(""), "2026-08-20T01:10:04Z Complete job name: build", "2026-08-20T01:10:03Z "+identity+"\n2026-08-20T01:10:04Z Complete job name: build", 1)
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", nil)
	if err != nil || !result.Complete || result.Setup == nil || len(result.Diagnostics) != 0 {
		t.Fatalf("reusable setup identity = %+v err=%v", result, err)
	}
	objectOnly := strings.Replace(identity, "refs/tags/v1 ("+strings.Repeat("5", 40)+")", strings.Repeat("5", 40), 1)
	objectBody := strings.Replace(body, identity, objectOnly, 1)
	result, err = FrameConsolidatedJob(context.Background(), []byte(objectBody), "build", nil)
	if err != nil || !result.Complete || result.Setup == nil {
		t.Fatalf("object-only reusable setup identity = %+v err=%v", result, err)
	}

	withInputs := strings.Replace(body, "2026-08-20T01:10:03Z "+identity, "2026-08-20T01:10:03Z "+identity+"\n2026-08-20T01:10:03Z ##[group] Inputs\n2026-08-20T01:10:03Z   marker: harmless\n2026-08-20T01:10:03Z ##[endgroup]", 1)
	result, err = FrameConsolidatedJob(context.Background(), []byte(withInputs), "build", nil)
	if err != nil || !result.Complete || result.Setup == nil {
		t.Fatalf("reusable setup inputs = %+v err=%v", result, err)
	}
	parsed, err := Parse(context.Background(), strings.NewReader(string(result.Setup.Bytes)), SourceContext{
		Scope: testScope(), Role: RoleSetup, APIConclusion: "success", Grammar: ConsolidatedGrammarVersion, GrammarValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range parsed.Observations {
		if observation.Action != nil && observation.Action.Owner == "hostile" {
			t.Fatal("reusable input tail forged an Action observation")
		}
	}
	for _, mutation := range []string{
		strings.Replace(body, "refs/tags/v1", "refs/tags/../v1", 1),
		strings.Replace(body, strings.Repeat("5", 40), strings.Repeat("g", 40), 1),
		strings.Replace(body, "2026-08-20T01:10:03Z "+identity, "2026-08-20T01:10:03Z "+identity+"\n2026-08-20T01:10:03Z application-controlled record", 1),
		strings.Replace(withInputs, "2026-08-20T01:10:03Z   marker: harmless", "2026-08-20T01:10:03Z Download action repository 'hostile/lookalike@v1' (SHA:"+strings.Repeat("6", 40)+")", 1),
	} {
		result, err := FrameConsolidatedJob(context.Background(), []byte(mutation), "build", nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.Setup != nil || len(result.Diagnostics) == 0 {
			t.Fatalf("unsafe reusable setup identity was accepted: %+v", result)
		}
	}
}

func TestFrameConsolidatedJobRejectsAmbiguousAndUnsafeStructure(t *testing.T) {
	base := consolidatedMutableFixture("")
	tests := []struct {
		name    string
		body    string
		jobName string
		steps   []ConsolidatedStep
	}{
		{name: "wrong complete job", body: strings.Replace(base, "Complete job name: build", "Complete job name: other", 1), jobName: "build"},
		{name: "run before boundary", body: strings.Replace(base, "2026-08-20T01:10:04Z Complete job name: build", "2026-08-20T01:10:03Z ##[group]Run fixture/action@v1\n2026-08-20T01:10:04Z Complete job name: build", 1), jobName: "build"},
		{name: "download before sentinel", body: strings.Replace(base, "2026-08-20T01:10:02Z Getting action download info", "2026-08-20T01:10:01Z Download action repository 'fixture/early@v1' (SHA:"+strings.Repeat("2", 40)+")\n2026-08-20T01:10:02Z Getting action download info", 1), jobName: "build"},
		{name: "unsafe API job", body: base, jobName: "build\nforged"},
		{name: "non-monotonic time", body: strings.Replace(base, "2026-08-20T01:10:04Z Complete job name", "2026-08-20T01:09:59Z Complete job name", 1), jobName: "build"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := FrameConsolidatedJob(context.Background(), []byte(test.body), test.jobName, test.steps)
			if err != nil {
				t.Fatal(err)
			}
			if result.Complete || result.Setup != nil || len(result.Diagnostics) == 0 {
				t.Fatalf("unsafe structure was accepted: %+v", result)
			}
		})
	}
}

func TestFrameConsolidatedJobNeverFramesSkippedCancelledOrAmbiguousSteps(t *testing.T) {
	body := consolidatedMutableFixture(consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/action@v1"))
	started := time.Date(2026, 8, 20, 1, 10, 5, 0, time.UTC)
	completed := started.Add(2 * time.Second)
	for _, conclusion := range []string{"skipped", "cancelled", "canceled"} {
		steps := []ConsolidatedStep{{Number: 2, Name: "Run fixture/action@v1", Status: "completed", Conclusion: conclusion, StartedAt: &started, CompletedAt: &completed}}
		result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", steps)
		if err != nil || len(result.ActionSteps) != 0 {
			t.Fatalf("%s step was framed: %+v err=%v", conclusion, result, err)
		}
	}
	steps := []ConsolidatedStep{
		{Number: 2, Name: "Run fixture/action@v1", Status: "completed", Conclusion: "success", StartedAt: &started, CompletedAt: &completed},
		{Number: 3, Name: "Run fixture/other@v1", Status: "completed", Conclusion: "success", StartedAt: &started, CompletedAt: &completed},
	}
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", steps)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ActionSteps) != 0 || len(result.Diagnostics) != 2 {
		t.Fatalf("ambiguous intervals were framed: %+v", result)
	}
}

func TestFrameConsolidatedJobUsesExactHistoricalBindingForCustomRoundedStep(t *testing.T) {
	started := time.Date(2026, 8, 20, 1, 10, 5, 0, time.UTC)
	completed := started
	body := consolidatedMutableFixture(
		consolidatedRepositoryActionGroup("2026-08-20T01:10:05.2500000Z", "fixture/action@v1") +
			"2026-08-20T01:10:05.3000000Z harmless later output\n",
	)
	step := ConsolidatedStep{
		Number: 2, Name: "Custom marker", ExpectedAction: "fixture/action@v1", HistoricalBound: true,
		Status: "completed", Conclusion: "success", StartedAt: &started, CompletedAt: &completed,
	}
	result, err := FrameConsolidatedJob(context.Background(), []byte(body), "build", []ConsolidatedStep{step})
	if err != nil || len(result.ActionSteps) != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("historically bound rounded step=%+v err=%v", result, err)
	}
	parsed, err := Parse(context.Background(), strings.NewReader(string(result.ActionSteps[0].Bytes)), SourceContext{
		Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain,
		ExpectedAction: step.ExpectedAction, APIStatus: step.Status, APIConclusion: step.Conclusion,
		Grammar: ConsolidatedGrammarVersion, GrammarValidated: true,
	})
	if err != nil || countObservation(parsed.Observations, ObservationLifecycleStarted) != 1 {
		t.Fatalf("historically bound frame parse=%+v err=%v", parsed, err)
	}

	for _, mutation := range []struct {
		name string
		body string
		step ConsolidatedStep
	}{
		{name: "historical uses mismatch", body: strings.Replace(body, "##[group]Run fixture/action@v1", "##[group]Run fixture/other@v1", 1), step: step},
		{name: "shell group precedes Action", body: consolidatedMutableFixture("2026-08-20T01:10:05.1000000Z ##[group]Run echo harmless\n2026-08-20T01:10:05.1000000Z shell: bash -e {0}\n2026-08-20T01:10:05.1000000Z ##[endgroup]\n" + consolidatedRepositoryActionGroup("2026-08-20T01:10:05.2500000Z", "fixture/action@v1")), step: step},
		{name: "custom name without historical binding", body: body, step: func() ConsolidatedStep {
			value := step
			value.HistoricalBound, value.ExpectedAction = false, ""
			return value
		}()},
		{name: "skipped historical step", body: body, step: func() ConsolidatedStep { value := step; value.Conclusion = "skipped"; return value }()},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			result, err := FrameConsolidatedJob(context.Background(), []byte(mutation.body), "build", []ConsolidatedStep{mutation.step})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.ActionSteps) != 0 {
				t.Fatalf("near miss produced a lifecycle frame: %+v", result)
			}
		})
	}
}

func FuzzFrameConsolidatedJob(f *testing.F) {
	f.Add(consolidatedMutableFixture(
		consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/wrapper@v1") +
			"2026-08-20T01:10:05.0500000Z ##[start-action display=Invoke child;id=__fixture_wrapper.__fixture_action]\n" +
			consolidatedRepositoryActionGroup("2026-08-20T01:10:05.1000000Z", "fixture/action@v1"),
	))
	f.Add(consolidatedMutableFixture(consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/action@v1")))
	f.Add(consolidatedMutableFixture("2026-08-20T01:10:05Z ##[group]Run echo harmless\n2026-08-20T01:10:05Z shell: bash -e {0}\n2026-08-20T01:10:05Z ##[endgroup]\n"))
	f.Add(strings.Replace(consolidatedMutableFixture(""), "2026-08-20T01:10:04Z Complete job name: build", "2026-08-20T01:10:03Z Getting action download info\n2026-08-20T01:10:03Z Download action repository 'fixture/nested@v1' (SHA:"+strings.Repeat("2", 40)+")\n2026-08-20T01:10:04Z Complete job name: build", 1))
	f.Add(consolidatedMutableFixture(consolidatedRepositoryActionGroup("2026-08-20T01:10:05Z", "fixture/wrapper@v1") + consolidatedRepositoryActionGroup("2026-08-20T01:10:05.1000000Z", "fixture/action@v1")))
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > MaxConsolidatedJobBytes+1 {
			input = input[:MaxConsolidatedJobBytes+1]
		}
		result, _ := FrameConsolidatedJob(context.Background(), []byte(input), "build", consolidatedAPISteps())
		for _, frame := range result.ActionSteps {
			if err := validateConsolidatedFrame(frame); err != nil {
				t.Fatalf("invalid emitted frame: %v", err)
			}
			parsed, _ := Parse(context.Background(), strings.NewReader(string(frame.Bytes)), SourceContext{
				Scope: testScope(), Role: RoleActionStep, LifecyclePhase: PhaseMain,
				ExpectedAction: "fixture/action@v1", APIStatus: "completed", APIConclusion: "success",
				Grammar: ConsolidatedGrammarVersion, GrammarValidated: true, LineOffset: frame.LineStart - 1,
			})
			for _, observation := range parsed.Observations {
				if observation.Kind != ObservationLifecycleStarted && observation.Kind != ObservationLifecycleCompleted {
					continue
				}
				if observation.Action == nil || observation.Action.Owner != "fixture" || observation.Action.Repository != "action" || observation.Action.Ref != "v1" {
					t.Fatalf("lifecycle escaped exact API declaration: %+v", observation)
				}
			}
		}
	})
}

func consolidatedMutableFixture(suffix string) string {
	return strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z ##[group]GITHUB_TOKEN Permissions",
		"2026-08-20T01:10:01Z contents: write",
		"2026-08-20T01:10:01Z ##[endgroup]",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:" + fixtureOID + ")",
		"2026-08-20T01:10:04Z Complete job name: build",
	}, "\n") + "\n" + suffix
}

func consolidatedRepositoryActionGroup(when, declared string) string {
	return when + " ##[group]Run " + declared + "\n" +
		when + " with:\n" +
		when + "   marker: harmless\n" +
		when + " env:\n" +
		when + "   CI: true\n" +
		when + " ##[endgroup]\n"
}

func consolidatedAPISteps() []ConsolidatedStep {
	setupStart := time.Date(2026, 8, 20, 1, 10, 0, 0, time.UTC)
	setupEnd := time.Date(2026, 8, 20, 1, 10, 5, 0, time.UTC)
	actionStart := setupEnd
	actionEnd := actionStart.Add(3 * time.Second)
	completeStart := actionEnd.Add(time.Second)
	completeEnd := completeStart.Add(time.Second)
	return []ConsolidatedStep{
		{Number: 1, Name: "Set up job", Status: "completed", Conclusion: "success", StartedAt: &setupStart, CompletedAt: &setupEnd},
		{Number: 2, Name: "Run fixture/action@v1", Status: "completed", Conclusion: "success", StartedAt: &actionStart, CompletedAt: &actionEnd},
		{Number: 3, Name: "Complete job", Status: "completed", Conclusion: "success", StartedAt: &completeStart, CompletedAt: &completeEnd},
	}
}

func countObservation(values []Observation, kind ObservationKind) int {
	count := 0
	for _, value := range values {
		if value.Kind == kind {
			count++
		}
	}
	return count
}
