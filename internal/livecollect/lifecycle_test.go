package livecollect

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

func TestExactDefaultActionStepProducesLifecycleWithSetupAndStepEvidence(t *testing.T) {
	api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/action@v1", "success")}, map[string]string{
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	result := collectLifecycle(t, api)

	var started, completed *model.RuntimeActionObservation
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence.Observation.ActionRepository != "fixture/action" {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		switch observation.Kind {
		case model.ObservationLifecycleStarted:
			copy := observation
			started = &copy
		case model.ObservationLifecycleCompleted:
			copy := observation
			completed = &copy
		}
	}
	if started == nil || completed == nil {
		t.Fatalf("exact lifecycle observations missing: started=%v completed=%v", started != nil, completed != nil)
	}
	if started.SourceObjectID == nil || model.GitObjectID(*started.SourceObjectID).Value != testActionSHA {
		t.Fatalf("lifecycle lost exact setup SHA: %#v", started.SourceObjectID)
	}
	if started.Step == nil || started.Step.APIStepNumber == nil || *started.Step.APIStepNumber != 2 || started.Step.LifecyclePhase != model.LifecycleMain || started.Step.Occurrence != 1 {
		t.Fatalf("step identity is not exact: %#v", started.Step)
	}
	var setupEvidence, stepEvidence, jobAPIEvidence model.EvidenceID
	for _, envelope := range result.Batch.Evidence {
		switch envelope.Evidence.Derivation.RuleID {
		case "attempt-log-setup-entry":
			setupEvidence = envelope.Evidence.ID
		case "attempt-log-action-step-entry":
			stepEvidence = envelope.Evidence.ID
		}
		if envelope.Evidence.Source.EndpointTemplate == "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs" && envelope.Evidence.Scope.JobID != nil && *envelope.Evidence.Scope.JobID == 20 {
			jobAPIEvidence = envelope.Evidence.ID
		}
	}
	if setupEvidence == "" || stepEvidence == "" || jobAPIEvidence == "" || !containsEvidence(started.SourceEvidenceIDs, setupEvidence) || !containsEvidence(started.SourceEvidenceIDs, stepEvidence) || !containsEvidence(started.SourceEvidenceIDs, jobAPIEvidence) {
		t.Fatalf("lifecycle evidence chain = %#v, setup=%s step=%s job_api=%s", started.SourceEvidenceIDs, setupEvidence, stepEvidence, jobAPIEvidence)
	}
	if !actionExecutionCapability(result.Batch, archive.CapabilityStructuredOnly, "2") {
		t.Fatalf("action_execution capability does not report exact lifecycle facts: %#v", result.Batch.Capabilities)
	}
}

func TestContradictoryAttemptIdentityCannotReachLifecycleAndValidAttemptContinues(t *testing.T) {
	api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/action@v1", "success")}, map[string]string{
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	validRun := api.attempts[10][1]
	validRun.RunAttempt = 2
	contradictoryRun := validRun
	contradictoryRun.ID = 999
	contradictoryRun.RunAttempt = 1
	api.attempts[10] = map[int]githubapi.WorkflowRun{1: contradictoryRun, 2: validRun}

	validJob := api.jobs[10][1][0]
	validJob.ID = 21
	api.jobs[10] = map[int][]githubapi.WorkflowJob{
		1: {{ID: 20, RunID: 10, Name: "quarantined", Steps: validJob.Steps}},
		2: {validJob},
	}
	api.jobLogs[21] = []byte("valid sibling log\n")
	api.attemptLogs[10][2] = append([]byte(nil), api.attemptLogs[10][1]...)

	result := collectLifecycle(t, api)
	assertMaterialIdentityGap(t, result, "workflow_run_attempt", 1)
	var validStarts int
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactAttempt && fact.Attempt.RunAttempt == 1 {
			t.Fatal("contradictory attempt was persisted as an exact attempt fact")
		}
		if fact.Kind != archive.FactActionOccurrence {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.Execution.RunAttempt == 1 {
			t.Fatalf("contradictory attempt reached Action occurrence or lifecycle: %#v", observation)
		}
		if observation.Execution.RunAttempt == 2 && observation.Execution.JobID == 21 && observation.Kind == model.ObservationLifecycleStarted {
			validStarts++
		}
	}
	if validStarts != 1 {
		t.Fatalf("valid sibling lifecycle starts=%d, want 1", validStarts)
	}
	if calls := api.jobLogCalls(); calls != 1 {
		t.Fatalf("quarantined attempt drove job-log collection: calls=%d, want valid sibling only", calls)
	}
}

func TestContradictoryJobRunIdentityCannotReachLifecycleAndValidJobContinues(t *testing.T) {
	api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/action@v1", "success")}, map[string]string{
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	validJob := api.jobs[10][1][0]
	contradictoryJob := validJob
	contradictoryJob.ID = 21
	contradictoryJob.RunID = 999
	contradictoryJob.Name = "quarantined"
	api.jobs[10][1] = []githubapi.WorkflowJob{contradictoryJob, validJob}
	api.jobLogs[21] = []byte("must not be fetched\n")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"build/1_Set up job.txt":                 setupFixtureLog(),
		"build/2_Run fixtureaction@v1.txt":       repositoryActionFrame("fixture/action@v1"),
		"quarantined/1_Set up job.txt":           setupFixtureLog(),
		"quarantined/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})

	result := collectLifecycle(t, api)
	assertMaterialIdentityGap(t, result, "attempt_job", 1)
	assertMaterialIdentityGap(t, result, "attempt_log_job_identity", 1)
	var validStarts int
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactJob && fact.Job.Execution.JobID == 21 {
			t.Fatal("contradictory job was persisted as an exact job fact")
		}
		if fact.Kind != archive.FactActionOccurrence {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.Execution.JobID == 21 {
			t.Fatalf("contradictory job reached Action occurrence or lifecycle: %#v", observation)
		}
		if observation.Execution.JobID == 20 && observation.Kind == model.ObservationLifecycleStarted {
			validStarts++
		}
	}
	if validStarts != 1 {
		t.Fatalf("valid sibling lifecycle starts=%d, want 1", validStarts)
	}
	if calls := api.jobLogCalls(); calls != 1 {
		t.Fatalf("quarantined job drove job-log collection: calls=%d, want valid sibling only", calls)
	}
}

func TestImmutablePackageLifecycleKeepsDigestAndSourceSHA(t *testing.T) {
	api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/package@v2", "success")}, map[string]string{
		"build/2_Run fixturepackage@v2.txt": repositoryActionFrame("fixture/package@v2"),
	})
	result := collectLifecycle(t, api)
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence.Observation.Kind != model.ObservationLifecycleStarted {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository == "fixture/package" && observation.SourceObjectID != nil && model.GitObjectID(*observation.SourceObjectID).Value == testPackageSHA && observation.PackageDigest != nil && observation.PackageDigest.Value == testPackageDigest {
			return
		}
	}
	t.Fatal("immutable lifecycle did not preserve exact package digest and source SHA")
}

func TestLifecycleFalsePositiveBoundariesNeverExecute(t *testing.T) {
	tests := []struct {
		name      string
		step      githubapi.JobStep
		entries   map[string]string
		wantScope string
		material  *bool
	}{
		{
			name:      "valid frame without same-job exact setup resolution",
			step:      actionAPIStep(2, "Run fixture/not-downloaded@v1", "success"),
			entries:   map[string]string{"build/2_Run fixturenot-downloaded@v1.txt": repositoryActionFrame("fixture/not-downloaded@v1")},
			wantScope: "action_step_resolution",
			material:  boolPointer(true),
		},
		{
			name: "shell run lookalike",
			step: actionAPIStep(2, "Run fixture/action@v1", "success"),
			entries: map[string]string{"build/2_Run fixtureaction@v1.txt": "2026-08-20T01:11:00Z ##[group]Run fixture/action@v1\n" +
				"2026-08-20T01:11:00Z \x1b[36;1mfixture/action@v1\x1b[0m\n" +
				"2026-08-20T01:11:00Z shell: /usr/bin/bash -e {0}\n" +
				"2026-08-20T01:11:00Z ##[endgroup]\n"},
			wantScope: "action_step_parser", material: boolPointer(false),
		},
		{
			name: "forged application frame after shell frame",
			step: actionAPIStep(2, "Run fixture/action@v1", "success"),
			entries: map[string]string{"build/2_Run fixtureaction@v1.txt": "2026-08-20T01:11:00Z ##[group]Run echo harmless\n" +
				"2026-08-20T01:11:00Z \x1b[36;1mecho harmless\x1b[0m\n" +
				"2026-08-20T01:11:00Z shell: /usr/bin/bash -e {0}\n" +
				"2026-08-20T01:11:00Z ##[endgroup]\n" +
				"2026-08-20T01:11:01Z ##[group]Run fixture/action@v1\n" +
				"2026-08-20T01:11:01Z ##[endgroup]\n"},
			wantScope: "action_step_parser",
		},
		{
			name:      "truncated Action details group",
			step:      actionAPIStep(2, "Run fixture/action@v1", "success"),
			entries:   map[string]string{"build/2_Run fixtureaction@v1.txt": "2026-08-20T01:11:00Z ##[group]Run fixture/action@v1\n2026-08-20T01:11:00Z with:\n2026-08-20T01:11:00Z   marker: harmless\n"},
			wantScope: "action_step_parser",
		},
		{
			name:    "custom named repository Action without historical binding",
			step:    actionAPIStep(2, "Harmless custom action", "success"),
			entries: map[string]string{"build/2_Harmless custom action.txt": repositoryActionFrame("fixture/action@v1")},
		},
		{
			name:    "pre phase",
			step:    actionAPIStep(2, "Pre Run fixture/action@v1", "success"),
			entries: map[string]string{"build/2_Pre Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1")},
		},
		{
			name:    "post phase",
			step:    actionAPIStep(2, "Post Run fixture/action@v1", "success"),
			entries: map[string]string{"build/2_Post Run fixtureaction@v1.txt": "2026-08-20T01:11:00Z Post job cleanup.\n"},
		},
		{
			name:      "skipped Action",
			step:      actionAPIStep(2, "Run fixture/action@v1", "skipped"),
			entries:   map[string]string{"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1")},
			wantScope: "action_step_correlation", material: boolPointer(false),
		},
		{
			name:      "canceled Action",
			step:      actionAPIStep(2, "Run fixture/action@v1", "cancelled"),
			entries:   map[string]string{"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1")},
			wantScope: "action_step_correlation", material: boolPointer(true),
		},
		{
			name:      "missing Action entry",
			step:      actionAPIStep(2, "Run fixture/action@v1", "success"),
			entries:   map[string]string{},
			wantScope: "action_step_correlation", material: boolPointer(true),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if strings.EqualFold(test.step.Conclusion, "skipped") {
				test.step.StartedAt = nil
			}
			api := lifecycleAPI(t, []githubapi.JobStep{test.step}, test.entries)
			result := collectLifecycle(t, api)
			assertNoLifecycle(t, result)
			if test.wantScope != "" {
				assertGap(t, result.Gaps, test.wantScope, test.material)
			}
		})
	}
}

func TestStepEntryNameAndJobBindingMustBeUnambiguous(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "success")
	job := githubapi.WorkflowJob{ID: 20, Name: "build", Steps: []githubapi.JobStep{step}}
	if _, _, relevant, diagnostic := correlateActionStepEntry("build/2_wrong label.txt", []githubapi.WorkflowJob{job}); !relevant || diagnostic == "" {
		t.Fatalf("mismatched entry label was not rejected: relevant=%v diagnostic=%q", relevant, diagnostic)
	}
	duplicateName := job
	duplicateName.ID = 21
	if _, _, relevant, diagnostic := correlateActionStepEntry("build/2_Run fixtureaction@v1.txt", []githubapi.WorkflowJob{job, duplicateName}); !relevant || diagnostic == "" {
		t.Fatalf("ambiguous job name was not rejected: relevant=%v diagnostic=%q", relevant, diagnostic)
	}
}

func TestAmbiguousNumbersAndConflictingSetupResolutionNeverExecute(t *testing.T) {
	t.Run("duplicate API step number", func(t *testing.T) {
		api := lifecycleAPI(t, []githubapi.JobStep{
			actionAPIStep(2, "Run fixture/action@v1", "success"),
			actionAPIStep(2, "Run fixture/action@v1", "success"),
		}, map[string]string{"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1")})
		result := collectLifecycle(t, api)
		assertNoLifecycle(t, result)
		assertGap(t, result.Gaps, "action_step_correlation", boolPointer(true))
	})

	t.Run("conflicting exact setup SHAs", func(t *testing.T) {
		api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/action@v1", "success")}, map[string]string{
			"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
		})
		setup := setupFixtureLog() + "2026-08-20T01:10:05Z Download action repository 'fixture/action@v1' (SHA:" + strings.Repeat("f", 40) + ")\n"
		api.attemptLogs[10][1] = makeZIP(t, map[string]string{
			"build/1_Set up job.txt":           setup,
			"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
		})
		result := collectLifecycle(t, api)
		assertNoLifecycle(t, result)
		assertGap(t, result.Gaps, "action_step_resolution", boolPointer(true))
	})

	t.Run("duplicate ZIP entry", func(t *testing.T) {
		api := lifecycleAPI(t, []githubapi.JobStep{actionAPIStep(2, "Run fixture/action@v1", "success")}, nil)
		api.attemptLogs[10][1] = makeZIPEntries(t, []zipFixtureEntry{
			{name: "build/1_Set up job.txt", body: setupFixtureLog()},
			{name: "build/2_Run fixtureaction@v1.txt", body: repositoryActionFrame("fixture/action@v1")},
			{name: "build/2_Run fixtureaction@v1.txt", body: repositoryActionFrame("fixture/action@v1")},
		})
		result := collectLifecycle(t, api)
		assertNoLifecycle(t, result)
		assertGap(t, result.Gaps, "attempt_log", boolPointer(true))
	})
}

func TestDuplicateRefsNeedIndependentStepEntriesAndConcurrentOrderIsUnknown(t *testing.T) {
	steps := []githubapi.JobStep{
		actionAPIStep(2, "Run fixture/action@v1", "success"),
		actionAPIStep(3, "Run fixture/action@v1", "success"),
	}
	// Deliberately overlap the API intervals. This does not invalidate either
	// independently bound start, but it forbids an inferred relative order.
	steps[1].StartedAt = steps[0].StartedAt
	steps[1].CompletedAt = steps[0].CompletedAt
	api := lifecycleAPI(t, steps, map[string]string{
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
		"build/3_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	result := collectLifecycle(t, api)
	if got := lifecycleStarts(result); got != 2 {
		t.Fatalf("independently bound starts = %d, want 2", got)
	}
	assertGap(t, result.Gaps, "step_ordering", boolPointer(false))

	api = lifecycleAPI(t, steps, map[string]string{
		"build/2_Run fixtureaction@v1.txt": repositoryActionFrame("fixture/action@v1"),
	})
	result = collectLifecycle(t, api)
	if got := lifecycleStarts(result); got != 1 {
		t.Fatalf("starts with one missing duplicate-ref entry = %d, want 1", got)
	}
	assertGap(t, result.Gaps, "action_step_correlation", boolPointer(true))
}

func lifecycleAPI(t *testing.T, steps []githubapi.JobStep, entries map[string]string) *fakeAPI {
	t.Helper()
	api := successfulAPI(t, false)
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, steps...)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	allEntries := map[string]string{"build/1_Set up job.txt": setupFixtureLog()}
	for name, body := range entries {
		allEntries[name] = body
	}
	api.attemptLogs[10][1] = makeZIP(t, allEntries)
	return api
}

func actionAPIStep(number int, name, conclusion string) githubapi.JobStep {
	started := time.Date(2026, 8, 20, 1, 11, number, 0, time.UTC)
	completed := started.Add(time.Second)
	return githubapi.JobStep{Number: number, Name: name, Status: "completed", Conclusion: conclusion, StartedAt: &started, CompletedAt: &completed}
}

func TestAPIZeroStepAndJobTimesRemainUnknownOrOpenEnded(t *testing.T) {
	zero := time.Time{}
	valid := time.Date(2026, 8, 20, 3, 4, 5, 0, time.UTC)

	for _, test := range []struct {
		name  string
		event model.EventInterval
		open  bool
	}{
		{name: "step zero start", event: stepEventTime(githubapi.JobStep{StartedAt: &zero, CompletedAt: &valid})},
		{name: "job zero start", event: jobEventTime(githubapi.WorkflowJob{StartedAt: &zero, CompletedAt: &valid})},
		{name: "step zero completion", event: stepEventTime(githubapi.JobStep{StartedAt: &valid, CompletedAt: &zero}), open: true},
		{name: "job zero completion", event: jobEventTime(githubapi.WorkflowJob{StartedAt: &valid, CompletedAt: &zero}), open: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.event.Validate(); err != nil {
				t.Fatalf("event validation: %v", err)
			}
			if test.open {
				if test.event.Start == nil || test.event.End != nil {
					t.Fatalf("event = %#v, want valid start and omitted end", test.event)
				}
				return
			}
			if test.event.Start != nil || test.event.End != nil || test.event.Basis != model.TimeBasisUnknown {
				t.Fatalf("event = %#v, want explicitly unknown time", test.event)
			}
		})
	}
}

func setupFixtureLog() string {
	return strings.Join([]string{
		"2026-08-20T01:10:01Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:02Z ##[group]GITHUB_TOKEN Permissions",
		"2026-08-20T01:10:02Z contents: write",
		"2026-08-20T01:10:02Z ##[endgroup]",
		"2026-08-20T01:10:03Z Download action repository 'fixture/action@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:04Z Download immutable action package 'fixture/package@v2'",
		"2026-08-20T01:10:04Z Version: 2.0.0",
		"2026-08-20T01:10:04Z Source commit SHA: " + testPackageSHA,
		"2026-08-20T01:10:04Z Digest: sha256:" + testPackageDigest,
	}, "\n") + "\n"
}

func repositoryActionFrame(declared string) string {
	return "2026-08-20T01:11:00Z ##[group]Run " + declared + "\n" +
		"2026-08-20T01:11:00Z with:\n" +
		"2026-08-20T01:11:00Z   marker: harmless\n" +
		"2026-08-20T01:11:00Z env:\n" +
		"2026-08-20T01:11:00Z   CI: true\n" +
		"2026-08-20T01:11:00Z ##[endgroup]\n" +
		"2026-08-20T01:11:01Z harmless output\n"
}

func collectLifecycle(t *testing.T, api *fakeAPI) Result {
	t.Helper()
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertNoLifecycle(t *testing.T, result Result) {
	t.Helper()
	if got := lifecycleStarts(result); got != 0 {
		t.Fatalf("false-positive lifecycle starts = %d", got)
	}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleCompleted {
			t.Fatal("false-positive lifecycle completion was emitted")
		}
	}
}

func lifecycleStarts(result Result) int {
	count := 0
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			count++
		}
	}
	return count
}

func assertGap(t *testing.T, gaps []collect.Gap, scope string, material *bool) {
	t.Helper()
	for _, gap := range gaps {
		if gap.Scope == scope && (material == nil || gap.Material == *material) {
			return
		}
	}
	t.Fatalf("gap scope %q material=%v missing from %#v", scope, material, gaps)
}

func assertMaterialIdentityGap(t *testing.T, result Result, scope string, attempt int) {
	t.Helper()
	for _, gap := range result.Gaps {
		if gap.Scope == scope && gap.Attempt == attempt && gap.Reason == collect.GapAmbiguousCorrelation && gap.Material {
			for _, fact := range result.Batch.Facts {
				if fact.Kind == archive.FactCoverageGap && fact.CoverageGap.Assessment.Gap != nil && fact.CoverageGap.Assessment.Gap.Reason == model.GapAmbiguousCorrelation && fact.Subject.RunAttempt != nil && int(*fact.Subject.RunAttempt) == attempt {
					return
				}
			}
			t.Fatalf("identity gap %s was not persisted as coverage", scope)
		}
	}
	t.Fatalf("material identity gap %s/%d missing: %#v", scope, attempt, result.Gaps)
}

func boolPointer(value bool) *bool { return &value }

func containsEvidence(values []model.EvidenceID, wanted model.EvidenceID) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func actionExecutionCapability(batch archive.Batch, status archive.CapabilityStatus, count string) bool {
	for _, capability := range batch.Capabilities {
		if capability.Name == "action_execution" {
			return capability.Status == status && capability.Details["fact_count"] == count
		}
	}
	return false
}

type zipFixtureEntry struct {
	name string
	body string
}

func makeZIPEntries(t *testing.T, entries []zipFixtureEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	// Keep caller order stable while allowing intentionally duplicate names.
	ordered := append([]zipFixtureEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })
	for _, value := range ordered {
		entry, err := writer.Create(value.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, value.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
