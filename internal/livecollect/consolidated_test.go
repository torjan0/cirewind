package livecollect

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

func TestConsolidatedWholeJobProducesExactDownloadsAndStrictLifecycle(t *testing.T) {
	steps := []githubapi.JobStep{
		actionAPIStep(2, "Run fixture/action@v1", "success"),
		actionAPIStep(3, "Run fixture/package@v2", "success"),
	}
	api := consolidatedAPI(t, "build", steps, consolidatedSetupBlock("build")+
		consolidatedActionGroupAt(*steps[0].StartedAt, "fixture/action@v1")+
		consolidatedActionGroupAt(*steps[1].StartedAt, "fixture/package@v2"))
	result := collectLifecycle(t, api)
	if starts := lifecycleStarts(result); starts != 2 {
		t.Fatalf("consolidated lifecycle starts=%d, want 2", starts)
	}

	var mutableDownloaded, immutableDownloaded, immutableStarted bool
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		switch {
		case observation.ActionRepository == "fixture/action" && observation.Kind == model.ObservationPreparationComplete:
			mutableDownloaded = true
		case observation.ActionRepository == "fixture/package" && observation.Kind == model.ObservationPreparationComplete && observation.PackageDigest != nil && observation.PackageDigest.Value == testPackageDigest:
			immutableDownloaded = true
		case observation.ActionRepository == "fixture/package" && observation.Kind == model.ObservationLifecycleStarted && observation.PackageDigest != nil && observation.PackageDigest.Value == testPackageDigest && observation.SourceObjectID != nil && model.GitObjectID(*observation.SourceObjectID).Value == testPackageSHA:
			immutableStarted = true
		}
	}
	if !mutableDownloaded || !immutableDownloaded || !immutableStarted {
		t.Fatalf("consolidated facts missing: mutable_download=%v immutable_download=%v immutable_start=%v", mutableDownloaded, immutableDownloaded, immutableStarted)
	}

	var setupFrame, actionFrames int
	for _, envelope := range result.Batch.Evidence {
		switch envelope.Evidence.Derivation.RuleID {
		case "attempt-log-consolidated-setup-frame":
			setupFrame++
		case "attempt-log-consolidated-action-step-frame":
			actionFrames++
		}
	}
	if setupFrame != 1 || actionFrames != 2 {
		t.Fatalf("consolidated evidence frames: setup=%d action=%d", setupFrame, actionFrames)
	}
	if !actionExecutionCapability(result.Batch, archive.CapabilityStructuredOnly, "4") {
		t.Fatalf("action execution capability = %#v", result.Batch.Capabilities)
	}
}

func TestConsolidatedSkippedAndDownloadOnlyNeverExecuteOrConsumeLaterLookalikes(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "skipped")
	step.StartedAt = nil
	body := consolidatedSetupBlock("build") +
		"2026-08-20T01:11:02Z ##[error]later application error\n" +
		"2026-08-20T01:11:03Z Download action repository 'hostile/lookalike@v1' (SHA:" + strings.Repeat("f", 40) + ")\n" +
		consolidatedActionGroupAt(time.Date(2026, 8, 20, 1, 11, 4, 0, time.UTC), "fixture/action@v1")
	api := consolidatedAPI(t, "build", []githubapi.JobStep{step}, body)
	result := collectLifecycle(t, api)
	assertNoLifecycle(t, result)

	var completed, hostile bool
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository == "fixture/action" && observation.Kind == model.ObservationPreparationComplete {
			completed = true
		}
		if observation.ActionRepository == "hostile/lookalike" {
			hostile = true
		}
	}
	if !completed || hostile {
		t.Fatalf("setup isolation failed: completed=%v hostile_lookalike=%v", completed, hostile)
	}
	assertGap(t, result.Gaps, "action_step_correlation", boolPointer(false))
}

func TestConsolidatedShellOutputLookalikeNeverExecutes(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "success")
	when := step.StartedAt.UTC().Format(time.RFC3339Nano)
	body := consolidatedSetupBlock("build") +
		when + " ##[group]Run echo harmless\n" +
		when + " \x1b[36;1mecho harmless\x1b[0m\n" +
		when + " shell: /usr/bin/bash -e {0}\n" +
		when + " ##[endgroup]\n" +
		consolidatedActionGroupAt(step.StartedAt.Add(500*time.Millisecond), "fixture/action@v1")
	api := consolidatedAPI(t, "build", []githubapi.JobStep{step}, body)
	result := collectLifecycle(t, api)
	assertNoLifecycle(t, result)
	assertGap(t, result.Gaps, "action_step_parser", nil)
}

func TestConsolidatedRootEntryRequiresUniqueSafeAPIJobBinding(t *testing.T) {
	job := githubapi.WorkflowJob{ID: 20, Name: "build"}
	if matched, relevant, diagnostic := correlateConsolidatedJobEntry("0_build.txt", []githubapi.WorkflowJob{job}); !relevant || diagnostic != "" || matched.ID != job.ID {
		t.Fatalf("valid consolidated correlation = job:%+v relevant:%v diagnostic:%q", matched, relevant, diagnostic)
	}
	duplicate := job
	duplicate.ID = 21
	for _, name := range []string{"0_build.txt", "0_build\x1bforged.txt"} {
		jobs := []githubapi.WorkflowJob{job, duplicate}
		if strings.Contains(name, "\x1b") {
			jobs = []githubapi.WorkflowJob{{ID: 20, Name: "build\x1bforged"}}
		}
		if _, relevant, diagnostic := correlateConsolidatedJobEntry(name, jobs); !relevant || diagnostic == "" {
			t.Fatalf("unsafe/ambiguous root entry accepted: name=%q relevant=%v diagnostic=%q", name, relevant, diagnostic)
		}
	}
	for _, name := range []string{"job/0_build.txt", "00_build.txt", "0_build.log", "0_.txt"} {
		if _, relevant, diagnostic := correlateConsolidatedJobEntry(name, []githubapi.WorkflowJob{job}); relevant || diagnostic != "" {
			t.Fatalf("unsupported shape became relevant: %q", name)
		}
	}
}

func TestConsolidatedReusableJobFilenameEncodingRequiresUniqueAPIJob(t *testing.T) {
	job := githubapi.WorkflowJob{ID: 20, Name: "caller / reusable-job"}
	matched, relevant, diagnostic := correlateConsolidatedJobEntry("0_caller _ reusable-job.txt", []githubapi.WorkflowJob{job})
	if !relevant || diagnostic != "" || matched.ID != job.ID {
		t.Fatalf("encoded reusable job correlation = job:%+v relevant:%v diagnostic:%q", matched, relevant, diagnostic)
	}
	if !archiveJobLabelMatches("caller _ reusable-job", job.Name) || archiveJobLabelMatches("caller_reusable-job", job.Name) {
		t.Fatal("job-label encoding accepted a non-observed transformation")
	}
	alias := job
	alias.ID = 21
	alias.Name = "caller _ reusable-job"
	if _, relevant, diagnostic := correlateConsolidatedJobEntry("0_caller _ reusable-job.txt", []githubapi.WorkflowJob{job, alias}); !relevant || diagnostic == "" {
		t.Fatal("non-injective reusable job encoding did not remain ambiguous")
	}
}

func TestConsolidatedCompositeMultipleDownloadBlocksRemainExact(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/wrapper@v1", "success")
	setup := strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z Getting action download info",
		"2026-08-20T01:10:01Z Download action repository 'fixture/wrapper@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:" + strings.Repeat("2", 40) + ")",
		"2026-08-20T01:10:03Z Complete job name: composite",
	}, "\n") + "\n"
	api := consolidatedAPI(t, "composite", []githubapi.JobStep{step}, setup+consolidatedActionGroupAt(*step.StartedAt, "fixture/wrapper@v1"))
	result := collectLifecycle(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("composite root lifecycle starts=%d, want one; gaps=%+v", starts, result.Gaps)
	}
	for _, repository := range []model.RepositorySlug{"fixture/wrapper", "fixture/action"} {
		if countRuntimeRepositoryObservation(result, repository, model.ObservationPreparationComplete) != 1 {
			t.Fatalf("%s did not retain one exact preparation fact", repository)
		}
	}
}

func TestConsolidatedMultipleJobsRemainBoundToTheirOwnSetup(t *testing.T) {
	api := successfulAPI(t, false)
	build := api.jobs[10][1][0]
	buildStep := actionAPIStep(2, "Run fixture/action@v1", "success")
	build.Steps = append(build.Steps, buildStep)
	testJob := build
	testJob.ID = 21
	testJob.Name = "test"
	testStep := actionAPIStep(2, "Run fixture/action@v1", "skipped")
	testStep.StartedAt = nil
	testJob.Steps = append([]githubapi.JobStep(nil), testJob.Steps[:1]...)
	testJob.Steps = append(testJob.Steps, testStep)
	api.jobs[10][1] = []githubapi.WorkflowJob{build, testJob}
	api.jobLogs[21] = []byte("synthetic complete job log\n")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt": consolidatedSetupBlock("build") + consolidatedActionGroupAt(*buildStep.StartedAt, "fixture/action@v1"),
		"0_test.txt":  consolidatedSetupBlock("test"),
	})
	result := collectLifecycle(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("cross-job correlation changed lifecycle starts=%d, want 1; gaps=%+v", starts, result.Gaps)
	}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted && fact.ActionOccurrence.Observation.Execution.JobID != 20 {
			t.Fatalf("skipped sibling received lifecycle evidence: %+v", fact.ActionOccurrence.Observation)
		}
	}
}

func TestCurrentArchiveDuplicateViewsProduceOneDirectLifecycle(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "success")
	api := successfulAPI(t, false)
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, step)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	action := consolidatedActionGroupAt(*step.StartedAt, "fixture/action@v1")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt":                      setup + action,
		"build/1_Set up job.txt":           retimestampRunnerText(setup),
		"build/2_Run fixtureaction@v1.txt": retimestampRunnerText(action) + retimestampRunnerText(step.StartedAt.Add(time.Second).UTC().Format(time.RFC3339Nano)+" harmless application output\n"),
	})
	result := collectLifecycle(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("duplicate current views produced lifecycle starts=%d, want one; gaps=%+v", starts, result.Gaps)
	}
	assertNoMaterialCorrelationGap(t, result, "setup_correlation")
	assertNoMaterialCorrelationGap(t, result, "action_step_correlation")
}

func TestCurrentArchiveDuplicateViewsPreserveSkippedDownloadOnly(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "skipped")
	step.StartedAt, step.CompletedAt = nil, nil
	api := successfulAPI(t, false)
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, step)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt":            setup + "2026-08-20T01:12:00Z harmless later output\n",
		"build/1_Set up job.txt": retimestampRunnerText(setup),
	})
	result := collectLifecycle(t, api)
	assertNoLifecycle(t, result)
	var downloaded bool
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.ActionRepository == "fixture/action" && fact.ActionOccurrence.Observation.Kind == model.ObservationPreparationComplete {
			downloaded = true
		}
	}
	if !downloaded {
		t.Fatalf("skipped duplicate-view job lost exact download evidence: gaps=%+v", result.Gaps)
	}
	assertNoMaterialCorrelationGap(t, result, "setup_correlation")
}

func TestCurrentArchiveDuplicateViewsRemainAttemptScopedAcrossRerun(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "success")
	api := successfulAPI(t, false)
	jobOne := api.jobs[10][1][0]
	jobOne.Steps = append(jobOne.Steps, step)
	api.jobs[10][1] = []githubapi.WorkflowJob{jobOne}
	attemptTwo := api.attempts[10][1]
	attemptTwo.RunAttempt = 2
	api.attempts[10][2] = attemptTwo
	jobTwo := jobOne
	jobTwo.ID = 21
	api.jobs[10][2] = []githubapi.WorkflowJob{jobTwo}
	api.jobLogs[21] = []byte("synthetic complete job log discarded\n")
	setup := consolidatedMutableSetupBlock("build")
	duplicateViews := func(offset time.Duration) []byte {
		rootAction := consolidatedActionGroupAt(step.StartedAt.Add(offset), "fixture/action@v1")
		return makeZIP(t, map[string]string{
			"0_build.txt":                      setup + rootAction,
			"build/1_Set up job.txt":           retimestampRunnerText(setup),
			"build/2_Run fixtureaction@v1.txt": retimestampRunnerText(rootAction) + retimestampRunnerText(step.StartedAt.Add(offset+time.Second).UTC().Format(time.RFC3339Nano)+" harmless application output\n"),
		})
	}
	api.attemptLogs[10][1] = duplicateViews(0)
	api.attemptLogs[10][2] = duplicateViews(0)
	result := collectLifecycle(t, api)
	starts := map[model.RunAttempt]int{}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			starts[fact.ActionOccurrence.Observation.Execution.RunAttempt]++
		}
	}
	if starts[1] != 1 || starts[2] != 1 || len(starts) != 2 {
		t.Fatalf("rerun duplicate views were merged or lost: starts=%v gaps=%+v", starts, result.Gaps)
	}
	assertNoMaterialCorrelationGap(t, result, "setup_correlation")
	assertNoMaterialCorrelationGap(t, result, "action_step_correlation")
}

func TestCurrentArchiveMateriallyDifferentViewsRemainAmbiguous(t *testing.T) {
	step := actionAPIStep(2, "Run fixture/action@v1", "success")
	api := successfulAPI(t, false)
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, step)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	changedSetup := strings.Replace(setup, testActionSHA, strings.Repeat("f", 40), 1)
	action := consolidatedActionGroupAt(*step.StartedAt, "fixture/action@v1")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt":                      setup + action,
		"build/1_Set up job.txt":           retimestampRunnerText(changedSetup),
		"build/2_Run fixtureaction@v1.txt": retimestampRunnerText(action),
	})
	result := collectLifecycle(t, api)
	assertNoLifecycle(t, result)
	assertGap(t, result.Gaps, "setup_correlation", boolPointer(true))
}

func consolidatedAPI(t *testing.T, jobName string, steps []githubapi.JobStep, body string) *fakeAPI {
	t.Helper()
	api := successfulAPI(t, false)
	job := api.jobs[10][1][0]
	job.Name = jobName
	job.Steps = append(job.Steps, steps...)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{"0_" + jobName + ".txt": body, jobName + "/system.txt": "synthetic system metadata\n"})
	return api
}

func consolidatedSetupBlock(jobName string) string {
	return strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z ##[group]GITHUB_TOKEN Permissions",
		"2026-08-20T01:10:01Z contents: write",
		"2026-08-20T01:10:01Z id-token: write",
		"2026-08-20T01:10:01Z ##[endgroup]",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:03Z Download action repository 'fixture/action@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:04Z ##[group]Download immutable action package 'fixture/package@v2'",
		"2026-08-20T01:10:04Z Version: 2.0.0",
		"2026-08-20T01:10:04Z Source commit SHA: " + testPackageSHA,
		"2026-08-20T01:10:04Z Digest: sha256:" + testPackageDigest,
		"2026-08-20T01:10:04Z ##[endgroup]",
		"2026-08-20T01:10:05Z Complete job name: " + jobName,
	}, "\n") + "\n"
}

func consolidatedMutableSetupBlock(jobName string) string {
	return strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z ##[group]GITHUB_TOKEN Permissions",
		"2026-08-20T01:10:01Z contents: write",
		"2026-08-20T01:10:01Z ##[endgroup]",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:03Z Download action repository 'fixture/action@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:05Z Complete job name: " + jobName,
	}, "\n") + "\n"
}

func consolidatedActionGroupAt(when time.Time, declared string) string {
	stamp := when.UTC().Format(time.RFC3339Nano)
	return stamp + " ##[group]Run " + declared + "\n" +
		stamp + " with:\n" +
		stamp + "   marker: harmless\n" +
		stamp + " env:\n" +
		stamp + "   CI: true\n" +
		stamp + " ##[endgroup]\n"
}

func retimestampRunnerText(value string) string {
	return strings.ReplaceAll(value, "Z ", ".0000001Z ")
}

func assertNoMaterialCorrelationGap(t *testing.T, result Result, scope string) {
	t.Helper()
	for _, gap := range result.Gaps {
		if gap.Scope == scope && gap.Material {
			t.Fatalf("unexpected material %s gap: %+v", scope, gap)
		}
	}
}

func countRuntimeRepositoryObservation(result Result, repository model.RepositorySlug, kind model.RuntimeObservationKind) int {
	count := 0
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == kind && fact.ActionOccurrence.Observation.ActionRepository == repository {
			count++
		}
	}
	return count
}

func TestConsolidatedGrammarVersionIsStable(t *testing.T) {
	if logparse.ConsolidatedGrammarVersion != "github-attempt-log-consolidated/v1alpha1" {
		t.Fatalf("consolidated grammar drifted: %q", logparse.ConsolidatedGrammarVersion)
	}
}
