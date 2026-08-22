package livecollect

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

func TestCustomNamedActionUsesExactHistoricalStepBinding(t *testing.T) {
	api := customNamedHistoricalAPI(t, "fixture/action@v1", "Invoke mutable marker", "success", 1)
	result := collectHistoricalAPI(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("custom historical binding starts=%d, want one; gaps=%+v", starts, result.Gaps)
	}
	assertLifecycleRetainsHistoricalWorkflowEvidence(t, result)
	assertNoMaterialCorrelationGap(t, result, "setup_correlation")
	assertNoMaterialCorrelationGap(t, result, "action_step_correlation")
}

func TestCustomNamedActionUsesRootOnlyRoundedLifecycleFrame(t *testing.T) {
	api := customNamedHistoricalAPI(t, "fixture/action@v1", "Invoke mutable marker", "success", 1)
	job := api.jobs[10][1][0]
	step := job.Steps[1]
	step.CompletedAt = step.StartedAt
	job.Steps[1] = step
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	actionTime := step.StartedAt.Add(250 * time.Millisecond)
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt": setup + consolidatedActionGroupAt(actionTime, "fixture/action@v1") +
			step.StartedAt.Add(300*time.Millisecond).UTC().Format(time.RFC3339Nano) + " harmless later output\n",
	})
	result := collectHistoricalAPI(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("root-only rounded custom lifecycle starts=%d; gaps=%+v", starts, result.Gaps)
	}
	assertLifecycleRetainsHistoricalWorkflowEvidence(t, result)
}

func TestCustomNamedSkippedActionRemainsDownloadOnly(t *testing.T) {
	api := customNamedHistoricalAPI(t, "fixture/action@v1", "Never-started affected step", "skipped", 1)
	job := api.jobs[10][1][0]
	job.Steps[1].StartedAt, job.Steps[1].CompletedAt = nil, nil
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	api.attemptLogs[10][1] = makeZIP(t, map[string]string{
		"0_build.txt":            setup + "2026-08-20T01:12:00Z harmless later output\n",
		"build/1_Set up job.txt": retimestampRunnerText(setup),
	})
	result := collectHistoricalAPI(t, api)
	assertNoLifecycle(t, result)
	if countActionObservation(result, model.ObservationPreparationComplete, 1) != 1 {
		t.Fatalf("skipped custom step did not preserve one download: gaps=%+v", result.Gaps)
	}
}

func TestCustomNamedActionBindingRemainsAttemptScopedAcrossRerun(t *testing.T) {
	api := customNamedHistoricalAPI(t, "fixture/action@v1", "Invoke mutable marker", "success", 2)
	result := collectHistoricalAPI(t, api)
	starts := map[model.RunAttempt]int{}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			starts[fact.ActionOccurrence.Observation.Execution.RunAttempt]++
		}
	}
	if starts[1] != 1 || starts[2] != 1 || len(starts) != 2 {
		t.Fatalf("custom rerun bindings merged or lost attempts: starts=%v gaps=%+v", starts, result.Gaps)
	}
}

func TestCustomNamedActionRejectsHistoricalUsesNearMiss(t *testing.T) {
	api := customNamedHistoricalAPI(t, "fixture/other@v1", "Invoke mutable marker", "success", 1)
	result := collectHistoricalAPI(t, api)
	assertNoLifecycle(t, result)
	assertGap(t, result.Gaps, "action_step_parser", boolPointer(true))
}

func TestCustomNamedActionRejectsStaticNameAndOrdinalNearMisses(t *testing.T) {
	tests := []struct {
		name       string
		workflow   string
		apiStepNum int
	}{
		{name: "static display mismatch", workflow: callerWorkflowWithAction("fixture/action@v1", "Different display"), apiStepNum: 2},
		{name: "ordinal mismatch", workflow: "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo harmless\n      - name: Invoke mutable marker\n        uses: fixture/action@v1\n", apiStepNum: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := customNamedHistoricalAPI(t, "fixture/action@v1", "Invoke mutable marker", "success", 1)
			api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte(test.workflow))
			job := api.jobs[10][1][0]
			job.Steps[1].Number = test.apiStepNum
			api.jobs[10][1] = []githubapi.WorkflowJob{job}
			result := collectHistoricalAPI(t, api)
			assertNoLifecycle(t, result)
			assertGap(t, result.Gaps, "action_step_correlation", boolPointer(true))
		})
	}
}

func customNamedHistoricalAPI(t *testing.T, historicalUses, apiStepName, conclusion string, attempts int) *historicalExactAPI {
	t.Helper()
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte(callerWorkflowWithAction(historicalUses, apiStepName)))
	api.put("fixture/action", "action.yml", "sha1", testActionSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	step := actionAPIStep(2, apiStepName, conclusion)
	job := api.jobs[10][1][0]
	job.Steps = append(job.Steps, step)
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	setup := consolidatedMutableSetupBlock("build")
	action := consolidatedActionGroupAt(*step.StartedAt, "fixture/action@v1")
	archiveForAttempt := func() []byte {
		return makeZIP(t, map[string]string{
			"0_build.txt":            setup + action,
			"build/1_Set up job.txt": retimestampRunnerText(setup),
			"build/2_" + apiStepName + ".txt": retimestampRunnerText(action) +
				retimestampRunnerText(step.StartedAt.Add(time.Second).UTC().Format(time.RFC3339Nano)+" harmless application output\n"),
		})
	}
	api.attemptLogs[10][1] = archiveForAttempt()
	for attempt := 2; attempt <= attempts; attempt++ {
		attemptRun := api.attempts[10][1]
		attemptRun.RunAttempt = attempt
		api.attempts[10][attempt] = attemptRun
		attemptJob := job
		attemptJob.ID = int64(19 + attempt)
		api.jobs[10][attempt] = []githubapi.WorkflowJob{attemptJob}
		api.jobLogs[attemptJob.ID] = []byte("synthetic complete job log discarded\n")
		api.attemptLogs[10][attempt] = archiveForAttempt()
	}
	return api
}

func callerWorkflowWithAction(declaration, name string) string {
	return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: " + name + "\n        uses: " + declaration + "\n"
}

func assertLifecycleRetainsHistoricalWorkflowEvidence(t *testing.T, result Result) {
	t.Helper()
	var historical model.EvidenceID
	for _, envelope := range result.Batch.Evidence {
		if envelope.Evidence.Source.EndpointTemplate == "/repos/{owner}/{repo}/contents/{path}" &&
			envelope.Evidence.Source.RequestParameters["owner"] == "acme" &&
			envelope.Evidence.Source.RequestParameters["repo"] == "service" &&
			envelope.Evidence.Source.RequestParameters["path"] == ".github/workflows/ci.yml" {
			historical = envelope.Evidence.ID
		}
	}
	if historical == "" {
		t.Fatal("exact historical caller content evidence was absent")
	}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			if !containsEvidence(fact.EvidenceIDs, historical) {
				t.Fatalf("lifecycle omitted historical caller evidence %s: %+v", historical, fact.EvidenceIDs)
			}
			return
		}
	}
	t.Fatal("lifecycle start was absent")
}

func countActionObservation(result Result, kind model.RuntimeObservationKind, attempt model.RunAttempt) int {
	count := 0
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == kind && fact.ActionOccurrence.Observation.Execution.RunAttempt == attempt && strings.EqualFold(string(fact.ActionOccurrence.Observation.ActionRepository), "fixture/action") {
			count++
		}
	}
	return count
}
