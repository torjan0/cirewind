package livecollect

import (
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/workflow"
)

func TestReusableWorkflowCustomActionUsesExactCalledDefinitionBinding(t *testing.T) {
	api := reusableLifecycleAPI(t, "Invoke reusable marker", "success", 1)
	result := collectHistoricalAPI(t, api)
	if starts := lifecycleStarts(result); starts != 1 {
		t.Fatalf("reusable historical binding starts=%d, want one; gaps=%+v", starts, result.Gaps)
	}
	assertReusableLifecycleEvidence(t, result)
	assertNoMaterialCorrelationGap(t, result, "action_step_correlation")
}

func TestReusableWorkflowSkippedActionRemainsDownloadOnly(t *testing.T) {
	api := reusableLifecycleAPI(t, "Never-started reusable marker", "skipped", 1)
	job := api.jobs[10][1][0]
	job.Steps[1].StartedAt, job.Steps[1].CompletedAt = nil, nil
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	api.attemptLogs[10][1] = reusableLifecycleZIP(t, job, false)

	result := collectHistoricalAPI(t, api)
	assertNoLifecycle(t, result)
	if got := countActionObservation(result, model.ObservationPreparationComplete, 1); got != 1 {
		t.Fatalf("skipped reusable step downloads=%d, want one; gaps=%+v", got, result.Gaps)
	}
}

func TestReusableWorkflowBindingRemainsAttemptScopedAcrossReruns(t *testing.T) {
	api := reusableLifecycleAPI(t, "Invoke reusable marker", "success", 3)
	result := collectHistoricalAPI(t, api)
	starts := make(map[model.RunAttempt]int)
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			starts[fact.ActionOccurrence.Observation.Execution.RunAttempt]++
		}
	}
	if starts[1] != 1 || starts[2] != 1 || starts[3] != 1 || len(starts) != 3 {
		t.Fatalf("reusable rerun bindings merged or lost attempts: starts=%v gaps=%+v", starts, result.Gaps)
	}
}

func TestReusableWorkflowLifecycleRejectsAmbiguousOrHostileNearMisses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*historicalExactAPI)
	}{
		{
			name: "dynamic called job label",
			mutate: func(api *historicalExactAPI) {
				api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte(reusableCalledWorkflow("Invoke reusable marker", "name: Nested ${{ matrix.os }}\nstrategy:\n  matrix:\n    os: [ubuntu-latest]\n")))
			},
		},
		{
			name: "non-unique caller callee label pair",
			mutate: func(api *historicalExactAPI) {
				api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  first:\n    name: nested\n    runs-on: ubuntu-latest\n    steps:\n      - name: Invoke reusable marker\n        uses: fixture/action@v1\n  second:\n    name: nested\n    runs-on: ubuntu-latest\n    steps:\n      - name: Invoke reusable marker\n        uses: fixture/action@v1\n"))
			},
		},
		{
			name: "API custom step name mismatch",
			mutate: func(api *historicalExactAPI) {
				job := api.jobs[10][1][0]
				job.Steps[1].Name = "Forged display"
				api.jobs[10][1] = []githubapi.WorkflowJob{job}
				api.attemptLogs[10][1] = reusableLifecycleZIP(t, job, true)
			},
		},
		{
			name: "recorded ref incompatible with caller literal",
			mutate: func(api *historicalExactAPI) {
				attempt := api.attempts[10][1]
				attempt.ReferencedWorkflows[0].Ref = "refs/tags/v4"
				api.attempts[10][1] = attempt
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := reusableLifecycleAPI(t, "Invoke reusable marker", "success", 1)
			test.mutate(api)
			result := collectHistoricalAPI(t, api)
			assertNoLifecycle(t, result)
			assertGap(t, result.Gaps, "action_step_correlation", boolPointer(true))
		})
	}
}

func reusableLifecycleAPI(t *testing.T, stepName, conclusion string, attempts int) *historicalExactAPI {
	t.Helper()
	api := newHistoricalExactAPI(t)
	callerCommit := api.attempts[10][1].HeadSHA
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", callerCommit, []byte("on: push\njobs:\n  reusable:\n    uses: acme/shared/.github/workflows/reuse.yml@v3\n"))
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte(reusableCalledWorkflow(stepName, "")))
	api.put("fixture/action", "action.yml", "sha1", testActionSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))

	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) {
		value.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{
			Path: "acme/shared/.github/workflows/reuse.yml@v3", Ref: "refs/tags/v3", SHA: testCalledSHA,
		}}
	})
	base := api.jobs[10][1][0]
	base.Name = "reusable / nested"
	base.Steps = []githubapi.JobStep{base.Steps[0], actionAPIStep(2, stepName, conclusion), {
		Number: 3, Name: "Complete job", Status: "completed", Conclusion: "success",
	}}
	api.jobs[10][1] = []githubapi.WorkflowJob{base}
	api.attemptLogs[10][1] = reusableLifecycleZIP(t, base, conclusion != "skipped")

	for attemptNumber := 2; attemptNumber <= attempts; attemptNumber++ {
		attempt := api.attempts[10][1]
		attempt.RunAttempt = attemptNumber
		api.attempts[10][attemptNumber] = attempt
		job := base
		job.ID = int64(20 + attemptNumber)
		api.jobs[10][attemptNumber] = []githubapi.WorkflowJob{job}
		api.jobLogs[job.ID] = []byte("synthetic complete job log discarded\n")
		api.attemptLogs[10][attemptNumber] = reusableLifecycleZIP(t, job, conclusion != "skipped")
	}
	return api
}

func reusableCalledWorkflow(stepName, jobPrefix string) string {
	value := "on: workflow_call\njobs:\n  nested:\n"
	if jobPrefix != "" {
		value += "    " + strings.ReplaceAll(strings.TrimSuffix(jobPrefix, "\n"), "\n", "\n    ") + "\n"
	}
	return value + "    runs-on: ubuntu-latest\n    steps:\n      - name: " + stepName + "\n        uses: fixture/action@v1\n"
}

func reusableLifecycleZIP(t *testing.T, job githubapi.WorkflowJob, includeAction bool) []byte {
	t.Helper()
	setup := strings.Join([]string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z Getting action download info",
		"2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:03Z Uses: acme/shared/.github/workflows/reuse.yml@refs/tags/v3 (" + testCalledSHA + ")",
		"2026-08-20T01:10:04Z Complete job name: " + job.Name,
	}, "\n") + "\n"
	body := setup
	if includeAction && len(job.Steps) > 1 && job.Steps[1].StartedAt != nil {
		body += consolidatedActionGroupAt(*job.Steps[1].StartedAt, "fixture/action@v1")
	}
	return makeZIP(t, map[string]string{"0_reusable _ nested.txt": body})
}

func assertReusableLifecycleEvidence(t *testing.T, result Result) {
	t.Helper()
	var caller, called model.EvidenceID
	for _, envelope := range result.Batch.Evidence {
		if envelope.Evidence.Source.EndpointTemplate != "/repos/{owner}/{repo}/contents/{path}" {
			continue
		}
		switch envelope.Evidence.Source.RequestParameters["repo"] {
		case "service":
			caller = envelope.Evidence.ID
		case "shared":
			called = envelope.Evidence.ID
		}
	}
	if caller == "" || called == "" {
		t.Fatalf("exact reusable evidence absent: caller=%q called=%q", caller, called)
	}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence && fact.ActionOccurrence.Observation.Kind == model.ObservationLifecycleStarted {
			if !containsEvidence(fact.EvidenceIDs, caller) || !containsEvidence(fact.EvidenceIDs, called) {
				t.Fatalf("reusable lifecycle omitted exact definition evidence: %+v", fact.EvidenceIDs)
			}
			return
		}
	}
	t.Fatal("reusable lifecycle start was absent")
}

func TestBindReusableLifecyclePlansRequiresExactAPIStructure(t *testing.T) {
	reference := workflowReferenceForReusableTest()
	plan := reusableLifecyclePlan{
		apiName:     "caller / callee",
		job:         workflowJobForReusableTest(reference),
		evidenceIDs: []model.EvidenceID{historicalEvidence('b')},
	}
	setup := githubapi.JobStep{Number: 1, Name: "Set up job", Status: "completed", Conclusion: "success"}
	action := githubapi.JobStep{Number: 2, Name: "marker", Status: "completed", Conclusion: "success"}
	job := githubapi.WorkflowJob{ID: 20, Name: plan.apiName, Steps: []githubapi.JobStep{setup, action}}

	for _, test := range []struct {
		name      string
		plans     []reusableLifecyclePlan
		jobs      []githubapi.WorkflowJob
		wantBound bool
	}{
		{name: "exact", plans: []reusableLifecyclePlan{plan}, jobs: []githubapi.WorkflowJob{job}, wantBound: true},
		{name: "duplicate static path", plans: []reusableLifecyclePlan{plan, plan}, jobs: []githubapi.WorkflowJob{job}},
		{name: "duplicate API display", plans: []reusableLifecyclePlan{plan}, jobs: []githubapi.WorkflowJob{job, func() githubapi.WorkflowJob { copy := job; copy.ID = 21; return copy }()}},
		{name: "missing setup", plans: []reusableLifecyclePlan{plan}, jobs: []githubapi.WorkflowJob{{ID: 20, Name: plan.apiName, Steps: []githubapi.JobStep{action}}}},
		{name: "step ordinal mismatch", plans: []reusableLifecyclePlan{plan}, jobs: []githubapi.WorkflowJob{{ID: 20, Name: plan.apiName, Steps: []githubapi.JobStep{setup, {Number: 3, Name: "marker"}}}}},
		{name: "step name mismatch", plans: []reusableLifecyclePlan{plan}, jobs: []githubapi.WorkflowJob{{ID: 20, Name: plan.apiName, Steps: []githubapi.JobStep{setup, {Number: 2, Name: "other"}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindings, issues := bindReusableLifecyclePlans(test.plans, test.jobs)
			_, bound := bindings[20][2]
			if bound != test.wantBound {
				t.Fatalf("bound=%v bindings=%+v", bound, bindings)
			}
			if test.wantBound && len(issues) != 0 {
				t.Fatalf("exact binding issues=%+v", issues)
			}
			if !test.wantBound && len(issues) == 0 {
				t.Fatal("ambiguous structure produced no explicit issue")
			}
		})
	}
}

func workflowReferenceForReusableTest() *workflow.Reference {
	return &workflow.Reference{Kind: workflow.ReferenceRepository, Raw: "fixture/action@v1", Owner: "fixture", Repository: "action", Ref: "v1"}
}

func workflowJobForReusableTest(reference *workflow.Reference) workflow.Job {
	return workflow.Job{ID: "callee", Steps: []workflow.Step{{Ordinal: 1, Name: "marker", Uses: reference}}}
}
