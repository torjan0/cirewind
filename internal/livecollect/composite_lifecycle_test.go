package livecollect

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

const compositeChildSHA = "2222222222222222222222222222222222222222"

func TestCompositeImmediateFirstChildProducesExactLifecycle(t *testing.T) {
	api := compositeHistoricalAPI(t, compositeMetadata(""), true, false, "success")
	result := collectHistoricalAPI(t, api)
	if got := lifecycleStarts(result); got != 2 {
		t.Fatalf("composite parent+child starts=%d, want 2; gaps=%+v", got, result.Gaps)
	}
	assertCompositeChildLifecycle(t, result, true)
	assertNoMaterialCorrelationGap(t, result, "composite_step_correlation")
}

func TestReusableWorkflowCompositeImmediateFirstChildProducesExactLifecycle(t *testing.T) {
	api := reusableLifecycleAPI(t, "Invoke composite marker", "success", 1)
	api.put("acme/shared", ".github/workflows/reuse.yml", "sha1", testCalledSHA, []byte("on: workflow_call\njobs:\n  nested:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Invoke composite marker\n        uses: fixture/wrapper@v1\n"))
	api.put("fixture/wrapper", "action.yml", "sha1", testActionSHA, []byte(compositeMetadata("")))
	api.put("fixture/action", "action.yml", "sha1", compositeChildSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	job := api.jobs[10][1][0]
	api.attemptLogs[10][1] = reusableCompositeLifecycleZIP(t, job)

	result := collectHistoricalAPI(t, api)
	if got := lifecycleStarts(result); got != 2 {
		t.Fatalf("reusable composite parent+child starts=%d, want 2; gaps=%+v", got, result.Gaps)
	}
	assertCompositeChildLifecycle(t, result, true)
	assertReusableLifecycleEvidence(t, result)
}

func TestCompositePrefixRejectsSpoofableOrIncompleteNearMisses(t *testing.T) {
	tests := []struct {
		name            string
		metadata        string
		includeAdjacent bool
		intervening     bool
		conclusion      string
		wantParent      bool
	}{
		{name: "leaf output forges adjacent group", metadata: "runs:\n  using: node20\n  main: dist/index.js\n", includeAdjacent: true, conclusion: "success", wantParent: true},
		{name: "conditional first child", metadata: compositeMetadata("      if: ${{ false }}\n"), includeAdjacent: true, conclusion: "success", wantParent: true},
		{name: "application record breaks adjacency", metadata: compositeMetadata(""), includeAdjacent: true, intervening: true, conclusion: "success", wantParent: true},
		{name: "missing child group", metadata: compositeMetadata(""), conclusion: "success", wantParent: true},
		{name: "skipped parent", metadata: compositeMetadata(""), includeAdjacent: true, conclusion: "skipped"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := compositeHistoricalAPI(t, test.metadata, test.includeAdjacent, test.intervening, test.conclusion)
			result := collectHistoricalAPI(t, api)
			wantStarts := 0
			if test.wantParent {
				wantStarts = 1
			}
			if got := lifecycleStarts(result); got != wantStarts {
				t.Fatalf("lifecycle starts=%d want=%d gaps=%+v", got, wantStarts, result.Gaps)
			}
			assertCompositeChildLifecycle(t, result, false)
			if test.conclusion != "skipped" {
				assertGap(t, result.Gaps, "composite_step_correlation", boolPointer(true))
			}
		})
	}
}

func TestCompositePrefixRejectsMarkerDisplayMismatch(t *testing.T) {
	api := compositeHistoricalAPI(t, compositeMetadata(""), true, false, "success")
	job := api.jobs[10][1][0]
	api.attemptLogs[10][1] = directCompositeLifecycleZIPWithDisplay(t, job, true, false, "Different synthetic marker")
	result := collectHistoricalAPI(t, api)
	if got := lifecycleStarts(result); got != 1 {
		t.Fatalf("mismatched marker starts=%d want=1 gaps=%+v", got, result.Gaps)
	}
	assertCompositeChildLifecycle(t, result, false)
	assertGap(t, result.Gaps, "composite_step_correlation", boolPointer(true))
}

func compositeHistoricalAPI(t *testing.T, wrapperMetadata string, includeAdjacent, intervening bool, conclusion string) *historicalExactAPI {
	t.Helper()
	api := newHistoricalExactAPI(t)
	setHistoricalAttempt(api, func(value *githubapi.WorkflowRun) { value.ReferencedWorkflows = nil })
	caller := strings.Replace(callerWorkflowWithAction("fixture/wrapper@v1", "Invoke composite marker"), "jobs:\n  build:", "jobs:\n  composite:", 1)
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", api.attempts[10][1].HeadSHA, []byte(caller))
	api.put("fixture/wrapper", "action.yml", "sha1", testActionSHA, []byte(wrapperMetadata))
	api.put("fixture/action", "action.yml", "sha1", compositeChildSHA, []byte("runs:\n  using: node20\n  main: dist/index.js\n"))
	step := actionAPIStep(2, "Invoke composite marker", conclusion)
	job := api.jobs[10][1][0]
	job.Name = "composite"
	job.Steps = append(job.Steps, step)
	if conclusion == "skipped" {
		job.Steps[1].StartedAt, job.Steps[1].CompletedAt = nil, nil
	}
	api.jobs[10][1] = []githubapi.WorkflowJob{job}
	api.attemptLogs[10][1] = directCompositeLifecycleZIP(t, job, includeAdjacent, intervening)
	return api
}

func compositeMetadata(firstStepFields string) string {
	return "runs:\n  using: composite\n  steps:\n    - name: Invoke synthetic marker\n      uses: fixture/action@v1\n" + firstStepFields
}

func compositeSetupBlock(jobName string, reusable bool) string {
	lines := []string{
		"2026-08-20T01:10:00Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:01Z Getting action download info",
		"2026-08-20T01:10:01Z Download action repository 'fixture/wrapper@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:02Z Getting action download info",
		"2026-08-20T01:10:02Z Download action repository 'fixture/action@v1' (SHA:" + compositeChildSHA + ")",
	}
	if reusable {
		lines = append(lines, "2026-08-20T01:10:03Z Uses: acme/shared/.github/workflows/reuse.yml@refs/tags/v3 ("+testCalledSHA+")")
	}
	lines = append(lines, "2026-08-20T01:10:04Z Complete job name: "+jobName)
	return strings.Join(lines, "\n") + "\n"
}

func directCompositeLifecycleZIP(t *testing.T, job githubapi.WorkflowJob, includeAdjacent, intervening bool) []byte {
	return directCompositeLifecycleZIPWithDisplay(t, job, includeAdjacent, intervening, "Invoke synthetic marker")
}

func directCompositeLifecycleZIPWithDisplay(t *testing.T, job githubapi.WorkflowJob, includeAdjacent, intervening bool, markerDisplay string) []byte {
	t.Helper()
	body := compositeSetupBlock(job.Name, false)
	if len(job.Steps) > 1 && job.Steps[1].StartedAt != nil {
		body += consolidatedActionGroupAt(*job.Steps[1].StartedAt, "fixture/wrapper@v1")
		if intervening {
			body += job.Steps[1].StartedAt.Add(50).UTC().Format("2006-01-02T15:04:05.0000000Z") + " harmless application output\n"
		}
		if includeAdjacent {
			body += compositeStartMarkerAt(job.Steps[1].StartedAt.Add(75), markerDisplay)
			body += consolidatedActionGroupAt(job.Steps[1].StartedAt.Add(100), "fixture/action@v1")
		}
	}
	return makeZIP(t, map[string]string{"0_composite.txt": body})
}

func reusableCompositeLifecycleZIP(t *testing.T, job githubapi.WorkflowJob) []byte {
	t.Helper()
	body := compositeSetupBlock(job.Name, true)
	body += consolidatedActionGroupAt(*job.Steps[1].StartedAt, "fixture/wrapper@v1")
	body += compositeStartMarkerAt(job.Steps[1].StartedAt.Add(75), "Invoke synthetic marker")
	body += consolidatedActionGroupAt(job.Steps[1].StartedAt.Add(100), "fixture/action@v1")
	return makeZIP(t, map[string]string{"0_reusable _ nested.txt": body})
}

func compositeStartMarkerAt(at time.Time, display string) string {
	return at.UTC().Format("2006-01-02T15:04:05.0000000Z") + " ##[start-action display=" + display + ";id=__fixture_wrapper.__fixture_action]\n"
}

func assertCompositeChildLifecycle(t *testing.T, result Result, want bool) {
	t.Helper()
	found := false
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository != "fixture/action" || observation.Kind != model.ObservationLifecycleStarted {
			continue
		}
		found = true
		if observation.Step == nil || observation.Step.Occurrence != 2 || observation.Step.ASTOrdinal == nil || *observation.Step.ASTOrdinal != 1 {
			t.Fatalf("composite child step identity=%+v", observation.Step)
		}
		var wrapperMetadata, childMetadata bool
		for _, envelope := range result.Batch.Evidence {
			if !containsEvidence(fact.EvidenceIDs, envelope.Evidence.ID) || envelope.Evidence.Source.RequestParameters["path"] != "action.yml" {
				continue
			}
			switch envelope.Evidence.Source.RequestParameters["repo"] {
			case "wrapper":
				wrapperMetadata = true
			case "action":
				childMetadata = true
			}
		}
		if !wrapperMetadata || !childMetadata {
			t.Fatalf("composite child evidence omitted exact metadata: wrapper=%v child=%v", wrapperMetadata, childMetadata)
		}
	}
	if found != want {
		t.Fatalf("composite child lifecycle found=%v want=%v", found, want)
	}
}
