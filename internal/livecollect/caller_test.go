package livecollect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/workflow"
)

func TestDeriveHistoricalCallerCandidateByEvent(t *testing.T) {
	const workflow = ".github/workflows/ci.yml"
	pushSHA := strings.Repeat("1", 40)
	mergeSHA := strings.Repeat("2", 40)
	baseSHA := strings.Repeat("3", 40)
	headSHA := strings.Repeat("4", 40)

	tests := []struct {
		name      string
		event     string
		sha       string
		attempt   int
		pulls     []githubapi.PullRequestRef
		wantBasis string
		wantGap   bool
	}{
		{name: "push", event: "push", sha: pushSHA, wantBasis: "event-github-sha:push-tip"},
		{name: "workflow dispatch", event: "workflow_dispatch", sha: pushSHA, wantBasis: "event-github-sha:dispatched-ref"},
		{name: "pull request merge object", event: "pull_request", sha: mergeSHA, pulls: []githubapi.PullRequestRef{callerPullRequest(1, baseSHA, headSHA)}, wantBasis: "event-github-sha:pull-request-merge"},
		{name: "pull request target base object", event: "pull_request_target", sha: baseSHA, pulls: []githubapi.PullRequestRef{callerPullRequest(1, baseSHA, headSHA)}, wantBasis: "event-github-sha:pull-request-target-base"},
		{name: "issue comment default branch", event: "issue_comment", sha: pushSHA, wantBasis: "event-github-sha:default-branch-issue-comment"},
		{name: "repository dispatch default branch", event: "repository_dispatch", sha: pushSHA, wantBasis: "event-github-sha:default-branch-repository-dispatch"},
		{name: "schedule default branch", event: "schedule", sha: pushSHA, wantBasis: "event-github-sha:default-branch-schedule"},
		{name: "workflow run default branch", event: "workflow_run", sha: pushSHA, wantBasis: "event-github-sha:default-branch-workflow-run"},
		{name: "rerun preserves original event object", event: "push", sha: pushSHA, attempt: 2, wantBasis: "event-github-sha:push-tip"},
		{name: "workflow call is not independently attributable", event: "workflow_call", sha: pushSHA, wantGap: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newHistoricalExactAPI(t)
			target := historicalTarget(api)
			attempt := api.attempts[10][1]
			attempt.Path = workflow
			attempt.Event = test.event
			attempt.HeadSHA = test.sha
			attempt.PullRequests = test.pulls
			if test.attempt != 0 {
				attempt.RunAttempt = test.attempt
			}
			parent := attempt
			parent.RunAttempt = 1

			candidate, issue := deriveHistoricalCallerCandidate(target, parent, attempt)
			if test.wantGap {
				if issue == nil || candidate != (historicalCallerCandidate{}) {
					t.Fatalf("candidate=%+v issue=%+v, want explicit gap", candidate, issue)
				}
				return
			}
			if issue != nil {
				t.Fatalf("unexpected issue: %+v", issue)
			}
			if candidate.path != workflow || candidate.sha != test.sha || candidate.event != test.event || candidate.basis != test.wantBasis {
				t.Fatalf("candidate=%+v", candidate)
			}
		})
	}
}

func TestDeriveHistoricalCallerCandidateRejectsAmbiguousMetadata(t *testing.T) {
	sha := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	base := strings.Repeat("c", 40)
	head := strings.Repeat("d", 40)
	tests := []struct {
		name   string
		mutate func(*repositoryWork, *githubapi.WorkflowRun, *githubapi.WorkflowRun)
		reason collect.GapReason
	}{
		{name: "URL path", reason: collect.GapValidation, mutate: func(_ *repositoryWork, _, attempt *githubapi.WorkflowRun) {
			attempt.Path = "https://github.com/acme/service/blob/main/.github/workflows/ci.yml"
		}},
		{name: "GraphQL-style file URL", reason: collect.GapValidation, mutate: func(_ *repositoryWork, _, attempt *githubapi.WorkflowRun) {
			attempt.Path = "acme/service/.github/workflows/ci.yml@main"
		}},
		{name: "noncanonical event whitespace", reason: collect.GapValidation, mutate: func(_ *repositoryWork, _, attempt *githubapi.WorkflowRun) { attempt.Event = " push" }},
		{name: "parent path disagreement", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, _ *githubapi.WorkflowRun) { parent.Path = ".github/workflows/other.yml" }},
		{name: "parent event disagreement", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, _ *githubapi.WorkflowRun) { parent.Event = "schedule" }},
		{name: "parent SHA disagreement", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, _ *githubapi.WorkflowRun) { parent.HeadSHA = other }},
		{name: "pull request merge equals head", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, attempt.PullRequests = "pull_request", []githubapi.PullRequestRef{callerPullRequest(1, base, sha)}
			parent.Event, parent.PullRequests = attempt.Event, attempt.PullRequests
		}},
		{name: "pull request target without PR", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, attempt.PullRequests = "pull_request_target", nil
			parent.Event, parent.PullRequests = attempt.Event, nil
		}},
		{name: "pull request target foreign base repository", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, attempt.PullRequests = "pull_request_target", []githubapi.PullRequestRef{callerPullRequest(99, sha, head)}
			parent.Event, parent.PullRequests = attempt.Event, attempt.PullRequests
		}},
		{name: "pull request target multiple base objects", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, attempt.PullRequests = "pull_request_target", []githubapi.PullRequestRef{callerPullRequest(1, sha, head), callerPullRequest(1, other, head)}
			parent.Event, parent.PullRequests = attempt.Event, attempt.PullRequests
		}},
		{name: "pull request target candidate disagrees with head SHA", reason: collect.GapAmbiguousCorrelation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, attempt.PullRequests = "pull_request_target", []githubapi.PullRequestRef{callerPullRequest(1, base, head)}
			parent.Event, parent.PullRequests = attempt.Event, attempt.PullRequests
		}},
		{name: "unsupported event", reason: collect.GapValidation, mutate: func(_ *repositoryWork, parent, attempt *githubapi.WorkflowRun) {
			attempt.Event, parent.Event = "delete", "delete"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newHistoricalExactAPI(t)
			target := historicalTarget(api)
			attempt := api.attempts[10][1]
			attempt.Path, attempt.Event, attempt.HeadSHA = ".github/workflows/ci.yml", "push", sha
			parent := attempt
			test.mutate(&target, &parent, &attempt)
			candidate, issue := deriveHistoricalCallerCandidate(target, parent, attempt)
			if issue == nil || issue.reason != test.reason || candidate != (historicalCallerCandidate{}) {
				t.Fatalf("candidate=%+v issue=%+v, want %s", candidate, issue, test.reason)
			}
		})
	}
}

func TestHistoricalCallerRetrievalUsesOnlyEventCandidate(t *testing.T) {
	api := newHistoricalExactAPI(t)
	candidateSHA := strings.Repeat("7", 40)
	parent := api.runs["acme/service"][0]
	parent.Event, parent.Path, parent.HeadSHA = "workflow_dispatch", ".github/workflows/ci.yml", candidateSHA
	attempt := parent
	attempt.RunAttempt = 1
	attempt.ReferencedWorkflows = nil
	bundle := historicalBundle(api)
	bundle.Run = attempt
	api.put("acme/service", ".github/workflows/ci.yml", "sha1", candidateSHA, []byte("on: workflow_dispatch\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps: []\n"))

	result := repositoryResult{}
	err := (Collector{API: api}).resolveHistoricalAttemptWithParent(context.Background(), historicalTarget(api), parent, 10, bundle, historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('9'), &result)
	if err != nil {
		t.Fatal(err)
	}
	var matched bool
	for _, call := range api.calls {
		if call.repository == "acme/service" && call.path == ".github/workflows/ci.yml" {
			if call.object.Algorithm != "sha1" || call.object.Value != candidateSHA {
				t.Fatalf("caller content fetched at non-event object: %+v", call)
			}
			matched = true
		}
	}
	if !matched || result.callerWorkflowDefinitions != 1 {
		t.Fatalf("caller fetch=%v definitions=%d", matched, result.callerWorkflowDefinitions)
	}
}

func TestHistoricalCallerUnsupportedEventPersistsGapWithoutFetch(t *testing.T) {
	api := newHistoricalExactAPI(t)
	parent := api.runs["acme/service"][0]
	parent.Event = "workflow_call"
	attempt := parent
	attempt.RunAttempt = 1
	attempt.ReferencedWorkflows = nil
	bundle := historicalBundle(api)
	bundle.Run = attempt
	result := repositoryResult{}
	if err := (Collector{API: api}).resolveHistoricalAttemptWithParent(context.Background(), historicalTarget(api), parent, 10, bundle, historicalSession(), fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), nil, historicalEvidence('a'), &result); err != nil {
		t.Fatal(err)
	}
	for _, call := range api.calls {
		if call.repository == "acme/service" && call.path == ".github/workflows/ci.yml" {
			t.Fatalf("unsupported event fetched a guessed caller: %+v", call)
		}
	}
	if len(result.gaps) != 1 || result.gaps[0].Scope != "historical_workflow" || result.gaps[0].Reason != collect.GapValidation {
		t.Fatalf("unsupported event gaps=%+v", result.gaps)
	}
}

func TestHistoricalStepBindingsRequireUniqueStaticJobAndStep(t *testing.T) {
	reference := workflow.Reference{Kind: workflow.ReferenceRepository, Raw: "fixture/action@v1", Owner: "fixture", Repository: "action", Ref: "v1"}
	baseWorkflow := func() *workflow.Workflow {
		return &workflow.Workflow{Jobs: []workflow.Job{{ID: "build", Steps: []workflow.Step{{Ordinal: 1, Name: "Custom marker", Uses: &reference}}}}}
	}
	setup := githubapi.JobStep{Number: 1, Name: "Set up job", Status: "completed", Conclusion: "success"}
	action := githubapi.JobStep{Number: 2, Name: "Custom marker", Status: "completed", Conclusion: "success"}
	baseJob := githubapi.WorkflowJob{ID: 20, Name: "build", Steps: []githubapi.JobStep{setup, action}}
	evidenceIDs := []model.EvidenceID{historicalEvidence('b')}

	tests := []struct {
		name       string
		workflow   *workflow.Workflow
		jobs       []githubapi.WorkflowJob
		wantBound  bool
		wantIssues bool
	}{
		{name: "unique custom step", workflow: baseWorkflow(), jobs: []githubapi.WorkflowJob{baseJob}, wantBound: true},
		{name: "matrix-expanded duplicate API jobs", workflow: baseWorkflow(), jobs: []githubapi.WorkflowJob{baseJob, func() githubapi.WorkflowJob { value := baseJob; value.ID = 21; return value }()}, wantIssues: true},
		{name: "dynamic historical job name", workflow: func() *workflow.Workflow {
			value := baseWorkflow()
			value.Jobs[0].Name = "Build ${{ matrix.os }}"
			return value
		}(), jobs: []githubapi.WorkflowJob{baseJob}, wantIssues: true},
		{name: "dynamic historical step name", workflow: func() *workflow.Workflow {
			value := baseWorkflow()
			value.Jobs[0].Steps[0].Name = "Build ${{ matrix.os }}"
			return value
		}(), jobs: []githubapi.WorkflowJob{baseJob}, wantIssues: true},
		{name: "missing exact setup step", workflow: baseWorkflow(), jobs: []githubapi.WorkflowJob{{ID: 20, Name: "build", Steps: []githubapi.JobStep{action}}}, wantIssues: true},
		{name: "API step number mismatch", workflow: baseWorkflow(), jobs: []githubapi.WorkflowJob{{ID: 20, Name: "build", Steps: []githubapi.JobStep{setup, {Number: 3, Name: "Custom marker"}}}}, wantIssues: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bindings, issues := deriveHistoricalStepBindings(test.workflow, test.jobs, evidenceIDs)
			_, bound := bindings[20][2]
			if bound != test.wantBound || (len(issues) > 0) != test.wantIssues {
				t.Fatalf("bound=%v bindings=%+v issues=%+v", bound, bindings, issues)
			}
			if bound {
				value := bindings[20][2]
				if value.declaration != "fixture/action@v1" || value.workflowJob != "build" || value.stepOrdinal != 1 || len(value.evidenceIDs) != 1 || value.evidenceIDs[0] != evidenceIDs[0] {
					t.Fatalf("binding=%+v", value)
				}
			}
		})
	}
}

func callerPullRequest(baseRepositoryID int64, baseSHA, headSHA string) githubapi.PullRequestRef {
	value := githubapi.PullRequestRef{ID: 1, Number: 1}
	value.Base.SHA = baseSHA
	value.Base.Ref = "main"
	value.Base.Repo = &githubapi.Repository{ID: baseRepositoryID, FullName: "acme/service", Name: "service", Owner: githubapi.Actor{ID: 1, Login: "acme"}}
	value.Head.SHA = headSHA
	value.Head.Ref = "feature"
	value.Head.Repo = &githubapi.Repository{ID: 2, FullName: "fork/service", Name: "service", Owner: githubapi.Actor{ID: 2, Login: "fork"}}
	return value
}
