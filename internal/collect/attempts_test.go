package collect

import (
	"context"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/githubapi"
)

type fakeAttemptAPI struct {
	parents      []githubapi.WorkflowRun
	parentIndex  int
	attempts     map[int]githubapi.WorkflowRun
	jobs         map[int][]githubapi.WorkflowJob
	initialError error
	jobCalls     []int
}

func (f *fakeAttemptAPI) GetWorkflowRun(context.Context, string, string, int64) (githubapi.ObjectResult[githubapi.WorkflowRun], error) {
	if f.initialError != nil {
		err := f.initialError
		f.initialError = nil
		return githubapi.ObjectResult[githubapi.WorkflowRun]{}, err
	}
	index := f.parentIndex
	if index >= len(f.parents) {
		index = len(f.parents) - 1
	}
	if f.parentIndex < len(f.parents)-1 {
		f.parentIndex++
	}
	return githubapi.ObjectResult[githubapi.WorkflowRun]{Value: f.parents[index]}, nil
}

func (f *fakeAttemptAPI) GetWorkflowRunAttempt(_ context.Context, _, _ string, _ int64, attempt int) (githubapi.ObjectResult[githubapi.WorkflowRun], error) {
	return githubapi.ObjectResult[githubapi.WorkflowRun]{Value: f.attempts[attempt]}, nil
}

func (f *fakeAttemptAPI) ListJobsForAttempt(_ context.Context, _, _ string, _ int64, attempt int) (githubapi.JobList, error) {
	f.jobCalls = append(f.jobCalls, attempt)
	return githubapi.JobList{Jobs: append([]githubapi.WorkflowJob(nil), f.jobs[attempt]...)}, nil
}

func TestAttemptCollectorFindsNewAttemptAndKeepsPartialMembership(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	two := base.Add(time.Minute)
	three := base.Add(2 * time.Minute)
	api := &fakeAttemptAPI{
		parents: []githubapi.WorkflowRun{
			{ID: 99, RunAttempt: 2, Status: "completed", UpdatedAt: &two},
			{ID: 99, RunAttempt: 3, Status: "completed", UpdatedAt: &three},
			{ID: 99, RunAttempt: 3, Status: "completed", UpdatedAt: &three},
		},
		attempts: map[int]githubapi.WorkflowRun{
			1: {ID: 99, RunAttempt: 1}, 2: {ID: 99, RunAttempt: 2}, 3: {ID: 99, RunAttempt: 3},
		},
		jobs: map[int][]githubapi.WorkflowJob{
			1: {{ID: 1, RunID: 99}, {ID: 2, RunID: 99}},
			2: {{ID: 3, RunID: 99}},
			3: {{ID: 4, RunID: 99}},
		},
	}
	snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Stable || len(snapshot.Attempts) != 3 || snapshot.FinalParent.RunAttempt != 3 || len(snapshot.Gaps) != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if len(snapshot.Attempts[1].Jobs) != 1 || snapshot.Attempts[1].Jobs[0].ID != 3 {
		t.Fatalf("partial attempt membership was altered: %+v", snapshot.Attempts[1])
	}
}

func TestAttemptCollectorRecordsLiveStateRace(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	one := base.Add(time.Minute)
	two := base.Add(2 * time.Minute)
	three := base.Add(3 * time.Minute)
	api := &fakeAttemptAPI{
		parents: []githubapi.WorkflowRun{
			{ID: 99, RunAttempt: 1, Status: "queued", UpdatedAt: &one},
			{ID: 99, RunAttempt: 1, Status: "in_progress", UpdatedAt: &two},
			{ID: 99, RunAttempt: 2, Status: "in_progress", UpdatedAt: &three},
		},
		attempts: map[int]githubapi.WorkflowRun{1: {ID: 99, RunAttempt: 1}, 2: {ID: 99, RunAttempt: 2}},
		jobs:     map[int][]githubapi.WorkflowJob{},
	}
	snapshot, err := (AttemptCollector{API: api, MaxStabilizationPasses: 2}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Stable || len(snapshot.Gaps) != 1 || snapshot.Gaps[0].Reason != GapLiveStateRace || !snapshot.Gaps[0].Retryable {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestAttemptCollectorConvertsInitialAuthorizationFailureToCoverageGap(t *testing.T) {
	t.Parallel()
	api := &fakeAttemptAPI{initialError: &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "get run", Message: "denied"}}
	snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Gaps) != 1 || snapshot.Gaps[0].Reason != GapForbidden || snapshot.Stable {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestAttemptCollectorQuarantinesContradictoryAttemptAndContinuesValidSibling(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	api := &fakeAttemptAPI{
		parents: []githubapi.WorkflowRun{{ID: 99, RunAttempt: 2, UpdatedAt: &base}},
		attempts: map[int]githubapi.WorkflowRun{
			1: {ID: 100, RunAttempt: 1},
			2: {ID: 99, RunAttempt: 2},
		},
		jobs: map[int][]githubapi.WorkflowJob{
			1: {{ID: 1, RunID: 99}},
			2: {{ID: 2, RunID: 99}},
		},
	}
	snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Attempts) != 1 || snapshot.Attempts[0].Attempt != 2 || len(snapshot.Attempts[0].Jobs) != 1 || snapshot.Attempts[0].Jobs[0].ID != 2 {
		t.Fatalf("contradictory attempt was retained or valid sibling was lost: %#v", snapshot.Attempts)
	}
	if len(api.jobCalls) != 1 || api.jobCalls[0] != 2 {
		t.Fatalf("job enumeration crossed a quarantined attempt: calls=%v", api.jobCalls)
	}
	assertIdentityGap(t, snapshot.Gaps, "workflow_run_attempt", 1)
}

func TestAttemptCollectorQuarantinesContradictoryJobAndKeepsValidSibling(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	api := &fakeAttemptAPI{
		parents:  []githubapi.WorkflowRun{{ID: 99, RunAttempt: 1, UpdatedAt: &base}},
		attempts: map[int]githubapi.WorkflowRun{1: {ID: 99, RunAttempt: 1}},
		jobs: map[int][]githubapi.WorkflowJob{1: {
			{ID: 1, RunID: 100, Name: "untrusted"},
			{ID: 2, RunID: 99, Name: "valid"},
		}},
	}
	snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Attempts) != 1 || len(snapshot.Attempts[0].Jobs) != 1 || snapshot.Attempts[0].Jobs[0].ID != 2 {
		t.Fatalf("contradictory job was retained or valid sibling was lost: %#v", snapshot.Attempts)
	}
	if snapshot.Attempts[0].LogJobNameCorrelationSafe("untrusted") {
		t.Fatal("quarantined job name remained eligible for attempt-log correlation")
	}
	if !snapshot.Attempts[0].LogJobNameCorrelationSafe("valid") {
		t.Fatal("valid sibling name was unnecessarily quarantined")
	}
	assertIdentityGap(t, snapshot.Gaps, "attempt_job", 1)
	if snapshot.Gaps[0].JobID != 0 {
		t.Fatalf("contradictory job ID was invented into expected scope: %#v", snapshot.Gaps[0])
	}
}

func TestAttemptCollectorQuarantinesEveryDuplicateJobIDOccurrence(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	api := &fakeAttemptAPI{
		parents:  []githubapi.WorkflowRun{{ID: 99, RunAttempt: 1, UpdatedAt: &base}},
		attempts: map[int]githubapi.WorkflowRun{1: {ID: 99, RunAttempt: 1}},
		jobs: map[int][]githubapi.WorkflowJob{1: {
			{ID: 1, RunID: 99, Name: "first-body"},
			{ID: 1, RunID: 100, Name: "conflicting-body"},
			{ID: 2, RunID: 99, Name: "valid"},
		}},
	}
	snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Attempts) != 1 || len(snapshot.Attempts[0].Jobs) != 1 || snapshot.Attempts[0].Jobs[0].ID != 2 {
		t.Fatalf("response ordering selected a duplicate job body: %#v", snapshot.Attempts)
	}
	if snapshot.Attempts[0].LogJobNameCorrelationSafe("first-body") || snapshot.Attempts[0].LogJobNameCorrelationSafe("conflicting-body") {
		t.Fatal("duplicate job occurrence remained eligible for log correlation")
	}
	assertIdentityGap(t, snapshot.Gaps, "attempt_job", 1)
}

func TestAttemptCollectorRejectsMismatchedParentBeforeEnumerationAndStabilization(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		parents  []githubapi.WorkflowRun
		attempts map[int]githubapi.WorkflowRun
		want     string
	}{
		{name: "initial", parents: []githubapi.WorkflowRun{{ID: 100, RunAttempt: 1, UpdatedAt: &base}}, attempts: map[int]githubapi.WorkflowRun{}, want: "workflow_run"},
		{name: "stabilization", parents: []githubapi.WorkflowRun{{ID: 99, RunAttempt: 1, UpdatedAt: &base}, {ID: 100, RunAttempt: 2, UpdatedAt: &base}}, attempts: map[int]githubapi.WorkflowRun{1: {ID: 99, RunAttempt: 1}}, want: "workflow_run_stabilization"},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAttemptAPI{parents: test.parents, attempts: test.attempts, jobs: map[int][]githubapi.WorkflowJob{}}
			snapshot, err := (AttemptCollector{API: api}).Snapshot(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, 99)
			if err != nil {
				t.Fatal(err)
			}
			assertIdentityGap(t, snapshot.Gaps, test.want, 0)
			if snapshot.Stable {
				t.Fatal("contradictory parent marked stable")
			}
			if test.name == "initial" && (len(snapshot.Attempts) != 0 || len(api.jobCalls) != 0) {
				t.Fatalf("initial parent contradiction drove enumeration: attempts=%#v calls=%v", snapshot.Attempts, api.jobCalls)
			}
			if test.name == "stabilization" && len(snapshot.Attempts) != 1 {
				t.Fatalf("stabilization contradiction invented later attempts: %#v", snapshot.Attempts)
			}
		})
	}
}

func assertIdentityGap(t *testing.T, gaps []Gap, scope string, attempt int) {
	t.Helper()
	for _, gap := range gaps {
		if gap.Scope == scope && gap.Attempt == attempt && gap.Reason == GapAmbiguousCorrelation && gap.Material {
			return
		}
	}
	t.Fatalf("material identity-correlation gap %s/%d missing: %#v", scope, attempt, gaps)
}
