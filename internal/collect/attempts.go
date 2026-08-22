package collect

import (
	"context"
	"errors"
	"sort"

	"github.com/torjan0/cirewind/internal/githubapi"
)

type AttemptAPI interface {
	GetWorkflowRun(context.Context, string, string, int64) (githubapi.ObjectResult[githubapi.WorkflowRun], error)
	GetWorkflowRunAttempt(context.Context, string, string, int64, int) (githubapi.ObjectResult[githubapi.WorkflowRun], error)
	ListJobsForAttempt(context.Context, string, string, int64, int) (githubapi.JobList, error)
}

type AttemptBundle struct {
	Attempt   int                      `json:"attempt"`
	Run       githubapi.WorkflowRun    `json:"run"`
	Jobs      []githubapi.WorkflowJob  `json:"jobs"`
	Responses []githubapi.ResponseMeta `json:"responses"`

	// quarantinedJobNames is deliberately not serialized. These names came
	// from job objects whose run_id contradicted the attempt endpoint. They may
	// only be used to prevent an untrusted ZIP entry name from being correlated
	// to a valid sibling; they are never persisted as collected job identity.
	quarantinedJobNames []string
}

// LogJobNameCorrelationSafe reports whether an attempt-log directory name can
// still be correlated after contradictory job objects were quarantined. An
// empty name on any quarantined object makes all name-only correlation unsafe.
func (b AttemptBundle) LogJobNameCorrelationSafe(name string) bool {
	for _, quarantined := range b.quarantinedJobNames {
		if quarantined == "" || quarantined == name {
			return false
		}
	}
	return true
}

type AttemptSnapshot struct {
	InitialParent   githubapi.WorkflowRun    `json:"initial_parent"`
	FinalParent     githubapi.WorkflowRun    `json:"final_parent"`
	ParentResponses []githubapi.ResponseMeta `json:"parent_responses"`
	Attempts        []AttemptBundle          `json:"attempts"`
	Gaps            []Gap                    `json:"gaps,omitempty"`
	Stable          bool                     `json:"stable"`
}

type AttemptCollector struct {
	API                    AttemptAPI
	MaxStabilizationPasses int
}

func (c AttemptCollector) Snapshot(ctx context.Context, repository RepositoryTarget, runID int64) (AttemptSnapshot, error) {
	if c.API == nil {
		return AttemptSnapshot{}, errors.New("attempt API is nil")
	}
	if repository.ID <= 0 || repository.Owner == "" || repository.Name == "" || runID <= 0 {
		return AttemptSnapshot{}, errors.New("repository target or run ID is invalid")
	}
	if c.MaxStabilizationPasses <= 0 {
		c.MaxStabilizationPasses = 3
	}
	var snapshot AttemptSnapshot
	parent, err := c.API.GetWorkflowRun(ctx, repository.Owner, repository.Name, runID)
	snapshot.ParentResponses = append(snapshot.ParentResponses, parent.Responses...)
	if err != nil {
		snapshot.Gaps = append(snapshot.Gaps, GapFromError("workflow_run", repository.ID, runID, 0, err))
		if ctx.Err() != nil {
			return snapshot, ctx.Err()
		}
		return snapshot, nil
	}
	snapshot.InitialParent = parent.Value
	if parent.Value.ID != runID {
		snapshot.Gaps = append(snapshot.Gaps, identityGap("workflow_run", repository.ID, runID, 0, "parent response contradicted the requested run ID", parent.Responses))
		return snapshot, nil
	}
	current := parent.Value
	collected := make(map[int]bool)

	for pass := 0; pass < c.MaxStabilizationPasses; pass++ {
		if err := ctx.Err(); err != nil {
			snapshot.Gaps = append(snapshot.Gaps, Gap{Reason: GapCancelled, Scope: "workflow_run", RepositoryID: repository.ID, RunID: runID, Material: true, Diagnostic: "attempt collection cancelled"})
			return snapshot, err
		}
		if current.RunAttempt <= 0 {
			snapshot.Gaps = append(snapshot.Gaps, Gap{Reason: GapMalformedResponse, Scope: "workflow_run", RepositoryID: repository.ID, RunID: runID, Material: true, Diagnostic: "run_attempt must be positive"})
			return snapshot, nil
		}
		for attempt := 1; attempt <= current.RunAttempt; attempt++ {
			if collected[attempt] {
				continue
			}
			bundle := AttemptBundle{Attempt: attempt}
			attemptResult, attemptErr := c.API.GetWorkflowRunAttempt(ctx, repository.Owner, repository.Name, runID, attempt)
			bundle.Responses = append(bundle.Responses, attemptResult.Responses...)
			if attemptErr != nil {
				snapshot.Gaps = append(snapshot.Gaps, GapFromError("workflow_run_attempt", repository.ID, runID, attempt, attemptErr))
				collected[attempt] = true
				continue
			}
			bundle.Run = attemptResult.Value
			if bundle.Run.ID != runID || bundle.Run.RunAttempt != attempt {
				snapshot.Gaps = append(snapshot.Gaps, identityGap("workflow_run_attempt", repository.ID, runID, attempt, "attempt response contradicted the requested run-attempt identity", attemptResult.Responses))
				// The route parameters are not a license to repair a contradictory
				// response body. Do not enumerate jobs or expose this bundle to log
				// parsing, historical resolution, or finding derivation.
				collected[attempt] = true
				continue
			}
			jobs, jobsErr := c.API.ListJobsForAttempt(ctx, repository.Owner, repository.Name, runID, attempt)
			bundle.Responses = append(bundle.Responses, jobs.Responses...)
			if jobsErr != nil {
				snapshot.Gaps = append(snapshot.Gaps, GapFromError("attempt_jobs", repository.ID, runID, attempt, jobsErr))
			} else {
				jobIDCounts := make(map[int64]int, len(jobs.Jobs))
				for _, job := range jobs.Jobs {
					if job.ID > 0 {
						jobIDCounts[job.ID]++
					}
				}
				missingIdentity, contradictedRun := false, false
				duplicateIDs := make(map[int64]struct{})
				for _, job := range jobs.Jobs {
					if job.ID <= 0 {
						missingIdentity = true
						bundle.quarantinedJobNames = append(bundle.quarantinedJobNames, job.Name)
						continue
					}
					if jobIDCounts[job.ID] > 1 {
						// A duplicate ID makes every occurrence untrustworthy. Keeping
						// the first object would let response ordering choose forensic
						// truth when later fields materially disagree.
						duplicateIDs[job.ID] = struct{}{}
						bundle.quarantinedJobNames = append(bundle.quarantinedJobNames, job.Name)
						continue
					}
					if job.RunID != runID {
						// Do not attach the untrusted job ID to the expected run-attempt
						// scope. Only the requested attempt is safe to name in the gap.
						contradictedRun = true
						bundle.quarantinedJobNames = append(bundle.quarantinedJobNames, job.Name)
						continue
					}
					bundle.Jobs = append(bundle.Jobs, job)
				}
				if missingIdentity {
					snapshot.Gaps = append(snapshot.Gaps, identityGap("attempt_job", repository.ID, runID, attempt, "job response omitted a trustworthy execution identity", jobs.Responses))
				}
				if contradictedRun {
					snapshot.Gaps = append(snapshot.Gaps, identityGap("attempt_job", repository.ID, runID, attempt, "job response contradicted the requested run identity", jobs.Responses))
				}
				if len(duplicateIDs) != 0 {
					snapshot.Gaps = append(snapshot.Gaps, identityGap("attempt_job", repository.ID, runID, attempt, "attempt jobs response repeated a job ID; every occurrence was quarantined", jobs.Responses))
				}
				sort.Strings(bundle.quarantinedJobNames)
				sort.Slice(bundle.Jobs, func(i, j int) bool { return bundle.Jobs[i].ID < bundle.Jobs[j].ID })
			}
			snapshot.Attempts = append(snapshot.Attempts, bundle)
			collected[attempt] = true
		}

		nextResult, nextErr := c.API.GetWorkflowRun(ctx, repository.Owner, repository.Name, runID)
		snapshot.ParentResponses = append(snapshot.ParentResponses, nextResult.Responses...)
		if nextErr != nil {
			snapshot.Gaps = append(snapshot.Gaps, GapFromError("workflow_run_stabilization", repository.ID, runID, 0, nextErr))
			if ctx.Err() != nil {
				return snapshot, ctx.Err()
			}
			return snapshot, nil
		}
		next := nextResult.Value
		snapshot.FinalParent = next
		if next.ID != runID {
			snapshot.Gaps = append(snapshot.Gaps, identityGap("workflow_run_stabilization", repository.ID, runID, 0, "stabilization response contradicted the requested run ID", nextResult.Responses))
			return snapshot, nil
		}
		if sameRunSnapshot(current, next) {
			snapshot.Stable = true
			sort.Slice(snapshot.Attempts, func(i, j int) bool { return snapshot.Attempts[i].Attempt < snapshot.Attempts[j].Attempt })
			return snapshot, nil
		}
		current = next
	}
	snapshot.FinalParent = current
	snapshot.Gaps = append(snapshot.Gaps, Gap{Reason: GapLiveStateRace, Scope: "workflow_run", RepositoryID: repository.ID, RunID: runID, Material: true, Retryable: true, Diagnostic: "run changed throughout the stabilization budget"})
	sort.Slice(snapshot.Attempts, func(i, j int) bool { return snapshot.Attempts[i].Attempt < snapshot.Attempts[j].Attempt })
	return snapshot, nil
}

func identityGap(scope string, repositoryID, runID int64, attempt int, diagnostic string, responses []githubapi.ResponseMeta) Gap {
	return Gap{
		Reason: GapAmbiguousCorrelation, Scope: scope, RepositoryID: repositoryID, RunID: runID,
		Attempt: attempt, Material: true, Diagnostic: diagnostic,
		Responses: append([]githubapi.ResponseMeta(nil), responses...),
	}
}

func sameRunSnapshot(left, right githubapi.WorkflowRun) bool {
	if left.ID != right.ID || left.RunAttempt != right.RunAttempt || left.Status != right.Status || left.Conclusion != right.Conclusion {
		return false
	}
	if left.UpdatedAt == nil || right.UpdatedAt == nil {
		return left.UpdatedAt == nil && right.UpdatedAt == nil
	}
	return left.UpdatedAt.Equal(*right.UpdatedAt)
}
