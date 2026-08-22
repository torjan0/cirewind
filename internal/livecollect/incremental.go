package livecollect

import (
	"sort"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/model"
)

type archiveScheduleBasis string

const (
	scheduleInitial            archiveScheduleBasis = "initial-parent-horizon"
	scheduleCheckpointResume   archiveScheduleBasis = "checkpoint-resume"
	scheduleCheckpointFallback archiveScheduleBasis = "checkpoint-fallback-full-horizon"
	scheduleExplicitPreserve   archiveScheduleBasis = "explicit-window-preserve-checkpoint"
)

type repositoryArchiveSchedule struct {
	parentWindow    collect.Interval
	basis           archiveScheduleBasis
	writeCheckpoint bool
	requiredRefresh []collect.WatchedRun
	retainedByRunID map[int64]archive.WatchedParent
	continuityGap   *collect.Interval
}

func scheduleRepository(request Request, discovery collect.Interval, repositoryID model.RepositoryID) repositoryArchiveSchedule {
	initial := repositoryArchiveSchedule{
		parentWindow: discovery, basis: scheduleInitial, writeCheckpoint: true,
		requiredRefresh: []collect.WatchedRun{}, retainedByRunID: map[int64]archive.WatchedParent{},
	}
	if request.Purpose != PurposeArchive {
		return initial
	}
	if request.ArchiveSchedule == ArchiveSchedulePreserve {
		initial.basis = scheduleExplicitPreserve
		initial.writeCheckpoint = false
		return initial
	}
	if request.ArchiveSchedule != ArchiveScheduleResume {
		return initial
	}
	checkpoint, ok := checkpointForRepository(request.ArchiveCheckpoints, repositoryID)
	if !ok || !checkpointMatchesCurrentPolicy(checkpoint, request.Interval.To) {
		initial.basis = scheduleCheckpointFallback
		return initial
	}

	watched := make([]collect.WatchedRun, 0, len(checkpoint.WatchedParents))
	for _, parent := range checkpoint.WatchedParents {
		candidate := collect.WatchedRun{
			RepositoryID: int64(repositoryID), RunID: int64(parent.RunID), CreatedAt: parent.CreatedAt.Time,
			FinalRefreshComplete: parent.FinalRefreshComplete,
		}
		if parent.LastRefreshedAt != nil {
			candidate.LastSuccessfulRefresh = parent.LastRefreshedAt.Time
		}
		watched = append(watched, candidate)
	}
	plan, err := collect.PlanIncrementalArchive(request.Interval, checkpoint.DiscoveryWatermark.Time, watched)
	if err != nil {
		initial.basis = scheduleCheckpointFallback
		return initial
	}
	retained := make(map[int64]archive.WatchedParent, len(plan.Refresh))
	for _, refresh := range plan.Refresh {
		retained[refresh.RunID] = archive.WatchedParent{
			RunID: model.WorkflowRunID(refresh.RunID), CreatedAt: model.MustInstant(refresh.CreatedAt.UTC()),
			FinalRefreshComplete: refresh.FinalRefreshComplete,
		}
		if !refresh.LastSuccessfulRefresh.IsZero() {
			value := model.MustInstant(refresh.LastSuccessfulRefresh.UTC())
			parent := retained[refresh.RunID]
			parent.LastRefreshedAt = &value
			retained[refresh.RunID] = parent
		}
	}
	var continuityGap *collect.Interval
	if checkpoint.DiscoveryWatermark.Before(request.Interval.From) {
		value := collect.Interval{From: checkpoint.DiscoveryWatermark.Time, To: request.Interval.From}
		continuityGap = &value
	}
	return repositoryArchiveSchedule{
		parentWindow: plan.NewParentWindow, basis: scheduleCheckpointResume, writeCheckpoint: true,
		requiredRefresh: plan.Refresh, retainedByRunID: retained, continuityGap: continuityGap,
	}
}

func checkpointForRepository(checkpoints []archive.Checkpoint, repositoryID model.RepositoryID) (archive.Checkpoint, bool) {
	index := sort.Search(len(checkpoints), func(index int) bool {
		return checkpoints[index].RepositoryID >= repositoryID
	})
	if index == len(checkpoints) || checkpoints[index].RepositoryID != repositoryID {
		return archive.Checkpoint{}, false
	}
	return checkpoints[index], true
}

func checkpointMatchesCurrentPolicy(checkpoint archive.Checkpoint, cutoff time.Time) bool {
	if checkpoint.DiscoveryWatermark == nil || checkpoint.OverlapSeconds != uint32(collect.DefaultArchiveOverlap/time.Second) ||
		checkpoint.WatchHorizonDays != uint32(collect.ProvisionalParentLookback/(24*time.Hour)) {
		return false
	}
	if checkpoint.DiscoveryWatermark.After(cutoff.Add(collect.DefaultArchiveOverlap)) {
		return false
	}
	for _, parent := range checkpoint.WatchedParents {
		if parent.CreatedAt.After(cutoff) || (parent.LastRefreshedAt != nil && parent.LastRefreshedAt.Before(parent.CreatedAt.Time)) {
			return false
		}
	}
	return true
}

func sortedWatchedParents(parents map[int64]archive.WatchedParent) []archive.WatchedParent {
	result := make([]archive.WatchedParent, 0, len(parents))
	for _, parent := range parents {
		result = append(result, parent)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RunID < result[j].RunID })
	return result
}
