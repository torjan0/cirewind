package livecollect

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

func TestRepositoryScheduleInitialResumeMissingAndExplicit(t *testing.T) {
	cutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	requested, _ := collect.NewInterval(cutoff.Add(-time.Hour), cutoff)
	discovery, _ := collect.ExpandIncidentDiscoveryWindow(requested)
	created := cutoff.Add(-60 * 24 * time.Hour)
	watermark := cutoff.Add(-30 * time.Minute)
	checkpoint := archive.Checkpoint{
		RepositoryID: 1, DiscoveryWatermark: instantPointer(model.MustInstant(watermark)),
		OverlapSeconds:           uint32(collect.DefaultArchiveOverlap / time.Second),
		WatchHorizonDays:         uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
		LastSuccessfulCollection: "collection:test", WatchedParents: []archive.WatchedParent{{RunID: 10, CreatedAt: model.MustInstant(created)}},
	}

	initial := scheduleRepository(Request{Purpose: PurposeArchive, ArchiveSchedule: ArchiveScheduleInitial, Interval: requested}, discovery, 1)
	if initial.basis != scheduleInitial || !initial.parentWindow.From.Equal(discovery.From) || !initial.writeCheckpoint {
		t.Fatalf("initial schedule = %#v", initial)
	}

	resumed := scheduleRepository(Request{Purpose: PurposeArchive, ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{checkpoint}, Interval: requested}, discovery, 1)
	if got, want := resumed.parentWindow.From, watermark.Add(-collect.DefaultArchiveOverlap); !got.Equal(want) {
		t.Fatalf("resumed parent start = %s, want %s", got, want)
	}
	if resumed.basis != scheduleCheckpointResume || len(resumed.requiredRefresh) != 1 || resumed.requiredRefresh[0].RunID != 10 {
		t.Fatalf("resumed schedule = %#v", resumed)
	}

	missing := scheduleRepository(Request{Purpose: PurposeArchive, ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{}, Interval: requested}, discovery, 1)
	if missing.basis != scheduleCheckpointFallback || !missing.parentWindow.From.Equal(discovery.From) {
		t.Fatalf("missing-checkpoint schedule = %#v", missing)
	}

	incompatible := checkpoint
	incompatible.WatchHorizonDays = 35
	fallback := scheduleRepository(Request{Purpose: PurposeArchive, ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{incompatible}, Interval: requested}, discovery, 1)
	if fallback.basis != scheduleCheckpointFallback || !fallback.parentWindow.From.Equal(discovery.From) {
		t.Fatalf("incompatible-checkpoint schedule = %#v", fallback)
	}

	explicit := scheduleRepository(Request{Purpose: PurposeArchive, ArchiveSchedule: ArchiveSchedulePreserve, Interval: requested}, discovery, 1)
	if explicit.basis != scheduleExplicitPreserve || explicit.writeCheckpoint || !explicit.parentWindow.From.Equal(discovery.From) {
		t.Fatalf("explicit schedule = %#v", explicit)
	}
}

func TestIncrementalArchiveRefreshFindsLateAttemptAndDelayedJob(t *testing.T) {
	ctx := context.Background()
	api := successfulAPI(t, false)
	firstCutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	firstWindow, _ := collect.NewInterval(firstCutoff.Add(-time.Hour), firstCutoff)
	collector := Collector{API: api, Now: fixedClock(firstCutoff.Add(time.Minute)), TempDir: t.TempDir()}
	first, err := collector.Collect(ctx, Request{Repositories: []string{"acme/service"}, Interval: firstWindow, Purpose: PurposeArchive, Concurrency: 1, ArchiveSchedule: ArchiveScheduleInitial})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Batch.Checkpoints) != 1 || len(first.Batch.Checkpoints[0].WatchedParents) != 1 {
		t.Fatalf("initial checkpoint = %#v", first.Batch.Checkpoints)
	}

	lateTime := firstCutoff.Add(30 * time.Minute)
	secondAttempt := api.attempts[10][1]
	secondAttempt.RunAttempt = 2
	secondAttempt.UpdatedAt = &lateTime
	api.attempts[10][2] = secondAttempt
	started, completed := lateTime, lateTime.Add(time.Minute)
	lateJob := githubapi.WorkflowJob{ID: 22, RunID: 10, Name: "build", Status: "completed", Conclusion: "success", StartedAt: &started, CompletedAt: &completed, Labels: []string{"ubuntu-latest", "github-hosted"}, Steps: []githubapi.JobStep{{Number: 1, Name: "Set up job", Status: "completed", Conclusion: "success"}}}
	api.jobs[10][2] = []githubapi.WorkflowJob{lateJob}
	api.jobLogs[22] = []byte("late rerun job log\n")
	api.attemptLogs[10][2] = makeZIP(t, map[string]string{"build/1_Set up job.txt": "2026-08-20T02:30:01Z Current runner version: '2.400.0'\n"})

	secondCutoff := firstCutoff.Add(2 * time.Hour)
	secondWindow, _ := collect.NewInterval(firstCutoff.Add(-time.Hour), secondCutoff)
	collector.Now = fixedClock(secondCutoff.Add(time.Minute))
	second, err := collector.Collect(ctx, Request{
		Repositories: []string{"acme/service"}, Interval: secondWindow, Purpose: PurposeArchive, Concurrency: 1,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: first.Batch.Checkpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasAttemptFact(second.Batch.Facts, 10, 2) {
		t.Fatal("a late rerun attempt on the watched parent was not collected")
	}
	if len(second.Batch.Checkpoints) != 1 {
		t.Fatalf("late-attempt checkpoint = %#v", second.Batch.Checkpoints)
	}
	assertCollectionWindow(t, second.Batch.Collections[0].Scope.RequestedEventWindow, secondWindow, model.ApproximationExact)
	discovery, _ := collect.ExpandIncidentDiscoveryWindow(secondWindow)
	assertCollectionWindow(t, second.Batch.Collections[0].Scope.DiscoveryEventWindow, discovery, model.ApproximationConservativeExpanded)
	wantParentFrom := firstCutoff.Add(-collect.DefaultArchiveOverlap)
	if !apiCalled(api, "probe:"+wantParentFrom.Format(time.RFC3339)+".."+secondWindow.To.Format(time.RFC3339)) || !apiCalled(api, "get-run:10") {
		t.Fatalf("resume did not use bounded new-parent discovery plus by-ID refresh: %#v", api.calls)
	}

	delayedTime := secondCutoff.Add(30 * time.Minute)
	secondAttempt.UpdatedAt = &delayedTime
	api.attempts[10][2] = secondAttempt
	delayedStarted, delayedCompleted := delayedTime, delayedTime.Add(time.Minute)
	delayedJob := lateJob
	delayedJob.ID = 23
	delayedJob.Name = "environment-deploy"
	delayedJob.StartedAt, delayedJob.CompletedAt = &delayedStarted, &delayedCompleted
	api.jobs[10][2] = append(api.jobs[10][2], delayedJob)
	api.jobLogs[23] = []byte("environment-delayed job log\n")
	api.attemptLogs[10][2] = makeZIP(t, map[string]string{
		"build/1_Set up job.txt":              "2026-08-20T04:30:01Z Current runner version: '2.400.0'\n",
		"environment-deploy/1_Set up job.txt": "2026-08-20T04:30:02Z Current runner version: '2.400.0'\n",
	})
	thirdCutoff := secondCutoff.Add(2 * time.Hour)
	thirdWindow, _ := collect.NewInterval(secondCutoff, thirdCutoff)
	collector.Now = fixedClock(thirdCutoff.Add(time.Minute))
	third, err := collector.Collect(ctx, Request{
		Repositories: []string{"acme/service"}, Interval: thirdWindow, Purpose: PurposeArchive, Concurrency: 1,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: second.Batch.Checkpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasJobFact(third.Batch.Facts, 10, 2, 23) {
		t.Fatal("a job that appeared later on the watched attempt was not collected")
	}
}

func TestIncompleteWatchedRefreshPersistsGapAndDoesNotAdvanceCheckpoint(t *testing.T) {
	ctx := context.Background()
	api := successfulAPI(t, false)
	firstCutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	firstWindow, _ := collect.NewInterval(firstCutoff.Add(-time.Hour), firstCutoff)
	collector := Collector{API: api, Now: fixedClock(firstCutoff.Add(time.Minute)), TempDir: t.TempDir()}
	path := filepath.Join(t.TempDir(), "archive.db")
	store, err := archive.Create(ctx, path, archive.Options{CreatedAt: model.MustInstant(firstCutoff)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := collector.CollectInto(ctx, Request{Repositories: []string{"acme/service"}, Interval: firstWindow, Purpose: PurposeArchive, Concurrency: 1, ArchiveSchedule: ArchiveScheduleInitial}, store); err != nil {
		t.Fatal(err)
	}
	before, err := store.Checkpoints(ctx)
	if err != nil || len(before) != 1 {
		t.Fatalf("initial checkpoint=%#v err=%v", before, err)
	}

	api.getRunErrors[10] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "refresh watched run", StatusCode: 403, Message: "denied"}
	secondCutoff := firstCutoff.Add(2 * time.Hour)
	secondWindow, _ := collect.NewInterval(secondCutoff.Add(-time.Hour), secondCutoff)
	collector.Now = fixedClock(secondCutoff.Add(time.Minute))
	result, err := collector.CollectInto(ctx, Request{
		Repositories: []string{"acme/service"}, Interval: secondWindow, Purpose: PurposeArchive, Concurrency: 1,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: before,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Batch.Checkpoints) != 0 || !hasGap(result.Gaps, "watched_parent_refresh", collect.GapForbidden) {
		t.Fatalf("incomplete refresh result: checkpoints=%#v gaps=%#v", result.Batch.Checkpoints, result.Gaps)
	}
	after, err := store.Checkpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed refresh advanced or rewrote checkpoint: before=%#v after=%#v", before, after)
	}
}

func TestResumeWithoutCheckpointUsesFullHorizonAndExplicitScanPreservesState(t *testing.T) {
	api := successfulAPI(t, false)
	cutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	window, _ := collect.NewInterval(cutoff.Add(-time.Hour), cutoff)
	collector := Collector{API: api, Now: fixedClock(cutoff.Add(time.Minute)), TempDir: t.TempDir()}

	missing, err := collector.Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: window, Purpose: PurposeArchive,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRunFact(missing.Batch.Facts, 10) || len(missing.Batch.Checkpoints) != 1 {
		t.Fatalf("missing checkpoint silently skipped the older parent: facts=%d checkpoints=%d", len(missing.Batch.Facts), len(missing.Batch.Checkpoints))
	}

	explicit, err := collector.Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: window, Purpose: PurposeArchive,
		ArchiveSchedule: ArchiveSchedulePreserve,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasRunFact(explicit.Batch.Facts, 10) || len(explicit.Batch.Checkpoints) != 0 {
		t.Fatalf("explicit scan did not remain exact and checkpoint-preserving: facts=%d checkpoints=%d", len(explicit.Batch.Facts), len(explicit.Batch.Checkpoints))
	}
}

func TestResumeRecordsContinuityGapInsteadOfAdvancingPastIt(t *testing.T) {
	api := successfulAPI(t, false)
	firstCutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	firstWindow, _ := collect.NewInterval(firstCutoff.Add(-time.Hour), firstCutoff)
	collector := Collector{API: api, Now: fixedClock(firstCutoff.Add(time.Minute)), TempDir: t.TempDir()}
	first, err := collector.Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: firstWindow, Purpose: PurposeArchive,
		ArchiveSchedule: ArchiveScheduleInitial,
	})
	if err != nil || len(first.Batch.Checkpoints) != 1 {
		t.Fatalf("initial checkpoint=%#v err=%v", first.Batch.Checkpoints, err)
	}

	secondCutoff := firstCutoff.Add(8 * time.Hour)
	narrowWindow, _ := collect.NewInterval(secondCutoff.Add(-time.Hour), secondCutoff)
	collector.Now = fixedClock(secondCutoff.Add(time.Minute))
	resumed, err := collector.Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: narrowWindow, Purpose: PurposeArchive,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: first.Batch.Checkpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.Batch.Checkpoints) != 0 || !hasGap(resumed.Gaps, "archive_checkpoint_continuity", collect.GapValidation) {
		t.Fatalf("stale checkpoint was silently skipped: checkpoints=%#v gaps=%#v", resumed.Batch.Checkpoints, resumed.Gaps)
	}
}

func TestResumeRejectsStructurallyCorruptCheckpoint(t *testing.T) {
	api := successfulAPI(t, false)
	cutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	window, _ := collect.NewInterval(cutoff.Add(-time.Hour), cutoff)
	_, err := (Collector{API: api}).Collect(context.Background(), Request{
		Repositories: []string{"acme/service"}, Interval: window, Purpose: PurposeArchive,
		ArchiveSchedule:    ArchiveScheduleResume,
		ArchiveCheckpoints: []archive.Checkpoint{{RepositoryID: 1, OverlapSeconds: 900, WatchHorizonDays: 1, LastSuccessfulCollection: "collection:test", WatchedParents: []archive.WatchedParent{}}},
	})
	if err == nil || !strings.Contains(err.Error(), "watch horizon") {
		t.Fatalf("corrupt checkpoint error = %v", err)
	}
}

func TestRepeatedCollectionUsesSessionScopedRequestsAndStableEvidence(t *testing.T) {
	ctx := context.Background()
	api := successfulAPI(t, false)
	cutoff := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	window, _ := collect.NewInterval(cutoff.Add(-time.Hour), cutoff)
	collector := Collector{API: api, Now: fixedClock(cutoff.Add(time.Minute)), TempDir: t.TempDir()}
	store, err := archive.Create(ctx, filepath.Join(t.TempDir(), "archive.db"), archive.Options{CreatedAt: model.MustInstant(cutoff)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := Request{Repositories: []string{"acme/service"}, Interval: window, Purpose: PurposeArchive, Concurrency: 1, ArchiveSchedule: ArchiveScheduleInitial}
	if _, err := collector.CollectInto(ctx, request, store); err != nil {
		t.Fatal(err)
	}
	collector.Now = fixedClock(cutoff.Add(2 * time.Minute))
	if _, err := collector.CollectInto(ctx, request, store); err != nil {
		t.Fatalf("second collection conflicted with the first request identity: %v", err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Collections) != 2 {
		t.Fatalf("collection observations = %d, want 2", len(snapshot.Collections))
	}
	type observationSet struct {
		requests map[model.RequestID]struct{}
		count    int
	}
	byEvidence := make(map[model.EvidenceID]*observationSet)
	for _, envelope := range snapshot.Evidence {
		set := byEvidence[envelope.Evidence.ID]
		if set == nil {
			set = &observationSet{requests: map[model.RequestID]struct{}{}}
			byEvidence[envelope.Evidence.ID] = set
		}
		set.requests[envelope.Observation.RequestID] = struct{}{}
		set.count++
	}
	var found bool
	for _, set := range byEvidence {
		if set.count >= 2 && len(set.requests) >= 2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("recollection did not retain distinct request observations over stable evidence identity")
	}
}

func instantPointer(value model.Instant) *model.Instant { return &value }

func hasAttemptFact(facts []archive.Fact, runID int64, attempt uint32) bool {
	for _, fact := range facts {
		if fact.Attempt != nil && int64(fact.Attempt.RunID) == runID && uint32(fact.Attempt.RunAttempt) == attempt {
			return true
		}
	}
	return false
}

func hasJobFact(facts []archive.Fact, runID int64, attempt uint32, jobID int64) bool {
	for _, fact := range facts {
		if fact.Job != nil && int64(fact.Job.Execution.RunID) == runID && uint32(fact.Job.Execution.RunAttempt) == attempt && int64(fact.Job.Execution.JobID) == jobID {
			return true
		}
	}
	return false
}

func hasRunFact(facts []archive.Fact, runID int64) bool {
	for _, fact := range facts {
		if fact.Run != nil && int64(fact.Run.RunID) == runID {
			return true
		}
	}
	return false
}

func hasGap(gaps []collect.Gap, scope string, reason collect.GapReason) bool {
	for _, gap := range gaps {
		if gap.Scope == scope && gap.Reason == reason && gap.Material {
			return true
		}
	}
	return false
}

func apiCalled(api *fakeAPI, want string) bool {
	api.mu.Lock()
	defer api.mu.Unlock()
	for _, call := range api.calls {
		if call == want {
			return true
		}
	}
	return false
}
