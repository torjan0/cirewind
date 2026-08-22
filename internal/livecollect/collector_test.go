package livecollect

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	testActionSHA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPackageSHA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testPackageDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testCalledSHA     = "dddddddddddddddddddddddddddddddddddddddd"
)

func TestCollectBuildsReplayableCompactAttemptEvidence(t *testing.T) {
	api := successfulAPI(t, false)
	clock := fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC))
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	collector := Collector{API: api, Now: clock, TempDir: t.TempDir()}
	request := Request{Organization: "acme", Interval: interval, Purpose: PurposeInvestigate, Concurrency: 3, AuthKind: "environment"}

	result, err := collector.Collect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.Discovery.From, interval.From.Add(-collect.ProvisionalParentLookback); !got.Equal(want) {
		t.Fatalf("discovery start = %s, want %s", got, want)
	}
	if result.Batch.ID == "" {
		t.Fatal("batch was not normalized")
	}
	if got := len(result.Batch.Collections); got != 1 {
		t.Fatalf("collection sessions = %d, want 1", got)
	}
	session := result.Batch.Collections[0]
	if session.Mode != string(PurposeInvestigate) {
		t.Fatalf("collection mode = %q, want %q", session.Mode, PurposeInvestigate)
	}
	assertCollectionWindow(t, session.Scope.RequestedEventWindow, interval, model.ApproximationExact)
	assertCollectionWindow(t, session.Scope.DiscoveryEventWindow, result.Discovery, model.ApproximationConservativeExpanded)
	capabilities := make(map[string]archive.Capability, len(result.Batch.Capabilities))
	for _, capability := range result.Batch.Capabilities {
		capabilities[capability.Name] = capability
	}
	for _, name := range []string{"action_definitions", "action_execution", "action_resolution", "attempt_logs", "job_logs", "raw_logs", "repository_visibility", "referenced_workflow_identity", "runner_context", "runtime_permissions", "workflow_definitions"} {
		if _, ok := capabilities[name]; !ok {
			t.Errorf("canonical capability %q is missing", name)
		}
	}
	visibility := capabilities["repository_visibility"]
	if visibility.Details["requested_total_known"] != "false" || visibility.Details["accessible_count"] != "1" {
		t.Fatalf("organization visibility details = %#v", visibility.Details)
	}
	if len(result.CalledWorkflows) != 1 {
		t.Fatalf("called workflows = %d, want 1", len(result.CalledWorkflows))
	}
	called := result.CalledWorkflows[0]
	if model.GitObjectID(called.CalledObjectID).Value != testCalledSHA || called.RunAttempt != 1 {
		t.Fatalf("called-workflow identity lost: %#v", called)
	}

	var actionKinds []model.RuntimeObservationKind
	var exactAction, exactPackage, dependency, runtimePermission, oidc, runner bool
	var collectedCoverage int
	for _, fact := range result.Batch.Facts {
		switch fact.Kind {
		case archive.FactActionOccurrence:
			observation := fact.ActionOccurrence.Observation
			actionKinds = append(actionKinds, observation.Kind)
			if observation.Kind.SupportsExecuted() {
				t.Fatalf("setup-only collection produced execution evidence: %s", observation.Kind)
			}
			if observation.SourceObjectID != nil && model.GitObjectID(*observation.SourceObjectID).Value == testActionSHA {
				exactAction = true
			}
			if observation.PackageDigest != nil && observation.PackageDigest.Value == testPackageDigest && observation.SourceObjectID != nil && model.GitObjectID(*observation.SourceObjectID).Value == testPackageSHA {
				exactPackage = true
			}
		case archive.FactDependency:
			if fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata {
				dependency = fact.Dependency.AttemptExecution != nil && fact.Dependency.Execution == nil && model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID).Value == testCalledSHA
			}
		case archive.FactExposure:
			if fact.Exposure.Credential != nil {
				switch fact.Exposure.Credential.Kind {
				case model.ExposureGitHubTokenPermission:
					runtimePermission = true
				case model.ExposureOIDCMintingCapability:
					oidc = strings.Contains(fact.Exposure.Credential.Conclusion, "does not prove")
				}
			}
			if fact.Exposure.Runner != nil && fact.Exposure.Runner.Classification == "github-hosted" {
				runner = true
			}
		case archive.FactCoverage:
			collectedCoverage++
		}
	}
	if !exactAction || !exactPackage || !dependency || !runtimePermission || !oidc || !runner {
		t.Fatalf("missing compact facts: action=%v package=%v dependency=%v permission=%v oidc=%v runner=%v", exactAction, exactPackage, dependency, runtimePermission, oidc, runner)
	}
	if collectedCoverage < 4 {
		t.Fatalf("collected coverage facts = %d, want at least 4", collectedCoverage)
	}
	for _, kind := range actionKinds {
		if kind == model.ObservationLifecycleStarted || kind == model.ObservationLifecycleCompleted {
			t.Fatalf("unexpected lifecycle kind %s", kind)
		}
	}
	for _, envelope := range result.Batch.Evidence {
		if envelope.Evidence.Content.RawRetained || envelope.Evidence.Content.RetainedPath != "" {
			t.Fatalf("raw evidence retained: %#v", envelope.Evidence.Content)
		}
	}
	var runnerMetadataRetained bool
	for _, payload := range result.Batch.Payloads {
		if bytes.Contains(payload.Bytes, []byte("Download action repository")) || bytes.Contains(payload.Bytes, []byte("GITHUB_TOKEN Permissions")) {
			t.Fatal("raw log text leaked into compact payloads")
		}
		if bytes.Contains(payload.Bytes, []byte(`"schema":"cirewind.github-setup-runner-metadata/v1"`)) && bytes.Contains(payload.Bytes, []byte(`"attribute":"runner-version"`)) && bytes.Contains(payload.Bytes, []byte(`"value":"2.400.0"`)) {
			runnerMetadataRetained = true
		}
	}
	if !runnerMetadataRetained {
		t.Fatal("allowlisted setup-log runner metadata was not retained for offline replay")
	}

	casePath := filepath.Join(t.TempDir(), "archive.db")
	store, err := archive.Create(context.Background(), casePath, archive.Options{CreatedAt: model.MustInstant(clock())})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := collector.CollectInto(context.Background(), request, store); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Facts) == 0 || len(snapshot.Evidence) == 0 || len(snapshot.Checkpoints) != 1 {
		t.Fatalf("persisted snapshot incomplete: facts=%d evidence=%d checkpoints=%d", len(snapshot.Facts), len(snapshot.Evidence), len(snapshot.Checkpoints))
	}
	if got := api.jobLogCalls(); got != 2 { // Collect and CollectInto each retrieve the one job immediately.
		t.Fatalf("job log calls = %d, want 2", got)
	}
}

func TestCollectRejectsZeroClockWithoutPanickingOrProducingBatch(t *testing.T) {
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1}
	collector := Collector{API: successfulAPI(t, false), Now: func() time.Time { return time.Time{} }, TempDir: t.TempDir()}

	result, err := collector.Collect(context.Background(), request)
	var clockErr *ClockError
	if !errors.As(err, &clockErr) {
		t.Fatalf("Collect error = %v, want typed ClockError", err)
	}
	if result.Batch.ID != "" {
		t.Fatalf("invalid clock produced normalized batch %q", result.Batch.ID)
	}
}

func TestCollectLatchesLaterZeroClockWithoutCommittingBatch(t *testing.T) {
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)
	var calls int
	clock := func() time.Time {
		calls++
		if calls == 1 {
			return fixed
		}
		return time.Time{}
	}
	collector := Collector{API: successfulAPI(t, false), Now: clock, TempDir: t.TempDir()}
	request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1}

	result, err := collector.Collect(context.Background(), request)
	var clockErr *ClockError
	if !errors.As(err, &clockErr) {
		t.Fatalf("Collect error = %v, want typed ClockError", err)
	}
	if result.Batch.ID != "" {
		t.Fatalf("latched clock failure produced normalized batch %q", result.Batch.ID)
	}
}

func TestCollectRejectsZeroCheckpointTimesBeforeScheduling(t *testing.T) {
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	valid := model.MustInstant(time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC))
	zero := model.Instant{}
	for _, test := range []struct {
		name   string
		mutate func(*archive.Checkpoint)
	}{
		{name: "zero watermark", mutate: func(value *archive.Checkpoint) { value.DiscoveryWatermark = &zero }},
		{name: "zero creation", mutate: func(value *archive.Checkpoint) { value.WatchedParents[0].CreatedAt = zero }},
		{name: "zero refresh", mutate: func(value *archive.Checkpoint) { value.WatchedParents[0].LastRefreshedAt = &zero }},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := archive.Checkpoint{
				RepositoryID: 1, DiscoveryWatermark: &valid,
				OverlapSeconds: uint32(collect.DefaultArchiveOverlap / time.Second), WatchHorizonDays: uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
				LastSuccessfulCollection: "collection:test", WatchedParents: []archive.WatchedParent{{RunID: 10, CreatedAt: valid}},
			}
			test.mutate(&checkpoint)
			request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 1, ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{checkpoint}}
			_, err := (Collector{API: successfulAPI(t, false), Now: fixedClock(interval.To.Add(time.Hour)), TempDir: t.TempDir()}).Collect(context.Background(), request)
			if err == nil || !strings.Contains(err.Error(), "timestamp is zero") {
				t.Fatalf("error = %v, want checkpoint zero-time validation", err)
			}
		})
	}
}

func TestCollectContinuesAcrossRepositoryAndLogGaps(t *testing.T) {
	api := successfulAPI(t, false)
	api.repositories = append(api.repositories, githubapi.Repository{ID: 2, FullName: "acme/denied", Name: "denied", Owner: githubapi.Actor{Login: "acme"}})
	api.probeErrors["acme/denied"] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "probe", StatusCode: 403, Message: "permission denied"}
	api.jobLogErrors[20] = &githubapi.Error{Class: githubapi.ErrorNotFound, Operation: "job log", StatusCode: 404, Message: "log unavailable"}
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Organization: "acme", Interval: interval, Purpose: PurposeArchive, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	var forbidden, expiredLog, persistedGap bool
	for _, gap := range result.Gaps {
		forbidden = forbidden || (gap.RepositoryID == 2 && gap.Reason == collect.GapForbidden)
		expiredLog = expiredLog || (gap.JobID == 20 && gap.Scope == "job_log")
	}
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactCoverageGap && fact.CoverageGap.Assessment.Gap.Reason == model.GapRetentionOrDeletion {
			persistedGap = true
		}
	}
	if !forbidden || !expiredLog || !persistedGap {
		t.Fatalf("partial coverage not preserved: forbidden=%v expired=%v persisted=%v", forbidden, expiredLog, persistedGap)
	}
	var repositoryFacts int
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactRepository {
			repositoryFacts++
		}
	}
	if repositoryFacts != 2 {
		t.Fatalf("repository facts = %d, want 2", repositoryFacts)
	}
}

func TestMultiJobSetupCorrelationNeverInventsExecutionOrJobAttribution(t *testing.T) {
	api := successfulAPI(t, true)
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	var actionFacts, calledFacts, setupGaps int
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactActionOccurrence {
			actionFacts++
		}
		if fact.Kind == archive.FactDependency && fact.Dependency.Basis == archive.DefinitionRuntimeAttemptMetadata {
			calledFacts++
			if fact.Dependency.AttemptExecution == nil || fact.Dependency.Execution != nil {
				t.Fatal("called workflow was assigned to a job")
			}
		}
	}
	for _, gap := range result.Gaps {
		if gap.Scope == "setup_correlation" {
			setupGaps++
		}
	}
	if actionFacts != 0 || calledFacts != 1 || setupGaps != 2 {
		t.Fatalf("ambiguous result: action=%d called=%d setup gaps=%d", actionFacts, calledFacts, setupGaps)
	}
	if got := api.jobLogCalls(); got != 2 {
		t.Fatalf("job logs were not downloaded for every job: %d", got)
	}
}

func TestEveryRerunAttemptKeepsIndependentActionResolution(t *testing.T) {
	api := successfulAPI(t, false)
	secondSHA := "ffffffffffffffffffffffffffffffffffffffff"
	parent := api.runs["acme/service"][0]
	parent.RunAttempt = 2
	api.runs["acme/service"][0] = parent
	secondAttempt := api.attempts[10][1]
	secondAttempt.RunAttempt = 2
	api.attempts[10][2] = secondAttempt
	secondJob := api.jobs[10][1][0]
	secondJob.ID = 21
	secondJob.Name = "rerun-build"
	api.jobs[10][2] = []githubapi.WorkflowJob{secondJob}
	api.jobLogs[21] = []byte("second attempt log discarded\n")
	secondSetup := "2026-08-20T01:40:03Z Download action repository 'fixture/action@v1' (SHA:" + secondSHA + ")\n"
	api.attemptLogs[10][2] = makeZIP(t, map[string]string{"rerun-build/1_Set up job.txt": secondSetup})

	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeInvestigate, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	found := map[model.RunAttempt]map[string]bool{}
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence.Observation.Kind != model.ObservationResolutionObserved {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository != "fixture/action" {
			continue
		}
		if found[observation.Execution.RunAttempt] == nil {
			found[observation.Execution.RunAttempt] = map[string]bool{}
		}
		found[observation.Execution.RunAttempt][model.GitObjectID(*observation.SourceObjectID).Value] = true
	}
	if !found[1][testActionSHA] || !found[2][secondSHA] || found[1][secondSHA] || found[2][testActionSHA] {
		t.Fatalf("attempt identities were merged: %#v", found)
	}
	if got := api.jobLogCalls(); got != 2 {
		t.Fatalf("job log calls = %d, want 2", got)
	}
}

func TestCollectionOrderingDeterministicAndRawRetentionRequiresCustodySink(t *testing.T) {
	api := successfulAPI(t, false)
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	collector := Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}
	request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 4}
	first, err := collector.Collect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := collector.Collect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Batch.ID != second.Batch.ID || !reflect.DeepEqual(first.Batch, second.Batch) {
		t.Fatal("fixed source evidence and collection time produced nondeterministic batches")
	}
	request.RawRetention = true
	if _, err := collector.Collect(context.Background(), request); err == nil || !strings.Contains(err.Error(), "raw-capable archive sink") {
		t.Fatalf("raw retention error = %v", err)
	}
}

func TestCollectIntoRetainsExactRawLogsContentAddressedAndDeduplicated(t *testing.T) {
	api := successfulAPI(t, false)
	fixed := time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	temp := t.TempDir()
	collector := Collector{API: api, Now: fixedClock(fixed), TempDir: temp}
	request := Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 1, RawRetention: true}
	storePath := filepath.Join(t.TempDir(), "archive.db")
	store, err := archive.Create(context.Background(), storePath, archive.Options{CreatedAt: model.MustInstant(fixed)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for iteration := 0; iteration < 2; iteration++ {
		result, err := collector.CollectInto(context.Background(), request, store)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Batch.Collections[0].RawRetention {
			t.Fatal("raw custody decision was omitted from the collection session")
		}
	}
	if err := store.VerifyRaw(context.Background()); err != nil {
		t.Fatalf("verify retained raw logs: %v", err)
	}

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var rawCount int
	digests := make(map[string]uint64)
	for _, envelope := range snapshot.Evidence {
		content := envelope.Evidence.Content
		if !content.RawRetained {
			continue
		}
		rawCount++
		if content.RetainedPayloadSHA256 == nil || *content.RetainedPayloadSHA256 != content.SourceSHA256 || content.RetainedPath != "raw/"+content.SourceSHA256+".bin" {
			t.Fatalf("raw envelope is not exact and content-addressed: %#v", content)
		}
		digests[content.SourceSHA256] = content.ByteLength
		var copied bytes.Buffer
		if err := store.CopyRaw(context.Background(), content.SourceSHA256, &copied); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(copied.Bytes())
		if hex.EncodeToString(sum[:]) != content.SourceSHA256 || uint64(copied.Len()) != content.ByteLength {
			t.Fatal("copied raw bytes differ from their evidence descriptor")
		}
	}
	if rawCount != 2 || len(digests) != 2 {
		t.Fatalf("raw evidence count=%d unique=%d, want 2 and 2", rawCount, len(digests))
	}
	entries, err := os.ReadDir(storePath + ".raw")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(digests) {
		t.Fatalf("sidecar object count=%d, want deduplicated %d", len(entries), len(digests))
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != 68 || !strings.HasSuffix(name, ".bin") {
			t.Fatalf("unsafe sidecar entry %q", name)
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(name, ".bin")); err != nil {
			t.Fatalf("sidecar name was derived from hostile metadata: %q", name)
		}
	}
	if leftovers, err := os.ReadDir(temp); err != nil || len(leftovers) != 0 {
		t.Fatalf("transient raw files were not cleaned up: entries=%v err=%v", leftovers, err)
	}
}

type rejectingRawSink struct {
	appendCalled bool
	retainCalled int
}

func (s *rejectingRawSink) RetainRaw(context.Context, archive.RawInput) error {
	s.retainCalled++
	return errors.New("simulated raw custody interruption")
}

func (s *rejectingRawSink) Append(context.Context, archive.Batch) error {
	s.appendCalled = true
	return nil
}

func TestRawCustodyFailureDoesNotCommitAndCleansTransientFiles(t *testing.T) {
	api := successfulAPI(t, false)
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	temp := t.TempDir()
	collector := Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: temp}
	sink := &rejectingRawSink{}
	_, err := collector.CollectInto(context.Background(), Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive, Concurrency: 1, RawRetention: true}, sink)
	if err == nil || !strings.Contains(err.Error(), "simulated raw custody interruption") {
		t.Fatalf("raw custody error=%v", err)
	}
	if sink.retainCalled != 1 || sink.appendCalled {
		t.Fatalf("raw failure retain calls=%d append called=%v", sink.retainCalled, sink.appendCalled)
	}
	entries, readErr := os.ReadDir(temp)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("interrupted collection left transient files: entries=%v err=%v", entries, readErr)
	}
}

func TestCollectionSessionIdentityIncludesNormalizedSecurityAndLimitPolicy(t *testing.T) {
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	collector := Collector{API: successfulAPI(t, false)}
	base, err := collector.defaults(Request{Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive})
	if err != nil {
		t.Fatal(err)
	}
	started := model.MustInstant(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC))
	want, err := collectionSessionID(base, started)
	if err != nil {
		t.Fatal(err)
	}
	again, err := collectionSessionID(base, started)
	if err != nil || again != want {
		t.Fatalf("identical normalized requests are nondeterministic: first=%s second=%s err=%v", want, again, err)
	}
	variations := []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "auth kind", mutate: func(value *Request) { value.AuthKind = "fine-grained-pat" }},
		{name: "concurrency", mutate: func(value *Request) { value.Concurrency++ }},
		{name: "raw retention policy", mutate: func(value *Request) { value.RawRetention = true }},
		{name: "job log limit", mutate: func(value *Request) { value.MaxJobLogBytes++ }},
		{name: "attempt log limit", mutate: func(value *Request) { value.MaxAttemptLogBytes++ }},
		{name: "partition limit", mutate: func(value *Request) { value.MaxPartitions++ }},
		{name: "archive schedule", mutate: func(value *Request) { value.ArchiveSchedule = ArchiveSchedulePreserve }},
		{name: "archive checkpoint", mutate: func(value *Request) {
			watermark := model.MustInstant(interval.To)
			value.ArchiveSchedule = ArchiveScheduleResume
			value.ArchiveCheckpoints = []archive.Checkpoint{{
				RepositoryID: 1, DiscoveryWatermark: &watermark,
				OverlapSeconds: uint32(collect.DefaultArchiveOverlap / time.Second), WatchHorizonDays: uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
				LastSuccessfulCollection: "collection:test", WatchedParents: []archive.WatchedParent{},
			}}
		}},
	}
	for _, test := range variations {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			changed.Repositories = append([]string(nil), base.Repositories...)
			test.mutate(&changed)
			got, err := collectionSessionID(changed, started)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("session ID collided after changing %s", test.name)
			}
		})
	}
}

func TestDefaultsPreservesExplicitEmptyCheckpointWatchSet(t *testing.T) {
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	watermark := model.MustInstant(interval.To)
	checkpoint := archive.Checkpoint{
		RepositoryID: 1, DiscoveryWatermark: &watermark,
		OverlapSeconds: uint32(collect.DefaultArchiveOverlap / time.Second), WatchHorizonDays: uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
		LastSuccessfulCollection: "collection:test", WatchedParents: []archive.WatchedParent{},
	}
	request := Request{
		Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive,
		ArchiveSchedule: ArchiveScheduleResume, ArchiveCheckpoints: []archive.Checkpoint{checkpoint},
	}
	normalized, err := (Collector{API: successfulAPI(t, false)}).defaults(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ArchiveCheckpoints[0].WatchedParents == nil {
		t.Fatal("defaults changed an explicit empty watched-parent array to nil")
	}

	request.ArchiveCheckpoints[0].WatchedParents = nil
	if _, err := (Collector{API: successfulAPI(t, false)}).defaults(request); err == nil {
		t.Fatal("defaults accepted a nil watched-parent array")
	}
}

func TestAdapterByteLimitsBecomeTypedGapsAndTransientFilesAreRemoved(t *testing.T) {
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	tests := []struct {
		name       string
		jobLimit   int64
		attemptMax int64
		gapScope   string
	}{
		{name: "job log", jobLimit: 4, attemptMax: DefaultAttemptLogBytes, gapScope: "job_log"},
		{name: "attempt log", jobLimit: DefaultJobLogBytes, attemptMax: 64, gapScope: "attempt_log"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			result, err := (Collector{API: successfulAPI(t, false), Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: tempDir}).Collect(context.Background(), Request{
				Repositories: []string{"acme/service"}, Interval: interval, Purpose: PurposeArchive,
				MaxJobLogBytes: test.jobLimit, MaxAttemptLogBytes: test.attemptMax,
			})
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, gap := range result.Gaps {
				if gap.Scope == test.gapScope && gap.Reason == collect.GapSizeLimit && gap.Material {
					found = true
				}
			}
			if !found {
				t.Fatalf("typed %s size gap missing: %#v", test.gapScope, result.Gaps)
			}
			entries, err := os.ReadDir(tempDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("transient attempt-log files remain: %#v", entries)
			}
		})
	}
}

func TestCancellationBoundsWorkers(t *testing.T) {
	api := successfulAPI(t, false)
	api.blockProbe = true
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(ctx, Request{Organization: "acme", Interval: interval, Purpose: PurposeArchive, Concurrency: 2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestTopLevelEnumerationGapPersistsWithZeroTargets(t *testing.T) {
	api := successfulAPI(t, false)
	api.repositories = nil
	api.organizationError = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "list organization repositories", StatusCode: 403, Message: "permission denied"}
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Organization: "acme", Interval: interval, Purpose: PurposeInvestigate})
	if err != nil {
		t.Fatal(err)
	}
	if result.Batch.ID == "" || len(result.Batch.Collections) != 1 || len(result.Batch.Collections[0].Scope.Repositories) != 0 {
		t.Fatalf("zero-target batch did not normalize: %#v", result.Batch.Collections)
	}
	var persisted bool
	for _, fact := range result.Batch.Facts {
		if fact.Kind != archive.FactCoverageGap || fact.CoverageGap == nil {
			continue
		}
		gap := fact.CoverageGap
		if gap.Unit.Kind == model.CoverageRepositoryVisibility && gap.Unit.Scope.RepositoryID == nil && gap.Assessment.Gap != nil && gap.Assessment.Gap.Reason == model.GapForbidden {
			persisted = true
		}
	}
	if !persisted {
		t.Fatal("organization enumeration failure was not persisted as a global coverage gap")
	}
	for _, capability := range result.Batch.Capabilities {
		if capability.Name == "repository_visibility" {
			if capability.Status != archive.CapabilityGap || capability.Details["requested_total_known"] != "false" || capability.Details["denied_count"] != "unknown" {
				t.Fatalf("repository visibility capability overclaimed totals: %#v", capability)
			}
			return
		}
	}
	t.Fatal("repository_visibility capability missing")
}

func TestExplicitRepositoryDenialIsTargetKeyedAndPersisted(t *testing.T) {
	api := successfulAPI(t, false)
	api.getRepositoryErrors["acme/denied"] = &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "get repository", StatusCode: 403, Message: "permission denied"}
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Repositories: []string{"acme/service", "acme/denied"}, Interval: interval, Purpose: PurposeArchive})
	if err != nil {
		t.Fatal(err)
	}
	var globalGap bool
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactCoverageGap && fact.CoverageGap.Unit.Scope.RepositoryID == nil && strings.Contains(fact.CoverageGap.Assessment.Gap.SanitizedMessage, "acme/denied") {
			globalGap = true
		}
	}
	if !globalGap {
		t.Fatal("explicit inaccessible repository gap was not target-keyed in the archive")
	}
	for _, capability := range result.Batch.Capabilities {
		if capability.Name == "repository_visibility" {
			if capability.Details["requested_count"] != "2" || capability.Details["accessible_count"] != "1" || capability.Details["denied_count"] != "1" {
				t.Fatalf("explicit visibility counts = %#v", capability.Details)
			}
			return
		}
	}
	t.Fatal("repository_visibility capability missing")
}

func TestPartialOrganizationEnumerationContinuesVerifiedTargets(t *testing.T) {
	api := successfulAPI(t, false)
	api.organizationError = &githubapi.Error{Class: githubapi.ErrorPagination, Operation: "list organization repositories", Message: "later page unavailable"}
	interval, _ := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{Organization: "acme", Interval: interval, Purpose: PurposeArchive})
	if err != nil {
		t.Fatal(err)
	}
	var repositories, visibilityGaps int
	for _, fact := range result.Batch.Facts {
		if fact.Kind == archive.FactRepository {
			repositories++
		}
		if fact.Kind == archive.FactCoverageGap && fact.CoverageGap.Unit.Kind == model.CoverageRepositoryVisibility {
			visibilityGaps++
		}
	}
	if repositories != 1 || visibilityGaps != 1 {
		t.Fatalf("partial organization result lost facts: repositories=%d visibility_gaps=%d", repositories, visibilityGaps)
	}
}

type fakeAPI struct {
	mu                  sync.Mutex
	repositories        []githubapi.Repository
	runs                map[string][]githubapi.WorkflowRun
	attempts            map[int64]map[int]githubapi.WorkflowRun
	jobs                map[int64]map[int][]githubapi.WorkflowJob
	jobLogs             map[int64][]byte
	attemptLogs         map[int64]map[int][]byte
	probeErrors         map[string]error
	getRepositoryErrors map[string]error
	jobLogErrors        map[int64]error
	getRunErrors        map[int64]error
	blockProbe          bool
	organizationError   error
	calls               []string
}

func successfulAPI(t *testing.T, ambiguousTwoJobs bool) *fakeAPI {
	t.Helper()
	created := time.Date(2026, 6, 20, 1, 30, 0, 0, time.UTC) // older parent found by the 65-day horizon
	updated := time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)
	run := githubapi.WorkflowRun{ID: 10, RunAttempt: 1, Path: ".github/workflows/ci.yml", Event: "push", Status: "completed", Conclusion: "success", CreatedAt: created, UpdatedAt: &updated, HeadSHA: strings.Repeat("e", 40), HeadBranch: "main", Actor: githubapi.Actor{ID: 7, Login: "octocat"}, TriggeringActor: githubapi.Actor{ID: 8, Login: "rerunner"}}
	attempt := run
	attempt.ReferencedWorkflows = []githubapi.ReferencedWorkflow{{Path: "acme/shared/.github/workflows/reuse.yml@v3", SHA: testCalledSHA, Ref: "v3"}}
	started := time.Date(2026, 8, 20, 1, 10, 0, 0, time.UTC)
	completed := started.Add(time.Minute)
	job := githubapi.WorkflowJob{ID: 20, RunID: 10, Name: "build", Status: "completed", Conclusion: "success", StartedAt: &started, CompletedAt: &completed, Labels: []string{"ubuntu-latest", "github-hosted"}, RunnerID: 99, RunnerName: "runner", Steps: []githubapi.JobStep{{Number: 1, Name: "Set up job", Status: "completed", Conclusion: "success"}}}
	jobs := []githubapi.WorkflowJob{job}
	entryName := "build/1_Set up job.txt"
	if ambiguousTwoJobs {
		second := job
		second.ID = 21
		second.Name = "test"
		jobs = append(jobs, second)
		entryName = "unknown/1_Set up job.txt"
	}
	setup := strings.Join([]string{
		"2026-08-20T01:10:01Z Current runner version: '2.400.0'",
		"2026-08-20T01:10:02Z ##[group]GITHUB_TOKEN Permissions",
		"2026-08-20T01:10:02Z contents: write",
		"2026-08-20T01:10:02Z id-token: write",
		"2026-08-20T01:10:02Z ##[endgroup]",
		"2026-08-20T01:10:03Z Download action repository 'fixture/action@v1' (SHA:" + testActionSHA + ")",
		"2026-08-20T01:10:04Z Download immutable action package 'fixture/package@v2'",
		"2026-08-20T01:10:04Z Version: 2.0.0",
		"2026-08-20T01:10:04Z Source commit SHA: " + testPackageSHA,
		"2026-08-20T01:10:04Z Digest: sha256:" + testPackageDigest,
	}, "\n") + "\n"
	zipBytes := makeZIP(t, map[string]string{entryName: setup})
	jobLogs := map[int64][]byte{20: []byte("complete job log discarded\n")}
	if ambiguousTwoJobs {
		jobLogs[21] = []byte("second complete job log discarded\n")
	}
	return &fakeAPI{
		repositories: []githubapi.Repository{{ID: 1, FullName: "acme/service", Name: "service", Owner: githubapi.Actor{ID: 1, Login: "acme"}, Visibility: "private", Private: true, DefaultBranch: "main"}},
		runs:         map[string][]githubapi.WorkflowRun{"acme/service": {run}},
		attempts:     map[int64]map[int]githubapi.WorkflowRun{10: {1: attempt}}, jobs: map[int64]map[int][]githubapi.WorkflowJob{10: {1: jobs}},
		jobLogs: jobLogs, attemptLogs: map[int64]map[int][]byte{10: {1: zipBytes}}, probeErrors: map[string]error{}, getRepositoryErrors: map[string]error{}, jobLogErrors: map[int64]error{}, getRunErrors: map[int64]error{},
	}
}

func (f *fakeAPI) ListOrganizationRepositories(context.Context, string) (githubapi.RepositoryList, error) {
	if f.organizationError != nil {
		return githubapi.RepositoryList{Repositories: append([]githubapi.Repository(nil), f.repositories...)}, f.organizationError
	}
	return githubapi.RepositoryList{Repositories: append([]githubapi.Repository(nil), f.repositories...)}, nil
}
func (f *fakeAPI) GetRepository(_ context.Context, owner, repository string) (githubapi.ObjectResult[githubapi.Repository], error) {
	slug := owner + "/" + repository
	if err := f.getRepositoryErrors[slug]; err != nil {
		return githubapi.ObjectResult[githubapi.Repository]{}, err
	}
	for _, candidate := range f.repositories {
		if candidate.FullName == slug {
			return githubapi.ObjectResult[githubapi.Repository]{Value: candidate}, nil
		}
	}
	return githubapi.ObjectResult[githubapi.Repository]{}, &githubapi.Error{Class: githubapi.ErrorNotFound, Operation: "get repository", StatusCode: 404, Message: "not found"}
}
func (f *fakeAPI) GetRepositoryHashAlgorithm(context.Context, string, string) (githubapi.ObjectResult[string], error) {
	return githubapi.ObjectResult[string]{Value: "sha1"}, nil
}
func (f *fakeAPI) ProbeWorkflowRuns(ctx context.Context, owner, repository, created string) (githubapi.RunProbe, error) {
	if f.blockProbe {
		<-ctx.Done()
		return githubapi.RunProbe{}, ctx.Err()
	}
	slug := owner + "/" + repository
	f.mu.Lock()
	f.calls = append(f.calls, "probe:"+created)
	f.mu.Unlock()
	if err := f.probeErrors[slug]; err != nil {
		return githubapi.RunProbe{}, err
	}
	return githubapi.RunProbe{TotalCount: len(filterWorkflowRuns(f.runs[slug], created))}, nil
}
func (f *fakeAPI) ListWorkflowRuns(_ context.Context, owner, repository, created string) (githubapi.RunList, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "list:"+created)
	f.mu.Unlock()
	runs := filterWorkflowRuns(f.runs[owner+"/"+repository], created)
	return githubapi.RunList{TotalCount: len(runs), Runs: runs}, nil
}
func (f *fakeAPI) GetWorkflowRun(_ context.Context, _, _ string, runID int64) (githubapi.ObjectResult[githubapi.WorkflowRun], error) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf("get-run:%d", runID))
	f.mu.Unlock()
	if err := f.getRunErrors[runID]; err != nil {
		return githubapi.ObjectResult[githubapi.WorkflowRun]{}, err
	}
	values := f.attempts[runID]
	latest := 0
	for attempt := range values {
		if attempt > latest {
			latest = attempt
		}
	}
	run := values[latest]
	run.ReferencedWorkflows = nil
	return githubapi.ObjectResult[githubapi.WorkflowRun]{Value: run}, nil
}

func filterWorkflowRuns(input []githubapi.WorkflowRun, created string) []githubapi.WorkflowRun {
	parts := strings.SplitN(created, "..", 2)
	if len(parts) != 2 {
		return append([]githubapi.WorkflowRun(nil), input...)
	}
	from, fromErr := time.Parse(time.RFC3339, parts[0])
	to, toErr := time.Parse(time.RFC3339, parts[1])
	if fromErr != nil || toErr != nil {
		return nil
	}
	result := make([]githubapi.WorkflowRun, 0, len(input))
	for _, run := range input {
		if !run.CreatedAt.Before(from) && !run.CreatedAt.After(to) {
			result = append(result, run)
		}
	}
	return result
}
func (f *fakeAPI) GetWorkflowRunAttempt(_ context.Context, _, _ string, runID int64, attempt int) (githubapi.ObjectResult[githubapi.WorkflowRun], error) {
	return githubapi.ObjectResult[githubapi.WorkflowRun]{Value: f.attempts[runID][attempt]}, nil
}
func (f *fakeAPI) ListJobsForAttempt(_ context.Context, _, _ string, runID int64, attempt int) (githubapi.JobList, error) {
	jobs := append([]githubapi.WorkflowJob(nil), f.jobs[runID][attempt]...)
	return githubapi.JobList{TotalCount: len(jobs), Jobs: jobs}, nil
}
func (f *fakeAPI) DownloadAttemptLogs(_ context.Context, _, _ string, runID int64, attempt int, writer io.Writer) (githubapi.DownloadResult, error) {
	return fakeDownload(f.attemptLogs[runID][attempt], "application/zip", writer)
}
func (f *fakeAPI) DownloadJobLogs(_ context.Context, _, _ string, jobID int64, writer io.Writer) (githubapi.DownloadResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "job-log")
	f.mu.Unlock()
	if err := f.jobLogErrors[jobID]; err != nil {
		return githubapi.DownloadResult{}, err
	}
	return fakeDownload(f.jobLogs[jobID], "text/plain", writer)
}
func (f *fakeAPI) jobLogCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if call == "job-log" {
			count++
		}
	}
	return count
}

func fakeDownload(data []byte, media string, writer io.Writer) (githubapi.DownloadResult, error) {
	if _, err := writer.Write(data); err != nil {
		return githubapi.DownloadResult{}, &githubapi.Error{Class: githubapi.ErrorLocalIO, Operation: "download", Message: "destination rejected bounded log"}
	}
	sum := sha256.Sum256(data)
	return githubapi.DownloadResult{MediaType: media, ByteLength: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}, nil
}

func makeZIP(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func fixedClock(value time.Time) Clock { return func() time.Time { return value } }

func assertCollectionWindow(t *testing.T, got *model.EventInterval, want collect.Interval, approximation model.TimeApproximation) {
	t.Helper()
	if got == nil || got.Start == nil || got.End == nil || got.Bounds == nil {
		t.Fatalf("collection window is incomplete: %#v", got)
	}
	if !got.Start.Equal(want.From) || !got.End.Equal(want.To) || *got.Bounds != model.BoundsClosedOpen || got.Approximation != approximation {
		t.Fatalf("collection window = %#v, want [%s,%s) approximation %s", got, want.From, want.To, approximation)
	}
}
