package collect

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/githubapi"
)

type fakeRunWindowAPI struct {
	runs          []githubapi.WorkflowRun
	probeOverride map[string]int
	probeErrors   map[string]error
	threshold     int
}

func (f *fakeRunWindowAPI) ProbeWorkflowRuns(_ context.Context, _, _, created string) (githubapi.RunProbe, error) {
	if err := f.probeErrors[created]; err != nil {
		return githubapi.RunProbe{}, err
	}
	if count, ok := f.probeOverride[created]; ok {
		return githubapi.RunProbe{TotalCount: count}, nil
	}
	count := len(f.inclusiveRuns(created))
	if f.threshold > 0 && count > f.threshold {
		count = 1000
	}
	return githubapi.RunProbe{TotalCount: count}, nil
}

func (f *fakeRunWindowAPI) ListWorkflowRuns(_ context.Context, _, _, created string) (githubapi.RunList, error) {
	runs := f.inclusiveRuns(created)
	return githubapi.RunList{TotalCount: len(runs), Runs: runs}, nil
}

func (f *fakeRunWindowAPI) inclusiveRuns(created string) []githubapi.WorkflowRun {
	parts := strings.SplitN(created, "..", 2)
	if len(parts) != 2 {
		panic("invalid fixture filter: " + created)
	}
	from, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		panic(err)
	}
	to, err := time.Parse(time.RFC3339, parts[1])
	if err != nil {
		panic(err)
	}
	var result []githubapi.WorkflowRun
	for _, run := range f.runs {
		if !run.CreatedAt.Before(from) && !run.CreatedAt.After(to) {
			result = append(result, run)
		}
	}
	return result
}

func TestPartitionerSplitsAtCeilingAndDeduplicatesInclusiveBoundary(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	requested, _ := NewInterval(base, base.Add(4*time.Second))
	rootFilter := createdFilter(requested)
	api := &fakeRunWindowAPI{
		runs: []githubapi.WorkflowRun{
			{ID: 1, CreatedAt: base.Add(time.Second)},
			{ID: 2, CreatedAt: base.Add(2 * time.Second)},
			{ID: 3, CreatedAt: base.Add(3 * time.Second)},
		},
		probeOverride: map[string]int{rootFilter: 1000},
		probeErrors:   map[string]error{},
	}
	result, err := (Partitioner{API: api}).Enumerate(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, requested)
	if err != nil {
		t.Fatal(err)
	}
	if result.Root.Status != PartitionSplit || len(result.Root.Children) != 2 {
		t.Fatalf("root = %+v", result.Root)
	}
	if len(result.Runs) != 3 || result.Runs[0].ID != 1 || result.Runs[1].ID != 2 || result.Runs[2].ID != 3 {
		t.Fatalf("runs = %+v", result.Runs)
	}
	if result.DuplicateObservations != 0 || result.OverlapObservations != 1 {
		t.Fatalf("duplicates=%d overlap=%d", result.DuplicateObservations, result.OverlapObservations)
	}
	if len(result.Gaps) != 0 {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestPartitionerSaturatedSecondProducesGap(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	requested, _ := NewInterval(base, base.Add(time.Second))
	api := &fakeRunWindowAPI{
		probeOverride: map[string]int{createdFilter(requested): 1000},
		probeErrors:   map[string]error{},
	}
	result, err := (Partitioner{API: api}).Enumerate(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, requested)
	if err != nil {
		t.Fatal(err)
	}
	if result.Root.Status != PartitionSaturated || len(result.Gaps) != 1 || result.Gaps[0].Reason != GapDensityCeiling {
		t.Fatalf("result = %+v", result)
	}
}

func TestPartitionerPreservesSiblingResultsWhenOneLeafFails(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	requested, _ := NewInterval(base, base.Add(4*time.Second))
	left := Interval{From: base, To: base.Add(2 * time.Second)}
	api := &fakeRunWindowAPI{
		runs:          []githubapi.WorkflowRun{{ID: 9, CreatedAt: base.Add(3 * time.Second)}},
		probeOverride: map[string]int{createdFilter(requested): 1000},
		probeErrors: map[string]error{
			createdFilter(left): &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "probe", Message: "denied"},
		},
	}
	result, err := (Partitioner{API: api}).Enumerate(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Runs) != 1 || result.Runs[0].ID != 9 {
		t.Fatalf("runs = %+v", result.Runs)
	}
	if len(result.Gaps) != 1 || result.Gaps[0].Reason != GapForbidden || !result.Gaps[0].Material {
		t.Fatalf("gaps = %+v", result.Gaps)
	}
}

func TestPartitionerRandomizedCompleteness(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	random := rand.New(rand.NewSource(20260820))
	for iteration := 0; iteration < 30; iteration++ {
		var runs []githubapi.WorkflowRun
		for id := int64(1); id <= 100; id++ {
			runs = append(runs, githubapi.WorkflowRun{ID: id, CreatedAt: base.Add(time.Duration(random.Intn(512)) * time.Second)})
		}
		requested, _ := NewInterval(base, base.Add(512*time.Second))
		api := &fakeRunWindowAPI{runs: runs, threshold: 7, probeOverride: map[string]int{}, probeErrors: map[string]error{}}
		result, err := (Partitioner{API: api, MaxPartitions: 4096}).Enumerate(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, requested)
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if len(result.Gaps) != 0 || len(result.Runs) != 100 {
			t.Fatalf("iteration %d: runs=%d gaps=%+v", iteration, len(result.Runs), result.Gaps)
		}
		for index, run := range result.Runs {
			if index > 0 && (run.CreatedAt.Before(result.Runs[index-1].CreatedAt) ||
				(run.CreatedAt.Equal(result.Runs[index-1].CreatedAt) && run.ID < result.Runs[index-1].ID)) {
				t.Fatalf("iteration %d: output not stably sorted", iteration)
			}
		}
	}
}

func TestSecondCoverFiltersSubsecondBoundaryLocally(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 20, 0, 0, 0, 250_000_000, time.UTC)
	requested, _ := NewInterval(base, base.Add(1500*time.Millisecond))
	api := &fakeRunWindowAPI{
		runs: []githubapi.WorkflowRun{
			{ID: 1, CreatedAt: base.Add(-time.Nanosecond)},
			{ID: 2, CreatedAt: base},
			{ID: 3, CreatedAt: requested.To},
		},
		probeOverride: map[string]int{}, probeErrors: map[string]error{},
	}
	result, err := (Partitioner{API: api}).Enumerate(context.Background(), RepositoryTarget{ID: 10, Owner: "acme", Name: "service"}, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Runs) != 1 || result.Runs[0].ID != 2 {
		t.Fatalf("runs = %+v queried=%+v", result.Runs, result.Queried)
	}
}

func TestDiscoveryAndArchivePlannerUseProvisionalSixtyFiveDays(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	incident, _ := NewInterval(cutoff.Add(-time.Hour), cutoff)
	discovery, err := ExpandIncidentDiscoveryWindow(incident)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.From != incident.From.Add(-ProvisionalParentLookback) || discovery.To != cutoff {
		t.Fatalf("discovery = %+v", discovery)
	}

	last := cutoff.Add(-time.Hour)
	oldCreated := cutoff.Add(-66 * 24 * time.Hour)
	plan, err := PlanArchive(last, cutoff, []WatchedRun{
		{RepositoryID: 1, RunID: 1, CreatedAt: cutoff.Add(-10 * 24 * time.Hour)},
		{RepositoryID: 1, RunID: 2, CreatedAt: oldCreated},
		{RepositoryID: 1, RunID: 3, CreatedAt: oldCreated, FinalRefreshComplete: true, LastSuccessfulRefresh: oldCreated.Add(ProvisionalParentLookback + time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.NewParentWindow.From != last.Add(-DefaultArchiveOverlap) || plan.ParentLookback != 65*24*time.Hour {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Refresh) != 2 || len(plan.EvictionEligible) != 1 || plan.EvictionEligible[0].RunID != 3 {
		t.Fatalf("refresh/eviction = %+v / %+v", plan.Refresh, plan.EvictionEligible)
	}
}

func TestIncrementalArchivePlannerSeedsThenUsesRequestedBoundAndOverlap(t *testing.T) {
	t.Parallel()
	cutoff := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	requested, _ := NewInterval(cutoff.Add(-24*time.Hour), cutoff)

	initial, err := PlanIncrementalArchive(requested, time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := initial.NewParentWindow.From, requested.From.Add(-ProvisionalParentLookback); !got.Equal(want) {
		t.Fatalf("initial parent start = %s, want %s", got, want)
	}
	if !initial.NewParentWindow.To.Equal(cutoff) {
		t.Fatalf("initial parent end = %s, want %s", initial.NewParentWindow.To, cutoff)
	}

	watermark := cutoff.Add(-time.Hour)
	resumed, err := PlanIncrementalArchive(requested, watermark, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resumed.NewParentWindow.From, watermark.Add(-DefaultArchiveOverlap); !got.Equal(want) {
		t.Fatalf("resume parent start = %s, want overlap start %s", got, want)
	}

	backfill, _ := NewInterval(cutoff.Add(-7*24*time.Hour), cutoff)
	resumed, err = PlanIncrementalArchive(backfill, watermark, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resumed.NewParentWindow.From, watermark.Add(-DefaultArchiveOverlap); !got.Equal(want) {
		t.Fatalf("resume ignored the later watermark overlap: got %s want %s", got, want)
	}

	shortLookback, _ := NewInterval(cutoff.Add(-30*time.Minute), cutoff)
	resumed, err = PlanIncrementalArchive(shortLookback, watermark, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.NewParentWindow.From.Equal(shortLookback.From) {
		t.Fatalf("ordinary discovery escaped the requested --since bound: got %s want %s", resumed.NewParentWindow.From, shortLookback.From)
	}
}

func ExampleExpandIncidentDiscoveryWindow() {
	to := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	incident, _ := NewInterval(to.Add(-time.Hour), to)
	discovery, _ := ExpandIncidentDiscoveryWindow(incident)
	fmt.Println(discovery.From.Equal(incident.From.Add(-ProvisionalParentLookback)))
	// Output: true
}
