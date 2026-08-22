package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/torjan0/cirewind/internal/githubapi"
)

const (
	ProvisionalParentLookback = 65 * 24 * time.Hour
	DefaultArchiveOverlap     = 15 * time.Minute
)

type Interval struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

func NewInterval(from, to time.Time) (Interval, error) {
	from = from.UTC()
	to = to.UTC()
	if from.IsZero() || to.IsZero() || !from.Before(to) {
		return Interval{}, errors.New("collection interval must be a non-empty half-open UTC interval")
	}
	return Interval{From: from, To: to}, nil
}

func (i Interval) Contains(value time.Time) bool {
	value = value.UTC()
	return !value.Before(i.From) && value.Before(i.To)
}

func ExpandIncidentDiscoveryWindow(incident Interval) (Interval, error) {
	if _, err := NewInterval(incident.From, incident.To); err != nil {
		return Interval{}, err
	}
	return Interval{From: incident.From.UTC().Add(-ProvisionalParentLookback), To: incident.To.UTC()}, nil
}

type RepositoryTarget struct {
	ID    int64  `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type RunWindowAPI interface {
	ProbeWorkflowRuns(context.Context, string, string, string) (githubapi.RunProbe, error)
	ListWorkflowRuns(context.Context, string, string, string) (githubapi.RunList, error)
}

type PartitionStatus string

const (
	PartitionSplit     PartitionStatus = "split"
	PartitionComplete  PartitionStatus = "complete"
	PartitionGap       PartitionStatus = "gap"
	PartitionSaturated PartitionStatus = "saturated"
)

type PartitionNode struct {
	Window        Interval                 `json:"window"`
	CreatedFilter string                   `json:"created_filter"`
	TotalCount    int                      `json:"total_count"`
	Status        PartitionStatus          `json:"status"`
	Responses     []githubapi.ResponseMeta `json:"responses,omitempty"`
	RunCount      int                      `json:"run_count"`
	OverlapRows   int                      `json:"overlap_rows"`
	Children      []*PartitionNode         `json:"children,omitempty"`
}

type PartitionResult struct {
	Requested             Interval                `json:"requested"`
	Queried               Interval                `json:"queried"`
	Root                  *PartitionNode          `json:"root"`
	Runs                  []githubapi.WorkflowRun `json:"runs"`
	Gaps                  []Gap                   `json:"gaps,omitempty"`
	DuplicateObservations int                     `json:"duplicate_observations"`
	OverlapObservations   int                     `json:"overlap_observations"`
}

type Partitioner struct {
	API           RunWindowAPI
	MaxPartitions int
	MinBucket     time.Duration
}

func (p Partitioner) Enumerate(ctx context.Context, repository RepositoryTarget, requested Interval) (PartitionResult, error) {
	if p.API == nil {
		return PartitionResult{}, errors.New("run-window API is nil")
	}
	if _, err := NewInterval(requested.From, requested.To); err != nil {
		return PartitionResult{}, err
	}
	if repository.ID <= 0 || repository.Owner == "" || repository.Name == "" {
		return PartitionResult{}, errors.New("repository target is incomplete")
	}
	if p.MaxPartitions <= 0 {
		p.MaxPartitions = 8192
	}
	if p.MinBucket <= 0 {
		p.MinBucket = time.Second
	}
	queried := secondCover(requested)
	result := PartitionResult{Requested: requested, Queried: queried}
	work := 0
	runs, root, stopped := p.walk(ctx, repository, queried, &result.Gaps, &work)
	result.Root = root
	result.OverlapObservations = countOverlapRows(root)
	if stopped && ctx.Err() != nil {
		return result, ctx.Err()
	}

	seen := make(map[int64]githubapi.WorkflowRun)
	for _, run := range runs {
		if run.ID <= 0 || run.CreatedAt.IsZero() {
			result.Gaps = append(result.Gaps, Gap{
				Reason: GapMalformedResponse, Scope: "workflow_run", RepositoryID: repository.ID,
				RunID: run.ID, Material: true, Diagnostic: "workflow run omitted a stable ID or created_at",
			})
			continue
		}
		if !requested.Contains(run.CreatedAt) {
			continue
		}
		if _, exists := seen[run.ID]; exists {
			result.DuplicateObservations++
			continue
		}
		seen[run.ID] = run
	}
	result.Runs = make([]githubapi.WorkflowRun, 0, len(seen))
	for _, run := range seen {
		result.Runs = append(result.Runs, run)
	}
	sort.Slice(result.Runs, func(i, j int) bool {
		if result.Runs[i].CreatedAt.Equal(result.Runs[j].CreatedAt) {
			return result.Runs[i].ID < result.Runs[j].ID
		}
		return result.Runs[i].CreatedAt.Before(result.Runs[j].CreatedAt)
	})
	return result, nil
}

func (p Partitioner) walk(ctx context.Context, repository RepositoryTarget, window Interval, gaps *[]Gap, work *int) ([]githubapi.WorkflowRun, *PartitionNode, bool) {
	filter := createdFilter(window)
	node := &PartitionNode{Window: window, CreatedFilter: filter}
	if err := ctx.Err(); err != nil {
		node.Status = PartitionGap
		*gaps = append(*gaps, Gap{Reason: GapCancelled, Scope: "run_partition", RepositoryID: repository.ID, Material: true, Diagnostic: "partition collection cancelled"})
		return nil, node, true
	}
	(*work)++
	if *work > p.MaxPartitions {
		node.Status = PartitionGap
		*gaps = append(*gaps, Gap{Reason: GapPartitionLimit, Scope: "run_partition", RepositoryID: repository.ID, Material: true, Diagnostic: "partition work limit reached"})
		return nil, node, false
	}
	probe, err := p.API.ProbeWorkflowRuns(ctx, repository.Owner, repository.Name, filter)
	node.Responses = append(node.Responses, probe.Responses...)
	if err != nil {
		node.Status = PartitionGap
		*gaps = append(*gaps, GapFromError("run_partition_probe", repository.ID, 0, 0, err))
		return nil, node, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	node.TotalCount = probe.TotalCount
	if probe.TotalCount < 0 {
		node.Status = PartitionGap
		*gaps = append(*gaps, Gap{Reason: GapMalformedResponse, Scope: "run_partition_probe", RepositoryID: repository.ID, Material: true, Diagnostic: "negative total_count"})
		return nil, node, false
	}
	if probe.TotalCount >= 1000 {
		return p.splitOrSaturate(ctx, repository, node, gaps, work)
	}

	listed, err := p.API.ListWorkflowRuns(ctx, repository.Owner, repository.Name, filter)
	node.Responses = append(node.Responses, listed.Responses...)
	if err != nil {
		node.Status = PartitionGap
		*gaps = append(*gaps, GapFromError("run_partition_pages", repository.ID, 0, 0, err))
		return nil, node, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	if listed.Truncated || listed.TotalCount >= 1000 {
		node.TotalCount = max(node.TotalCount, listed.TotalCount)
		return p.splitOrSaturate(ctx, repository, node, gaps, work)
	}
	assigned := assignRunsToWindow(node, window, listed.Runs)
	countChanged := listed.TotalCount != probe.TotalCount
	if countChanged {
		*gaps = append(*gaps, Gap{
			Reason: GapLiveStateRace, Scope: "run_partition", RepositoryID: repository.ID,
			Material: true, Retryable: true, Diagnostic: "workflow-run total_count changed between probe and pagination",
		})
	}
	if listed.TotalCount > len(listed.Runs) {
		node.Status = PartitionGap
		*gaps = append(*gaps, Gap{
			Reason: GapPagination, Scope: "run_partition", RepositoryID: repository.ID,
			Material: true, Retryable: true, Diagnostic: "pagination ended before the reported workflow-run total was collected",
		})
		return assigned, node, false
	}
	if countChanged {
		node.Status = PartitionGap
	} else {
		node.Status = PartitionComplete
	}
	return assigned, node, false
}

func assignRunsToWindow(node *PartitionNode, window Interval, runs []githubapi.WorkflowRun) []githubapi.WorkflowRun {
	assigned := make([]githubapi.WorkflowRun, 0, len(runs))
	for _, run := range runs {
		if window.Contains(run.CreatedAt) {
			node.RunCount++
			assigned = append(assigned, run)
		} else {
			node.OverlapRows++
		}
	}
	return assigned
}

func countOverlapRows(node *PartitionNode) int {
	if node == nil {
		return 0
	}
	count := node.OverlapRows
	for _, child := range node.Children {
		count += countOverlapRows(child)
	}
	return count
}

func (p Partitioner) splitOrSaturate(ctx context.Context, repository RepositoryTarget, node *PartitionNode, gaps *[]Gap, work *int) ([]githubapi.WorkflowRun, *PartitionNode, bool) {
	leftWindow, rightWindow, ok := splitWindow(node.Window, p.MinBucket)
	if !ok {
		node.Status = PartitionSaturated
		*gaps = append(*gaps, Gap{
			Reason: GapDensityCeiling, Scope: "run_partition", RepositoryID: repository.ID, Material: true,
			Diagnostic: "smallest supported timestamp bucket reached the filtered-search ceiling",
		})
		return nil, node, false
	}
	node.Status = PartitionSplit
	leftRuns, left, stopped := p.walk(ctx, repository, leftWindow, gaps, work)
	node.Children = append(node.Children, left)
	if stopped {
		return leftRuns, node, true
	}
	rightRuns, right, stopped := p.walk(ctx, repository, rightWindow, gaps, work)
	node.Children = append(node.Children, right)
	return append(leftRuns, rightRuns...), node, stopped
}

func secondCover(interval Interval) Interval {
	from := interval.From.UTC().Truncate(time.Second)
	to := interval.To.UTC().Truncate(time.Second)
	if to.Before(interval.To) {
		to = to.Add(time.Second)
	}
	if !from.Before(to) {
		to = from.Add(time.Second)
	}
	return Interval{From: from, To: to}
}

func splitWindow(window Interval, minimum time.Duration) (Interval, Interval, bool) {
	if window.To.Sub(window.From) <= minimum {
		return Interval{}, Interval{}, false
	}
	seconds := int64(window.To.Sub(window.From) / time.Second)
	if seconds < 2 {
		return Interval{}, Interval{}, false
	}
	midpoint := window.From.Add(time.Duration(seconds/2) * time.Second).UTC().Truncate(time.Second)
	if !window.From.Before(midpoint) || !midpoint.Before(window.To) {
		return Interval{}, Interval{}, false
	}
	return Interval{From: window.From, To: midpoint}, Interval{From: midpoint, To: window.To}, true
}

func createdFilter(window Interval) string {
	// GitHub's API range is inclusive. Adjacent half-open scheduler windows
	// intentionally query the shared boundary and assign it locally.
	return fmt.Sprintf("%s..%s", window.From.UTC().Format(time.RFC3339), window.To.UTC().Format(time.RFC3339))
}

type WatchedRun struct {
	RepositoryID          int64     `json:"repository_id"`
	RunID                 int64     `json:"run_id"`
	CreatedAt             time.Time `json:"created_at"`
	LastSuccessfulRefresh time.Time `json:"last_successful_refresh,omitempty"`
	FinalRefreshComplete  bool      `json:"final_refresh_complete"`
}

type ArchivePlan struct {
	NewParentWindow  Interval      `json:"new_parent_window"`
	Refresh          []WatchedRun  `json:"refresh"`
	EvictionEligible []WatchedRun  `json:"eviction_eligible"`
	ParentLookback   time.Duration `json:"parent_lookback"`
	DiscoveryOverlap time.Duration `json:"discovery_overlap"`
}

// PlanIncrementalArchive separates ordinary parent discovery from watched-run
// refresh. A first collection must seed the complete provisional parent
// horizon. A resumed collection may narrow ordinary parent enumeration to the
// later of the user's requested start and the prior watermark overlap because
// older eligible parents are refreshed directly by run ID.
func PlanIncrementalArchive(requested Interval, lastSuccessfulWatermark time.Time, watched []WatchedRun) (ArchivePlan, error) {
	if _, err := NewInterval(requested.From, requested.To); err != nil {
		return ArchivePlan{}, err
	}
	if lastSuccessfulWatermark.IsZero() {
		discovery, err := ExpandIncidentDiscoveryWindow(requested)
		if err != nil {
			return ArchivePlan{}, err
		}
		plan, err := PlanArchive(time.Time{}, requested.To, watched)
		if err != nil {
			return ArchivePlan{}, err
		}
		plan.NewParentWindow = discovery
		return plan, nil
	}

	plan, err := PlanArchive(lastSuccessfulWatermark, requested.To, watched)
	if err != nil {
		return ArchivePlan{}, err
	}
	if plan.NewParentWindow.From.Before(requested.From) {
		plan.NewParentWindow.From = requested.From.UTC()
	}
	if !plan.NewParentWindow.From.Before(plan.NewParentWindow.To) {
		return ArchivePlan{}, errors.New("archive resume interval is empty after applying the requested start and checkpoint overlap")
	}
	return plan, nil
}

func PlanArchive(lastSuccessfulWatermark, cutoff time.Time, watched []WatchedRun) (ArchivePlan, error) {
	cutoff = cutoff.UTC()
	if cutoff.IsZero() {
		return ArchivePlan{}, errors.New("archive cutoff is required")
	}
	from := cutoff.Add(-ProvisionalParentLookback)
	if !lastSuccessfulWatermark.IsZero() {
		from = lastSuccessfulWatermark.UTC().Add(-DefaultArchiveOverlap)
	}
	if !from.Before(cutoff) {
		return ArchivePlan{}, errors.New("archive watermark must precede cutoff after overlap")
	}
	plan := ArchivePlan{
		NewParentWindow:  Interval{From: from, To: cutoff},
		ParentLookback:   ProvisionalParentLookback,
		DiscoveryOverlap: DefaultArchiveOverlap,
	}
	for _, run := range watched {
		if run.RepositoryID <= 0 || run.RunID <= 0 || run.CreatedAt.IsZero() {
			return ArchivePlan{}, errors.New("watched run identity and creation time are required")
		}
		boundary := run.CreatedAt.UTC().Add(ProvisionalParentLookback)
		if cutoff.Before(boundary) || !run.FinalRefreshComplete || run.LastSuccessfulRefresh.UTC().Before(boundary) {
			plan.Refresh = append(plan.Refresh, run)
			continue
		}
		plan.EvictionEligible = append(plan.EvictionEligible, run)
	}
	sortWatched := func(values []WatchedRun) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].RepositoryID == values[j].RepositoryID {
				return values[i].RunID < values[j].RunID
			}
			return values[i].RepositoryID < values[j].RepositoryID
		})
	}
	sortWatched(plan.Refresh)
	sortWatched(plan.EvictionEligible)
	return plan, nil
}
