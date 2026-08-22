// Package livecollect adapts read-only GitHub.com collection operations into
// compact archive batches. It never executes fetched content. Exact raw log
// retention is disabled by default and requires an explicit raw-capable sink.
package livecollect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	DefaultConcurrency      = 4
	HardMaxConcurrency      = 32
	DefaultJobLogBytes      = int64(128 << 20)
	DefaultAttemptLogBytes  = int64(512 << 20)
	HardMaxJobLogBytes      = int64(512 << 20)
	HardMaxAttemptLogBytes  = int64(2 << 30)
	DefaultMaxPartitions    = 8192
	ExtractorVersion        = "0.1.0"
	defaultRedactionPolicy  = "discard-raw-v1"
	structuredPolicyVersion = "structured-allowlist-v1"
)

// Purpose selects the parent-run discovery policy. Both v0.1 modes use the
// provisional 65-day parent horizon: investigations must find older runs that
// were rerun in the incident interval, while archives must refresh parents
// whose attempts may still change.
type Purpose string

const (
	PurposeInvestigate Purpose = "investigate"
	PurposeArchive     Purpose = "archive"
)

func (p Purpose) valid() bool { return p == PurposeInvestigate || p == PurposeArchive }

// ArchiveScheduleMode controls whether a network archive invocation seeds,
// resumes, or deliberately leaves existing checkpoint state unchanged.
type ArchiveScheduleMode string

const (
	ArchiveScheduleInitial  ArchiveScheduleMode = "initial"
	ArchiveScheduleResume   ArchiveScheduleMode = "resume"
	ArchiveSchedulePreserve ArchiveScheduleMode = "preserve"
)

func (m ArchiveScheduleMode) valid() bool {
	return m == ArchiveScheduleInitial || m == ArchiveScheduleResume || m == ArchiveSchedulePreserve
}

// Request describes one bounded live collection. Organization and
// Repositories are mutually exclusive. RawRetention is an explicit custody
// decision because retained logs may contain sensitive application output.
type Request struct {
	Organization       string
	Repositories       []string
	Interval           collect.Interval
	Purpose            Purpose
	Concurrency        int
	RawRetention       bool
	AuthKind           string
	MaxJobLogBytes     int64
	MaxAttemptLogBytes int64
	MaxPartitions      int
	ArchiveSchedule    ArchiveScheduleMode
	ArchiveCheckpoints []archive.Checkpoint
}

// API is deliberately a closed set of read-only GitHub operations. The
// concrete githubapi.Client satisfies it; tests use an in-memory fake.
type API interface {
	ListOrganizationRepositories(context.Context, string) (githubapi.RepositoryList, error)
	GetRepository(context.Context, string, string) (githubapi.ObjectResult[githubapi.Repository], error)
	GetRepositoryHashAlgorithm(context.Context, string, string) (githubapi.ObjectResult[string], error)
	ProbeWorkflowRuns(context.Context, string, string, string) (githubapi.RunProbe, error)
	ListWorkflowRuns(context.Context, string, string, string) (githubapi.RunList, error)
	GetWorkflowRun(context.Context, string, string, int64) (githubapi.ObjectResult[githubapi.WorkflowRun], error)
	GetWorkflowRunAttempt(context.Context, string, string, int64, int) (githubapi.ObjectResult[githubapi.WorkflowRun], error)
	ListJobsForAttempt(context.Context, string, string, int64, int) (githubapi.JobList, error)
	DownloadAttemptLogs(context.Context, string, string, int64, int, io.Writer) (githubapi.DownloadResult, error)
	DownloadJobLogs(context.Context, string, string, int64, io.Writer) (githubapi.DownloadResult, error)
}

var _ API = (*githubapi.Client)(nil)

// Sink is implemented by archive.Archive.
type Sink interface {
	Append(context.Context, archive.Batch) error
}

// RawSink is required only for opted-in exact log retention. RetainRaw verifies
// and takes custody of one already-bounded transient file before its evidence
// envelope can be committed by Append.
type RawSink interface {
	Sink
	RetainRaw(context.Context, archive.RawInput) error
}

type Clock func() time.Time

// ClockError reports an invalid timestamp returned by the injected collection
// clock. Collection clocks are an external boundary in tests and embeddings;
// a malformed value must fail the collection rather than panic or be committed
// as evidence.
type ClockError struct {
	Operation string
	Err       error
}

func (e *ClockError) Error() string {
	if e == nil {
		return "collection clock error"
	}
	if e.Operation == "" {
		return fmt.Sprintf("collection clock: %v", e.Err)
	}
	return fmt.Sprintf("collection clock %s: %v", e.Operation, e.Err)
}

func (e *ClockError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Collector struct {
	API       API
	Now       Clock
	TempDir   string
	LogLimits logparse.ArchiveLimits
}

// CalledWorkflowObservation preserves GitHub's exact attempt-scoped called
// workflow identity without inventing an exact caller workflow commit.
// Archive evidence retains the same normalized fields for offline replay.
type CalledWorkflowObservation struct {
	RepositoryID     model.RepositoryID
	RunID            model.WorkflowRunID
	RunAttempt       model.RunAttempt
	CallerPath       model.WorkflowPath
	TargetRepository model.RepositorySlug
	TargetPath       model.WorkflowPath
	// DeclaredRef is the caller literal preserved in ReferencedWorkflow.Path;
	// RecordedRef is GitHub's separate, often fully qualified ref field. They
	// are never collapsed because refs/tags/v1 and the caller literal v1 have
	// different evidentiary roles.
	DeclaredRef    string
	RecordedRef    string
	CalledObjectID model.CalledWorkflowObjectID
	EvidenceID     model.EvidenceID
}

type Result struct {
	Requested       collect.Interval
	Discovery       collect.Interval
	Batch           archive.Batch
	Gaps            []collect.Gap
	CalledWorkflows []CalledWorkflowObservation
	rawInputs       []archive.RawInput
}

func (c Collector) defaults(request Request) (Request, error) {
	if c.API == nil {
		return Request{}, errors.New("live GitHub API is nil")
	}
	if _, err := collect.NewInterval(request.Interval.From, request.Interval.To); err != nil {
		return Request{}, err
	}
	if !request.Purpose.valid() {
		return Request{}, errors.New("collection purpose must be investigate or archive")
	}
	if request.ArchiveSchedule == "" {
		request.ArchiveSchedule = ArchiveScheduleInitial
	}
	if !request.ArchiveSchedule.valid() {
		return Request{}, errors.New("archive scheduling mode is unsupported")
	}
	if request.Purpose != PurposeArchive && request.ArchiveSchedule != ArchiveScheduleInitial {
		return Request{}, errors.New("checkpoint resume and preservation are archive-only")
	}
	if request.ArchiveSchedule != ArchiveScheduleResume && len(request.ArchiveCheckpoints) != 0 {
		return Request{}, errors.New("archive checkpoints require resume scheduling")
	}
	if len(request.ArchiveCheckpoints) > 1_000_000 {
		return Request{}, errors.New("archive checkpoint count exceeds the compiled limit")
	}
	request.ArchiveCheckpoints = append([]archive.Checkpoint(nil), request.ArchiveCheckpoints...)
	for index := range request.ArchiveCheckpoints {
		checkpoint := &request.ArchiveCheckpoints[index]
		if checkpoint.WatchedParents != nil {
			parents := make([]archive.WatchedParent, len(checkpoint.WatchedParents))
			copy(parents, checkpoint.WatchedParents)
			checkpoint.WatchedParents = parents
		}
		sort.Slice(checkpoint.WatchedParents, func(i, j int) bool {
			return checkpoint.WatchedParents[i].RunID < checkpoint.WatchedParents[j].RunID
		})
		if err := checkpoint.Validate(); err != nil {
			return Request{}, fmt.Errorf("archive checkpoint %d: %w", index, err)
		}
	}
	sort.Slice(request.ArchiveCheckpoints, func(i, j int) bool {
		return request.ArchiveCheckpoints[i].RepositoryID < request.ArchiveCheckpoints[j].RepositoryID
	})
	for index := 1; index < len(request.ArchiveCheckpoints); index++ {
		if request.ArchiveCheckpoints[index-1].RepositoryID == request.ArchiveCheckpoints[index].RepositoryID {
			return Request{}, errors.New("archive checkpoints repeat a repository")
		}
	}
	if request.Organization == "" && len(request.Repositories) == 0 {
		return Request{}, errors.New("organization or explicit repositories are required")
	}
	if request.Organization != "" && len(request.Repositories) != 0 {
		return Request{}, errors.New("organization and explicit repositories are mutually exclusive")
	}
	if len(request.Repositories) > 0 {
		slugs, err := normalizeRequestedSlugs(request.Repositories)
		if err != nil {
			return Request{}, err
		}
		request.Repositories = make([]string, len(slugs))
		for index, slug := range slugs {
			request.Repositories[index] = string(slug)
		}
	}
	if request.Concurrency == 0 {
		request.Concurrency = DefaultConcurrency
	}
	if request.Concurrency < 1 || request.Concurrency > HardMaxConcurrency {
		return Request{}, errors.New("concurrency is outside the compiled bounds")
	}
	if request.MaxJobLogBytes == 0 {
		request.MaxJobLogBytes = DefaultJobLogBytes
	}
	if request.MaxAttemptLogBytes == 0 {
		request.MaxAttemptLogBytes = DefaultAttemptLogBytes
	}
	if request.MaxJobLogBytes < 1 || request.MaxJobLogBytes > HardMaxJobLogBytes ||
		request.MaxAttemptLogBytes < 1 || request.MaxAttemptLogBytes > HardMaxAttemptLogBytes {
		return Request{}, errors.New("log byte limits are outside the compiled bounds")
	}
	if request.MaxPartitions == 0 {
		request.MaxPartitions = DefaultMaxPartitions
	}
	if request.MaxPartitions < 1 || request.MaxPartitions > 1_000_000 {
		return Request{}, errors.New("partition limit is outside the compiled bounds")
	}
	if request.AuthKind == "" {
		request.AuthKind = "environment"
	}
	switch request.AuthKind {
	case "none", "classic-pat", "fine-grained-pat", "github-app", "gh-cli", "environment":
	default:
		return Request{}, errors.New("authentication kind is unsupported")
	}
	return request, nil
}
