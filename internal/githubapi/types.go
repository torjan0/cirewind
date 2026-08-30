// Package githubapi provides the read-only GitHub.com transport used by
// CIRewind collectors. It deliberately exposes typed operations instead of a
// general URL fetcher.
package githubapi

import "time"

const (
	APIBaseURL    = "https://api.github.com"
	APIVersion    = "2026-03-10"
	DefaultAccept = "application/vnd.github+json"
)

// GitObjectID keeps the repository object-hash namespace separate from
// package and content digests. Value is always the complete object ID.
type GitObjectID struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// GitObjectKind is the type recorded in a Git tag object's target header. Tag
// is intentionally supported so annotated tag chains can be preserved and
// peeled one evidence-backed hop at a time.
type GitObjectKind string

const (
	GitObjectCommit GitObjectKind = "commit"
	GitObjectTag    GitObjectKind = "tag"
	GitObjectTree   GitObjectKind = "tree"
	GitObjectBlob   GitObjectKind = "blob"
)

func (kind GitObjectKind) Valid() bool {
	return kind == GitObjectCommit || kind == GitObjectTag || kind == GitObjectTree || kind == GitObjectBlob
}

// GitObjectTarget is an explicitly typed target of another Git object.
type GitObjectTarget struct {
	Kind     GitObjectKind `json:"kind"`
	ObjectID GitObjectID   `json:"object_id"`
}

// GitTagObject preserves an annotated tag object separately from the object it
// targets. TagObjectID must never be substituted for Target.ObjectID or called
// a commit merely because commit is the common target kind.
type GitTagObject struct {
	TagObjectID GitObjectID     `json:"tag_object_id"`
	NodeID      string          `json:"node_id,omitempty"`
	TagName     string          `json:"tag_name"`
	Target      GitObjectTarget `json:"target"`
}

// GitCommitObject is a positively typed Git commit object returned by the Git
// database API. It deliberately excludes commit message, author identity, and
// response URLs because object typing and ancestry are the only collector
// inputs needed for bounded tag peeling.
type GitCommitObject struct {
	CommitObjectID  GitObjectID   `json:"commit_object_id"`
	NodeID          string        `json:"node_id,omitempty"`
	TreeObjectID    GitObjectID   `json:"tree_object_id"`
	ParentObjectIDs []GitObjectID `json:"parent_object_ids"`
}

// GitObjectPeel preserves the recorded object and every evidence-backed tag
// hop separately from the positively typed terminal commit.
type GitObjectPeel struct {
	RecordedObjectID GitObjectID      `json:"recorded_object_id"`
	RecordedKind     GitObjectKind    `json:"recorded_kind"`
	TagObjects       []GitTagObject   `json:"tag_objects"`
	CommitObject     *GitCommitObject `json:"commit_object,omitempty"`
	Responses        []ResponseMeta   `json:"responses"`
}

type Actor struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type Repository struct {
	ID            int64      `json:"id"`
	NodeID        string     `json:"node_id"`
	Name          string     `json:"name"`
	FullName      string     `json:"full_name"`
	Private       bool       `json:"private"`
	Visibility    string     `json:"visibility"`
	Archived      bool       `json:"archived"`
	Disabled      bool       `json:"disabled"`
	Fork          bool       `json:"fork"`
	Owner         Actor      `json:"owner"`
	DefaultBranch string     `json:"default_branch"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

type PullRequestRef struct {
	ID     int64 `json:"id"`
	Number int64 `json:"number"`
	Head   struct {
		SHA  string      `json:"sha"`
		Ref  string      `json:"ref"`
		Repo *Repository `json:"repo"`
	} `json:"head"`
	Base struct {
		SHA  string      `json:"sha"`
		Ref  string      `json:"ref"`
		Repo *Repository `json:"repo"`
	} `json:"base"`
}

type ReferencedWorkflow struct {
	Path string `json:"path"`
	SHA  string `json:"sha"`
	Ref  string `json:"ref"`
}

// WorkflowRun is a transport DTO. HeadSHA intentionally remains named as the
// API names it; collectors must not copy it into workflow or Action identity.
type WorkflowRun struct {
	ID                  int64                `json:"id"`
	NodeID              string               `json:"node_id"`
	RunNumber           int64                `json:"run_number"`
	RunAttempt          int                  `json:"run_attempt"`
	WorkflowID          int64                `json:"workflow_id"`
	Path                string               `json:"path"`
	Event               string               `json:"event"`
	Status              string               `json:"status"`
	Conclusion          string               `json:"conclusion"`
	CreatedAt           time.Time            `json:"created_at"`
	RunStartedAt        *time.Time           `json:"run_started_at"`
	UpdatedAt           *time.Time           `json:"updated_at"`
	HeadSHA             string               `json:"head_sha"`
	HeadBranch          string               `json:"head_branch"`
	Actor               Actor                `json:"actor"`
	TriggeringActor     Actor                `json:"triggering_actor"`
	PullRequests        []PullRequestRef     `json:"pull_requests"`
	Repository          *Repository          `json:"repository"`
	HeadRepository      *Repository          `json:"head_repository"`
	CheckSuiteID        int64                `json:"check_suite_id"`
	ReferencedWorkflows []ReferencedWorkflow `json:"referenced_workflows"`
}

type JobStep struct {
	Number      int        `json:"number"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Conclusion  string     `json:"conclusion"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

type WorkflowJob struct {
	ID              int64      `json:"id"`
	NodeID          string     `json:"node_id"`
	RunID           int64      `json:"run_id"`
	WorkflowName    string     `json:"workflow_name"`
	HeadSHA         string     `json:"head_sha"`
	HeadBranch      string     `json:"head_branch"`
	Status          string     `json:"status"`
	Conclusion      string     `json:"conclusion"`
	StartedAt       *time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	Name            string     `json:"name"`
	Steps           []JobStep  `json:"steps"`
	Labels          []string   `json:"labels"`
	RunnerID        int64      `json:"runner_id"`
	RunnerName      string     `json:"runner_name"`
	RunnerGroupID   *int64     `json:"runner_group_id"`
	RunnerGroupName string     `json:"runner_group_name"`
}

type Content struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Content  string `json:"content"`
}

// ResponseMeta is safe to persist. It intentionally has no raw URL, request
// headers, response headers, cookies, redirect location, or response body.
type ResponseMeta struct {
	Method             string            `json:"method"`
	RouteTemplate      string            `json:"route_template"`
	RequestParameters  map[string]string `json:"request_parameters,omitempty"`
	StatusCode         int               `json:"status_code"`
	RequestID          string            `json:"request_id,omitempty"`
	APIVersion         string            `json:"api_version"`
	ResponseAPIVersion string            `json:"response_api_version,omitempty"`
	MediaType          string            `json:"media_type,omitempty"`
	ByteLength         int64             `json:"byte_length"`
	SHA256             string            `json:"sha256,omitempty"`
	BodyComplete       bool              `json:"body_complete"`
	ETag               string            `json:"etag,omitempty"`
	RateLimit          int64             `json:"rate_limit,omitempty"`
	RateRemaining      int64             `json:"rate_remaining,omitempty"`
	RateUsed           int64             `json:"rate_used,omitempty"`
	RateReset          int64             `json:"rate_reset,omitempty"`
	RateResource       string            `json:"rate_resource,omitempty"`
	RetryAfterSeconds  int64             `json:"retry_after_seconds,omitempty"`
	StartedAt          time.Time         `json:"started_at"`
	CompletedAt        time.Time         `json:"completed_at"`
	ErrorClass         ErrorClass        `json:"error_class,omitempty"`
}

type RepositoryList struct {
	Repositories []Repository   `json:"repositories"`
	Responses    []ResponseMeta `json:"responses"`
}

type RunList struct {
	TotalCount int            `json:"total_count"`
	Runs       []WorkflowRun  `json:"workflow_runs"`
	Responses  []ResponseMeta `json:"responses"`
	// Truncated is conservative: it is true whenever the filtered result is at
	// the documented ceiling or pagination itself could not prove exhaustion.
	Truncated bool `json:"truncated"`
}

type RunProbe struct {
	TotalCount int            `json:"total_count"`
	Responses  []ResponseMeta `json:"responses"`
}

type JobList struct {
	TotalCount int            `json:"total_count"`
	Jobs       []WorkflowJob  `json:"jobs"`
	Responses  []ResponseMeta `json:"responses"`
}

type ObjectResult[T any] struct {
	Value     T              `json:"value"`
	Responses []ResponseMeta `json:"responses"`
}

type DownloadResult struct {
	LogicalSourceRoute string         `json:"logical_source_route"`
	APIResponses       []ResponseMeta `json:"api_responses"`
	StorageResponses   []ResponseMeta `json:"storage_responses"`
	MediaType          string         `json:"media_type"`
	ByteLength         int64          `json:"byte_length"`
	SHA256             string         `json:"sha256"`
	RenewedRedirect    bool           `json:"renewed_redirect"`
}
