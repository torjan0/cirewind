package githubapi

import "time"

// PartialError is a stable, serializable capability failure. It deliberately
// excludes request URLs, response bodies, and authentication material.
type PartialError struct {
	Class      ErrorClass `json:"class"`
	Operation  string     `json:"operation"`
	StatusCode int        `json:"status_code,omitempty"`
	Message    string     `json:"message,omitempty"`
	Retryable  bool       `json:"retryable"`
}

// CapabilityListMetadata accompanies every optional enrichment. Items from
// completed pages remain usable when a later page fails, while Partial makes
// it impossible to mistake that prefix for complete coverage.
type CapabilityListMetadata struct {
	Responses []ResponseMeta `json:"responses"`
	Partial   bool           `json:"partial"`
	Failure   *PartialError  `json:"failure,omitempty"`
}

type Artifact struct {
	ID                 int64      `json:"id"`
	NodeID             string     `json:"node_id"`
	Name               string     `json:"name"`
	SizeInBytes        int64      `json:"size_in_bytes"`
	Expired            bool       `json:"expired"`
	CreatedAt          *time.Time `json:"created_at"`
	UpdatedAt          *time.Time `json:"updated_at"`
	ExpiresAt          *time.Time `json:"expires_at"`
	Digest             string     `json:"digest"`
	ArchiveDownloadURL string     `json:"archive_download_url"`
}

type ArtifactList struct {
	TotalCount int        `json:"total_count"`
	Artifacts  []Artifact `json:"artifacts"`
	CapabilityListMetadata
}

type Deployment struct {
	ID                    int64      `json:"id"`
	NodeID                string     `json:"node_id"`
	SHA                   string     `json:"sha"`
	Ref                   string     `json:"ref"`
	Task                  string     `json:"task"`
	Environment           string     `json:"environment"`
	OriginalEnvironment   string     `json:"original_environment"`
	Description           string     `json:"description"`
	Creator               Actor      `json:"creator"`
	CreatedAt             *time.Time `json:"created_at"`
	UpdatedAt             *time.Time `json:"updated_at"`
	TransientEnvironment  bool       `json:"transient_environment"`
	ProductionEnvironment bool       `json:"production_environment"`
}

type DeploymentList struct {
	Deployments []Deployment `json:"deployments"`
	CapabilityListMetadata
}

type DeploymentStatus struct {
	ID          int64      `json:"id"`
	NodeID      string     `json:"node_id"`
	State       string     `json:"state"`
	Description string     `json:"description"`
	Environment string     `json:"environment"`
	Creator     Actor      `json:"creator"`
	CreatedAt   *time.Time `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
}

type DeploymentStatusList struct {
	Statuses []DeploymentStatus `json:"statuses"`
	CapabilityListMetadata
}

type EnvironmentReviewerIdentity struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Slug  string `json:"slug"`
}

type EnvironmentReviewer struct {
	Type     string                      `json:"type"`
	Reviewer EnvironmentReviewerIdentity `json:"reviewer"`
}

type EnvironmentProtectionRule struct {
	ID                int64                 `json:"id"`
	NodeID            string                `json:"node_id"`
	Type              string                `json:"type"`
	WaitTimer         int                   `json:"wait_timer"`
	PreventSelfReview bool                  `json:"prevent_self_review"`
	Reviewers         []EnvironmentReviewer `json:"reviewers"`
}

type DeploymentBranchPolicy struct {
	ProtectedBranches    bool `json:"protected_branches"`
	CustomBranchPolicies bool `json:"custom_branch_policies"`
}

type Environment struct {
	ID                     int64                       `json:"id"`
	NodeID                 string                      `json:"node_id"`
	Name                   string                      `json:"name"`
	CreatedAt              *time.Time                  `json:"created_at"`
	UpdatedAt              *time.Time                  `json:"updated_at"`
	ProtectionRules        []EnvironmentProtectionRule `json:"protection_rules"`
	DeploymentBranchPolicy *DeploymentBranchPolicy     `json:"deployment_branch_policy"`
}

type EnvironmentList struct {
	TotalCount   int           `json:"total_count"`
	Environments []Environment `json:"environments"`
	CapabilityListMetadata
}

type PendingDeployment struct {
	Environment           Environment           `json:"environment"`
	WaitTimer             int                   `json:"wait_timer"`
	WaitTimerStartedAt    *time.Time            `json:"wait_timer_started_at"`
	CurrentUserCanApprove bool                  `json:"current_user_can_approve"`
	Reviewers             []EnvironmentReviewer `json:"reviewers"`
}

type PendingDeploymentList struct {
	PendingDeployments []PendingDeployment `json:"pending_deployments"`
	CapabilityListMetadata
}

type EnvironmentApproval struct {
	Environments []Environment `json:"environments"`
	State        string        `json:"state"`
	User         Actor         `json:"user"`
	Comment      string        `json:"comment"`
	CreatedAt    *time.Time    `json:"created_at"`
}

type EnvironmentApprovalList struct {
	Approvals []EnvironmentApproval `json:"approvals"`
	CapabilityListMetadata
}

// SecretMetadata is intentionally incapable of representing a secret value.
// GitHub's extra response fields are ignored by JSON decoding.
type SecretMetadata struct {
	Name       string     `json:"name"`
	CreatedAt  *time.Time `json:"created_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
	Visibility string     `json:"visibility,omitempty"`
}

type SecretMetadataList struct {
	TotalCount int              `json:"total_count"`
	Secrets    []SecretMetadata `json:"secrets"`
	CapabilityListMetadata
}

type RunnerLabel struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type SelfHostedRunner struct {
	ID        int64         `json:"id"`
	Name      string        `json:"name"`
	OS        string        `json:"os"`
	Status    string        `json:"status"`
	Busy      bool          `json:"busy"`
	Ephemeral bool          `json:"ephemeral"`
	Version   string        `json:"version"`
	Labels    []RunnerLabel `json:"labels"`
}

type RunnerList struct {
	TotalCount int                `json:"total_count"`
	Runners    []SelfHostedRunner `json:"runners"`
	CapabilityListMetadata
}

type RunnerGroup struct {
	ID                           int64    `json:"id"`
	Name                         string   `json:"name"`
	Visibility                   string   `json:"visibility"`
	Default                      bool     `json:"default"`
	AllowsPublicRepositories     bool     `json:"allows_public_repositories"`
	RestrictedToWorkflows        bool     `json:"restricted_to_workflows"`
	SelectedWorkflows            []string `json:"selected_workflows"`
	WorkflowRestrictionsReadOnly bool     `json:"workflow_restrictions_read_only"`
	Inherited                    bool     `json:"inherited"`
}

type RunnerGroupList struct {
	TotalCount   int           `json:"total_count"`
	RunnerGroups []RunnerGroup `json:"runner_groups"`
	CapabilityListMetadata
}

type ReleaseAsset struct {
	ID            int64      `json:"id"`
	NodeID        string     `json:"node_id"`
	Name          string     `json:"name"`
	Label         string     `json:"label"`
	State         string     `json:"state"`
	ContentType   string     `json:"content_type"`
	Size          int64      `json:"size"`
	DownloadCount int64      `json:"download_count"`
	Digest        string     `json:"digest"`
	CreatedAt     *time.Time `json:"created_at"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

type Release struct {
	ID              int64          `json:"id"`
	NodeID          string         `json:"node_id"`
	TagName         string         `json:"tag_name"`
	TargetCommitish string         `json:"target_commitish"`
	Name            string         `json:"name"`
	Draft           bool           `json:"draft"`
	Prerelease      bool           `json:"prerelease"`
	Immutable       bool           `json:"immutable"`
	Author          Actor          `json:"author"`
	CreatedAt       *time.Time     `json:"created_at"`
	PublishedAt     *time.Time     `json:"published_at"`
	Assets          []ReleaseAsset `json:"assets"`
}

type ReleaseList struct {
	Releases []Release `json:"releases"`
	CapabilityListMetadata
}

type ReleaseAssetList struct {
	Assets []ReleaseAsset `json:"assets"`
	CapabilityListMetadata
}
