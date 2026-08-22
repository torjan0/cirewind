package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

const SnapshotSchemaVersion = "cirewind.archive-snapshot/v1alpha1"

const (
	maxPayloadBytes     = 16 << 20
	maxSnapshotPayloads = 100_000
	maxSnapshotFacts    = 1_000_000
	maxSnapshotEvidence = 1_000_000
)

type Options struct {
	ArchiveID string        `json:"archive_id,omitempty"`
	CreatedAt model.Instant `json:"created_at"`
}

type SnapshotMetadata struct {
	SchemaVersion      string        `json:"schema_version"`
	StoreSchemaVersion int           `json:"store_schema_version"`
	ArchiveID          string        `json:"archive_id"`
	CreatedAt          model.Instant `json:"created_at"`
}

type CollectionScope struct {
	Organization         string               `json:"organization,omitempty"`
	Repositories         []model.RepositoryID `json:"repositories"`
	RequestedEventWindow *model.EventInterval `json:"requested_event_window,omitempty"`
	DiscoveryEventWindow *model.EventInterval `json:"discovery_event_window,omitempty"`
}

type CollectionSession struct {
	ID         model.CollectionSessionID `json:"id"`
	Mode       string                    `json:"mode"`
	APIVersion string                    `json:"api_version,omitempty"`
	AuthKind   string                    `json:"auth_kind"`
	// RawRetention records the operator's collection-time custody decision. It
	// does not imply that every requested log was available or that a later copy
	// of the archive still has its optional raw sidecar.
	RawRetention bool              `json:"raw_retention"`
	StartedAt    model.Instant     `json:"started_at"`
	EndedAt      model.Instant     `json:"ended_at"`
	Scope        CollectionScope   `json:"scope"`
	Limits       map[string]uint64 `json:"limits"`
}

func (s CollectionSession) Validate() error {
	if err := s.ID.Validate(); err != nil {
		return err
	}
	if s.Mode != "archive" && s.Mode != "investigate" && s.Mode != "fixture" {
		return fmt.Errorf("archive collection mode %q is invalid", s.Mode)
	}
	switch s.AuthKind {
	case "none", "classic-pat", "fine-grained-pat", "github-app", "gh-cli", "environment":
	default:
		return fmt.Errorf("archive auth kind %q is invalid", s.AuthKind)
	}
	if err := s.StartedAt.Validate(); err != nil {
		return err
	}
	if err := s.EndedAt.Validate(); err != nil {
		return err
	}
	if s.EndedAt.Before(s.StartedAt.Time) {
		return errors.New("archive collection ends before it starts")
	}
	if err := safeText(s.APIVersion, 128, true); err != nil {
		return err
	}
	if err := safeText(s.Scope.Organization, 256, true); err != nil {
		return err
	}
	if s.Scope.Repositories == nil || s.Limits == nil {
		return errors.New("collection scope repositories and limits must be explicit")
	}
	for index, repositoryID := range s.Scope.Repositories {
		if err := repositoryID.Validate(); err != nil {
			return err
		}
		if index > 0 && s.Scope.Repositories[index-1] >= repositoryID {
			return errors.New("collection repository IDs must be sorted and unique")
		}
	}
	if err := validateCollectionWindows(s.Scope.RequestedEventWindow, s.Scope.DiscoveryEventWindow); err != nil {
		return err
	}
	for name := range s.Limits {
		if err := safeMachineName(name, 128); err != nil || sensitiveName(name) {
			return fmt.Errorf("unsafe collection limit name %q", name)
		}
	}
	return nil
}

func validateCollectionWindows(requested, discovery *model.EventInterval) error {
	windows := []struct {
		label    string
		interval *model.EventInterval
	}{
		{label: "requested", interval: requested},
		{label: "discovery", interval: discovery},
	}
	for _, window := range windows {
		label, interval := window.label, window.interval
		if interval == nil {
			continue
		}
		if err := interval.Validate(); err != nil {
			return fmt.Errorf("%s event window: %w", label, err)
		}
		if interval.Start == nil || interval.End == nil || interval.Bounds == nil {
			return fmt.Errorf("%s event window must be bounded", label)
		}
	}
	if requested != nil && discovery != nil {
		if discovery.Start.Time.After(requested.Start.Time) || discovery.End.Time.Before(requested.End.Time) {
			return errors.New("discovery event window must contain the requested event window")
		}
	}
	return nil
}

type Payload struct {
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
	Bytes     []byte `json:"bytes"`
}

func (p Payload) Validate() error {
	if len(p.Bytes) > maxPayloadBytes {
		return fmt.Errorf("compact payload exceeds %d bytes", maxPayloadBytes)
	}
	if err := safeText(p.MediaType, 256, false); err != nil {
		return err
	}
	sum := sha256.Sum256(p.Bytes)
	if p.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("compact payload SHA-256 does not match bytes")
	}
	if containsCredentialMaterial(p.Bytes) {
		return errors.New("compact payload contains prohibited credential-like material")
	}
	return nil
}

type CapabilityStatus string

const (
	CapabilityRetained       CapabilityStatus = "retained"
	CapabilityStructuredOnly CapabilityStatus = "structured-only"
	CapabilityHashOnly       CapabilityStatus = "hash-only"
	CapabilityNotCollected   CapabilityStatus = "not-collected"
	CapabilityGap            CapabilityStatus = "gap"
)

func (s CapabilityStatus) Valid() bool {
	return s == CapabilityRetained || s == CapabilityStructuredOnly || s == CapabilityHashOnly || s == CapabilityNotCollected || s == CapabilityGap
}

type Capability struct {
	Name             string            `json:"name"`
	Status           CapabilityStatus  `json:"status"`
	ExtractorVersion string            `json:"extractor_version,omitempty"`
	Details          map[string]string `json:"details"`
}

func (c Capability) Validate() error {
	if err := safeMachineName(c.Name, 128); err != nil {
		return err
	}
	if !c.Status.Valid() {
		return fmt.Errorf("invalid archive capability status %q", c.Status)
	}
	if err := safeText(c.ExtractorVersion, 128, true); err != nil {
		return err
	}
	if c.Details == nil || len(c.Details) > 64 {
		return errors.New("capability details must be an explicit bounded object")
	}
	for key, value := range c.Details {
		if err := safeMachineName(key, 128); err != nil || sensitiveName(key) {
			return fmt.Errorf("unsafe capability detail key %q", key)
		}
		if err := safeText(value, 2048, true); err != nil || looksSensitive(value) {
			return fmt.Errorf("unsafe capability detail %q", key)
		}
	}
	return nil
}

type WatchedParent struct {
	RunID                model.WorkflowRunID `json:"run_id"`
	CreatedAt            model.Instant       `json:"created_at"`
	LastRefreshedAt      *model.Instant      `json:"last_refreshed_at,omitempty"`
	FinalRefreshComplete bool                `json:"final_refresh_complete"`
}

type Checkpoint struct {
	RepositoryID             model.RepositoryID        `json:"repository_id"`
	DiscoveryWatermark       *model.Instant            `json:"discovery_watermark,omitempty"`
	OverlapSeconds           uint32                    `json:"overlap_seconds"`
	WatchHorizonDays         uint32                    `json:"watch_horizon_days"`
	LastSuccessfulCollection model.CollectionSessionID `json:"last_successful_collection_id"`
	WatchedParents           []WatchedParent           `json:"watched_parents"`
}

func (c Checkpoint) Validate() error {
	if err := c.RepositoryID.Validate(); err != nil {
		return err
	}
	if c.DiscoveryWatermark != nil {
		if err := c.DiscoveryWatermark.Validate(); err != nil {
			return err
		}
	}
	if c.WatchHorizonDays < 35 {
		return errors.New("archive watch horizon cannot be below 35 days")
	}
	if err := c.LastSuccessfulCollection.Validate(); err != nil {
		return err
	}
	if c.WatchedParents == nil {
		return errors.New("watched parents must be an explicit array")
	}
	for index, parent := range c.WatchedParents {
		if err := parent.RunID.Validate(); err != nil {
			return err
		}
		if err := parent.CreatedAt.Validate(); err != nil {
			return err
		}
		if parent.LastRefreshedAt != nil {
			if err := parent.LastRefreshedAt.Validate(); err != nil {
				return err
			}
		}
		if index > 0 && c.WatchedParents[index-1].RunID >= parent.RunID {
			return errors.New("watched parents must be sorted and unique by run ID")
		}
	}
	return nil
}

type FactKind string

const (
	FactRepository       FactKind = "repository"
	FactRun              FactKind = "run"
	FactAttempt          FactKind = "attempt"
	FactJob              FactKind = "job"
	FactActionOccurrence FactKind = "action-occurrence"
	FactDependency       FactKind = "dependency"
	FactCoverage         FactKind = "coverage-assessment"
	FactCoverageGap      FactKind = "coverage-gap"
	FactExposure         FactKind = "exposure"
)

func (k FactKind) Valid() bool {
	return k == FactRepository || k == FactRun || k == FactAttempt || k == FactJob || k == FactActionOccurrence || k == FactDependency || k == FactCoverage || k == FactCoverageGap || k == FactExposure
}

type FactSubject struct {
	RepositoryID model.RepositoryID   `json:"repository_id"`
	RunID        *model.WorkflowRunID `json:"run_id,omitempty"`
	RunAttempt   *model.RunAttempt    `json:"run_attempt,omitempty"`
	JobID        *model.JobID         `json:"job_id,omitempty"`
	StepKey      string               `json:"step_key,omitempty"`
}

func (s FactSubject) Validate() error {
	if s.RepositoryID == 0 {
		if s.RunID != nil || s.RunAttempt != nil || s.JobID != nil || s.StepKey != "" {
			return errors.New("global fact subject cannot carry repository-child identity")
		}
		return nil
	}
	if err := s.RepositoryID.Validate(); err != nil {
		return err
	}
	if s.RunID != nil {
		if err := s.RunID.Validate(); err != nil {
			return err
		}
	}
	if s.RunAttempt != nil {
		if s.RunID == nil {
			return errors.New("fact attempt requires run ID")
		}
		if err := s.RunAttempt.Validate(); err != nil {
			return err
		}
	}
	if s.JobID != nil {
		if s.RunAttempt == nil {
			return errors.New("fact job requires run attempt")
		}
		if err := s.JobID.Validate(); err != nil {
			return err
		}
	}
	if s.StepKey != "" {
		if s.JobID == nil {
			return errors.New("fact step requires job ID")
		}
		return safeText(s.StepKey, 1024, false)
	}
	return nil
}

type RepositoryFact struct {
	Repository    model.RepositorySubject `json:"repository"`
	Visibility    string                  `json:"visibility,omitempty"`
	Private       *bool                   `json:"private,omitempty"`
	Fork          *bool                   `json:"fork,omitempty"`
	Archived      *bool                   `json:"archived,omitempty"`
	Disabled      *bool                   `json:"disabled,omitempty"`
	DefaultBranch string                  `json:"default_branch,omitempty"`
}

type ActorFact struct {
	ID    *model.ActorID `json:"id,omitempty"`
	Login string         `json:"login,omitempty"`
}

func (a ActorFact) Validate() error {
	if a.ID != nil {
		if err := a.ID.Validate(); err != nil {
			return err
		}
	}
	return safeText(a.Login, 256, true)
}

type RunFact struct {
	RepositoryID  model.RepositoryID     `json:"repository_id"`
	RunID         model.WorkflowRunID    `json:"run_id"`
	WorkflowPath  *model.WorkflowPath    `json:"workflow_path,omitempty"`
	EventType     string                 `json:"event_type"`
	Status        string                 `json:"status,omitempty"`
	Conclusion    string                 `json:"conclusion,omitempty"`
	TriggerObject *model.TriggerObjectID `json:"trigger_object_id,omitempty"`
	TriggerRef    string                 `json:"trigger_ref,omitempty"`
	Actor         ActorFact              `json:"actor"`
	EventTime     model.EventInterval    `json:"event_time"`
}

type AttemptFact struct {
	RepositoryID    model.RepositoryID  `json:"repository_id"`
	RunID           model.WorkflowRunID `json:"run_id"`
	RunAttempt      model.RunAttempt    `json:"run_attempt"`
	Status          string              `json:"status,omitempty"`
	Conclusion      string              `json:"conclusion,omitempty"`
	Actor           ActorFact           `json:"actor"`
	TriggeringActor ActorFact           `json:"triggering_actor"`
	EventTime       model.EventInterval `json:"event_time"`
}

type JobFact struct {
	Execution   model.JobExecutionIdentity `json:"execution"`
	DisplayName string                     `json:"display_name"`
	Status      string                     `json:"status,omitempty"`
	Conclusion  string                     `json:"conclusion,omitempty"`
	EventTime   model.EventInterval        `json:"event_time"`
}

type ActionOccurrenceFact struct {
	Observation model.RuntimeActionObservation `json:"observation"`
}

// DependencyRelation names the reconstruction edge without implying execution.
// These values intentionally match the evidence-graph relation vocabulary.
type DependencyRelation string

const (
	DependencyWorkflowDeclaredAction DependencyRelation = "WORKFLOW_DECLARED_ACTION"
	DependencyWorkflowCalledWorkflow DependencyRelation = "WORKFLOW_CALLED_WORKFLOW"
	DependencyActionContainsAction   DependencyRelation = "ACTION_CONTAINS_ACTION"
	DependencyLocalActionResolvedTo  DependencyRelation = "LOCAL_ACTION_RESOLVED_TO"
	DependencyRefResolvedTo          DependencyRelation = "REF_RESOLVED_TO"
)

func (r DependencyRelation) Valid() bool {
	switch r {
	case DependencyWorkflowDeclaredAction, DependencyWorkflowCalledWorkflow,
		DependencyActionContainsAction, DependencyLocalActionResolvedTo,
		DependencyRefResolvedTo:
		return true
	default:
		return false
	}
}

type DependencyTargetKind string

const (
	DependencyTargetAction           DependencyTargetKind = "action"
	DependencyTargetReusableWorkflow DependencyTargetKind = "reusable-workflow"
	DependencyTargetLocalAction      DependencyTargetKind = "local-action"
)

func (k DependencyTargetKind) Valid() bool {
	return k == DependencyTargetAction || k == DependencyTargetReusableWorkflow || k == DependencyTargetLocalAction
}

type DefinitionBasis string

const (
	DefinitionHistoricalAtRun        DefinitionBasis = "historical-at-run"
	DefinitionCurrentSnapshot        DefinitionBasis = "current-snapshot"
	DefinitionRuntimeAttemptMetadata DefinitionBasis = "runtime-attempt-metadata"
)

func (b DefinitionBasis) Valid() bool {
	return b == DefinitionHistoricalAtRun || b == DefinitionCurrentSnapshot || b == DefinitionRuntimeAttemptMetadata
}

// DependencyFact is either a non-executing definition reconstruction assertion
// or an attempt-scoped called-workflow identity recorded by GitHub. Exact Action
// and called-workflow object identities stay in distinct typed fields. An absent
// exact identity means only declaration or reachability was observed.
type DependencyFact struct {
	Relation                     DependencyRelation            `json:"relation"`
	TargetKind                   DependencyTargetKind          `json:"target_kind"`
	Basis                        DefinitionBasis               `json:"basis"`
	CallerRepositoryID           model.RepositoryID            `json:"caller_repository_id"`
	CallerRepository             model.RepositorySlug          `json:"caller_repository"`
	CallerPath                   string                        `json:"caller_path"`
	CallerWorkflowObjectID       *model.CallerWorkflowObjectID `json:"caller_workflow_object_id,omitempty"`
	CallerActionObjectID         *model.ActionSourceObjectID   `json:"caller_action_object_id,omitempty"`
	TargetRepository             model.RepositorySlug          `json:"target_repository"`
	TargetPath                   string                        `json:"target_path,omitempty"`
	DeclaredRef                  string                        `json:"declared_ref,omitempty"`
	TargetActionObjectID         *model.ActionSourceObjectID   `json:"target_action_object_id,omitempty"`
	TargetCalledWorkflowObjectID *model.CalledWorkflowObjectID `json:"target_called_workflow_object_id,omitempty"`
	PackageDigest                *model.PackageDigest          `json:"package_digest,omitempty"`
	TransitiveDepth              uint32                        `json:"transitive_depth"`
	AttemptExecution             *model.RunAttemptIdentity     `json:"attempt_execution,omitempty"`
	Execution                    *model.JobExecutionIdentity   `json:"execution,omitempty"`
	StepKey                      string                        `json:"step_key,omitempty"`
	ContradictsFactIDs           []string                      `json:"contradicts_fact_ids"`
	EventTime                    model.EventInterval           `json:"event_time"`
}

type CoverageGapFact struct {
	Unit       model.CoverageUnit       `json:"unit"`
	Assessment model.CoverageAssessment `json:"assessment"`
}

// CoverageFact preserves a terminal, non-gap coverage assessment. These facts
// are required before absence can support NO_MATCH_CONFIRMED; merely failing to
// record a gap is never treated as closed coverage.
type CoverageFact struct {
	Unit       model.CoverageUnit       `json:"unit"`
	Assessment model.CoverageAssessment `json:"assessment"`
}

type RunnerContextFact struct {
	Classification string   `json:"classification"`
	RunnerID       *int64   `json:"runner_id,omitempty"`
	RunnerName     string   `json:"runner_name,omitempty"`
	RunnerGroup    string   `json:"runner_group,omitempty"`
	Labels         []string `json:"labels"`
}

type EnvironmentEligibilityFact struct {
	EnvironmentName string             `json:"environment_name"`
	GateState       string             `json:"gate_state"`
	JobStarted      bool               `json:"job_started"`
	SecretNames     []model.SecretName `json:"secret_names"`
}

type ExposureFact struct {
	Execution   model.JobExecutionIdentity  `json:"execution"`
	StepKey     string                      `json:"step_key,omitempty"`
	Credential  *model.CredentialExposure   `json:"credential,omitempty"`
	Resource    *model.ResourceExposure     `json:"resource,omitempty"`
	Runner      *RunnerContextFact          `json:"runner,omitempty"`
	Environment *EnvironmentEligibilityFact `json:"environment,omitempty"`
	EventTime   model.EventInterval         `json:"event_time"`
}

type Fact struct {
	ID               string                `json:"id"`
	Kind             FactKind              `json:"kind"`
	Subject          FactSubject           `json:"subject"`
	EventTime        model.EventInterval   `json:"event_time"`
	EvidenceIDs      []model.EvidenceID    `json:"evidence_ids"`
	Repository       *RepositoryFact       `json:"repository,omitempty"`
	Run              *RunFact              `json:"run,omitempty"`
	Attempt          *AttemptFact          `json:"attempt,omitempty"`
	Job              *JobFact              `json:"job,omitempty"`
	ActionOccurrence *ActionOccurrenceFact `json:"action_occurrence,omitempty"`
	Dependency       *DependencyFact       `json:"dependency,omitempty"`
	Coverage         *CoverageFact         `json:"coverage,omitempty"`
	CoverageGap      *CoverageGapFact      `json:"coverage_gap,omitempty"`
	Exposure         *ExposureFact         `json:"exposure,omitempty"`
}

type Batch struct {
	ID           string              `json:"id,omitempty"`
	Collections  []CollectionSession `json:"collections"`
	Payloads     []Payload           `json:"payloads"`
	Evidence     []evidence.Envelope `json:"evidence"`
	Facts        []Fact              `json:"facts"`
	Capabilities []Capability        `json:"capabilities"`
	Checkpoints  []Checkpoint        `json:"checkpoints"`
}

type Snapshot struct {
	Metadata     SnapshotMetadata    `json:"metadata"`
	Collections  []CollectionSession `json:"collections"`
	Payloads     []Payload           `json:"payloads"`
	Evidence     []evidence.Envelope `json:"evidence"`
	Facts        []Fact              `json:"facts"`
	Capabilities []Capability        `json:"capabilities"`
	Checkpoints  []Checkpoint        `json:"checkpoints"`
}

func defaultMetadata(options Options) (SnapshotMetadata, error) {
	if err := options.CreatedAt.Validate(); err != nil {
		return SnapshotMetadata{}, err
	}
	archiveID := options.ArchiveID
	if archiveID == "" {
		hash, err := evidence.CanonicalSHA256(struct {
			Version   string        `json:"version"`
			CreatedAt model.Instant `json:"created_at"`
		}{"arc1", options.CreatedAt})
		if err != nil {
			return SnapshotMetadata{}, err
		}
		archiveID = "arc1:" + hash
	}
	if !validPrefixedHash(archiveID, "arc1:") {
		return SnapshotMetadata{}, errors.New("archive ID is invalid")
	}
	return SnapshotMetadata{
		SchemaVersion:      SnapshotSchemaVersion,
		StoreSchemaVersion: store.SchemaVersion,
		ArchiveID:          archiveID,
		CreatedAt:          options.CreatedAt,
	}, nil
}

func safeText(value string, max int, emptyOK bool) error {
	if (!emptyOK && value == "") || len(value) > max || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return errors.New("text is empty, unbounded, or invalid UTF-8")
	}
	return nil
}

func safeMachineName(value string, max int) error {
	if value == "" || len(value) > max {
		return errors.New("machine name is empty or too long")
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:/-", char) {
			continue
		}
		return errors.New("machine name contains an unsupported character")
	}
	return nil
}

func validPrefixedHash(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && value == strings.ToLower(value)
}

func sensitiveName(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{"token", "secret", "password", "authorization", "cookie", "credential", "private_key"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func looksSensitive(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{"bearer ", "authorization:", "token=", "x-amz-signature", "private key-----"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func containsCredentialMaterial(value []byte) bool {
	lower := strings.ToLower(string(value))
	for _, token := range []string{"-----begin private key-----", "-----begin rsa private key-----", "authorization: bearer ", "ghp_", "github_pat_", "x-amz-signature="} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func sortEvidenceIDs(ids []model.EvidenceID) []model.EvidenceID {
	result := append([]model.EvidenceID(nil), ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) == 0 {
		return result
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write]
}
