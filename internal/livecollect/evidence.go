package livecollect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/sanitize"
)

var extractorRulesetSHA256 = sha256Hex([]byte("livecollect/v1;github-runner-control/v1alpha1;github-attempt-log-consolidated/v1alpha1;setup-exact-resolution;strict-action-details-group;api-job-step-number-binding;exact-historical-caller-step-binding;exact-reusable-step-binding;duplicate-view-equivalence;bounded-reusable-setup-tail;exact-composite-immediate-prefix-binding;called-workflow-object-peel-v1"))

type responseProjection struct {
	Method             string                     `json:"method"`
	RouteTemplate      string                     `json:"route_template"`
	RequestParameters  evidence.RequestParameters `json:"request_parameters"`
	StatusCode         int                        `json:"status_code"`
	RequestID          string                     `json:"request_id,omitempty"`
	APIVersion         string                     `json:"api_version,omitempty"`
	ResponseAPIVersion string                     `json:"response_api_version,omitempty"`
	MediaType          string                     `json:"media_type,omitempty"`
	ByteLength         int64                      `json:"byte_length"`
	SHA256             string                     `json:"sha256,omitempty"`
	Complete           bool                       `json:"complete"`
	ETag               string                     `json:"etag,omitempty"`
	RateLimit          int64                      `json:"rate_limit"`
	RateRemaining      int64                      `json:"rate_remaining"`
	RateUsed           int64                      `json:"rate_used"`
	RateReset          int64                      `json:"rate_reset"`
	RateResource       string                     `json:"rate_resource,omitempty"`
	RetryAfterSeconds  int64                      `json:"retry_after_seconds"`
	StartedAt          string                     `json:"started_at,omitempty"`
	CompletedAt        string                     `json:"completed_at,omitempty"`
	ErrorClass         githubapi.ErrorClass       `json:"error_class,omitempty"`
}

type repositoryProjectionDocument struct {
	Schema        string `json:"schema"`
	RepositoryID  int64  `json:"repository_id"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility,omitempty"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

type organizationProjectionDocument struct {
	Schema          string               `json:"schema"`
	Organization    string               `json:"organization"`
	RepositoryCount int                  `json:"repository_count"`
	RepositoryIDs   []int64              `json:"repository_ids"`
	Responses       []responseProjection `json:"responses"`
}

type runProjectionDocument struct {
	Schema               string                         `json:"schema"`
	RepositoryID         int64                          `json:"repository_id"`
	RunID                int64                          `json:"run_id"`
	RunAttempt           int                            `json:"run_attempt"`
	WorkflowPath         string                         `json:"workflow_path,omitempty"`
	Event                string                         `json:"event"`
	Status               string                         `json:"status,omitempty"`
	Conclusion           string                         `json:"conclusion,omitempty"`
	CreatedAt            string                         `json:"created_at"`
	HeadSHA              string                         `json:"head_sha,omitempty"`
	HeadBranch           string                         `json:"head_branch,omitempty"`
	ActorID              int64                          `json:"actor_id,omitempty"`
	ActorLogin           string                         `json:"actor_login,omitempty"`
	TriggeringActorID    int64                          `json:"triggering_actor_id,omitempty"`
	TriggeringActorLogin string                         `json:"triggering_actor_login,omitempty"`
	ReferencedWorkflows  []referencedWorkflowProjection `json:"referenced_workflows"`
}

type runPartitionProjectionDocument struct {
	Schema                string                    `json:"schema"`
	RepositoryID          int64                     `json:"repository_id"`
	RequestedFrom         string                    `json:"requested_from"`
	RequestedTo           string                    `json:"requested_to"`
	QueriedFrom           string                    `json:"queried_from"`
	QueriedTo             string                    `json:"queried_to"`
	DuplicateObservations int                       `json:"duplicate_observations"`
	OverlapObservations   int                       `json:"overlap_observations"`
	Nodes                 []partitionNodeProjection `json:"nodes"`
}

type partitionNodeProjection struct {
	From          string               `json:"from"`
	To            string               `json:"to"`
	CreatedFilter string               `json:"created_filter"`
	TotalCount    int                  `json:"total_count"`
	Status        string               `json:"status"`
	RunCount      int                  `json:"run_count"`
	OverlapRows   int                  `json:"overlap_rows"`
	Responses     []responseProjection `json:"responses"`
}

type referencedWorkflowProjection struct {
	Path string `json:"path"`
	SHA  string `json:"sha"`
	Ref  string `json:"ref,omitempty"`
}

type attemptProjectionDocument struct {
	Schema              string                         `json:"schema"`
	RepositoryID        int64                          `json:"repository_id"`
	RunID               int64                          `json:"run_id"`
	RunAttempt          int                            `json:"run_attempt"`
	Event               string                         `json:"event"`
	Status              string                         `json:"status,omitempty"`
	Conclusion          string                         `json:"conclusion,omitempty"`
	WorkflowPath        string                         `json:"workflow_path,omitempty"`
	HeadSHA             string                         `json:"head_sha,omitempty"`
	HeadBranch          string                         `json:"head_branch,omitempty"`
	PullRequestCount    int                            `json:"pull_request_count"`
	PullRequestsLimited bool                           `json:"pull_requests_limited"`
	PullRequests        []pullRequestProjection        `json:"pull_requests"`
	ReferencedWorkflows []referencedWorkflowProjection `json:"referenced_workflows"`
	Responses           []responseProjection           `json:"responses"`
}

type pullRequestProjection struct {
	ID               int64  `json:"id"`
	Number           int64  `json:"number"`
	HeadSHA          string `json:"head_sha,omitempty"`
	HeadRef          string `json:"head_ref,omitempty"`
	HeadRepositoryID int64  `json:"head_repository_id,omitempty"`
	BaseSHA          string `json:"base_sha,omitempty"`
	BaseRef          string `json:"base_ref,omitempty"`
	BaseRepositoryID int64  `json:"base_repository_id,omitempty"`
}

type jobProjectionDocument struct {
	Schema          string   `json:"schema"`
	RepositoryID    int64    `json:"repository_id"`
	RunID           int64    `json:"run_id"`
	RunAttempt      int      `json:"run_attempt"`
	JobID           int64    `json:"job_id"`
	Name            string   `json:"name"`
	Status          string   `json:"status,omitempty"`
	Conclusion      string   `json:"conclusion,omitempty"`
	StartedAt       string   `json:"started_at,omitempty"`
	CompletedAt     string   `json:"completed_at,omitempty"`
	Labels          []string `json:"labels"`
	RunnerID        int64    `json:"runner_id,omitempty"`
	RunnerName      string   `json:"runner_name,omitempty"`
	RunnerGroupID   *int64   `json:"runner_group_id,omitempty"`
	RunnerGroupName string   `json:"runner_group_name,omitempty"`
}

func repositoryProjection(repository githubapi.Repository) repositoryProjectionDocument {
	return repositoryProjectionDocument{
		Schema: "cirewind.github-repository-projection/v1", RepositoryID: repository.ID,
		FullName: safeField(repository.FullName, 512), Private: repository.Private,
		Visibility: safeField(repository.Visibility, 32), Archived: repository.Archived,
		Disabled: repository.Disabled, Fork: repository.Fork, DefaultBranch: safeField(repository.DefaultBranch, 1024),
	}
}

func organizationProjection(organization string, listed githubapi.RepositoryList) organizationProjectionDocument {
	ids := make([]int64, 0, len(listed.Repositories))
	for _, repository := range listed.Repositories {
		if repository.ID > 0 {
			ids = append(ids, repository.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return organizationProjectionDocument{
		Schema: "cirewind.github-organization-repositories-projection/v1", Organization: safeField(organization, 256),
		RepositoryCount: len(listed.Repositories), RepositoryIDs: ids, Responses: projectResponses(listed.Responses),
	}
}

func projectRun(repositoryID int64, run githubapi.WorkflowRun) runProjectionDocument {
	refs := projectReferenced(run.ReferencedWorkflows)
	return runProjectionDocument{
		Schema: "cirewind.github-workflow-run-projection/v1", RepositoryID: repositoryID, RunID: run.ID,
		RunAttempt: run.RunAttempt, WorkflowPath: safeField(run.Path, 4096), Event: safeMachine(run.Event, 128),
		Status: safeMachine(run.Status, 128), Conclusion: safeMachine(run.Conclusion, 128),
		CreatedAt: run.CreatedAt.UTC().Format(time.RFC3339Nano), HeadSHA: safeHex(run.HeadSHA, 64),
		HeadBranch: safeField(run.HeadBranch, 1024), ActorID: run.Actor.ID, ActorLogin: safeField(run.Actor.Login, 256),
		TriggeringActorID: run.TriggeringActor.ID, TriggeringActorLogin: safeField(run.TriggeringActor.Login, 256),
		ReferencedWorkflows: refs,
	}
}

func projectAttempt(repositoryID int64, bundle collect.AttemptBundle) attemptProjectionDocument {
	run := bundle.Run
	pullRequests, limited := projectPullRequests(run.PullRequests)
	return attemptProjectionDocument{
		Schema: "cirewind.github-run-attempt-projection/v1", RepositoryID: repositoryID, RunID: run.ID,
		RunAttempt: bundle.Attempt, Event: safeMachine(run.Event, 128), Status: safeMachine(run.Status, 128), Conclusion: safeMachine(run.Conclusion, 128),
		WorkflowPath: safeField(run.Path, 4096), HeadSHA: safeHex(run.HeadSHA, 64), HeadBranch: safeField(run.HeadBranch, 1024),
		PullRequestCount: len(run.PullRequests), PullRequestsLimited: limited, PullRequests: pullRequests,
		ReferencedWorkflows: projectReferenced(run.ReferencedWorkflows),
		Responses:           projectResponses(bundle.Responses),
	}
}

func projectPullRequests(values []githubapi.PullRequestRef) ([]pullRequestProjection, bool) {
	result := make([]pullRequestProjection, 0, min(len(values), maxCallerPullRequestCandidates))
	for index, value := range values {
		if index >= maxCallerPullRequestCandidates {
			break
		}
		projection := pullRequestProjection{
			ID: value.ID, Number: value.Number, HeadSHA: safeHex(value.Head.SHA, 64), HeadRef: safeField(value.Head.Ref, 1024),
			BaseSHA: safeHex(value.Base.SHA, 64), BaseRef: safeField(value.Base.Ref, 1024),
		}
		if value.Head.Repo != nil && value.Head.Repo.ID > 0 {
			projection.HeadRepositoryID = value.Head.Repo.ID
		}
		if value.Base.Repo != nil && value.Base.Repo.ID > 0 {
			projection.BaseRepositoryID = value.Base.Repo.ID
		}
		result = append(result, projection)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		if result[i].Number != result[j].Number {
			return result[i].Number < result[j].Number
		}
		if result[i].BaseRepositoryID != result[j].BaseRepositoryID {
			return result[i].BaseRepositoryID < result[j].BaseRepositoryID
		}
		return result[i].BaseSHA < result[j].BaseSHA
	})
	limited := len(values) > maxCallerPullRequestCandidates
	return result, limited
}

func projectRunPartition(repositoryID int64, partition collect.PartitionResult) runPartitionProjectionDocument {
	result := runPartitionProjectionDocument{
		Schema: "cirewind.github-run-partition-projection/v1", RepositoryID: repositoryID,
		RequestedFrom: partition.Requested.From.UTC().Format(time.RFC3339Nano), RequestedTo: partition.Requested.To.UTC().Format(time.RFC3339Nano),
		QueriedFrom: partition.Queried.From.UTC().Format(time.RFC3339Nano), QueriedTo: partition.Queried.To.UTC().Format(time.RFC3339Nano),
		DuplicateObservations: partition.DuplicateObservations, OverlapObservations: partition.OverlapObservations,
		Nodes: []partitionNodeProjection{},
	}
	var visit func(*collect.PartitionNode)
	visit = func(node *collect.PartitionNode) {
		if node == nil {
			return
		}
		result.Nodes = append(result.Nodes, partitionNodeProjection{
			From: node.Window.From.UTC().Format(time.RFC3339Nano), To: node.Window.To.UTC().Format(time.RFC3339Nano),
			CreatedFilter: safeField(node.CreatedFilter, 256), TotalCount: node.TotalCount, Status: string(node.Status),
			RunCount: node.RunCount, OverlapRows: node.OverlapRows, Responses: projectResponses(node.Responses),
		})
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(partition.Root)
	return result
}

func partitionFilterForRun(node *collect.PartitionNode, created time.Time) string {
	if node == nil || created.Before(node.Window.From) || !created.Before(node.Window.To) {
		return ""
	}
	for _, child := range node.Children {
		if filter := partitionFilterForRun(child, created); filter != "" {
			return filter
		}
	}
	return safeField(node.CreatedFilter, 256)
}

func projectJob(repositoryID int64, runID int64, attempt int, job githubapi.WorkflowJob) jobProjectionDocument {
	labels := safeStrings(job.Labels, 256, 256)
	result := jobProjectionDocument{
		Schema: "cirewind.github-job-projection/v1", RepositoryID: repositoryID, RunID: runID,
		RunAttempt: attempt, JobID: job.ID, Name: safeField(job.Name, 4096), Status: safeMachine(job.Status, 128),
		Conclusion: safeMachine(job.Conclusion, 128), Labels: labels, RunnerID: job.RunnerID,
		RunnerName: safeField(job.RunnerName, 1024), RunnerGroupID: cloneOptionalInt64(job.RunnerGroupID),
		RunnerGroupName: safeField(job.RunnerGroupName, 1024),
	}
	if job.StartedAt != nil && !job.StartedAt.IsZero() {
		result.StartedAt = job.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if job.CompletedAt != nil && !job.CompletedAt.IsZero() {
		result.CompletedAt = job.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	return result
}

func cloneOptionalInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func projectReferenced(values []githubapi.ReferencedWorkflow) []referencedWorkflowProjection {
	result := make([]referencedWorkflowProjection, 0, len(values))
	for _, value := range values {
		result = append(result, referencedWorkflowProjection{Path: safeField(value.Path, 4096), SHA: safeHex(value.SHA, 64), Ref: safeField(value.Ref, 1024)})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		if result[i].SHA != result[j].SHA {
			return result[i].SHA < result[j].SHA
		}
		return result[i].Ref < result[j].Ref
	})
	return result
}

func projectResponses(values []githubapi.ResponseMeta) []responseProjection {
	result := make([]responseProjection, 0, len(values))
	for _, value := range values {
		projected := responseProjection{
			Method: safeMachine(value.Method, 16), RouteTemplate: safeField(value.RouteTemplate, 2048),
			RequestParameters: projectResponseParameters(value.RequestParameters), StatusCode: value.StatusCode,
			RequestID: safeField(value.RequestID, 256), APIVersion: safeField(value.APIVersion, 128),
			ResponseAPIVersion: safeField(value.ResponseAPIVersion, 128), MediaType: safeField(value.MediaType, 256),
			ByteLength: value.ByteLength, SHA256: safeHex(value.SHA256, 64), Complete: value.BodyComplete,
			ETag: safeField(value.ETag, 1024), RateLimit: value.RateLimit, RateRemaining: value.RateRemaining,
			RateUsed: value.RateUsed, RateReset: value.RateReset, RateResource: safeField(value.RateResource, 128),
			RetryAfterSeconds: value.RetryAfterSeconds, ErrorClass: value.ErrorClass,
		}
		if !value.StartedAt.IsZero() {
			projected.StartedAt = value.StartedAt.UTC().Format(time.RFC3339Nano)
		}
		if !value.CompletedAt.IsZero() {
			projected.CompletedAt = value.CompletedAt.UTC().Format(time.RFC3339Nano)
		}
		result = append(result, projected)
	}
	return result
}

func projectResponseParameters(values map[string]string) evidence.RequestParameters {
	result := make(evidence.RequestParameters, len(values))
	for key, value := range values {
		result[safeField(key, 128)] = safeField(value, 4096)
	}
	return result
}

func compactEnvelope(sessionID model.CollectionSessionID, request model.RequestID, canonicalSource string, kind evidence.SourceKind, apiVersion, endpoint string, parameters evidence.RequestParameters, scope model.CoverageScope, projection any, started, ended model.Instant) (archive.Payload, evidence.Envelope, error) {
	return compactEnvelopeAt(sessionID, request, canonicalSource, kind, apiVersion, endpoint, parameters, scope, unknownTime(), projection, started, ended)
}

func compactEnvelopeAt(sessionID model.CollectionSessionID, request model.RequestID, canonicalSource string, kind evidence.SourceKind, apiVersion, endpoint string, parameters evidence.RequestParameters, scope model.CoverageScope, event model.EventInterval, projection any, started, ended model.Instant) (archive.Payload, evidence.Envelope, error) {
	data, err := evidence.CanonicalJSON(projection)
	if err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	if len(data) > 16<<20 {
		return archive.Payload{}, evidence.Envelope{}, errors.New("structured evidence projection exceeds compact payload limit")
	}
	payloadHash := sha256Hex(data)
	payload := archive.Payload{SHA256: payloadHash, MediaType: "application/json", Bytes: data}
	if err := payload.Validate(); err != nil {
		return archive.Payload{}, evidence.Envelope{}, fmt.Errorf("structured evidence payload: %w", err)
	}
	envelope, err := makeEnvelope(sessionID, request, canonicalSource, kind, evidence.ProviderCIRewind, apiVersion, endpoint, parameters, scope, event, "application/json", uint64(len(data)), payloadHash, &payloadHash, false, "", true, evidence.RedactionStructuredAllowlist, structuredPolicyVersion, nil, started, ended)
	return payload, envelope, err
}

func logEnvelope(sessionID model.CollectionSessionID, request model.RequestID, canonicalSource string, kind evidence.SourceKind, endpoint string, parameters evidence.RequestParameters, scope model.CoverageScope, event model.EventInterval, download githubapi.DownloadResult, localBytes uint64, localSHA string, rawRetained bool, started, ended model.Instant) (evidence.Envelope, error) {
	if download.ByteLength < 0 || uint64(download.ByteLength) != localBytes {
		return evidence.Envelope{}, errors.New("download byte length disagrees with locally observed bytes")
	}
	if download.SHA256 == "" || download.SHA256 != localSHA {
		return evidence.Envelope{}, errors.New("download SHA-256 disagrees with locally observed bytes")
	}
	mediaType := safeField(download.MediaType, 256)
	if mediaType == "" {
		if kind == evidence.SourceWorkflowRunAttemptLog {
			mediaType = "application/zip"
		} else {
			mediaType = "text/plain"
		}
	}
	var retainedSHA *string
	retainedPath := ""
	policy := defaultRedactionPolicy
	if rawRetained {
		retainedSHA = &localSHA
		var err error
		retainedPath, err = archive.RawRelativePath(localSHA)
		if err != nil {
			return evidence.Envelope{}, err
		}
		policy = "raw-exact-opt-in-v1"
	}
	return makeEnvelope(sessionID, request, canonicalSource, kind, evidence.ProviderGitHub, githubapi.APIVersion, endpoint, parameters, scope, event, mediaType, localBytes, localSHA, retainedSHA, rawRetained, retainedPath, true, evidence.RedactionNotInspected, policy, nil, started, ended)
}

func derivedSetupEntryEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, started, ended model.Instant) (evidence.Envelope, error) {
	return derivedLogRegionEnvelope(sessionID, request, scope, event, byteLength, sourceSHA, parent, "archive_entry_extraction", "attempt-log-setup-entry", started, ended)
}

func derivedActionStepEntryEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, started, ended model.Instant) (evidence.Envelope, error) {
	return derivedLogRegionEnvelope(sessionID, request, scope, event, byteLength, sourceSHA, parent, "archive_entry_extraction", "attempt-log-action-step-entry", started, ended)
}

func derivedConsolidatedSetupFrameEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, started, ended model.Instant) (evidence.Envelope, error) {
	return derivedLogRegionEnvelope(sessionID, request, scope, event, byteLength, sourceSHA, parent, "log_region_framing", "attempt-log-consolidated-setup-frame", started, ended)
}

func derivedConsolidatedActionFrameEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, started, ended model.Instant) (evidence.Envelope, error) {
	return derivedLogRegionEnvelope(sessionID, request, scope, event, byteLength, sourceSHA, parent, "log_region_framing", "attempt-log-consolidated-action-step-frame", started, ended)
}

func derivedConsolidatedCompositePrefixFrameEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, started, ended model.Instant) (evidence.Envelope, error) {
	return derivedLogRegionEnvelope(sessionID, request, scope, event, byteLength, sourceSHA, parent, "log_region_framing", "attempt-log-consolidated-composite-prefix-frame", started, ended)
}

func derivedLogRegionEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, byteLength uint64, sourceSHA string, parent model.EvidenceID, derivationKind, ruleID string, started, ended model.Instant) (evidence.Envelope, error) {
	if err := parent.Validate(); err != nil {
		return evidence.Envelope{}, err
	}
	if len(sourceSHA) != 64 {
		return evidence.Envelope{}, errors.New("log-entry SHA-256 is invalid")
	}
	if ended.Before(started.Time) {
		ended = started
	}
	derivation := evidence.DerivationDescriptor{
		Kind: derivationKind, ParentEvidenceIDs: []model.EvidenceID{parent},
		RuleID: ruleID, RuleVersion: ExtractorVersion,
	}
	logicalSource, err := evidence.NewDerivedLogicalSource(scope, derivation, sourceSHA)
	if err != nil {
		return evidence.Envelope{}, err
	}
	retention := evidence.RetentionDescriptor{
		MediaType: "text/plain", ByteLength: byteLength, RawRetained: false, RetainedPayloadSHA256: nil,
		RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: defaultRedactionPolicy,
	}
	evidenceID, err := evidence.NewEvidenceID(logicalSource.ID, sourceSHA, retention)
	if err != nil {
		return evidence.Envelope{}, err
	}
	request = collectionRequestID(sessionID, request)
	observationID, err := evidence.NewCollectionObservationID(evidenceID, sessionID, request, ended, 1)
	if err != nil {
		return evidence.Envelope{}, err
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID, LogicalSource: logicalSource,
			Source: evidence.SourceDescriptor{Provider: evidence.ProviderCIRewind, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1},
			Scope:  scope, EventTime: event,
			Content:    evidence.ContentDescriptor{MediaType: "text/plain", ByteLength: byteLength, Complete: true, SourceSHA256: sourceSHA, RawRetained: false},
			Extractor:  evidence.ExtractorDescriptor{Name: "livecollect", Version: ExtractorVersion, RulesetSHA256: extractorRulesetSHA256},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: defaultRedactionPolicy},
			Derivation: derivation, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: sessionID, RequestID: request, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: started, EndedAt: ended}},
	}
	if err := envelope.Validate(); err != nil {
		return evidence.Envelope{}, fmt.Errorf("log-entry evidence: %w", err)
	}
	return envelope, nil
}

func compactDerivedEnvelope(sessionID model.CollectionSessionID, request model.RequestID, scope model.CoverageScope, event model.EventInterval, projection any, parents []model.EvidenceID, derivationKind, ruleID string, started, ended model.Instant) (archive.Payload, evidence.Envelope, error) {
	data, err := evidence.CanonicalJSON(projection)
	if err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	if len(data) > 16<<20 {
		return archive.Payload{}, evidence.Envelope{}, errors.New("derived structured evidence exceeds compact payload limit")
	}
	payloadHash := sha256Hex(data)
	payload := archive.Payload{SHA256: payloadHash, MediaType: "application/json", Bytes: data}
	if err := payload.Validate(); err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	parents = model.SortEvidenceIDs(parents)
	derivation := evidence.DerivationDescriptor{Kind: derivationKind, ParentEvidenceIDs: parents, RuleID: ruleID, RuleVersion: ExtractorVersion}
	logicalSource, err := evidence.NewDerivedLogicalSource(scope, derivation, payloadHash)
	if err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	retention := evidence.RetentionDescriptor{
		MediaType: "application/json", ByteLength: uint64(len(data)), RawRetained: false, RetainedPayloadSHA256: &payloadHash,
		RedactionStatus: evidence.RedactionStructuredAllowlist, RedactionPolicyVersion: structuredPolicyVersion,
	}
	evidenceID, err := evidence.NewEvidenceID(logicalSource.ID, payloadHash, retention)
	if err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	if ended.Before(started.Time) {
		ended = started
	}
	request = collectionRequestID(sessionID, request)
	observationID, err := evidence.NewCollectionObservationID(evidenceID, sessionID, request, ended, 1)
	if err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID, LogicalSource: logicalSource,
			Source: evidence.SourceDescriptor{Provider: evidence.ProviderCIRewind, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1},
			Scope:  scope, EventTime: event,
			Content:    evidence.ContentDescriptor{MediaType: "application/json", ByteLength: uint64(len(data)), Complete: true, SourceSHA256: payloadHash, RetainedPayloadSHA256: &payloadHash, RawRetained: false},
			Extractor:  evidence.ExtractorDescriptor{Name: "livecollect", Version: ExtractorVersion, RulesetSHA256: extractorRulesetSHA256},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionStructuredAllowlist, PolicyVersion: structuredPolicyVersion},
			Derivation: derivation, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: sessionID, RequestID: request, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: started, EndedAt: ended}},
	}
	if err := envelope.Validate(); err != nil {
		return archive.Payload{}, evidence.Envelope{}, err
	}
	return payload, envelope, nil
}

func makeEnvelope(sessionID model.CollectionSessionID, request model.RequestID, canonicalSource string, kind evidence.SourceKind, provider evidence.Provider, apiVersion, endpoint string, parameters evidence.RequestParameters, scope model.CoverageScope, event model.EventInterval, mediaType string, byteLength uint64, sourceSHA string, retainedSHA *string, rawRetained bool, retainedPath string, complete bool, redaction evidence.RedactionStatus, policy string, evidenceErrors []evidence.EvidenceError, started, ended model.Instant) (evidence.Envelope, error) {
	if ended.Before(started.Time) {
		ended = started
	}
	logicalIdentity := evidence.LogicalSourceIdentity{Kind: kind, CanonicalID: canonicalSource, Scope: scope, RequestParameters: parameters}
	logicalID, err := evidence.NewLogicalSourceID(logicalIdentity)
	if err != nil {
		return evidence.Envelope{}, err
	}
	retention := evidence.RetentionDescriptor{MediaType: mediaType, ByteLength: byteLength, RawRetained: rawRetained, RetainedPayloadSHA256: retainedSHA, RedactionStatus: redaction, RedactionPolicyVersion: policy}
	evidenceID, err := evidence.NewEvidenceID(logicalID, sourceSHA, retention)
	if err != nil {
		return evidence.Envelope{}, err
	}
	request = collectionRequestID(sessionID, request)
	observationID, err := evidence.NewCollectionObservationID(evidenceID, sessionID, request, ended, 1)
	if err != nil {
		return evidence.Envelope{}, err
	}
	if evidenceErrors == nil {
		evidenceErrors = []evidence.EvidenceError{}
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
			LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: kind, CanonicalID: canonicalSource, RequestParameters: parameters},
			Source:        evidence.SourceDescriptor{Provider: provider, APIVersion: apiVersion, EndpointTemplate: endpoint, RequestParameters: parameters, RequestAttempt: 1},
			Scope:         scope, EventTime: event,
			Content:    evidence.ContentDescriptor{MediaType: mediaType, ByteLength: byteLength, Complete: complete, SourceSHA256: sourceSHA, RetainedPayloadSHA256: retainedSHA, RawRetained: rawRetained, RetainedPath: retainedPath},
			Extractor:  evidence.ExtractorDescriptor{Name: "livecollect", Version: ExtractorVersion, RulesetSHA256: extractorRulesetSHA256},
			Redaction:  evidence.RedactionDescriptor{Status: redaction, PolicyVersion: policy},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: evidenceErrors,
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: sessionID, RequestID: request, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: started, EndedAt: ended}},
	}
	if err := envelope.Validate(); err != nil {
		return evidence.Envelope{}, err
	}
	return envelope, nil
}

func requestID(parts ...string) model.RequestID {
	return model.RequestID("request:" + sha256Hex([]byte(strings.Join(parts, "\x00"))))
}

// scopedRequestID distinguishes repeated logical reads performed for separate
// forensic subjects in one collection session. Evidence content may dedupe by
// hash, but the actual API request and its collection window remain distinct.
func scopedRequestID(kind string, scope model.CoverageScope, parts ...string) model.RequestID {
	scopeParts := []string{kind, "repository", "-", "run", "-", "attempt", "-", "job", "-"}
	if scope.RepositoryID != nil {
		scopeParts[2] = fmt.Sprint(*scope.RepositoryID)
	}
	if scope.RunID != nil {
		scopeParts[4] = fmt.Sprint(*scope.RunID)
	}
	if scope.RunAttempt != nil {
		scopeParts[6] = fmt.Sprint(*scope.RunAttempt)
	}
	if scope.JobID != nil {
		scopeParts[8] = fmt.Sprint(*scope.JobID)
	}
	return requestID(append(scopeParts, parts...)...)
}

func collectionRequestID(sessionID model.CollectionSessionID, base model.RequestID) model.RequestID {
	return requestID("collection-request/v1", string(sessionID), string(base))
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func safeKey(value string) string { return sha256Hex([]byte(value)) }

func safeField(value string, limit int) string {
	value = sanitize.Terminal(value, limit)
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization:", "bearer ", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "ghc_", "github_pat_", "x-amz-signature", "private key-----"} {
		if strings.Contains(lower, marker) {
			return "[redacted]"
		}
	}
	return value
}

func safeMachine(value string, limit int) string {
	value = safeField(value, limit)
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:/-", char) {
			continue
		}
		return "unknown"
	}
	return value
}

func safeHex(value string, limit int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > limit {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}

func safeStrings(values []string, count, size int) []string {
	if len(values) > count {
		values = values[:count]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = safeField(value, size)
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write > 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func unknownTime() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}
