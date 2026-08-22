package livecollect

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	artifactProjectionLimit    = 10_000
	environmentProjectionLimit = 1_024

	scopeRunArtifacts       = "run_artifacts"
	scopePendingDeployments = "pending_deployments"
	scopeEnvironmentReviews = "environment_approvals"
)

// Optional enrichment interfaces deliberately remain outside API. A minimal
// collector fake does not have to implement unrelated capabilities, while the
// read-only githubapi.Client satisfies each interface without an adapter.
type runArtifactAPI interface {
	ListWorkflowRunArtifacts(context.Context, string, string, int64) (githubapi.ArtifactList, error)
}

type pendingDeploymentAPI interface {
	ListPendingDeployments(context.Context, string, string, int64) (githubapi.PendingDeploymentList, error)
}

type environmentApprovalAPI interface {
	ListEnvironmentApprovals(context.Context, string, string, int64) (githubapi.EnvironmentApprovalList, error)
}

var (
	_ runArtifactAPI         = (*githubapi.Client)(nil)
	_ pendingDeploymentAPI   = (*githubapi.Client)(nil)
	_ environmentApprovalAPI = (*githubapi.Client)(nil)
)

type enrichmentRun struct {
	runID model.WorkflowRunID
}

// collectRepositoryEnrichments runs only after the required attempt collection
// has completed. Optional failures become scoped coverage gaps and never
// invalidate an otherwise safe polling checkpoint.
func (c Collector) collectRepositoryEnrichments(ctx context.Context, target repositoryWork, sessionID model.CollectionSessionID, now Clock, result *repositoryResult) error {
	runs := enrichmentRuns(result.facts)
	for _, run := range runs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if api, ok := c.API.(runArtifactAPI); ok {
			if err := collectRunArtifacts(ctx, api, target, run.runID, sessionID, now, result); err != nil {
				return err
			}
		}
		if api, ok := c.API.(pendingDeploymentAPI); ok {
			if err := collectPendingDeployments(ctx, api, target, run.runID, sessionID, now, result); err != nil {
				return err
			}
		}
		if api, ok := c.API.(environmentApprovalAPI); ok {
			if err := collectEnvironmentApprovals(ctx, api, target, run.runID, sessionID, now, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func enrichmentRuns(facts []archive.Fact) []enrichmentRun {
	seen := make(map[model.WorkflowRunID]struct{})
	for _, fact := range facts {
		if fact.Kind != archive.FactRun || fact.Run == nil || fact.Run.RunID <= 0 {
			continue
		}
		seen[fact.Run.RunID] = struct{}{}
	}
	runs := make([]enrichmentRun, 0, len(seen))
	for runID := range seen {
		runs = append(runs, enrichmentRun{runID: runID})
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].runID < runs[j].runID })
	return runs
}

type artifactProjectionDocument struct {
	Schema                string               `json:"schema"`
	RepositoryID          int64                `json:"repository_id"`
	RunID                 int64                `json:"run_id"`
	Association           string               `json:"association"`
	AttributionLimitation string               `json:"attribution_limitation"`
	Causation             string               `json:"causation"`
	ReportedTotal         int                  `json:"reported_total"`
	Artifacts             []artifactProjection `json:"artifacts"`
	Responses             []responseProjection `json:"responses"`
}

type artifactProjection struct {
	ID        int64  `json:"id"`
	Name      string `json:"name,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
	Expired   bool   `json:"expired"`
	Digest    string `json:"digest,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func collectRunArtifacts(ctx context.Context, api runArtifactAPI, target repositoryWork, runID model.WorkflowRunID, sessionID model.CollectionSessionID, now Clock, result *repositoryResult) error {
	started := model.MustInstant(now().UTC())
	listed, listErr := api.ListWorkflowRunArtifacts(ctx, target.owner, target.name, int64(runID))
	ended := model.MustInstant(now().UTC())
	projected, truncated := projectArtifacts(listed.Artifacts)
	document := artifactProjectionDocument{
		Schema: "cirewind.github-run-artifacts-projection/v1", RepositoryID: target.repository.ID, RunID: int64(runID),
		Association:           "DIRECT_RUN_ATTRIBUTION",
		AttributionLimitation: "attempt, job, and step attribution not established",
		Causation:             "malicious intent and causation not established",
		ReportedTotal:         listed.TotalCount, Artifacts: projected, Responses: projectResponses(listed.Responses),
	}
	repositoryID := model.RepositoryID(target.repository.ID)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID}
	payload, envelope, err := compactEnvelope(
		sessionID,
		requestID("run-artifacts", fmt.Sprint(target.repository.ID), fmt.Sprint(runID)),
		fmt.Sprintf("normalized:github:workflow-run-artifacts:%d:%d", target.repository.ID, runID),
		evidence.SourceAPIJSON,
		githubapi.APIVersion,
		"/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
		evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(runID), "per_page": "100"},
		scope,
		document,
		started,
		ended,
	)
	if err != nil {
		return fmt.Errorf("construct run-artifact evidence: %w", err)
	}
	result.payloads = append(result.payloads, payload)
	result.evidence = append(result.evidence, envelope)
	if listErr != nil || listed.Partial {
		if err := appendOptionalEnrichmentGap(result, scopeRunArtifacts, target.repository.ID, int64(runID), listErr, "workflow-run artifact enumeration was incomplete"); err != nil {
			return err
		}
	} else if truncated {
		if err := appendGap(result, collect.Gap{Reason: collect.GapSizeLimit, Scope: scopeRunArtifacts, RepositoryID: target.repository.ID, RunID: int64(runID), Material: false, Diagnostic: "workflow-run artifact projection exceeded its item limit; retained evidence is incomplete"}); err != nil {
			return err
		}
	} else if err := appendCollectedCoverage(result, model.CoverageEnrichment, scope, coverageLogicalKey(scopeRunArtifacts, target.repository.ID, int64(runID), 0, 0), uint64(len(projected)), []model.EvidenceID{envelope.Evidence.ID}, false); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func projectArtifacts(values []githubapi.Artifact) ([]artifactProjection, bool) {
	truncated := len(values) > artifactProjectionLimit
	if truncated {
		values = values[:artifactProjectionLimit]
	}
	result := make([]artifactProjection, 0, len(values))
	for _, value := range values {
		result = append(result, artifactProjection{
			ID: value.ID, Name: safeField(value.Name, 1024), SizeBytes: value.SizeInBytes, Expired: value.Expired,
			Digest: safeField(value.Digest, 256), CreatedAt: optionalTime(value.CreatedAt), UpdatedAt: optionalTime(value.UpdatedAt), ExpiresAt: optionalTime(value.ExpiresAt),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result, truncated
}

type pendingDeploymentProjectionDocument struct {
	Schema                string                        `json:"schema"`
	RepositoryID          int64                         `json:"repository_id"`
	RunID                 int64                         `json:"run_id"`
	Scope                 string                        `json:"scope"`
	EligibilityLimitation string                        `json:"eligibility_limitation"`
	Pending               []pendingDeploymentProjection `json:"pending"`
	Responses             []responseProjection          `json:"responses"`
}

type pendingDeploymentProjection struct {
	EnvironmentID      int64  `json:"environment_id"`
	EnvironmentName    string `json:"environment_name"`
	WaitTimerMinutes   int    `json:"wait_timer_minutes"`
	WaitTimerStartedAt string `json:"wait_timer_started_at,omitempty"`
}

func collectPendingDeployments(ctx context.Context, api pendingDeploymentAPI, target repositoryWork, runID model.WorkflowRunID, sessionID model.CollectionSessionID, now Clock, result *repositoryResult) error {
	started := model.MustInstant(now().UTC())
	listed, listErr := api.ListPendingDeployments(ctx, target.owner, target.name, int64(runID))
	ended := model.MustInstant(now().UTC())
	projected, truncated := projectPendingDeployments(listed.PendingDeployments)
	document := pendingDeploymentProjectionDocument{
		Schema: "cirewind.github-run-pending-deployments-projection/v1", RepositoryID: target.repository.ID, RunID: int64(runID),
		Scope:                 "workflow run only",
		EligibilityLimitation: "no exact job-environment join; environment-secret eligibility not derived",
		Pending:               projected, Responses: projectResponses(listed.Responses),
	}
	repositoryID := model.RepositoryID(target.repository.ID)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID}
	payload, envelope, err := compactEnvelope(
		sessionID,
		requestID("pending-deployments", fmt.Sprint(target.repository.ID), fmt.Sprint(runID)),
		fmt.Sprintf("normalized:github:workflow-run-pending-deployments:%d:%d", target.repository.ID, runID),
		evidence.SourceAPIJSON,
		githubapi.APIVersion,
		"/repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments",
		evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(runID)},
		scope,
		document,
		started,
		ended,
	)
	if err != nil {
		return fmt.Errorf("construct pending-deployment evidence: %w", err)
	}
	result.payloads = append(result.payloads, payload)
	result.evidence = append(result.evidence, envelope)
	if listErr != nil || listed.Partial {
		if err := appendOptionalEnrichmentGap(result, scopePendingDeployments, target.repository.ID, int64(runID), listErr, "pending-deployment enumeration was incomplete"); err != nil {
			return err
		}
	} else if truncated {
		if err := appendGap(result, collect.Gap{Reason: collect.GapSizeLimit, Scope: scopePendingDeployments, RepositoryID: target.repository.ID, RunID: int64(runID), Material: false, Diagnostic: "pending-deployment projection exceeded its item limit; retained evidence is incomplete"}); err != nil {
			return err
		}
	} else if err := appendCollectedCoverage(result, model.CoverageEnrichment, scope, coverageLogicalKey(scopePendingDeployments, target.repository.ID, int64(runID), 0, 0), uint64(len(projected)), []model.EvidenceID{envelope.Evidence.ID}, false); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func projectPendingDeployments(values []githubapi.PendingDeployment) ([]pendingDeploymentProjection, bool) {
	truncated := len(values) > environmentProjectionLimit
	if truncated {
		values = values[:environmentProjectionLimit]
	}
	result := make([]pendingDeploymentProjection, 0, len(values))
	for _, value := range values {
		result = append(result, pendingDeploymentProjection{
			EnvironmentID: value.Environment.ID, EnvironmentName: safeField(value.Environment.Name, 1024),
			WaitTimerMinutes: value.WaitTimer, WaitTimerStartedAt: optionalTime(value.WaitTimerStartedAt),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].EnvironmentID != result[j].EnvironmentID {
			return result[i].EnvironmentID < result[j].EnvironmentID
		}
		return result[i].EnvironmentName < result[j].EnvironmentName
	})
	return result, truncated
}

type environmentApprovalProjectionDocument struct {
	Schema                string                          `json:"schema"`
	RepositoryID          int64                           `json:"repository_id"`
	RunID                 int64                           `json:"run_id"`
	Scope                 string                          `json:"scope"`
	EligibilityLimitation string                          `json:"eligibility_limitation"`
	Approvals             []environmentApprovalProjection `json:"approvals"`
	Responses             []responseProjection            `json:"responses"`
}

type environmentApprovalProjection struct {
	State        string                          `json:"state"`
	CreatedAt    string                          `json:"created_at,omitempty"`
	Environments []environmentIdentityProjection `json:"environments"`
}

type environmentIdentityProjection struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func collectEnvironmentApprovals(ctx context.Context, api environmentApprovalAPI, target repositoryWork, runID model.WorkflowRunID, sessionID model.CollectionSessionID, now Clock, result *repositoryResult) error {
	started := model.MustInstant(now().UTC())
	listed, listErr := api.ListEnvironmentApprovals(ctx, target.owner, target.name, int64(runID))
	ended := model.MustInstant(now().UTC())
	projected, truncated := projectEnvironmentApprovals(listed.Approvals)
	document := environmentApprovalProjectionDocument{
		Schema: "cirewind.github-run-environment-approvals-projection/v1", RepositoryID: target.repository.ID, RunID: int64(runID),
		Scope:                 "workflow run only",
		EligibilityLimitation: "approval plus job start is insufficient without an exact job-environment join; environment-secret eligibility not derived",
		Approvals:             projected, Responses: projectResponses(listed.Responses),
	}
	repositoryID := model.RepositoryID(target.repository.ID)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID}
	payload, envelope, err := compactEnvelope(
		sessionID,
		requestID("environment-approvals", fmt.Sprint(target.repository.ID), fmt.Sprint(runID)),
		fmt.Sprintf("normalized:github:workflow-run-environment-approvals:%d:%d", target.repository.ID, runID),
		evidence.SourceAPIJSON,
		githubapi.APIVersion,
		"/repos/{owner}/{repo}/actions/runs/{run_id}/approvals",
		evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(runID)},
		scope,
		document,
		started,
		ended,
	)
	if err != nil {
		return fmt.Errorf("construct environment-approval evidence: %w", err)
	}
	result.payloads = append(result.payloads, payload)
	result.evidence = append(result.evidence, envelope)
	if listErr != nil || listed.Partial {
		if err := appendOptionalEnrichmentGap(result, scopeEnvironmentReviews, target.repository.ID, int64(runID), listErr, "environment-approval enumeration was incomplete"); err != nil {
			return err
		}
	} else if truncated {
		if err := appendGap(result, collect.Gap{Reason: collect.GapSizeLimit, Scope: scopeEnvironmentReviews, RepositoryID: target.repository.ID, RunID: int64(runID), Material: false, Diagnostic: "environment-approval projection exceeded its item limit; retained evidence is incomplete"}); err != nil {
			return err
		}
	} else if err := appendCollectedCoverage(result, model.CoverageEnrichment, scope, coverageLogicalKey(scopeEnvironmentReviews, target.repository.ID, int64(runID), 0, 0), uint64(len(projected)), []model.EvidenceID{envelope.Evidence.ID}, false); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func projectEnvironmentApprovals(values []githubapi.EnvironmentApproval) ([]environmentApprovalProjection, bool) {
	truncated := len(values) > environmentProjectionLimit
	if truncated {
		values = values[:environmentProjectionLimit]
	}
	result := make([]environmentApprovalProjection, 0, len(values))
	for _, value := range values {
		environments := make([]environmentIdentityProjection, 0, min(len(value.Environments), environmentProjectionLimit))
		for _, environment := range value.Environments {
			if len(environments) == environmentProjectionLimit {
				truncated = true
				break
			}
			environments = append(environments, environmentIdentityProjection{ID: environment.ID, Name: safeField(environment.Name, 1024)})
		}
		sort.Slice(environments, func(i, j int) bool {
			if environments[i].ID != environments[j].ID {
				return environments[i].ID < environments[j].ID
			}
			return environments[i].Name < environments[j].Name
		})
		result = append(result, environmentApprovalProjection{State: safeMachine(value.State, 128), CreatedAt: optionalTime(value.CreatedAt), Environments: environments})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt != result[j].CreatedAt {
			return result[i].CreatedAt < result[j].CreatedAt
		}
		if result[i].State != result[j].State {
			return result[i].State < result[j].State
		}
		return fmt.Sprint(result[i].Environments) < fmt.Sprint(result[j].Environments)
	})
	return result, truncated
}

func appendOptionalEnrichmentGap(result *repositoryResult, scope string, repositoryID, runID int64, sourceErr error, fallback string) error {
	var gap collect.Gap
	if sourceErr != nil {
		gap = collect.GapFromError(scope, repositoryID, runID, 0, sourceErr)
	} else {
		gap = collect.Gap{Reason: collect.GapPagination, Scope: scope, RepositoryID: repositoryID, RunID: runID, Diagnostic: fallback}
	}
	gap.Material = false
	if gap.Diagnostic == "" {
		gap.Diagnostic = fallback
	}
	return appendGap(result, gap)
}

func optionalTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func enrichmentCapabilities(api API, envelopes []evidence.Envelope, gaps []collect.Gap) []archive.Capability {
	_, artifactsSupported := api.(runArtifactAPI)
	_, pendingSupported := api.(pendingDeploymentAPI)
	_, approvalsSupported := api.(environmentApprovalAPI)
	artifactEvidence := countLogicalSources(envelopes, "normalized:github:workflow-run-artifacts:")
	pendingEvidence := countLogicalSources(envelopes, "normalized:github:workflow-run-pending-deployments:")
	approvalEvidence := countLogicalSources(envelopes, "normalized:github:workflow-run-environment-approvals:")

	artifactStatus := optionalCapabilityStatus(artifactsSupported, gaps, scopeRunArtifacts)
	environmentStatus := archive.CapabilityNotCollected
	if pendingSupported || approvalsSupported {
		environmentStatus = archive.CapabilityStructuredOnly
	}
	if pendingSupported != approvalsSupported || hasGapScope(gaps, scopePendingDeployments, scopeEnvironmentReviews) {
		environmentStatus = archive.CapabilityGap
	}

	return []archive.Capability{
		{Name: "deployments", Status: archive.CapabilityNotCollected, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"collected_count": "0", "reason": "no_proven_join", "scope": "repository",
		}},
		{Name: "environment_gate_metadata", Status: environmentStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"collected_count": fmt.Sprint(pendingEvidence + approvalEvidence), "fact_count": "0", "reason": "no_exact_job_join", "scope": "run",
		}},
		{Name: "releases", Status: archive.CapabilityNotCollected, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"collected_count": "0", "reason": "no_proven_join", "scope": "repository",
		}},
		{Name: "run_artifacts", Status: artifactStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"collected_count": fmt.Sprint(artifactEvidence), "reason": "no_attempt_job_step_join", "scope": "run",
		}},
		{Name: "secret_metadata", Status: archive.CapabilityNotCollected, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"collected_count": "0", "fact_count": "0", "reason": "no_proven_join", "scope": "repository",
		}},
	}
}

func optionalCapabilityStatus(supported bool, gaps []collect.Gap, scopes ...string) archive.CapabilityStatus {
	if !supported {
		return archive.CapabilityNotCollected
	}
	if hasGapScope(gaps, scopes...) {
		return archive.CapabilityGap
	}
	return archive.CapabilityStructuredOnly
}

func hasGapScope(gaps []collect.Gap, scopes ...string) bool {
	allowed := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		allowed[scope] = struct{}{}
	}
	for _, gap := range gaps {
		if _, ok := allowed[gap.Scope]; ok {
			return true
		}
	}
	return false
}

func countLogicalSources(envelopes []evidence.Envelope, prefix string) int {
	count := 0
	for _, envelope := range envelopes {
		if len(envelope.Evidence.LogicalSource.CanonicalID) >= len(prefix) && envelope.Evidence.LogicalSource.CanonicalID[:len(prefix)] == prefix {
			count++
		}
	}
	return count
}
