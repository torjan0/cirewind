package livecollect

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
)

type enrichmentFakeAPI struct {
	*fakeAPI

	mu             sync.Mutex
	artifacts      githubapi.ArtifactList
	artifactErr    error
	pending        githubapi.PendingDeploymentList
	pendingErr     error
	approvals      githubapi.EnvironmentApprovalList
	approvalErr    error
	optionalCalls  []string
	repositoryKeys githubapi.SecretMetadataList
}

func (f *enrichmentFakeAPI) ListWorkflowRunArtifacts(context.Context, string, string, int64) (githubapi.ArtifactList, error) {
	f.recordOptional("artifacts")
	return f.artifacts, f.artifactErr
}

func (f *enrichmentFakeAPI) ListPendingDeployments(context.Context, string, string, int64) (githubapi.PendingDeploymentList, error) {
	f.recordOptional("pending")
	return f.pending, f.pendingErr
}

func (f *enrichmentFakeAPI) ListEnvironmentApprovals(context.Context, string, string, int64) (githubapi.EnvironmentApprovalList, error) {
	f.recordOptional("approvals")
	return f.approvals, f.approvalErr
}

// These methods intentionally make the fake capable of returning broader
// metadata. The live adapter must not call them without a proven identity join.
func (f *enrichmentFakeAPI) ListRepositorySecrets(context.Context, string, string) (githubapi.SecretMetadataList, error) {
	f.recordOptional("repository-secrets")
	return f.repositoryKeys, nil
}

func (f *enrichmentFakeAPI) ListDeployments(context.Context, string, string) (githubapi.DeploymentList, error) {
	f.recordOptional("deployments")
	return githubapi.DeploymentList{}, nil
}

func (f *enrichmentFakeAPI) ListReleases(context.Context, string, string) (githubapi.ReleaseList, error) {
	f.recordOptional("releases")
	return githubapi.ReleaseList{}, nil
}

func (f *enrichmentFakeAPI) recordOptional(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.optionalCalls = append(f.optionalCalls, name)
}

func (f *enrichmentFakeAPI) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.optionalCalls...)
}

func TestLiveEnrichmentRetainsRunScopedContextWithoutInventingExposure(t *testing.T) {
	created := time.Date(2026, 8, 20, 1, 25, 0, 0, time.UTC)
	approved := created.Add(time.Minute)
	api := &enrichmentFakeAPI{
		fakeAPI: successfulAPI(t, false),
		artifacts: githubapi.ArtifactList{TotalCount: 2, Artifacts: []githubapi.Artifact{
			{ID: 2, Name: "second", CreatedAt: &created},
			{ID: 1, Name: "<script>first</script>", Digest: "sha256:aaaaaaaa", CreatedAt: &created},
		}},
		pending: githubapi.PendingDeploymentList{PendingDeployments: []githubapi.PendingDeployment{{
			Environment: githubapi.Environment{ID: 30, Name: "prod"}, WaitTimer: 15, WaitTimerStartedAt: &created,
		}}},
		approvals: githubapi.EnvironmentApprovalList{Approvals: []githubapi.EnvironmentApproval{{
			Environments: []githubapi.Environment{{ID: 30, Name: "prod"}}, State: "approved", CreatedAt: &approved,
			Comment: "COMMENT_MUST_NOT_BE_RETAINED", User: githubapi.Actor{Login: "REVIEWER_MUST_NOT_BE_RETAINED"},
		}}},
		repositoryKeys: githubapi.SecretMetadataList{Secrets: []githubapi.SecretMetadata{{Name: "DEPLOY_KEY_MUST_NOT_BE_RETAINED"}}},
	}

	result := collectWithEnrichment(t, api)
	if got := strings.Join(api.calls(), ","); got != "artifacts,pending,approvals" {
		t.Fatalf("optional calls = %q; broad metadata was called without a proven join", got)
	}

	capabilities := capabilityMap(t, result.Batch.Capabilities)
	if capabilities["run_artifacts"].Status != archive.CapabilityStructuredOnly || capabilities["environment_gate_metadata"].Status != archive.CapabilityStructuredOnly {
		t.Fatalf("structured enrichment capabilities = artifacts:%s environment:%s", capabilities["run_artifacts"].Status, capabilities["environment_gate_metadata"].Status)
	}
	for _, name := range []string{"secret_metadata", "deployments", "releases"} {
		if capability := capabilities[name]; capability.Status != archive.CapabilityNotCollected || capability.Details["reason"] != "no_proven_join" {
			t.Fatalf("%s capability overclaimed collection: %#v", name, capability)
		}
	}

	var artifactEnvelope, pendingEnvelope, approvalEnvelope bool
	for _, envelope := range result.Batch.Evidence {
		canonical := envelope.Evidence.LogicalSource.CanonicalID
		switch {
		case strings.HasPrefix(canonical, "normalized:github:workflow-run-artifacts:"):
			artifactEnvelope = assertRunOnlyScope(t, envelope.Evidence.Scope)
		case strings.HasPrefix(canonical, "normalized:github:workflow-run-pending-deployments:"):
			pendingEnvelope = assertRunOnlyScope(t, envelope.Evidence.Scope)
		case strings.HasPrefix(canonical, "normalized:github:workflow-run-environment-approvals:"):
			approvalEnvelope = assertRunOnlyScope(t, envelope.Evidence.Scope)
		}
	}
	if !artifactEnvelope || !pendingEnvelope || !approvalEnvelope {
		t.Fatalf("run-scoped evidence missing: artifacts=%v pending=%v approvals=%v", artifactEnvelope, pendingEnvelope, approvalEnvelope)
	}

	var joined []byte
	for _, payload := range result.Batch.Payloads {
		joined = append(joined, payload.Bytes...)
	}
	for _, prohibited := range [][]byte{[]byte("COMMENT_MUST_NOT_BE_RETAINED"), []byte("REVIEWER_MUST_NOT_BE_RETAINED"), []byte("DEPLOY_KEY_MUST_NOT_BE_RETAINED")} {
		if bytes.Contains(joined, prohibited) {
			t.Fatalf("unneeded metadata retained: %q", prohibited)
		}
	}
	if !bytes.Contains(joined, []byte(`"association":"DIRECT_RUN_ATTRIBUTION"`)) ||
		!bytes.Contains(joined, []byte("malicious intent and causation not established")) ||
		!bytes.Contains(joined, []byte("environment-secret eligibility not derived")) {
		t.Fatalf("neutral attribution/eligibility limits absent from compact evidence")
	}
	if first, second := bytes.Index(joined, []byte(`"id":1`)), bytes.Index(joined, []byte(`"id":2`)); first < 0 || second < 0 || first > second {
		t.Fatal("artifact projection ordering was not deterministic")
	}

	assertNoEnrichmentExposureFacts(t, result.Batch.Facts)
}

func TestDeniedOptionalEnrichmentPersistsGapAndPreservesCheckpoint(t *testing.T) {
	const hostile = "github_pat_ENRICHMENT_SENTINEL"
	response := githubapi.ResponseMeta{RouteTemplate: "/repos/{owner}/{repo}/optional", StatusCode: 403, ErrorClass: githubapi.ErrorForbidden, BodyComplete: true}
	permissionErr := &githubapi.Error{Class: githubapi.ErrorForbidden, Operation: "optional enrichment", StatusCode: 403, Message: hostile, Responses: []githubapi.ResponseMeta{response}}
	api := &enrichmentFakeAPI{
		fakeAPI:     successfulAPI(t, false),
		artifacts:   githubapi.ArtifactList{CapabilityListMetadata: githubapi.CapabilityListMetadata{Responses: []githubapi.ResponseMeta{response}, Partial: true}},
		artifactErr: permissionErr,
		pending:     githubapi.PendingDeploymentList{CapabilityListMetadata: githubapi.CapabilityListMetadata{Responses: []githubapi.ResponseMeta{response}, Partial: true}},
		pendingErr:  permissionErr,
		approvals:   githubapi.EnvironmentApprovalList{CapabilityListMetadata: githubapi.CapabilityListMetadata{Responses: []githubapi.ResponseMeta{response}, Partial: true}},
		approvalErr: permissionErr,
	}

	result := collectWithEnrichment(t, api)
	if len(result.Batch.Checkpoints) != 1 {
		t.Fatalf("optional denial erased a successful core checkpoint: %#v", result.Batch.Checkpoints)
	}
	seen := map[string]bool{}
	for _, gap := range result.Gaps {
		if gap.Scope == scopeRunArtifacts || gap.Scope == scopePendingDeployments || gap.Scope == scopeEnvironmentReviews {
			seen[gap.Scope] = true
			if gap.Reason != collect.GapForbidden || gap.Material {
				t.Fatalf("optional gap = %#v, want non-material forbidden", gap)
			}
			if strings.Contains(gap.Diagnostic, hostile) {
				t.Fatal("hostile API diagnostic survived sanitization")
			}
		}
	}
	for _, scope := range []string{scopeRunArtifacts, scopePendingDeployments, scopeEnvironmentReviews} {
		if !seen[scope] {
			t.Errorf("missing persisted optional gap %q", scope)
		}
	}
	capabilities := capabilityMap(t, result.Batch.Capabilities)
	if capabilities["run_artifacts"].Status != archive.CapabilityGap || capabilities["environment_gate_metadata"].Status != archive.CapabilityGap {
		t.Fatalf("denied capabilities were not gaps: %#v %#v", capabilities["run_artifacts"], capabilities["environment_gate_metadata"])
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(hostile)) {
		t.Fatal("hostile permission error leaked into collection output")
	}
}

func TestRunEnvironmentMetadataNeverBecomesJobEligibilityWithoutExactJoin(t *testing.T) {
	for _, test := range []struct {
		name     string
		started  bool
		pending  bool
		approved bool
	}{
		{name: "job not started and approval pending", pending: true},
		{name: "job started and run approval observed", started: true, approved: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &enrichmentFakeAPI{fakeAPI: successfulAPI(t, false)}
			job := api.jobs[10][1][0]
			if !test.started {
				job.StartedAt, job.CompletedAt = nil, nil
				api.jobs[10][1][0] = job
			}
			if test.pending {
				api.pending.PendingDeployments = []githubapi.PendingDeployment{{Environment: githubapi.Environment{ID: 30, Name: "prod"}}}
			}
			if test.approved {
				api.approvals.Approvals = []githubapi.EnvironmentApproval{{Environments: []githubapi.Environment{{ID: 30, Name: "prod"}}, State: "approved"}}
			}
			result := collectWithEnrichment(t, api)
			assertNoEnrichmentExposureFacts(t, result.Batch.Facts)
			capability := capabilityMap(t, result.Batch.Capabilities)["environment_gate_metadata"]
			if capability.Details["fact_count"] != "0" || capability.Details["reason"] != "no_exact_job_join" {
				t.Fatalf("environment capability invented eligibility: %#v", capability)
			}
		})
	}
}

func TestRunnerFactRequiresAuthoritativeHostedEvidence(t *testing.T) {
	tests := []struct {
		name           string
		job            githubapi.WorkflowJob
		classification string
	}{
		{name: "self hosted", job: githubapi.WorkflowJob{RunnerID: 42, RunnerName: "local", RunnerGroupName: "restricted", Labels: []string{"linux", "self-hosted"}}, classification: "self-hosted"},
		{name: "github hosted explicit", job: githubapi.WorkflowJob{Labels: []string{"ubuntu-24.04", "github-hosted"}}, classification: "github-hosted"},
		{name: "github hosted API tuple", job: githubapi.WorkflowJob{RunnerID: 1000001120, RunnerName: "GitHub Actions 1000001120", RunnerGroupID: 0, RunnerGroupName: "GitHub Actions", Labels: []string{"ubuntu-24.04"}}, classification: "github-hosted"},
		{name: "ambiguous hosted label", job: githubapi.WorkflowJob{Labels: []string{"ubuntu-24.04"}}, classification: "unknown"},
		{name: "spoofable names without sentinel group ID", job: githubapi.WorkflowJob{RunnerID: 42, RunnerName: "GitHub Actions 42", RunnerGroupID: 17, RunnerGroupName: "GitHub Actions", Labels: []string{"ubuntu-24.04"}}, classification: "unknown"},
		{name: "sentinel group without exact runner name", job: githubapi.WorkflowJob{RunnerID: 42, RunnerName: "custom", RunnerGroupID: 0, RunnerGroupName: "GitHub Actions", Labels: []string{"ubuntu-24.04"}}, classification: "unknown"},
		{name: "self hosted label overrides hosted-looking tuple", job: githubapi.WorkflowJob{RunnerID: 42, RunnerName: "GitHub Actions 42", RunnerGroupID: 0, RunnerGroupName: "GitHub Actions", Labels: []string{"self-hosted"}}, classification: "self-hosted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact := runnerFact(test.job)
			if fact.Classification != test.classification {
				t.Fatalf("classification = %q, want %q", fact.Classification, test.classification)
			}
			if test.job.RunnerID > 0 && (fact.RunnerID == nil || *fact.RunnerID != test.job.RunnerID || fact.RunnerGroup != test.job.RunnerGroupName) {
				t.Fatalf("runner identity/group lost: %#v", fact)
			}
			if _, err := archive.NormalizeFact(archive.Fact{
				Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{testEvidenceID('a')},
				Exposure: &archive.ExposureFact{Execution: model.JobExecutionIdentity{RepositoryID: 1, RunID: 1, RunAttempt: 1, JobID: 1}, Runner: fact, EventTime: unknownTime()},
			}); err != nil {
				t.Fatalf("runner fact validation: %v", err)
			}
		})
	}
}

func TestEnrichmentCapabilitiesAlwaysSatisfyArchiveContract(t *testing.T) {
	api := &enrichmentFakeAPI{fakeAPI: &fakeAPI{}}
	for _, capability := range enrichmentCapabilities(api, nil, nil) {
		if err := capability.Validate(); err != nil {
			t.Fatalf("capability %q: %v", capability.Name, err)
		}
	}
}

func collectWithEnrichment(t *testing.T, api API) Result {
	t.Helper()
	interval, err := collect.NewInterval(time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	result, err := (Collector{API: api, Now: fixedClock(time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC)), TempDir: t.TempDir()}).Collect(context.Background(), Request{
		Organization: "acme", Interval: interval, Purpose: PurposeArchive, Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func capabilityMap(t *testing.T, values []archive.Capability) map[string]archive.Capability {
	t.Helper()
	result := make(map[string]archive.Capability, len(values))
	for _, capability := range values {
		if err := capability.Validate(); err != nil {
			t.Fatalf("capability %q: %v", capability.Name, err)
		}
		result[capability.Name] = capability
	}
	return result
}

func assertRunOnlyScope(t *testing.T, scope model.CoverageScope) bool {
	t.Helper()
	if scope.RepositoryID == nil || scope.RunID == nil || scope.RunAttempt != nil || scope.JobID != nil || scope.StepKey != "" {
		t.Fatalf("enrichment scope invented attempt/job/step attribution: %#v", scope)
	}
	return true
}

func assertNoEnrichmentExposureFacts(t *testing.T, facts []archive.Fact) {
	t.Helper()
	for _, fact := range facts {
		if fact.Kind != archive.FactExposure || fact.Exposure == nil {
			continue
		}
		if fact.Exposure.Resource != nil || fact.Exposure.Environment != nil {
			t.Fatalf("run-scoped enrichment was forced into a job exposure: %#v", fact.Exposure)
		}
		if fact.Exposure.Credential != nil {
			switch fact.Exposure.Credential.Kind {
			case model.ExposureSecretReferencedByJob, model.ExposureSecretPassedToStep, model.ExposureReusableSecretMapped, model.ExposureReusableSecretInherited, model.ExposureEnvironmentSecretEligible:
				t.Fatalf("metadata existence or run gate state became a named exposure: %#v", fact.Exposure.Credential)
			}
		}
	}
}

func testEvidenceID(char byte) model.EvidenceID {
	return model.EvidenceID("ev1:" + strings.Repeat(string(char), 64))
}
