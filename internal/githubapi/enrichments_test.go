package githubapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEnrichmentEndpointsAndDTOAllowlist(t *testing.T) {
	t.Parallel()
	const token = "ENRICHMENT_TOKEN_SENTINEL"
	const secretValue = "VALUE_MUST_NOT_SURVIVE_DTO_DECODING"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		if r.Header.Get("Accept") != DefaultAccept || r.Header.Get("X-GitHub-Api-Version") != APIVersion {
			t.Error("required GitHub headers absent")
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/artifacts") {
			switch r.URL.Query().Get("page") {
			case "":
				w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/service/actions/runs/99/artifacts?per_page=100&page=2>; rel="next"`, server.URL))
				_, _ = w.Write([]byte(`{"total_count":2,"artifacts":[{"id":1,"name":"first","size_in_bytes":12,"digest":"sha256:aaaa"}]}`))
			case "2":
				_, _ = w.Write([]byte(`{"total_count":2,"artifacts":[{"id":2,"name":"second","expired":true}]}`))
			default:
				http.Error(w, `{"message":"unexpected page"}`, http.StatusBadRequest)
			}
			return
		}
		switch r.URL.EscapedPath() {
		case "/repos/acme/service/deployments":
			_, _ = w.Write([]byte(`[{"id":10,"sha":"abcdef","ref":"main","task":"deploy","environment":"prod","creator":{"id":7,"login":"octocat"}}]`))
		case "/repos/acme/service/deployments/10/statuses":
			_, _ = w.Write([]byte(`[{"id":11,"state":"success","environment":"prod"}]`))
		case "/repos/acme/service/environments":
			_, _ = w.Write([]byte(`{"total_count":1,"environments":[{"id":20,"name":"prod/us east","protection_rules":[{"id":21,"type":"wait_timer","wait_timer":5}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}]}`))
		case "/repos/acme/service/environments/prod%2Fus%20east":
			_, _ = w.Write([]byte(`{"id":20,"name":"prod/us east"}`))
		case "/repos/acme/service/actions/runs/99/pending_deployments":
			_, _ = w.Write([]byte(`[{"environment":{"id":20,"name":"prod"},"wait_timer":5,"current_user_can_approve":false}]`))
		case "/repos/acme/service/actions/runs/99/approvals":
			_, _ = w.Write([]byte(`[{"environments":[{"id":20,"name":"prod"}],"state":"approved","user":{"id":7,"login":"reviewer"},"comment":"approved"}]`))
		case "/repos/acme/service/actions/secrets":
			_, _ = fmt.Fprintf(w, `{"total_count":1,"secrets":[{"name":"DEPLOY_KEY","created_at":"2026-08-20T00:00:00Z","updated_at":"2026-08-20T01:00:00Z","value":%q,"encrypted_value":%q}]}`, secretValue, secretValue)
		case "/repos/acme/service/actions/organization-secrets":
			_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"ORG_KEY","visibility":"selected"}]}`))
		case "/orgs/acme/actions/secrets":
			_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"ORG_KEY","visibility":"selected"}]}`))
		case "/repos/acme/service/environments/prod/secrets":
			_, _ = w.Write([]byte(`{"total_count":1,"secrets":[{"name":"ENV_KEY"}]}`))
		case "/orgs/acme/actions/runners":
			_, _ = w.Write([]byte(`{"total_count":1,"runners":[{"id":30,"name":"runner","os":"linux","status":"online","busy":true,"ephemeral":true,"version":"2.999.0","labels":[{"id":31,"name":"self-hosted","type":"read-only"}]}]}`))
		case "/repos/acme/service/actions/runners":
			_, _ = w.Write([]byte(`{"total_count":1,"runners":[{"id":30,"name":"runner","os":"linux"}]}`))
		case "/orgs/acme/actions/runner-groups":
			_, _ = w.Write([]byte(`{"total_count":1,"runner_groups":[{"id":40,"name":"restricted","visibility":"selected","restricted_to_workflows":true,"selected_workflows":["acme/service/.github/workflows/deploy.yml@refs/heads/main"],"inherited":true}]}`))
		case "/repos/acme/service/releases":
			_, _ = w.Write([]byte(`[{"id":50,"tag_name":"v1","target_commitish":"abcdef","immutable":true,"author":{"id":7,"login":"octocat"},"assets":[{"id":51,"name":"tool","digest":"sha256:bbbb"}]}]`))
		case "/repos/acme/service/releases/50/assets":
			_, _ = w.Write([]byte(`[{"id":51,"name":"tool","digest":"sha256:bbbb"}]`))
		default:
			http.Error(w, `{"message":"unexpected endpoint"}`, http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server, StaticToken(token))
	ctx := context.Background()

	artifacts, err := client.ListWorkflowRunArtifacts(ctx, "acme", "service", 99)
	if err != nil || artifacts.TotalCount != 2 || len(artifacts.Artifacts) != 2 || artifacts.Partial || len(artifacts.Responses) != 2 {
		t.Fatalf("artifacts=%+v err=%v", artifacts, err)
	}
	deployments, err := client.ListDeployments(ctx, "acme", "service")
	if err != nil || len(deployments.Deployments) != 1 || deployments.Deployments[0].SHA != "abcdef" {
		t.Fatalf("deployments=%+v err=%v", deployments, err)
	}
	statuses, err := client.ListDeploymentStatuses(ctx, "acme", "service", 10)
	if err != nil || len(statuses.Statuses) != 1 || statuses.Statuses[0].State != "success" {
		t.Fatalf("statuses=%+v err=%v", statuses, err)
	}
	environments, err := client.ListEnvironments(ctx, "acme", "service")
	if err != nil || len(environments.Environments) != 1 || len(environments.Environments[0].ProtectionRules) != 1 {
		t.Fatalf("environments=%+v err=%v", environments, err)
	}
	environment, err := client.GetEnvironment(ctx, "acme", "service", "prod/us east")
	if err != nil || environment.Value.Name != "prod/us east" {
		t.Fatalf("environment=%+v err=%v", environment, err)
	}
	pending, err := client.ListPendingDeployments(ctx, "acme", "service", 99)
	if err != nil || len(pending.PendingDeployments) != 1 || pending.PendingDeployments[0].CurrentUserCanApprove {
		t.Fatalf("pending=%+v err=%v", pending, err)
	}
	approvals, err := client.ListEnvironmentApprovals(ctx, "acme", "service", 99)
	if err != nil || len(approvals.Approvals) != 1 || approvals.Approvals[0].State != "approved" {
		t.Fatalf("approvals=%+v err=%v", approvals, err)
	}

	repositorySecrets, err := client.ListRepositorySecrets(ctx, "acme", "service")
	if err != nil || len(repositorySecrets.Secrets) != 1 || repositorySecrets.Secrets[0].Name != "DEPLOY_KEY" {
		t.Fatalf("repository secrets=%+v err=%v", repositorySecrets, err)
	}
	encodedSecrets, err := json.Marshal(repositorySecrets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedSecrets), secretValue) || strings.Contains(string(encodedSecrets), token) {
		t.Fatalf("secret value or token survived metadata DTO: %s", encodedSecrets)
	}
	if result, err := client.ListRepositoryOrganizationSecrets(ctx, "acme", "service"); err != nil || result.Secrets[0].Visibility != "selected" {
		t.Fatalf("repository org secrets=%+v err=%v", result, err)
	}
	if result, err := client.ListOrganizationSecrets(ctx, "acme"); err != nil || result.Secrets[0].Name != "ORG_KEY" {
		t.Fatalf("organization secrets=%+v err=%v", result, err)
	}
	if result, err := client.ListEnvironmentSecrets(ctx, "acme", "service", "prod"); err != nil || result.Secrets[0].Name != "ENV_KEY" {
		t.Fatalf("environment secrets=%+v err=%v", result, err)
	}

	if result, err := client.ListOrganizationRunners(ctx, "acme"); err != nil || len(result.Runners) != 1 || !result.Runners[0].Ephemeral {
		t.Fatalf("organization runners=%+v err=%v", result, err)
	}
	if result, err := client.ListRepositoryRunners(ctx, "acme", "service"); err != nil || len(result.Runners) != 1 {
		t.Fatalf("repository runners=%+v err=%v", result, err)
	}
	if result, err := client.ListOrganizationRunnerGroups(ctx, "acme"); err != nil || len(result.RunnerGroups) != 1 || !result.RunnerGroups[0].Inherited {
		t.Fatalf("runner groups=%+v err=%v", result, err)
	}
	if result, err := client.ListReleases(ctx, "acme", "service"); err != nil || len(result.Releases) != 1 || !result.Releases[0].Immutable || result.Releases[0].Assets[0].Digest != "sha256:bbbb" {
		t.Fatalf("releases=%+v err=%v", result, err)
	}
	if result, err := client.ListReleaseAssets(ctx, "acme", "service", 50); err != nil || len(result.Assets) != 1 || result.Assets[0].Digest != "sha256:bbbb" {
		t.Fatalf("release assets=%+v err=%v", result, err)
	}
}

func TestEnrichmentPermissionFailuresAreNormalizedAndTokenSafe(t *testing.T) {
	t.Parallel()
	const token = "PERMISSION_TOKEN_SENTINEL"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("request omitted expected authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"message":"permission denied %s\n\u001b[31m"}`, token)
	}))
	defer server.Close()
	client := newTestClient(t, server, StaticToken(token))
	ctx := context.Background()
	tests := []struct {
		name string
		call func() (CapabilityListMetadata, error)
	}{
		{"artifacts", func() (CapabilityListMetadata, error) {
			r, e := client.ListWorkflowRunArtifacts(ctx, "acme", "service", 1)
			return r.CapabilityListMetadata, e
		}},
		{"deployments", func() (CapabilityListMetadata, error) {
			r, e := client.ListDeployments(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"deployment statuses", func() (CapabilityListMetadata, error) {
			r, e := client.ListDeploymentStatuses(ctx, "acme", "service", 1)
			return r.CapabilityListMetadata, e
		}},
		{"environments", func() (CapabilityListMetadata, error) {
			r, e := client.ListEnvironments(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"pending deployments", func() (CapabilityListMetadata, error) {
			r, e := client.ListPendingDeployments(ctx, "acme", "service", 1)
			return r.CapabilityListMetadata, e
		}},
		{"environment approvals", func() (CapabilityListMetadata, error) {
			r, e := client.ListEnvironmentApprovals(ctx, "acme", "service", 1)
			return r.CapabilityListMetadata, e
		}},
		{"repository secrets", func() (CapabilityListMetadata, error) {
			r, e := client.ListRepositorySecrets(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"repository organization secrets", func() (CapabilityListMetadata, error) {
			r, e := client.ListRepositoryOrganizationSecrets(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"organization secrets", func() (CapabilityListMetadata, error) {
			r, e := client.ListOrganizationSecrets(ctx, "acme")
			return r.CapabilityListMetadata, e
		}},
		{"environment secrets", func() (CapabilityListMetadata, error) {
			r, e := client.ListEnvironmentSecrets(ctx, "acme", "service", "prod")
			return r.CapabilityListMetadata, e
		}},
		{"organization runners", func() (CapabilityListMetadata, error) {
			r, e := client.ListOrganizationRunners(ctx, "acme")
			return r.CapabilityListMetadata, e
		}},
		{"repository runners", func() (CapabilityListMetadata, error) {
			r, e := client.ListRepositoryRunners(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"runner groups", func() (CapabilityListMetadata, error) {
			r, e := client.ListOrganizationRunnerGroups(ctx, "acme")
			return r.CapabilityListMetadata, e
		}},
		{"releases", func() (CapabilityListMetadata, error) {
			r, e := client.ListReleases(ctx, "acme", "service")
			return r.CapabilityListMetadata, e
		}},
		{"release assets", func() (CapabilityListMetadata, error) {
			r, e := client.ListReleaseAssets(ctx, "acme", "service", 1)
			return r.CapabilityListMetadata, e
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata, err := test.call()
			if !IsClass(err, ErrorForbidden) || !metadata.Partial || metadata.Failure == nil || metadata.Failure.Class != ErrorForbidden || len(metadata.Responses) != 1 {
				t.Fatalf("metadata=%+v err=%v", metadata, err)
			}
			encoded, marshalErr := json.Marshal(metadata)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(string(encoded), token) || strings.ContainsRune(err.Error(), '\x1b') || strings.ContainsRune(err.Error(), '\n') {
				t.Fatalf("permission failure leaked hostile/token material: error=%q metadata=%s", err, encoded)
			}
		})
	}
	environment, err := client.GetEnvironment(ctx, "acme", "service", "prod")
	if !IsClass(err, ErrorForbidden) || len(environment.Responses) != 1 || strings.Contains(err.Error(), token) {
		t.Fatalf("environment=%+v err=%v", environment, err)
	}
}

func TestEnrichmentPreservesCompletedPagesAndNeverFollowsChangedEndpoint(t *testing.T) {
	t.Parallel()
	const token = "NO_FORWARD_TOKEN"
	var calls atomic.Int32
	var userCalls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user" {
			userCalls.Add(1)
			t.Errorf("pagination followed a changed capability endpoint with authorization=%q", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/user?page=2>; rel="next"`, server.URL))
		_, _ = w.Write([]byte(`[{"id":1,"tag_name":"v1"}]`))
	}))
	defer server.Close()
	result, err := newTestClient(t, server, StaticToken(token)).ListReleases(context.Background(), "acme", "service")
	if !IsClass(err, ErrorPagination) || !result.Partial || result.Failure == nil || len(result.Releases) != 1 || calls.Load() != 1 || userCalls.Load() != 0 {
		t.Fatalf("result=%+v err=%v calls=%d userCalls=%d", result, err, calls.Load(), userCalls.Load())
	}
}

func TestEnrichmentSecondPagePermissionFailurePreservesPrefix(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"permission changed"}`))
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/acme/service/actions/runs/1/artifacts?per_page=100&page=2>; rel="next"`, server.URL))
		_, _ = w.Write([]byte(`{"total_count":2,"artifacts":[{"id":1,"name":"retained-prefix"}]}`))
	}))
	defer server.Close()
	result, err := newTestClient(t, server, NoToken()).ListWorkflowRunArtifacts(context.Background(), "acme", "service", 1)
	if !IsClass(err, ErrorForbidden) || !result.Partial || result.Failure == nil || result.Failure.Class != ErrorForbidden || len(result.Artifacts) != 1 || len(result.Responses) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestEnrichmentReportedTotalMismatchIsPartial(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_count":0,"secrets":[{"name":"UNEXPECTED"}]}`))
	}))
	defer server.Close()
	result, err := newTestClient(t, server, NoToken()).ListRepositorySecrets(context.Background(), "acme", "service")
	if !IsClass(err, ErrorPagination) || !result.Partial || result.Failure == nil || len(result.Secrets) != 1 || result.TotalCount != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestEnrichmentDoesNotFollowArtifactMetadataURL(t *testing.T) {
	t.Parallel()
	const token = "ARTIFACT_METADATA_TOKEN"
	var trapCalls atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trapCalls.Add(1)
		t.Errorf("artifact metadata URL was followed with authorization=%q", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer trap.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"total_count":1,"artifacts":[{"id":1,"name":"evidence","archive_download_url":%q}]}`, trap.URL+"/signed?token=hostile")
	}))
	defer server.Close()
	result, err := newTestClient(t, server, StaticToken(token)).ListWorkflowRunArtifacts(context.Background(), "acme", "service", 1)
	if err != nil || result.Artifacts[0].ArchiveDownloadURL != trap.URL+"/signed?token=hostile" || trapCalls.Load() != 0 {
		t.Fatalf("result=%+v err=%v trapCalls=%d", result, err, trapCalls.Load())
	}
}

func TestEnrichmentRejectsUnsafeArgumentsBeforeRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newTestClient(t, server, NoToken())
	tests := []struct {
		name string
		call func() error
	}{
		{"artifact run ID", func() error {
			_, err := client.ListWorkflowRunArtifacts(context.Background(), "acme", "service", 0)
			return err
		}},
		{"deployment ID", func() error {
			_, err := client.ListDeploymentStatuses(context.Background(), "acme", "service", -1)
			return err
		}},
		{"release ID", func() error {
			_, err := client.ListReleaseAssets(context.Background(), "acme", "service", 0)
			return err
		}},
		{"environment dot segment", func() error {
			_, err := client.GetEnvironment(context.Background(), "acme", "service", "..")
			return err
		}},
		{"environment control", func() error {
			_, err := client.ListEnvironmentSecrets(context.Background(), "acme", "service", "prod\nforged")
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !IsClass(err, ErrorInvalidRequest) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid arguments caused %d requests", calls.Load())
	}
}
