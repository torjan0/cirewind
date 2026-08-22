package githubapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

type pageDecoder[T any] func(rawResponse) (items []T, reportedTotal int, hasTotal bool, err error)

func paginateCapability[T any](ctx context.Context, client *Client, first requestSpec, decode pageDecoder[T]) ([]T, int, CapabilityListMetadata, error) {
	items := []T{}
	metadata := CapabilityListMetadata{Responses: []ResponseMeta{}}
	reportedTotal := -1
	seenPages := make(map[string]struct{})
	spec := first
	for page := 0; ; page++ {
		if page >= client.limits.MaxPages {
			err := paginationError(first.operation, metadata.Responses, "maximum page count exceeded")
			markPartial(&metadata, err)
			return items, max(reportedTotal, len(items)), metadata, err
		}
		response, requestErr := client.get(ctx, spec)
		metadata.Responses = append(metadata.Responses, response.attempts...)
		if requestErr != nil {
			markPartial(&metadata, requestErr)
			return items, max(reportedTotal, len(items)), metadata, requestErr
		}
		pageItems, total, hasTotal, decodeErr := decode(response)
		if decodeErr != nil {
			markPartial(&metadata, decodeErr)
			return items, max(reportedTotal, len(items)), metadata, decodeErr
		}
		items = append(items, pageItems...)
		if hasTotal && total > reportedTotal {
			reportedTotal = total
		}
		if response.next == nil {
			if reportedTotal >= 0 && reportedTotal != len(items) {
				err := paginationError(first.operation, metadata.Responses, "collected item count did not match GitHub's reported total")
				markPartial(&metadata, err)
				return items, reportedTotal, metadata, err
			}
			return items, max(reportedTotal, len(items)), metadata, nil
		}
		if response.next.EscapedPath() != strings.TrimSuffix(client.base.EscapedPath(), "/")+first.path {
			err := paginationError(first.operation, metadata.Responses, "next link changed the capability endpoint")
			markPartial(&metadata, err)
			return items, max(reportedTotal, len(items)), metadata, err
		}
		key := response.next.String()
		if _, duplicate := seenPages[key]; duplicate {
			err := paginationError(first.operation, metadata.Responses, "pagination repeated a next link")
			markPartial(&metadata, err)
			return items, max(reportedTotal, len(items)), metadata, err
		}
		seenPages[key] = struct{}{}
		spec = first
		spec.absoluteURL = response.next
		spec.query = nil
		spec.parameters = paginationParameters(first.parameters, response.next)
	}
}

func markPartial(metadata *CapabilityListMetadata, err error) {
	metadata.Partial = true
	failure := &PartialError{Class: ErrorTransient, Operation: "enrichment", Message: "capability collection failed"}
	var apiError *Error
	if errors.As(err, &apiError) {
		failure.Class = apiError.Class
		failure.Operation = apiError.Operation
		failure.StatusCode = apiError.StatusCode
		failure.Message = apiError.Message
		failure.Retryable = apiError.Retryable
		if len(apiError.Responses) > 0 && len(metadata.Responses) >= len(apiError.Responses) {
			copy(metadata.Responses[len(metadata.Responses)-len(apiError.Responses):], apiError.Responses)
		}
	}
	metadata.Failure = failure
}

func wrappedPage[T any](operation, field string) pageDecoder[T] {
	return func(response rawResponse) ([]T, int, bool, error) {
		var raw map[string]json.RawMessage
		if err := decodeJSON(response, &raw, operation); err != nil {
			return nil, 0, false, err
		}
		var total int
		if encoded, ok := raw["total_count"]; ok {
			if err := json.Unmarshal(encoded, &total); err != nil {
				return nil, 0, false, malformedError(operation, response, "GitHub total_count was invalid")
			}
		} else {
			return nil, 0, false, malformedError(operation, response, "GitHub response omitted total_count")
		}
		var items []T
		encoded, ok := raw[field]
		if !ok || json.Unmarshal(encoded, &items) != nil || items == nil {
			return nil, 0, false, malformedError(operation, response, "GitHub response omitted or malformed its item array")
		}
		return items, total, true, nil
	}
}

func arrayPage[T any](operation string) pageDecoder[T] {
	return func(response rawResponse) ([]T, int, bool, error) {
		var items []T
		if err := decodeJSON(response, &items, operation); err != nil {
			return nil, 0, false, err
		}
		if items == nil {
			return nil, 0, false, malformedError(operation, response, "GitHub response was not an item array")
		}
		return items, 0, false, nil
	}
}

func (c *Client) ListWorkflowRunArtifacts(ctx context.Context, owner, repository string, runID int64) (ArtifactList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ArtifactList{}, err
	}
	if runID <= 0 {
		return ArtifactList{}, invalidArgument("list workflow run artifacts", "run ID must be positive")
	}
	first := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/artifacts",
		query:         url.Values{"per_page": {"100"}},
		parameters:    map[string]string{"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10), "per_page": "100"},
		operation:     "list workflow run artifacts",
	}
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[Artifact](first.operation, "artifacts"))
	return ArtifactList{TotalCount: total, Artifacts: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListDeployments(ctx context.Context, owner, repository string) (DeploymentList, error) {
	first, err := repositoryListSpec(owner, repository, "/deployments", "/repos/{owner}/{repo}/deployments", "list deployments")
	if err != nil {
		return DeploymentList{}, err
	}
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[Deployment](first.operation))
	return DeploymentList{Deployments: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListDeploymentStatuses(ctx context.Context, owner, repository string, deploymentID int64) (DeploymentStatusList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return DeploymentStatusList{}, err
	}
	if deploymentID <= 0 {
		return DeploymentStatusList{}, invalidArgument("list deployment statuses", "deployment ID must be positive")
	}
	first := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/deployments/" + strconv.FormatInt(deploymentID, 10) + "/statuses",
		query:         url.Values{"per_page": {"100"}},
		parameters:    map[string]string{"owner": owner, "repo": repository, "deployment_id": strconv.FormatInt(deploymentID, 10), "per_page": "100"},
		operation:     "list deployment statuses",
	}
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[DeploymentStatus](first.operation))
	return DeploymentStatusList{Statuses: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListEnvironments(ctx context.Context, owner, repository string) (EnvironmentList, error) {
	first, err := repositoryListSpec(owner, repository, "/environments", "/repos/{owner}/{repo}/environments", "list environments")
	if err != nil {
		return EnvironmentList{}, err
	}
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[Environment](first.operation, "environments"))
	return EnvironmentList{TotalCount: total, Environments: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) GetEnvironment(ctx context.Context, owner, repository, environmentName string) (ObjectResult[Environment], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[Environment]{}, err
	}
	namePart, err := escapeOpaqueSegment("environment name", environmentName)
	if err != nil {
		return ObjectResult[Environment]{}, err
	}
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/environments/{environment_name}",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/environments/" + namePart,
		parameters:    map[string]string{"owner": owner, "repo": repository, "environment_name": environmentName},
		operation:     "get environment",
	})
	return decodeObject[Environment](response, getErr, "get environment")
}

func (c *Client) ListPendingDeployments(ctx context.Context, owner, repository string, runID int64) (PendingDeploymentList, error) {
	return c.listRunEnvironmentArray(ctx, owner, repository, runID, "pending_deployments")
}

func (c *Client) ListEnvironmentApprovals(ctx context.Context, owner, repository string, runID int64) (EnvironmentApprovalList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return EnvironmentApprovalList{}, err
	}
	if runID <= 0 {
		return EnvironmentApprovalList{}, invalidArgument("list environment approvals", "run ID must be positive")
	}
	first := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}/approvals",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/approvals",
		parameters:    map[string]string{"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10)},
		operation:     "list environment approvals",
	}
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[EnvironmentApproval](first.operation))
	return EnvironmentApprovalList{Approvals: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) listRunEnvironmentArray(ctx context.Context, owner, repository string, runID int64, suffix string) (PendingDeploymentList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return PendingDeploymentList{}, err
	}
	if runID <= 0 {
		return PendingDeploymentList{}, invalidArgument("list pending deployments", "run ID must be positive")
	}
	first := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}/" + suffix,
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10) + "/" + suffix,
		parameters:    map[string]string{"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10)},
		operation:     "list pending deployments",
	}
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[PendingDeployment](first.operation))
	return PendingDeploymentList{PendingDeployments: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListRepositorySecrets(ctx context.Context, owner, repository string) (SecretMetadataList, error) {
	return c.listRepositorySecrets(ctx, owner, repository, "/actions/secrets", "/repos/{owner}/{repo}/actions/secrets", "list repository secrets")
}

func (c *Client) ListRepositoryOrganizationSecrets(ctx context.Context, owner, repository string) (SecretMetadataList, error) {
	return c.listRepositorySecrets(ctx, owner, repository, "/actions/organization-secrets", "/repos/{owner}/{repo}/actions/organization-secrets", "list repository organization secrets")
}

func (c *Client) ListEnvironmentSecrets(ctx context.Context, owner, repository, environmentName string) (SecretMetadataList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return SecretMetadataList{}, err
	}
	namePart, err := escapeOpaqueSegment("environment name", environmentName)
	if err != nil {
		return SecretMetadataList{}, err
	}
	first := listSpec(
		"/repos/{owner}/{repo}/environments/{environment_name}/secrets",
		"/repos/"+ownerPart+"/"+repositoryPart+"/environments/"+namePart+"/secrets",
		map[string]string{"owner": owner, "repo": repository, "environment_name": environmentName, "per_page": "100"},
		"list environment secrets",
	)
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[SecretMetadata](first.operation, "secrets"))
	return SecretMetadataList{TotalCount: total, Secrets: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) listRepositorySecrets(ctx context.Context, owner, repository, suffix, route, operation string) (SecretMetadataList, error) {
	first, err := repositoryListSpec(owner, repository, suffix, route, operation)
	if err != nil {
		return SecretMetadataList{}, err
	}
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[SecretMetadata](first.operation, "secrets"))
	return SecretMetadataList{TotalCount: total, Secrets: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListOrganizationSecrets(ctx context.Context, organization string) (SecretMetadataList, error) {
	org, err := escapeIdentifier("organization", organization)
	if err != nil {
		return SecretMetadataList{}, err
	}
	first := listSpec("/orgs/{org}/actions/secrets", "/orgs/"+org+"/actions/secrets", map[string]string{"org": organization, "per_page": "100"}, "list organization secrets")
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[SecretMetadata](first.operation, "secrets"))
	return SecretMetadataList{TotalCount: total, Secrets: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListOrganizationRunners(ctx context.Context, organization string) (RunnerList, error) {
	org, err := escapeIdentifier("organization", organization)
	if err != nil {
		return RunnerList{}, err
	}
	first := listSpec("/orgs/{org}/actions/runners", "/orgs/"+org+"/actions/runners", map[string]string{"org": organization, "per_page": "100"}, "list organization runners")
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[SelfHostedRunner](first.operation, "runners"))
	return RunnerList{TotalCount: total, Runners: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListRepositoryRunners(ctx context.Context, owner, repository string) (RunnerList, error) {
	first, err := repositoryListSpec(owner, repository, "/actions/runners", "/repos/{owner}/{repo}/actions/runners", "list repository runners")
	if err != nil {
		return RunnerList{}, err
	}
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[SelfHostedRunner](first.operation, "runners"))
	return RunnerList{TotalCount: total, Runners: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListOrganizationRunnerGroups(ctx context.Context, organization string) (RunnerGroupList, error) {
	org, err := escapeIdentifier("organization", organization)
	if err != nil {
		return RunnerGroupList{}, err
	}
	first := listSpec("/orgs/{org}/actions/runner-groups", "/orgs/"+org+"/actions/runner-groups", map[string]string{"org": organization, "per_page": "100"}, "list organization runner groups")
	items, total, metadata, err := paginateCapability(ctx, c, first, wrappedPage[RunnerGroup](first.operation, "runner_groups"))
	return RunnerGroupList{TotalCount: total, RunnerGroups: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListReleases(ctx context.Context, owner, repository string) (ReleaseList, error) {
	first, err := repositoryListSpec(owner, repository, "/releases", "/repos/{owner}/{repo}/releases", "list releases")
	if err != nil {
		return ReleaseList{}, err
	}
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[Release](first.operation))
	return ReleaseList{Releases: items, CapabilityListMetadata: metadata}, err
}

func (c *Client) ListReleaseAssets(ctx context.Context, owner, repository string, releaseID int64) (ReleaseAssetList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ReleaseAssetList{}, err
	}
	if releaseID <= 0 {
		return ReleaseAssetList{}, invalidArgument("list release assets", "release ID must be positive")
	}
	first := listSpec(
		"/repos/{owner}/{repo}/releases/{release_id}/assets",
		"/repos/"+ownerPart+"/"+repositoryPart+"/releases/"+strconv.FormatInt(releaseID, 10)+"/assets",
		map[string]string{"owner": owner, "repo": repository, "release_id": strconv.FormatInt(releaseID, 10), "per_page": "100"},
		"list release assets",
	)
	items, _, metadata, err := paginateCapability(ctx, c, first, arrayPage[ReleaseAsset](first.operation))
	return ReleaseAssetList{Assets: items, CapabilityListMetadata: metadata}, err
}

func repositoryListSpec(owner, repository, suffix, route, operation string) (requestSpec, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return requestSpec{}, err
	}
	return listSpec(route, "/repos/"+ownerPart+"/"+repositoryPart+suffix, map[string]string{"owner": owner, "repo": repository, "per_page": "100"}, operation), nil
}

func listSpec(route, requestPath string, parameters map[string]string, operation string) requestSpec {
	return requestSpec{routeTemplate: route, path: requestPath, query: url.Values{"per_page": {"100"}}, parameters: parameters, operation: operation}
}

func escapeOpaqueSegment(field, value string) (string, error) {
	if value == "" || value == "." || value == ".." || len(value) > 1024 || strings.ContainsAny(value, "\\\x00\r\n") {
		return "", invalidArgument("validate "+field, field+" is empty or invalid")
	}
	return url.PathEscape(value), nil
}
