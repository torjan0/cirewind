package githubapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func (c *Client) GetRepository(ctx context.Context, owner, repository string) (ObjectResult[Repository], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[Repository]{}, err
	}
	route := "/repos/{owner}/{repo}"
	response, err := c.get(ctx, requestSpec{
		routeTemplate: route,
		path:          "/repos/" + ownerPart + "/" + repositoryPart,
		parameters:    map[string]string{"owner": owner, "repo": repository},
		operation:     "get repository",
	})
	return decodeObject[Repository](response, err, "get repository")
}

func (c *Client) ListOrganizationRepositories(ctx context.Context, organization string) (RepositoryList, error) {
	org, err := escapeIdentifier("organization", organization)
	if err != nil {
		return RepositoryList{}, err
	}
	query := url.Values{"per_page": {"100"}, "type": {"all"}}
	return c.listRepositories(ctx, requestSpec{
		routeTemplate: "/orgs/{org}/repos",
		path:          "/orgs/" + org + "/repos",
		query:         query,
		parameters:    map[string]string{"org": organization, "per_page": "100", "type": "all"},
		operation:     "list organization repositories",
	}, false)
}

func (c *Client) ListInstallationRepositories(ctx context.Context) (RepositoryList, error) {
	return c.listRepositories(ctx, requestSpec{
		routeTemplate: "/installation/repositories",
		path:          "/installation/repositories",
		query:         url.Values{"per_page": {"100"}},
		parameters:    map[string]string{"per_page": "100"},
		operation:     "list installation repositories",
	}, true)
}

func (c *Client) ListUserInstallationRepositories(ctx context.Context, installationID int64) (RepositoryList, error) {
	if installationID <= 0 {
		return RepositoryList{}, invalidArgument("list user installation repositories", "installation ID must be positive")
	}
	return c.listRepositories(ctx, requestSpec{
		routeTemplate: "/user/installations/{installation_id}/repositories",
		path:          "/user/installations/" + strconv.FormatInt(installationID, 10) + "/repositories",
		query:         url.Values{"per_page": {"100"}},
		parameters:    map[string]string{"installation_id": strconv.FormatInt(installationID, 10), "per_page": "100"},
		operation:     "list user installation repositories",
	}, true)
}

func (c *Client) listRepositories(ctx context.Context, first requestSpec, wrapped bool) (RepositoryList, error) {
	var result RepositoryList
	expectedTotal := -1
	seenPages := make(map[string]struct{})
	spec := first
	for page := 0; ; page++ {
		if page >= c.limits.MaxPages {
			return result, paginationError(first.operation, result.Responses, "maximum page count exceeded")
		}
		response, err := c.get(ctx, spec)
		if err != nil {
			return result, err
		}
		result.Responses = append(result.Responses, response.attempts...)
		if wrapped {
			var document struct {
				TotalCount   int          `json:"total_count"`
				Repositories []Repository `json:"repositories"`
			}
			if err := decodeJSON(response, &document, first.operation); err != nil {
				return result, err
			}
			result.Repositories = append(result.Repositories, document.Repositories...)
			if document.TotalCount > expectedTotal {
				expectedTotal = document.TotalCount
			}
		} else {
			var repositories []Repository
			if err := decodeJSON(response, &repositories, first.operation); err != nil {
				return result, err
			}
			result.Repositories = append(result.Repositories, repositories...)
		}
		if response.next == nil {
			if wrapped && expectedTotal > len(result.Repositories) {
				return result, paginationError(first.operation, result.Responses, "pagination ended before the reported repository total was collected")
			}
			return result, nil
		}
		key := response.next.String()
		if _, exists := seenPages[key]; exists {
			return result, paginationError(first.operation, result.Responses, "pagination repeated a next link")
		}
		seenPages[key] = struct{}{}
		spec = first
		spec.absoluteURL = response.next
		spec.query = nil
		spec.parameters = paginationParameters(first.parameters, response.next)
	}
}

// ProbeWorkflowRuns requests a single item so a scheduler can decide whether
// the documented filtered-search ceiling requires recursive partitioning.
func (c *Client) ProbeWorkflowRuns(ctx context.Context, owner, repository, created string) (RunProbe, error) {
	spec, err := workflowRunsSpec(owner, repository, created, 1)
	if err != nil {
		return RunProbe{}, err
	}
	response, err := c.get(ctx, spec)
	if err != nil {
		return RunProbe{Responses: response.attempts}, err
	}
	var document struct {
		TotalCount int `json:"total_count"`
	}
	if err := decodeJSON(response, &document, spec.operation); err != nil {
		return RunProbe{Responses: response.attempts}, err
	}
	return RunProbe{TotalCount: document.TotalCount, Responses: response.attempts}, nil
}

func (c *Client) ListWorkflowRuns(ctx context.Context, owner, repository, created string) (RunList, error) {
	first, err := workflowRunsSpec(owner, repository, created, 100)
	if err != nil {
		return RunList{}, err
	}
	var result RunList
	seenPages := make(map[string]struct{})
	spec := first
	pageCount := 0
	fullPages := 0
	for {
		if pageCount >= c.limits.MaxPages {
			result.Truncated = true
			return result, paginationError(first.operation, result.Responses, "maximum page count exceeded")
		}
		response, getErr := c.get(ctx, spec)
		if getErr != nil {
			return result, getErr
		}
		result.Responses = append(result.Responses, response.attempts...)
		var document struct {
			TotalCount   int           `json:"total_count"`
			WorkflowRuns []WorkflowRun `json:"workflow_runs"`
		}
		if err := decodeJSON(response, &document, first.operation); err != nil {
			return result, err
		}
		if document.TotalCount > result.TotalCount {
			result.TotalCount = document.TotalCount
		}
		result.Runs = append(result.Runs, document.WorkflowRuns...)
		pageCount++
		if len(document.WorkflowRuns) == 100 {
			fullPages++
		}
		if response.next == nil {
			result.Truncated = result.TotalCount >= 1000 || fullPages >= 10
			if !result.Truncated && result.TotalCount > len(result.Runs) {
				return result, paginationError(first.operation, result.Responses, "pagination ended before the reported workflow-run total was collected")
			}
			return result, nil
		}
		key := response.next.String()
		if _, exists := seenPages[key]; exists {
			result.Truncated = true
			return result, paginationError(first.operation, result.Responses, "pagination repeated a next link")
		}
		seenPages[key] = struct{}{}
		spec = first
		spec.absoluteURL = response.next
		spec.query = nil
		spec.parameters = paginationParameters(first.parameters, response.next)
	}
}

func workflowRunsSpec(owner, repository, created string, perPage int) (requestSpec, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return requestSpec{}, err
	}
	if strings.TrimSpace(created) == "" || len(created) > 256 || strings.ContainsAny(created, "\r\n") {
		return requestSpec{}, invalidArgument("list workflow runs", "created filter is empty or invalid")
	}
	perPageString := strconv.Itoa(perPage)
	return requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs",
		query:         url.Values{"created": {created}, "per_page": {perPageString}},
		parameters:    map[string]string{"owner": owner, "repo": repository, "created": created, "per_page": perPageString},
		operation:     "list workflow runs",
	}, nil
}

func (c *Client) GetWorkflowRun(ctx context.Context, owner, repository string, runID int64) (ObjectResult[WorkflowRun], error) {
	return c.getWorkflowRunRoute(ctx, owner, repository, runID, 0)
}

func (c *Client) GetWorkflowRunAttempt(ctx context.Context, owner, repository string, runID int64, attempt int) (ObjectResult[WorkflowRun], error) {
	if attempt <= 0 {
		return ObjectResult[WorkflowRun]{}, invalidArgument("get workflow run attempt", "attempt must be positive")
	}
	return c.getWorkflowRunRoute(ctx, owner, repository, runID, attempt)
}

func (c *Client) getWorkflowRunRoute(ctx context.Context, owner, repository string, runID int64, attempt int) (ObjectResult[WorkflowRun], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[WorkflowRun]{}, err
	}
	if runID <= 0 {
		return ObjectResult[WorkflowRun]{}, invalidArgument("get workflow run", "run ID must be positive")
	}
	route := "/repos/{owner}/{repo}/actions/runs/{run_id}"
	requestPath := "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10)
	parameters := map[string]string{"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10)}
	operation := "get workflow run"
	if attempt > 0 {
		route += "/attempts/{attempt_number}"
		requestPath += "/attempts/" + strconv.Itoa(attempt)
		parameters["attempt_number"] = strconv.Itoa(attempt)
		operation = "get workflow run attempt"
	}
	response, getErr := c.get(ctx, requestSpec{routeTemplate: route, path: requestPath, parameters: parameters, operation: operation})
	return decodeObject[WorkflowRun](response, getErr, operation)
}

func (c *Client) ListJobsForAttempt(ctx context.Context, owner, repository string, runID int64, attempt int) (JobList, error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return JobList{}, err
	}
	if runID <= 0 || attempt <= 0 {
		return JobList{}, invalidArgument("list attempt jobs", "run ID and attempt must be positive")
	}
	first := requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs",
		path: "/repos/" + ownerPart + "/" + repositoryPart + "/actions/runs/" + strconv.FormatInt(runID, 10) +
			"/attempts/" + strconv.Itoa(attempt) + "/jobs",
		query: url.Values{"filter": {"all"}, "per_page": {"100"}},
		parameters: map[string]string{
			"owner": owner, "repo": repository, "run_id": strconv.FormatInt(runID, 10),
			"attempt_number": strconv.Itoa(attempt), "filter": "all", "per_page": "100",
		},
		operation: "list attempt jobs",
	}
	var result JobList
	seenPages := make(map[string]struct{})
	spec := first
	for page := 0; ; page++ {
		if page >= c.limits.MaxPages {
			return result, paginationError(first.operation, result.Responses, "maximum page count exceeded")
		}
		response, getErr := c.get(ctx, spec)
		if getErr != nil {
			return result, getErr
		}
		result.Responses = append(result.Responses, response.attempts...)
		var document struct {
			TotalCount int           `json:"total_count"`
			Jobs       []WorkflowJob `json:"jobs"`
		}
		if err := decodeJSON(response, &document, first.operation); err != nil {
			return result, err
		}
		if document.TotalCount > result.TotalCount {
			result.TotalCount = document.TotalCount
		}
		result.Jobs = append(result.Jobs, document.Jobs...)
		if response.next == nil {
			if result.TotalCount > len(result.Jobs) {
				return result, paginationError(first.operation, result.Responses, "pagination ended before the reported job total was collected")
			}
			return result, nil
		}
		key := response.next.String()
		if _, exists := seenPages[key]; exists {
			return result, paginationError(first.operation, result.Responses, "pagination repeated a next link")
		}
		seenPages[key] = struct{}{}
		spec = first
		spec.absoluteURL = response.next
		spec.query = nil
		spec.parameters = paginationParameters(first.parameters, response.next)
	}
}

func (c *Client) GetRepositoryHashAlgorithm(ctx context.Context, owner, repository string) (ObjectResult[string], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[string]{}, err
	}
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/hash-algorithm",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/hash-algorithm",
		parameters:    map[string]string{"owner": owner, "repo": repository},
		operation:     "get repository hash algorithm",
	})
	if getErr != nil {
		return ObjectResult[string]{Responses: response.attempts}, getErr
	}
	var document struct {
		HashAlgorithm string `json:"hash_algorithm"`
	}
	if err := decodeJSON(response, &document, "get repository hash algorithm"); err != nil {
		return ObjectResult[string]{Responses: response.attempts}, err
	}
	if strings.TrimSpace(document.HashAlgorithm) == "" {
		return ObjectResult[string]{Responses: response.attempts}, malformedError("get repository hash algorithm", response, "response omitted hash_algorithm")
	}
	return ObjectResult[string]{Value: document.HashAlgorithm, Responses: response.attempts}, nil
}

func (c *Client) GetContentAtObject(ctx context.Context, owner, repository, contentPath string, object GitObjectID) (ObjectResult[Content], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[Content]{}, err
	}
	escapedPath, err := escapeRepositoryPath(contentPath)
	if err != nil {
		return ObjectResult[Content]{}, err
	}
	if strings.TrimSpace(object.Algorithm) == "" || strings.TrimSpace(object.Value) == "" || strings.ContainsAny(object.Value, "\r\n") {
		return ObjectResult[Content]{}, invalidArgument("get repository content", "typed Git object ID is incomplete")
	}
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/contents/{path}",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/contents/" + escapedPath,
		query:         url.Values{"ref": {object.Value}},
		parameters: map[string]string{
			"owner": owner, "repo": repository, "path": contentPath,
			"ref_algorithm": object.Algorithm, "ref": object.Value,
		},
		operation: "get repository content",
	})
	return decodeObject[Content](response, getErr, "get repository content")
}

func (c *Client) GetBlob(ctx context.Context, owner, repository string, blob GitObjectID) (ObjectResult[Content], error) {
	ownerPart, repositoryPart, err := repositoryParts(owner, repository)
	if err != nil {
		return ObjectResult[Content]{}, err
	}
	if strings.TrimSpace(blob.Algorithm) == "" || strings.TrimSpace(blob.Value) == "" || strings.ContainsAny(blob.Value, "\r\n/") {
		return ObjectResult[Content]{}, invalidArgument("get Git blob", "typed blob object ID is incomplete")
	}
	response, getErr := c.get(ctx, requestSpec{
		routeTemplate: "/repos/{owner}/{repo}/git/blobs/{file_sha}",
		path:          "/repos/" + ownerPart + "/" + repositoryPart + "/git/blobs/" + url.PathEscape(blob.Value),
		parameters: map[string]string{
			"owner": owner, "repo": repository, "blob_algorithm": blob.Algorithm, "file_sha": blob.Value,
		},
		operation: "get Git blob",
	})
	return decodeObject[Content](response, getErr, "get Git blob")
}

func decodeObject[T any](response rawResponse, requestErr error, operation string) (ObjectResult[T], error) {
	result := ObjectResult[T]{Responses: response.attempts}
	if requestErr != nil {
		return result, requestErr
	}
	if err := decodeJSON(response, &result.Value, operation); err != nil {
		return result, err
	}
	return result, nil
}

func decodeJSON(response rawResponse, destination any, operation string) error {
	mediaType := response.meta.MediaType
	if mediaType != "" {
		parsed, _, err := mime.ParseMediaType(mediaType)
		if err != nil || (parsed != "application/json" && parsed != "application/vnd.github+json") {
			responses := markLastError(response.attempts, ErrorUnexpectedMedia)
			return &Error{Class: ErrorUnexpectedMedia, Operation: operation, StatusCode: response.meta.StatusCode, Message: "GitHub returned a non-JSON media type", Responses: responses}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(response.body))
	if err := decoder.Decode(destination); err != nil {
		return malformedError(operation, response, "could not decode GitHub JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return malformedError(operation, response, "GitHub JSON contained trailing data")
	}
	return nil
}

func malformedError(operation string, response rawResponse, message string) error {
	responses := markLastError(response.attempts, ErrorMalformedResponse)
	return &Error{Class: ErrorMalformedResponse, Operation: operation, StatusCode: response.meta.StatusCode, Message: message, Responses: responses}
}

func markLastError(responses []ResponseMeta, class ErrorClass) []ResponseMeta {
	result := append([]ResponseMeta(nil), responses...)
	if len(result) > 0 {
		result[len(result)-1].ErrorClass = class
	}
	return result
}

func paginationError(operation string, responses []ResponseMeta, message string) error {
	return &Error{Class: ErrorPagination, Operation: operation, Message: message, Responses: markLastError(responses, ErrorPagination)}
}

func invalidArgument(operation, message string) error {
	return &Error{Class: ErrorInvalidRequest, Operation: operation, Message: message}
}

func repositoryParts(owner, repository string) (string, string, error) {
	ownerPart, err := escapeIdentifier("owner", owner)
	if err != nil {
		return "", "", err
	}
	repositoryPart, err := escapeIdentifier("repository", repository)
	if err != nil {
		return "", "", err
	}
	return ownerPart, repositoryPart, nil
}

func escapeIdentifier(field, value string) (string, error) {
	if value == "" || value == "." || value == ".." || len(value) > 256 || strings.ContainsAny(value, "/\\\x00\r\n") {
		return "", invalidArgument("validate "+field, field+" is empty or invalid")
	}
	return url.PathEscape(value), nil
}

func escapeRepositoryPath(value string) (string, error) {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00\r\n") {
		return "", invalidArgument("validate repository path", "repository path is empty or unsafe")
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", invalidArgument("validate repository path", "repository path is not canonical")
	}
	parts := strings.Split(cleaned, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/"), nil
}
