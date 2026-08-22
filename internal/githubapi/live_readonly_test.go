package githubapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveReadOnlyRunQualification is an explicitly opt-in GitHub.com
// transport check. It performs GET requests only, streams logs to io.Discard,
// and records no response body. Default and CI test runs always skip it.
func TestLiveReadOnlyRunQualification(t *testing.T) {
	if os.Getenv("CIREWIND_LIVE_READONLY") != "1" {
		t.Skip("set CIREWIND_LIVE_READONLY=1 with an explicit public repository and completed run")
	}
	owner, repository := liveRepository(t, os.Getenv("CIREWIND_LIVE_REPOSITORY"))
	runID := livePositiveInt64(t, "CIREWIND_LIVE_RUN_ID")
	attempt := int(livePositiveInt64(t, "CIREWIND_LIVE_ATTEMPT"))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client, err := New(EnvToken(), WithUserAgent("CIRewind/live-readonly-qualification"), WithLimits(Limits{
		JSONResponseBytes: 32 << 20,
		MaxPages:          20,
		AttemptLogBytes:   128 << 20,
		JobLogBytes:       32 << 20,
	}))
	if err != nil {
		t.Fatal(err)
	}

	repositoryResult, err := client.GetRepository(ctx, owner, repository)
	if err != nil {
		t.Fatalf("get public repository: %v", err)
	}
	if repositoryResult.Value.ID <= 0 || repositoryResult.Value.Private {
		t.Fatalf("qualification target is not an identified public repository")
	}
	assertLiveResponseMetadata(t, repositoryResult.Responses)

	hashResult, err := client.GetRepositoryHashAlgorithm(ctx, owner, repository)
	if err != nil {
		t.Fatalf("get repository hash algorithm: %v", err)
	}
	if hashResult.Value != "sha1" && hashResult.Value != "sha256" {
		t.Fatalf("unexpected repository hash algorithm %q", hashResult.Value)
	}
	assertLiveResponseMetadata(t, hashResult.Responses)

	parent, err := client.GetWorkflowRun(ctx, owner, repository, runID)
	if err != nil {
		t.Fatalf("get workflow run: %v", err)
	}
	if parent.Value.ID != runID || parent.Value.Status != "completed" || parent.Value.RunAttempt < attempt {
		t.Fatalf("run is not the requested stable completed parent: id=%d status=%q attempts=%d", parent.Value.ID, parent.Value.Status, parent.Value.RunAttempt)
	}
	assertLiveResponseMetadata(t, parent.Responses)

	created := parent.Value.CreatedAt.UTC()
	createdFilter := created.Add(-time.Second).Format(time.RFC3339) + ".." + created.Add(time.Second).Format(time.RFC3339)
	probe, err := client.ProbeWorkflowRuns(ctx, owner, repository, createdFilter)
	if err != nil {
		t.Fatalf("probe workflow runs: %v", err)
	}
	if probe.TotalCount < 1 {
		t.Fatal("created-time probe did not find the selected run")
	}
	assertLiveResponseMetadata(t, probe.Responses)
	listed, err := client.ListWorkflowRuns(ctx, owner, repository, createdFilter)
	if err != nil {
		t.Fatalf("list workflow runs: %v", err)
	}
	found := false
	for _, run := range listed.Runs {
		found = found || run.ID == runID
	}
	if !found {
		t.Fatal("created-time list omitted the selected run")
	}
	assertLiveResponseMetadata(t, listed.Responses)

	attemptResult, err := client.GetWorkflowRunAttempt(ctx, owner, repository, runID, attempt)
	if err != nil {
		t.Fatalf("get workflow run attempt: %v", err)
	}
	if attemptResult.Value.ID != runID || attemptResult.Value.RunAttempt != attempt {
		t.Fatalf("attempt identity disagrees with route: id=%d attempt=%d", attemptResult.Value.ID, attemptResult.Value.RunAttempt)
	}
	assertLiveResponseMetadata(t, attemptResult.Responses)
	if expected := strings.TrimSpace(os.Getenv("CIREWIND_LIVE_EXPECT_CALLED_SHA")); expected != "" {
		matched := false
		for _, called := range attemptResult.Value.ReferencedWorkflows {
			matched = matched || strings.EqualFold(called.SHA, expected)
		}
		if !matched {
			t.Fatalf("attempt did not include the expected called-workflow object ID")
		}
	}

	jobs, err := client.ListJobsForAttempt(ctx, owner, repository, runID, attempt)
	if err != nil {
		t.Fatalf("list jobs for attempt: %v", err)
	}
	expectNoJobs := os.Getenv("CIREWIND_LIVE_EXPECT_NO_JOBS") == "1"
	if jobs.TotalCount != len(jobs.Jobs) || (len(jobs.Jobs) == 0) != expectNoJobs {
		t.Fatalf("attempt job coverage is incomplete: total=%d collected=%d", jobs.TotalCount, len(jobs.Jobs))
	}
	for _, job := range jobs.Jobs {
		if job.ID <= 0 || job.RunID != runID {
			t.Fatalf("job identity disagrees with selected run")
		}
	}
	assertLiveResponseMetadata(t, jobs.Responses)

	expectMissingLogs := os.Getenv("CIREWIND_LIVE_EXPECT_MISSING_LOGS") == "1"
	attemptLog, err := client.DownloadAttemptLogs(ctx, owner, repository, runID, attempt, io.Discard)
	if err != nil {
		missingClass := IsClass(err, ErrorNotFound) || IsClass(err, ErrorRetentionOrDeletion)
		if (!expectNoJobs && !expectMissingLogs) || !missingClass {
			t.Fatalf("download attempt log to discard sink: %v", err)
		}
		assertLiveNotFoundMetadata(t, err, "attempt log")
		if expectMissingLogs && len(jobs.Jobs) != 0 {
			_, jobErr := client.DownloadJobLogs(ctx, owner, repository, jobs.Jobs[0].ID, io.Discard)
			if !IsClass(jobErr, ErrorNotFound) && !IsClass(jobErr, ErrorRetentionOrDeletion) {
				t.Fatalf("expired job log did not return a typed not-found result: %v", jobErr)
			}
			assertLiveNotFoundMetadata(t, jobErr, "job log")
		}
		t.Logf("qualified GET-only missing-log attempt: parent_attempts=%d selected_attempt=%d jobs=%d called_workflows=%d", parent.Value.RunAttempt, attempt, len(jobs.Jobs), len(attemptResult.Value.ReferencedWorkflows))
		return
	}
	if expectMissingLogs {
		t.Fatal("selected missing-log qualification target still retained its attempt log")
	}
	assertLiveDownload(t, attemptLog, "application/zip")
	if expectNoJobs {
		t.Logf("qualified GET-only jobless attempt: parent_attempts=%d selected_attempt=%d called_workflows=%d attempt_log=available", parent.Value.RunAttempt, attempt, len(attemptResult.Value.ReferencedWorkflows))
		return
	}
	jobLog, err := client.DownloadJobLogs(ctx, owner, repository, jobs.Jobs[0].ID, io.Discard)
	if err != nil {
		t.Fatalf("download job log to discard sink: %v", err)
	}
	assertLiveDownload(t, jobLog, "text/plain")

	t.Logf("qualified GET-only run metadata: parent_attempts=%d selected_attempt=%d jobs=%d called_workflows=%d", parent.Value.RunAttempt, attempt, len(jobs.Jobs), len(attemptResult.Value.ReferencedWorkflows))
}

func assertLiveNotFoundMetadata(t *testing.T, err error, subject string) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) || len(apiErr.Responses) == 0 {
		t.Fatalf("missing %s did not retain sanitized response metadata", subject)
	}
	last := apiErr.Responses[len(apiErr.Responses)-1]
	if last.StatusCode != http.StatusNotFound && last.StatusCode != http.StatusGone {
		t.Fatalf("missing %s status = %d, want 404 or 410", subject, last.StatusCode)
	}
	if last.Method != "GET" || last.RequestID == "" || last.APIVersion != APIVersion || last.RateLimit <= 0 || last.RateReset <= 0 {
		t.Fatalf("missing %s response provenance is incomplete", subject)
	}
}

func liveRepository(t *testing.T, value string) (string, string) {
	t.Helper()
	parts := strings.Split(value, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		t.Fatal("CIREWIND_LIVE_REPOSITORY must be one explicit owner/repository")
	}
	return parts[0], parts[1]
}

func livePositiveInt64(t *testing.T, name string) int64 {
	t.Helper()
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(name)), 10, 64)
	if err != nil || value <= 0 {
		t.Fatalf("%s must be a positive decimal integer", name)
	}
	return value
}

func assertLiveResponseMetadata(t *testing.T, responses []ResponseMeta) {
	t.Helper()
	if len(responses) == 0 {
		t.Fatal("request returned no response metadata")
	}
	finalSuccess := false
	for _, response := range responses {
		statusAllowed := response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound ||
			response.StatusCode == http.StatusTemporaryRedirect || response.StatusCode == http.StatusPermanentRedirect ||
			(response.StatusCode >= 200 && response.StatusCode < 300)
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			finalSuccess = true
		}
		if response.Method != "GET" || !statusAllowed ||
			response.RequestID == "" || response.APIVersion != APIVersion || !response.BodyComplete ||
			response.ResponseAPIVersion != APIVersion || response.ByteLength <= 0 || response.SHA256 == "" ||
			response.RateLimit <= 0 || response.RateReset <= 0 {
			t.Fatalf("incomplete safe response metadata: method=%q status=%d request_id=%t api=%q complete=%t bytes=%d hash=%t rate_limit=%d rate_reset=%d",
				response.Method, response.StatusCode, response.RequestID != "", response.APIVersion, response.BodyComplete,
				response.ByteLength, response.SHA256 != "", response.RateLimit, response.RateReset)
		}
	}
	if !finalSuccess {
		t.Fatal("request metadata did not end in a successful response")
	}
}

func assertLiveDownload(t *testing.T, result DownloadResult, mediaPrefix string) {
	t.Helper()
	if result.ByteLength <= 0 || result.SHA256 == "" || !strings.HasPrefix(result.MediaType, mediaPrefix) {
		t.Fatalf("download metadata is incomplete: media=%q bytes=%d hash=%t", result.MediaType, result.ByteLength, result.SHA256 != "")
	}
	if len(result.APIResponses) == 0 {
		t.Fatal("download returned no GitHub redirect response metadata")
	}
	finalTemporaryObject := false
	for _, response := range result.APIResponses {
		statusAllowed := response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusTemporaryRedirect ||
			response.StatusCode == http.StatusPermanentRedirect || response.StatusCode == http.StatusFound
		if response.StatusCode == http.StatusFound {
			finalTemporaryObject = true
		}
		if response.Method != "GET" || !statusAllowed || response.RequestID == "" ||
			response.APIVersion != APIVersion || !response.BodyComplete || response.SHA256 == "" ||
			response.RateLimit <= 0 || response.RateReset <= 0 {
			t.Fatalf("GitHub log-redirect response metadata is incomplete")
		}
	}
	if !finalTemporaryObject {
		t.Fatal("GitHub log acquisition did not end in a temporary-object redirect")
	}
	if len(result.StorageResponses) == 0 {
		t.Fatal("download returned no temporary-object response metadata")
	}
	for _, response := range result.StorageResponses {
		if response.Method != "GET" || response.StatusCode < 200 || response.StatusCode >= 300 || !response.BodyComplete || response.ByteLength <= 0 || response.SHA256 == "" {
			t.Fatalf("temporary log response metadata is incomplete")
		}
	}
}
