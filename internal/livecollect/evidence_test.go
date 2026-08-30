package livecollect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/githubapi"
)

func TestProjectResponsesPreservesSafeAcquisitionMetadata(t *testing.T) {
	t.Parallel()
	started := time.Date(2026, time.August, 21, 1, 2, 3, 0, time.UTC)
	completed := started.Add(time.Second)
	got := projectResponses([]githubapi.ResponseMeta{{
		Method: "GET", RouteTemplate: "/repos/{owner}/{repo}/actions/runs",
		RequestParameters: map[string]string{"page": "2", "created": "2026-08-20T00:00:00Z..2026-08-21T00:00:00Z"},
		StatusCode:        200, RequestID: "request-1", APIVersion: githubapi.APIVersion,
		ResponseAPIVersion: githubapi.APIVersion, MediaType: "application/json", ByteLength: 42,
		SHA256: strings.Repeat("a", 64), BodyComplete: true, ETag: `"fixture"`,
		RateLimit: 5000, RateRemaining: 4998, RateUsed: 2, RateReset: 1787274000,
		RateResource: "core", RetryAfterSeconds: 0, StartedAt: started, CompletedAt: completed,
	}})
	if len(got) != 1 {
		t.Fatalf("projected responses = %d, want 1", len(got))
	}
	response := got[0]
	if response.Method != "GET" || response.StatusCode != 200 || response.RequestID != "request-1" ||
		response.APIVersion != githubapi.APIVersion || response.ResponseAPIVersion != githubapi.APIVersion ||
		response.RequestParameters["page"] != "2" || response.ETag != `"fixture"` ||
		response.RateLimit != 5000 || response.RateRemaining != 4998 || response.RateUsed != 2 ||
		response.RateReset != 1787274000 || response.RateResource != "core" {
		t.Fatalf("response metadata was not preserved: %#v", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"Authorization", "Bearer ", "signed_redirect"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("projected response contains forbidden material %q: %s", forbidden, encoded)
		}
	}
}

func TestJobProjectionPreservesRunnerGroupIDPresenceIncludingZero(t *testing.T) {
	t.Parallel()
	zero := int64(0)
	withZero := projectJob(1, 2, 1, githubapi.WorkflowJob{ID: 3, Labels: []string{}, RunnerGroupID: &zero})
	zero = 99
	encoded, err := json.Marshal(withZero)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"runner_group_id":0`) {
		t.Fatalf("meaningful zero runner-group ID was not retained: %s", encoded)
	}

	withoutID := projectJob(1, 2, 1, githubapi.WorkflowJob{ID: 3, Labels: []string{}, RunnerGroupName: "GitHub Actions"})
	encoded, err = json.Marshal(withoutID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "runner_group_id") {
		t.Fatalf("absent runner-group ID was manufactured from a group name: %s", encoded)
	}
}
