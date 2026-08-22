package githubapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, server *httptest.Server, tokens TokenSource, options ...Option) *Client {
	t.Helper()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	options = append([]Option{WithHTTPClient(server.Client()), WithRetryPolicy(RetryPolicy{MaxAttempts: 1})}, options...)
	client, err := newClient(base, tokens, true, options...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestGetRepositoryHeadersAndEvidenceMetadata(t *testing.T) {
	t.Parallel()
	const token = "TEST_TOKEN_SENTINEL"
	body := `{"id":42,"name":"service","full_name":"acme/service","owner":{"id":7,"login":"acme"}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != DefaultAccept {
			t.Errorf("accept = %q", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != APIVersion {
			t.Errorf("API version = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "CIRewind/test" {
			t.Errorf("user agent = %q", got)
		}
		if r.URL.Path != "/repos/acme/service" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-GitHub-Request-Id", "request-1")
		w.Header().Set("X-GitHub-Api-Version", APIVersion)
		w.Header().Set("ETag", `"fixture"`)
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4999")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := newTestClient(t, server, StaticToken(token), WithUserAgent("CIRewind/test"))
	result, err := client.GetRepository(context.Background(), "acme", "service")
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.ID != 42 || len(result.Responses) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	meta := result.Responses[0]
	wantHash := sha256.Sum256([]byte(body))
	if meta.SHA256 != hex.EncodeToString(wantHash[:]) || !meta.BodyComplete || meta.ByteLength != int64(len(body)) {
		t.Fatalf("unexpected body evidence: %+v", meta)
	}
	if meta.RouteTemplate != "/repos/{owner}/{repo}" || meta.RequestID != "request-1" || meta.RateRemaining != 4999 {
		t.Fatalf("unexpected request evidence: %+v", meta)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(token)) || bytes.Contains(encoded, []byte("Authorization")) {
		t.Fatalf("serialized result contains authentication material: %s", encoded)
	}
}

func TestEnvTokenPrecedence(t *testing.T) {
	t.Parallel()
	values := map[string]string{
		"CIREWIND_GITHUB_TOKEN": "first",
		"GITHUB_TOKEN":          "second",
		"GH_TOKEN":              "third",
	}
	source := EnvTokenWithLookup(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "first" {
		t.Fatalf("token = %q", token)
	}
}

func TestOrganizationRepositoryPagination(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?per_page=100&type=all&page=2>; rel="next"`, server.URL))
			_, _ = w.Write([]byte(`[ {"id":1,"name":"one"} ]`))
		case "2":
			_, _ = w.Write([]byte(`[ {"id":2,"name":"two"} ]`))
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).ListOrganizationRepositories(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 2 || result.Repositories[0].ID != 1 || result.Repositories[1].ID != 2 || len(result.Responses) != 2 {
		t.Fatalf("unexpected pagination result: %+v", result)
	}
}

func TestPaginationRejectsCrossOriginNextLink(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", `<https://example.invalid/stolen>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	_, err := newTestClient(t, server, NoToken()).ListOrganizationRepositories(context.Background(), "acme")
	if !IsClass(err, ErrorPagination) {
		t.Fatalf("error = %v", err)
	}
}

func TestGetFollowsBoundedSameOriginRepositoryRedirect(t *testing.T) {
	t.Parallel()
	const token = "TEST_RENAME_TOKEN_SENTINEL"
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Api-Version-Selected", APIVersion)
		switch r.URL.Path {
		case "/repos/acme/old-name":
			w.Header().Set("Location", server.URL+"/repositories/42")
			w.WriteHeader(http.StatusMovedPermanently)
			_, _ = w.Write([]byte(`{"message":"Moved Permanently"}`))
		case "/repositories/42":
			_, _ = w.Write([]byte(`{"id":42,"name":"new-name","full_name":"acme/new-name","owner":{"id":7,"login":"acme"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := newTestClient(t, server, StaticToken(token)).GetRepository(context.Background(), "acme", "old-name")
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.ID != 42 || result.Value.FullName != "acme/new-name" || calls.Load() != 2 || len(result.Responses) != 2 {
		t.Fatalf("redirect result=%+v calls=%d", result, calls.Load())
	}
	if result.Responses[0].StatusCode != http.StatusMovedPermanently || result.Responses[1].StatusCode != http.StatusOK ||
		result.Responses[0].ResponseAPIVersion != APIVersion || result.Responses[1].ResponseAPIVersion != APIVersion {
		t.Fatalf("redirect response provenance = %+v", result.Responses)
	}
}

func TestGetRejectsCrossOriginRepositoryRedirectWithoutCredentialForwarding(t *testing.T) {
	t.Parallel()
	var attackerCalls atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		attackerCalls.Add(1)
	}))
	defer attacker.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", attacker.URL+"/capture")
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte(`{"message":"Moved Permanently"}`))
	}))
	defer server.Close()

	_, err := newTestClient(t, server, StaticToken("TEST_REDIRECT_TOKEN_SENTINEL")).GetRepository(context.Background(), "acme", "old-name")
	if !IsClass(err, ErrorUnsafeRedirect) || attackerCalls.Load() != 0 {
		t.Fatalf("error=%v attacker_calls=%d", err, attackerCalls.Load())
	}
}

func TestGetRejectsRepositoryRedirectCycle(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/repos/acme/old-name" {
			w.Header().Set("Location", server.URL+"/repositories/42")
		} else {
			w.Header().Set("Location", server.URL+"/repos/acme/old-name")
		}
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte(`{"message":"Moved Permanently"}`))
	}))
	defer server.Close()

	_, err := newTestClient(t, server, NoToken()).GetRepository(context.Background(), "acme", "old-name")
	if !IsClass(err, ErrorUnsafeRedirect) {
		t.Fatalf("error = %v", err)
	}
}

func TestRetryAfterIsHonoredAndRecorded(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"slow down"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":42}`))
	}))
	defer server.Close()

	var slept time.Duration
	option := func(cfg *clientConfig) error {
		cfg.retry = RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Minute, SecondaryMinDelay: time.Minute}
		cfg.jitter = func(time.Duration) time.Duration { return 0 }
		cfg.sleep = func(_ context.Context, duration time.Duration) error {
			slept = duration
			return nil
		}
		return nil
	}
	client := newTestClient(t, server, NoToken(), option)
	result, err := client.GetRepository(context.Background(), "acme", "service")
	if err != nil {
		t.Fatal(err)
	}
	if slept != 7*time.Second || len(result.Responses) != 2 || result.Responses[0].RetryAfterSeconds != 7 {
		t.Fatalf("sleep=%s responses=%+v", slept, result.Responses)
	}
}

func TestErrorSanitizesTokenAndControls(t *testing.T) {
	t.Parallel()
	const token = "TEST_TOKEN_DO_NOT_PERSIST"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, "denied %s\n\x1b[31m", token)
	}))
	defer server.Close()

	_, err := newTestClient(t, server, StaticToken(token)).GetRepository(context.Background(), "acme", "service")
	if !IsClass(err, ErrorForbidden) {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), token) || strings.ContainsRune(err.Error(), '\x1b') || strings.ContainsRune(err.Error(), '\n') {
		t.Fatalf("unsafe diagnostic: %q", err.Error())
	}
}

func TestHTTPFailuresHaveStableClasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status  int
		body    string
		headers map[string]string
		want    ErrorClass
	}{
		{http.StatusUnauthorized, `{"message":"bad credentials"}`, nil, ErrorUnauthorized},
		{http.StatusForbidden, `{"message":"permission denied"}`, nil, ErrorForbidden},
		{http.StatusNotFound, `{"message":"not found"}`, nil, ErrorNotFound},
		{http.StatusGone, `{"message":"version retired"}`, nil, ErrorAPIVersion},
		{http.StatusUnprocessableEntity, `{"message":"invalid"}`, nil, ErrorValidation},
		{http.StatusTooManyRequests, `{"message":"rate"}`, map[string]string{"Retry-After": "1"}, ErrorRateLimited},
		{http.StatusInternalServerError, `{"message":"temporary"}`, nil, ErrorTransient},
		{http.StatusForbidden, `{"message":"secondary rate limit"}`, nil, ErrorSecondaryLimit},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%d-%s", test.status, test.want), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				for key, value := range test.headers {
					w.Header().Set(key, value)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestClient(t, server, NoToken()).GetRepository(context.Background(), "acme", "service")
			if !IsClass(err, test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCancelledContextMakesNoRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestClient(t, server, NoToken()).GetRepository(ctx, "acme", "service")
	if !IsClass(err, ErrorCancelled) || calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestBoundedResponseDoesNotClaimCompleteHash(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":123456789,"name":"too-large"}`))
	}))
	defer server.Close()

	limitOption := func(cfg *clientConfig) error {
		cfg.limits.JSONResponseBytes = 8
		return nil
	}
	_, err := newTestClient(t, server, NoToken(), limitOption).GetRepository(context.Background(), "acme", "service")
	if !IsClass(err, ErrorSizeLimit) {
		t.Fatalf("error = %v", err)
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) || len(apiErr.Responses) != 1 {
		t.Fatalf("missing response evidence: %#v", err)
	}
	meta := apiErr.Responses[0]
	if meta.BodyComplete || meta.SHA256 != "" || meta.ByteLength != 8 {
		t.Fatalf("oversize response incorrectly represented: %+v", meta)
	}
}

func TestAttemptJobContentAndHashRoutes(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/service/actions/runs/99":
			_, _ = w.Write([]byte(`{"id":99,"run_attempt":2,"created_at":"2026-08-20T00:00:00Z"}`))
		case "/repos/acme/service/actions/runs/99/attempts/1":
			_, _ = w.Write([]byte(`{"id":99,"run_attempt":1,"created_at":"2026-08-20T00:00:00Z","referenced_workflows":[{"path":"acme/shared/.github/workflows/x.yml@v1","sha":"abc","ref":"refs/tags/v1"}]}`))
		case "/repos/acme/service/actions/runs/99/attempts/1/jobs":
			if r.URL.Query().Get("filter") != "all" || r.URL.Query().Get("per_page") != "100" {
				t.Errorf("job query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"total_count":1,"jobs":[{"id":501,"run_id":99,"name":"matrix"}]}`))
		case "/repos/acme/service/hash-algorithm":
			_, _ = w.Write([]byte(`{"hash_algorithm":"sha256"}`))
		case "/repos/acme/service/contents/.github/workflows/build.yml":
			if r.URL.Query().Get("ref") != "abcdef" {
				t.Errorf("content ref = %q", r.URL.Query().Get("ref"))
			}
			_, _ = w.Write([]byte(`{"type":"file","path":".github/workflows/build.yml","sha":"blob","encoding":"base64","content":"eA=="}`))
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server, NoToken())

	if result, err := client.GetWorkflowRun(context.Background(), "acme", "service", 99); err != nil || result.Value.RunAttempt != 2 {
		t.Fatalf("run=%+v err=%v", result, err)
	}
	if result, err := client.GetWorkflowRunAttempt(context.Background(), "acme", "service", 99, 1); err != nil || len(result.Value.ReferencedWorkflows) != 1 {
		t.Fatalf("attempt=%+v err=%v", result, err)
	}
	if result, err := client.ListJobsForAttempt(context.Background(), "acme", "service", 99, 1); err != nil || len(result.Jobs) != 1 {
		t.Fatalf("jobs=%+v err=%v", result, err)
	}
	if result, err := client.GetRepositoryHashAlgorithm(context.Background(), "acme", "service"); err != nil || result.Value != "sha256" {
		t.Fatalf("algorithm=%+v err=%v", result, err)
	}
	object := GitObjectID{Algorithm: "sha1", Value: "abcdef"}
	if result, err := client.GetContentAtObject(context.Background(), "acme", "service", ".github/workflows/build.yml", object); err != nil || result.Value.SHA != "blob" {
		t.Fatalf("content=%+v err=%v", result, err)
	}
}

func TestWorkflowRunProbeAndFilteredCeiling(t *testing.T) {
	t.Parallel()
	created := "2026-08-20T00:00:00Z..2026-08-20T01:00:00Z"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/repos/acme/service/actions/runs" || r.URL.Query().Get("created") != created {
			http.Error(w, "unexpected route", http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("per_page") {
		case "1":
			_, _ = w.Write([]byte(`{"total_count":1000,"workflow_runs":[]}`))
		case "100":
			runs := make([]map[string]any, 100)
			for index := range runs {
				runs[index] = map[string]any{"id": index + 1, "created_at": "2026-08-20T00:00:00Z"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1000, "workflow_runs": runs})
		default:
			http.Error(w, "unexpected per_page", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server, NoToken())
	probe, err := client.ProbeWorkflowRuns(context.Background(), "acme", "service", created)
	if err != nil || probe.TotalCount != 1000 {
		t.Fatalf("probe=%+v err=%v", probe, err)
	}
	listed, err := client.ListWorkflowRuns(context.Background(), "acme", "service", created)
	if err != nil {
		t.Fatal(err)
	}
	if !listed.Truncated || listed.TotalCount != 1000 || len(listed.Runs) != 100 {
		t.Fatalf("listed = %+v", listed)
	}
}

func TestNewRejectsNonGitHubEndpointByDefault(t *testing.T) {
	t.Parallel()
	base, _ := url.Parse("https://github.example.test/api")
	_, err := newClient(base, NoToken(), false)
	if !IsClass(err, ErrorUnsupportedTarget) {
		t.Fatalf("error = %v", err)
	}
}

func TestRequestLoopInvariantFailsClosed(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request must not be attempted with an invalid retry invariant")
	}))
	defer server.Close()

	client := newTestClient(t, server, NoToken())
	client.retry.MaxAttempts = 0 // Simulate a future internal refactor bypassing constructor validation.
	_, err := client.GetRepository(context.Background(), "acme", "service")
	if !IsClass(err, ErrorRetryBudget) {
		t.Fatalf("error = %v", err)
	}
}
