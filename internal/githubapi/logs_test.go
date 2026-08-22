package githubapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLogRedirectStripsAuthorizationAndSignedLocation(t *testing.T) {
	t.Parallel()
	const token = "LOG_TOKEN_SENTINEL"
	content := []byte("runner-owned fixture log\n")
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("storage authorization = %q", got)
		}
		if got := r.Header.Get("Cookie"); got != "" {
			t.Errorf("storage cookie = %q", got)
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(content)
	}))
	defer storage.Close()

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("API authorization = %q", got)
		}
		w.Header().Set("Location", storage.URL+"/object?sig=SIGNED_QUERY_SENTINEL")
		w.WriteHeader(http.StatusFound)
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, StaticToken(token))
	var destination bytes.Buffer
	result, err := client.DownloadAttemptLogs(context.Background(), "acme", "service", 99, 1, &destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), content) {
		t.Fatalf("download = %q", destination.Bytes())
	}
	hash := sha256.Sum256(content)
	if result.SHA256 != hex.EncodeToString(hash[:]) || result.ByteLength != int64(len(content)) || result.RenewedRedirect {
		t.Fatalf("result = %+v", result)
	}
	encoded := result.StringForTest()
	if strings.Contains(encoded, "SIGNED_QUERY_SENTINEL") || strings.Contains(encoded, token) || strings.Contains(encoded, storage.URL) {
		t.Fatalf("result persisted redirect or token: %s", encoded)
	}
}

func TestExpiredLogRedirectIsRenewedOnce(t *testing.T) {
	t.Parallel()
	var storageCalls atomic.Int32
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if storageCalls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("job log"))
	}))
	defer storage.Close()
	var apiCalls atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		apiCalls.Add(1)
		w.Header().Set("Location", storage.URL+"/object?sig=short-lived")
		w.WriteHeader(http.StatusFound)
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken())
	var destination bytes.Buffer
	result, err := client.DownloadJobLogs(context.Background(), "acme", "service", 501, &destination)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RenewedRedirect || apiCalls.Load() != 2 || len(result.StorageResponses) != 2 || result.StorageResponses[0].ErrorClass != ErrorRedirectExpired || destination.String() != "job log" {
		t.Fatalf("result=%+v apiCalls=%d body=%q", result, apiCalls.Load(), destination.String())
	}
}

func TestLogDownloadFollowsBoundedSameOriginRepositoryRelocation(t *testing.T) {
	t.Parallel()
	const token = "LOG_RENAME_TOKEN_SENTINEL"
	content := []byte("renamed repository log\n")
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("authorization reached temporary storage")
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(content)
	}))
	defer storage.Close()
	var calls atomic.Int32
	var api *httptest.Server
	api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("API authorization = %q", got)
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Location", api.URL+"/repositories/42/actions/jobs/501/logs")
			w.WriteHeader(http.StatusMovedPermanently)
			_, _ = w.Write([]byte(`{"message":"Moved Permanently"}`))
			return
		}
		w.Header().Set("Location", storage.URL+"/object?sig=short-lived")
		w.WriteHeader(http.StatusFound)
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, StaticToken(token))
	var destination bytes.Buffer
	result, err := client.DownloadJobLogs(context.Background(), "acme", "old-name", 501, &destination)
	if err != nil {
		t.Fatal(err)
	}
	if destination.String() != string(content) || calls.Load() != 2 || len(result.APIResponses) != 2 ||
		result.APIResponses[0].StatusCode != http.StatusMovedPermanently || result.APIResponses[1].StatusCode != http.StatusFound {
		t.Fatalf("destination=%q calls=%d result=%+v", destination.String(), calls.Load(), result)
	}
}

func TestLogDownloadRejectsCrossOriginRepositoryRelocationWithoutCredentialForwarding(t *testing.T) {
	t.Parallel()
	var storageCalls atomic.Int32
	storage := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer storage.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", storage.URL+"/capture")
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte(`{"message":"Moved Permanently"}`))
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, StaticToken("LOG_REDIRECT_TOKEN_SENTINEL"))
	_, err := client.DownloadJobLogs(context.Background(), "acme", "old-name", 501, io.Discard)
	if !IsClass(err, ErrorUnsafeRedirect) || storageCalls.Load() != 0 {
		t.Fatalf("error=%v storage_calls=%d", err, storageCalls.Load())
	}
}

func TestExpiredRetainedLogIsNotMisclassifiedAsAPIVersionFailure(t *testing.T) {
	t.Parallel()
	var storageCalls atomic.Int32
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		storageCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer storage.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Api-Version-Selected", APIVersion)
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"message":"Server Error","status":"410"}`))
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken())
	_, err := client.DownloadAttemptLogs(context.Background(), "acme", "service", 99, 1, io.Discard)
	if !IsClass(err, ErrorRetentionOrDeletion) || IsClass(err, ErrorAPIVersion) || storageCalls.Load() != 0 {
		t.Fatalf("error=%v storage_calls=%d", err, storageCalls.Load())
	}
}

func TestLogGoneWithoutSelectedAPIVersionRemainsVersionFailure(t *testing.T) {
	t.Parallel()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer storage.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"message":"API version retired"}`))
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken())
	_, err := client.DownloadAttemptLogs(context.Background(), "acme", "service", 99, 1, io.Discard)
	if !IsClass(err, ErrorAPIVersion) || IsClass(err, ErrorRetentionOrDeletion) {
		t.Fatalf("error=%v", err)
	}
}

func TestSecondStorageRedirectIsRejected(t *testing.T) {
	t.Parallel()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://example.invalid/again")
		w.WriteHeader(http.StatusFound)
	}))
	defer storage.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", storage.URL+"/object")
		w.WriteHeader(http.StatusFound)
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken())
	_, err := client.DownloadJobLogs(context.Background(), "acme", "service", 501, &bytes.Buffer{})
	if !IsClass(err, ErrorUnsafeRedirect) {
		t.Fatalf("error = %v", err)
	}
}

func TestLogDownloadByteLimit(t *testing.T) {
	t.Parallel()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("123456789"))
	}))
	defer storage.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", storage.URL+"/object")
		w.WriteHeader(http.StatusFound)
	}))
	defer api.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken(), func(cfg *clientConfig) error {
		cfg.limits.JobLogBytes = 4
		return nil
	})
	var destination bytes.Buffer
	result, err := client.DownloadJobLogs(context.Background(), "acme", "service", 501, &destination)
	if !IsClass(err, ErrorSizeLimit) {
		t.Fatalf("error = %v", err)
	}
	if len(result.StorageResponses) != 1 || destination.String() != "1234" || result.StorageResponses[0].BodyComplete || result.StorageResponses[0].SHA256 != "" {
		t.Fatalf("destination=%q result=%+v", destination.String(), result)
	}
}

func TestDefaultRedirectValidatorRejectsHTTPAndPrivateAddress(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"http://results.actions.githubusercontent.com/object",
		"https://127.0.0.1/object",
		"https://example.invalid/object",
	} {
		t.Run(value, func(t *testing.T) {
			target, err := url.Parse(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := defaultRedirectValidator(context.Background(), target); err == nil {
				t.Fatal("unsafe redirect accepted")
			}
		})
	}
}

func TestLogRedirectLoopInvariantFailsClosed(t *testing.T) {
	t.Parallel()
	api := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request must not be attempted with an invalid retry invariant")
	}))
	defer api.Close()
	storage := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("storage must not be contacted with an invalid retry invariant")
	}))
	defer storage.Close()

	client := newTLSRedirectTestClient(t, api, storage, NoToken())
	client.retry.MaxAttempts = 0 // Simulate a future internal refactor bypassing constructor validation.
	var destination bytes.Buffer
	_, err := client.DownloadJobLogs(context.Background(), "acme", "service", 501, &destination)
	if !IsClass(err, ErrorRetryBudget) {
		t.Fatalf("error = %v", err)
	}
}

func newTLSRedirectTestClient(t *testing.T, api, storage *httptest.Server, tokens TokenSource, options ...Option) *Client {
	t.Helper()
	base, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // test servers only
	storageURL, _ := url.Parse(storage.URL)
	baseOptions := []Option{
		WithHTTPClient(httpClient),
		WithRetryPolicy(RetryPolicy{MaxAttempts: 1}),
		func(cfg *clientConfig) error {
			cfg.redirectValidator = func(_ context.Context, candidate *url.URL) error {
				if candidate.Scheme != "https" || candidate.Host != storageURL.Host || candidate.User != nil {
					return &Error{Class: ErrorUnsafeRedirect, Operation: "test", Message: "redirect outside test storage"}
				}
				return nil
			}
			return nil
		},
	}
	baseOptions = append(baseOptions, options...)
	client, err := newClient(base, tokens, true, baseOptions...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (d DownloadResult) StringForTest() string {
	encoded, _ := json.Marshal(d)
	return string(encoded)
}
