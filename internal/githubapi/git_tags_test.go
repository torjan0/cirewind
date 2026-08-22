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
	"strings"
	"sync/atomic"
	"testing"
)

func TestGetGitTagPreservesTagObjectAndCommitTarget(t *testing.T) {
	t.Parallel()
	tagID := strings.Repeat("a", 40)
	commitID := strings.Repeat("b", 40)
	body := fmt.Sprintf(`{"node_id":"tag-node","tag":"v1.2.3","sha":"%s","url":"https://api.github.test/ignored","object":{"type":"commit","sha":"%s","url":"https://api.github.test/ignored-commit"}}`, tagID, commitID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/shared/git/tags/"+tagID || r.URL.RawQuery != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("Accept") != DefaultAccept || r.Header.Get("X-GitHub-Api-Version") != APIVersion {
			t.Errorf("missing versioned GitHub headers")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", "tag-request-1")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).GetGitTag(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: tagID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.TagObjectID.Value != tagID || result.Value.Target.Kind != GitObjectCommit || result.Value.Target.ObjectID.Value != commitID {
		t.Fatalf("tag and target identities were not kept separate: %+v", result.Value)
	}
	if result.Value.TagObjectID == result.Value.Target.ObjectID {
		t.Fatal("tag object was overwritten by its commit target")
	}
	if len(result.Responses) != 1 {
		t.Fatalf("response metadata = %+v", result.Responses)
	}
	meta := result.Responses[0]
	hash := sha256.Sum256([]byte(body))
	if meta.RouteTemplate != "/repos/{owner}/{repo}/git/tags/{tag_sha}" || meta.RequestID != "tag-request-1" ||
		meta.RequestParameters["tag_algorithm"] != "sha1" || meta.RequestParameters["tag_sha"] != tagID ||
		meta.SHA256 != hex.EncodeToString(hash[:]) || !meta.BodyComplete {
		t.Fatalf("response metadata is incomplete: %+v", meta)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("api.github.test")) {
		t.Fatalf("normalized tag result retained an unneeded response URL: %s", encoded)
	}
}

func TestGetGitTagPreservesNestedTagTarget(t *testing.T) {
	t.Parallel()
	outerID := strings.Repeat("c", 64)
	innerID := strings.Repeat("d", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tag":"release","sha":"%s","object":{"type":"tag","sha":"%s"}}`, outerID, innerID)
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).GetGitTag(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha256", Value: outerID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.TagObjectID != (GitObjectID{Algorithm: "sha256", Value: outerID}) ||
		result.Value.Target.Kind != GitObjectTag ||
		result.Value.Target.ObjectID != (GitObjectID{Algorithm: "sha256", Value: innerID}) {
		t.Fatalf("nested tag target = %+v", result.Value)
	}
}

func TestGetGitTagRejectsIncompleteInputBeforeRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := newTestClient(t, server, NoToken())

	for _, object := range []GitObjectID{
		{},
		{Algorithm: "sha512", Value: strings.Repeat("a", 128)},
		{Algorithm: "sha1", Value: strings.Repeat("a", 39)},
		{Algorithm: "sha1", Value: strings.Repeat("A", 40)},
		{Algorithm: "sha256", Value: strings.Repeat("g", 64)},
	} {
		if _, err := client.GetGitTag(context.Background(), "acme", "shared", object); !IsClass(err, ErrorInvalidRequest) {
			t.Errorf("object=%+v error=%v", object, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid object IDs caused %d requests", calls.Load())
	}
}

func TestGetGitTagRejectsMalformedTypedResponses(t *testing.T) {
	t.Parallel()
	tagID := strings.Repeat("a", 40)
	targetID := strings.Repeat("b", 40)
	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", `{"tag":`},
		{"missing tag name", fmt.Sprintf(`{"sha":"%s","object":{"type":"commit","sha":"%s"}}`, tagID, targetID)},
		{"missing returned tag ID", fmt.Sprintf(`{"tag":"v1","object":{"type":"commit","sha":"%s"}}`, targetID)},
		{"mismatched returned tag ID", fmt.Sprintf(`{"tag":"v1","sha":"%s","object":{"type":"commit","sha":"%s"}}`, targetID, targetID)},
		{"unsupported target type", fmt.Sprintf(`{"tag":"v1","sha":"%s","object":{"type":"commitish","sha":"%s"}}`, tagID, targetID)},
		{"short target ID", fmt.Sprintf(`{"tag":"v1","sha":"%s","object":{"type":"commit","sha":"abc"}}`, tagID)},
		{"uppercase target ID", fmt.Sprintf(`{"tag":"v1","sha":"%s","object":{"type":"commit","sha":"%s"}}`, tagID, strings.Repeat("B", 40))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			result, err := newTestClient(t, server, NoToken()).GetGitTag(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: tagID})
			if !IsClass(err, ErrorMalformedResponse) {
				t.Fatalf("error = %v", err)
			}
			if len(result.Responses) != 1 || result.Responses[0].StatusCode != http.StatusOK {
				t.Fatalf("malformed response metadata = %+v", result.Responses)
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || len(apiErr.Responses) != 1 || apiErr.Responses[0].ErrorClass != ErrorMalformedResponse {
				t.Fatalf("malformed error provenance = %#v", err)
			}
		})
	}
}

func TestGetGitTagNotFoundIsSanitizedAndRecorded(t *testing.T) {
	t.Parallel()
	const token = "TEST_GIT_TAG_TOKEN_SENTINEL"
	tagID := strings.Repeat("e", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", "missing-tag")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, "missing %s\n\x1b[31m", token)
	}))
	defer server.Close()

	result, err := newTestClient(t, server, StaticToken(token)).GetGitTag(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: tagID})
	if !IsClass(err, ErrorNotFound) || strings.Contains(err.Error(), token) || strings.ContainsRune(err.Error(), '\n') || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("unsafe or incorrect error: %q", err)
	}
	if len(result.Responses) != 1 || result.Responses[0].StatusCode != http.StatusNotFound || result.Responses[0].ErrorClass != ErrorNotFound {
		t.Fatalf("not-found response metadata = %+v", result.Responses)
	}
}

func TestGetGitTagCancelledContextMakesNoRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := newTestClient(t, server, NoToken()).GetGitTag(ctx, "acme", "shared", GitObjectID{Algorithm: "sha1", Value: strings.Repeat("f", 40)})
	if !IsClass(err, ErrorCancelled) || calls.Load() != 0 || len(result.Responses) != 0 {
		t.Fatalf("error=%v calls=%d responses=%+v", err, calls.Load(), result.Responses)
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) || !errors.Is(apiErr, context.Canceled) {
		t.Fatalf("cancel cause was not preserved: %v", err)
	}
}
