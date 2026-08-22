package githubapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetGitCommitPositivelyTypesExactObject(t *testing.T) {
	t.Parallel()
	commitID, treeID, parentID := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/acme/shared/git/commits/"+commitID || r.URL.RawQuery != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", "commit-request-1")
		_, _ = fmt.Fprintf(w, `{"sha":"%s","node_id":"commit-node","url":"https://ignored.invalid","tree":{"sha":"%s","url":"https://ignored.invalid/tree"},"parents":[{"sha":"%s","url":"https://ignored.invalid/parent"}]}`, commitID, treeID, parentID)
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).GetGitCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: commitID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value.CommitObjectID.Value != commitID || result.Value.TreeObjectID.Value != treeID ||
		len(result.Value.ParentObjectIDs) != 1 || result.Value.ParentObjectIDs[0].Value != parentID {
		t.Fatalf("commit object = %+v", result.Value)
	}
	if len(result.Responses) != 1 || result.Responses[0].RouteTemplate != "/repos/{owner}/{repo}/git/commits/{commit_sha}" ||
		result.Responses[0].RequestParameters["commit_sha"] != commitID {
		t.Fatalf("response provenance = %+v", result.Responses)
	}
	if strings.Contains(fmt.Sprintf("%+v", result.Value), "ignored.invalid") {
		t.Fatal("normalized commit retained response URLs")
	}
}

func TestGetGitCommitRejectsWrongOrMalformedObject(t *testing.T) {
	t.Parallel()
	requested, other, tree := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	for _, test := range []struct {
		name string
		body string
	}{
		{"mismatch", fmt.Sprintf(`{"sha":"%s","tree":{"sha":"%s"},"parents":[]}`, other, tree)},
		{"short tree", fmt.Sprintf(`{"sha":"%s","tree":{"sha":"abc"},"parents":[]}`, requested)},
		{"bad parent", fmt.Sprintf(`{"sha":"%s","tree":{"sha":"%s"},"parents":[{"sha":"xyz"}]}`, requested, tree)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestClient(t, server, NoToken()).GetGitCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: requested})
			if !IsClass(err, ErrorMalformedResponse) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestGetGitCommitRejectsInvalidInputWithoutRequest(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("request made") }))
	defer server.Close()
	_, err := newTestClient(t, server, NoToken()).GetGitCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: "short"})
	if !IsClass(err, ErrorInvalidRequest) {
		t.Fatalf("error = %v", err)
	}
}
