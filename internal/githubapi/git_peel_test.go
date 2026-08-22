package githubapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPeelGitObjectPreservesRecordedTagAndPositiveCommit(t *testing.T) {
	t.Parallel()
	tagID, commitID, treeID := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/shared/git/tags/" + tagID:
			_, _ = fmt.Fprintf(w, `{"tag":"v1","sha":"%s","object":{"type":"commit","sha":"%s"}}`, tagID, commitID)
		case "/repos/acme/shared/git/commits/" + commitID:
			_, _ = fmt.Fprintf(w, `{"sha":"%s","tree":{"sha":"%s"},"parents":[]}`, commitID, treeID)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).PeelGitObjectToCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: tagID})
	if err != nil {
		t.Fatal(err)
	}
	if result.RecordedKind != GitObjectTag || result.RecordedObjectID.Value != tagID || len(result.TagObjects) != 1 ||
		result.CommitObject == nil || result.CommitObject.CommitObjectID.Value != commitID {
		t.Fatalf("peel result = %+v", result)
	}
	if result.RecordedObjectID == result.CommitObject.CommitObjectID {
		t.Fatal("recorded tag object was overwritten by commit")
	}
}

func TestPeelGitObjectRequiresPositiveCommitAfterTagMiss(t *testing.T) {
	t.Parallel()
	commitID, treeID := strings.Repeat("d", 40), strings.Repeat("e", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/shared/git/tags/" + commitID:
			http.NotFound(w, r)
		case "/repos/acme/shared/git/commits/" + commitID:
			_, _ = fmt.Fprintf(w, `{"sha":"%s","tree":{"sha":"%s"},"parents":[]}`, commitID, treeID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := newTestClient(t, server, NoToken()).PeelGitObjectToCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: commitID})
	if err != nil {
		t.Fatal(err)
	}
	if result.RecordedKind != GitObjectCommit || result.CommitObject == nil || len(result.TagObjects) != 0 || len(result.Responses) != 2 {
		t.Fatalf("commit typing result = %+v", result)
	}

	missingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer missingServer.Close()
	missing, err := newTestClient(t, missingServer, NoToken()).PeelGitObjectToCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: commitID})
	if err == nil || missing.CommitObject != nil {
		t.Fatalf("two 404s invented a commit: result=%+v error=%v", missing, err)
	}
}

func TestPeelGitObjectRejectsCycleAndNonCommitTerminal(t *testing.T) {
	t.Parallel()
	first, second, tree := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	t.Run("cycle", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/repos/acme/shared/git/tags/" + first:
				_, _ = fmt.Fprintf(w, `{"tag":"one","sha":"%s","object":{"type":"tag","sha":"%s"}}`, first, second)
			case "/repos/acme/shared/git/tags/" + second:
				_, _ = fmt.Fprintf(w, `{"tag":"two","sha":"%s","object":{"type":"tag","sha":"%s"}}`, second, first)
			}
		}))
		defer server.Close()
		result, err := newTestClient(t, server, NoToken()).PeelGitObjectToCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: first})
		if err == nil || !strings.Contains(err.Error(), "cycle") || result.CommitObject != nil || len(result.TagObjects) != 2 {
			t.Fatalf("cycle result=%+v error=%v", result, err)
		}
	})
	t.Run("tree", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"tag":"tree","sha":"%s","object":{"type":"tree","sha":"%s"}}`, first, tree)
		}))
		defer server.Close()
		result, err := newTestClient(t, server, NoToken()).PeelGitObjectToCommit(context.Background(), "acme", "shared", GitObjectID{Algorithm: "sha1", Value: first})
		if err == nil || !strings.Contains(err.Error(), "unsupported tree") || result.CommitObject != nil {
			t.Fatalf("tree result=%+v error=%v", result, err)
		}
	})
}
