package packreview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizePlatformSnapshotFromPaginatedGitHubResponse(t *testing.T) {
	reviewBody := "ignored hostile <script> SYNTHETIC_REVIEW_BODY_MARKER"
	raw := []byte(`[[{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"Synthetic-Reviewer","id":301,"type":"User"},"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z","body":"` + reviewBody + `","irrelevant":"ignored hostile <script>\u001b[31m"}],[{"id":43,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-43","user":null,"state":"PENDING","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":null}]]`)
	snapshot, canonical, err := NormalizePlatformSnapshot(context.Background(), raw, syntheticPlatformOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Approvals) != 1 || snapshot.Approvals[0].Reviewer.Login != "synthetic-reviewer" || snapshot.ResponseSHA256 != digestHex(raw) ||
		snapshot.Approvals[0].BodySHA256 != digestHex([]byte(reviewBody)) {
		t.Fatalf("unexpected normalized snapshot: %+v", snapshot)
	}
	if !bytes.HasSuffix(canonical, []byte("\n")) || bytes.Contains(canonical, []byte("ignored hostile")) || bytes.Contains(canonical, []byte("CIRewind review assertion")) {
		t.Fatalf("canonical snapshot retained unneeded review content: %s", canonical)
	}
}

func TestNormalizePlatformSnapshotRejectsHostileSourceForms(t *testing.T) {
	for _, test := range []struct {
		name, raw, code string
	}{
		{"duplicate key", `[{"id":1,"id":2}]`, "DUPLICATE_JSON_KEY"},
		{"mixed pages", `[[{"id":1}],{"id":2}]`, "PLATFORM_SOURCE_SHAPE"},
		{"unknown state", `[{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"reviewer","id":301,"type":"User"},"state":"MYSTERY","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z"}]`, "PLATFORM_SOURCE_STATE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NormalizePlatformSnapshot(context.Background(), []byte(test.raw), syntheticPlatformOptions())
			assertProblemCode(t, err, test.code)
		})
	}
	deep := []byte(strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1))
	_, _, err := NormalizePlatformSnapshot(context.Background(), deep, syntheticPlatformOptions())
	assertProblemCode(t, err, "JSON_STRUCTURE_LIMIT")
	_, _, err = NormalizePlatformSnapshot(context.Background(), []byte{'[', '"', 0xff, '"', ']'}, syntheticPlatformOptions())
	assertProblemCode(t, err, "INVALID_JSON_ENCODING")
}

func TestNormalizePlatformSnapshotTreatsNullBodyAsEmptyAndRetainsOnlyHash(t *testing.T) {
	raw := []byte(`[{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"reviewer","id":301,"type":"User"},"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z","body":null}]`)
	snapshot, canonical, err := NormalizePlatformSnapshot(context.Background(), raw, syntheticPlatformOptions())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Approvals[0].BodySHA256 != digestHex(nil) || bytes.Contains(canonical, []byte(`"body":`)) {
		t.Fatalf("null body was not normalized to an empty-body hash only: %+v %s", snapshot.Approvals[0], canonical)
	}
}

func TestNormalizePlatformSnapshotEnforcesSourceAndObservationBoundsDuringDecode(t *testing.T) {
	tooLarge := make([]byte, maxPlatformSourceBytes+1)
	for index := range tooLarge {
		tooLarge[index] = ' '
	}
	_, _, err := NormalizePlatformSnapshot(context.Background(), tooLarge, syntheticPlatformOptions())
	assertProblemCode(t, err, "PLATFORM_SOURCE_SIZE")

	review := `{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"reviewer","id":301,"type":"User"},"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z","body":"CIRewind review assertion v1 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	raw := []byte("[" + strings.Repeat(review+",", 2000) + review + "]")
	_, _, err = NormalizePlatformSnapshot(context.Background(), raw, syntheticPlatformOptions())
	assertProblemCode(t, err, "PLATFORM_SOURCE_COUNT")
}

func TestWritePlatformSnapshotUsesFixedDistinctOutput(t *testing.T) {
	root := t.TempDir()
	raw := []byte(`[{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"reviewer","id":301,"type":"User"},"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z","body":"CIRewind review assertion v1 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`)
	source := filepath.Join(root, "reviews.json")
	output := filepath.Join(root, "platform-approvals.json")
	mustWrite(t, source, raw)
	_, first, err := WritePlatformSnapshot(context.Background(), source, output, syntheticPlatformOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := WritePlatformSnapshot(context.Background(), source, output, syntheticPlatformOptions())
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("idempotent write: %v", err)
	}
	retained, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(retained, first) {
		t.Fatalf("retained snapshot mismatch: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(output, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := WritePlatformSnapshot(context.Background(), source, output, syntheticPlatformOptions()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(output)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("idempotent snapshot write did not restore 0600 mode: mode=%v", info.Mode().Perm())
		}
	}
	_, _, err = WritePlatformSnapshot(context.Background(), source, filepath.Join(root, "wrong.json"), syntheticPlatformOptions())
	assertProblemCode(t, err, "PLATFORM_SNAPSHOT_PATH")
}

func syntheticPlatformOptions() PlatformSnapshotOptions {
	return PlatformSnapshotOptions{Repository: "example/cirewind", PullRequestNumber: 7,
		CandidateCommit: syntheticCommit, ObservedAt: "2026-08-21T00:01:00Z",
		WorkflowSourceCommit: syntheticCommit, WorkflowRunURL: "https://github.com/example/cirewind/actions/runs/77", WorkflowRunID: 77, WorkflowRunAttempt: 1}
}
