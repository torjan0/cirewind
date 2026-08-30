package packreview

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadStrictJSONRejectsHostileForms(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, data, code string }{
		{"duplicate", `{"schemaVersion":"x","schemaVersion":"y"}`, "DUPLICATE_JSON_KEY"},
		{"unknown", `{"schemaVersion":"x","unknown":true}`, "STRICT_JSON"},
		{"trailing", `{"schemaVersion":"x"} {}`, "TRAILING_JSON"},
		{"bom", "\ufeff{}", "INVALID_JSON_ENCODING"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			mustWrite(t, path, []byte(test.data))
			_, _, err := readStrictJSON[Packet](context.Background(), path)
			assertProblemCode(t, err, test.code)
		})
	}
}

func TestReadStrictJSONRejectsExcessiveDepth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deep.json")
	mustWrite(t, path, []byte(strings.Repeat("[", maxJSONDepth+2)+"0"+strings.Repeat("]", maxJSONDepth+2)))
	_, _, err := readStrictJSON[any](context.Background(), path)
	assertProblemCode(t, err, "JSON_STRUCTURE_LIMIT")
}

func TestReadStrictJSONRejectsOversizedArrayBeforeTypedDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wide.json")
	mustWrite(t, path, []byte("["+strings.Repeat("0,", maxJSONArrayValues)+"0]"))
	_, _, err := readStrictJSON[[]any](context.Background(), path)
	assertProblemCode(t, err, "JSON_STRUCTURE_LIMIT")
}

func TestManifestDeterminismAndTamperDetection(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	first, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName))
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("manifest generation is not deterministic")
	}
	mustWrite(t, filepath.Join(repo.candidate, "expected-findings.json"), []byte("{\"findings\":[\"tampered\"]}\n"))
	_, _, err = VerifyCandidateManifest(context.Background(), repo.candidate)
	assertProblemCode(t, err, "MANIFEST_MISMATCH")
}

func TestManifestRejectsUnsafeTrees(t *testing.T) {
	t.Run("unexpected file", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		mustWrite(t, filepath.Join(repo.candidate, "unexpected.txt"), []byte("inert\n"))
		_, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName))
		assertProblemCode(t, err, "UNEXPECTED_CANDIDATE_FILE")
	})
	t.Run("unexpected empty directory", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		mustMkdir(t, filepath.Join(repo.candidate, "unexpected"))
		_, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName))
		assertProblemCode(t, err, "UNEXPECTED_CANDIDATE_DIRECTORY")
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "target.txt"), []byte("x"))
		if err := os.Symlink("target.txt", filepath.Join(root, "alias.txt")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "NON_REGULAR_ENTRY")
	})
	t.Run("hard link", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("hard-link behavior is platform-specific on Windows")
		}
		root := t.TempDir()
		first := filepath.Join(root, "first.txt")
		mustWrite(t, first, []byte("x"))
		if err := os.Link(first, filepath.Join(root, "second.txt")); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "HARD_LINK")
	})
	t.Run("active data", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "payload.txt"), []byte("#!/bin/sh\necho no\n"))
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "ACTIVE_FIXTURE")
	})
	t.Run("secret-like data", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "payload.txt"), []byte("github_pat_unmistakably_synthetic_but_forbidden\n"))
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "SENSITIVE_FIXTURE")
	})
	t.Run("reserved filename", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "CON.txt"), []byte("x"))
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "MANIFEST_PATH")
	})
	t.Run("multi-dot reserved filename", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "CON.synthetic.txt"), []byte("x"))
		_, err := BuildFixtureManifest(context.Background(), root, filepath.Join(root, FixtureManifestName))
		assertProblemCode(t, err, "MANIFEST_PATH")
	})
}

func TestManifestCancellation(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "fixture.txt"), []byte("x"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := BuildFixtureManifest(ctx, root, filepath.Join(root, FixtureManifestName))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
}

func TestManifestParserRejectsTraversalAndNonCanonicalOrder(t *testing.T) {
	for _, input := range []string{
		stringOf('a', 64) + "  ../escape.txt\n",
		stringOf('a', 64) + "  b.txt\n" + stringOf('b', 64) + "  a.txt\n",
		stringOf('A', 64) + "  a.txt\n",
		stringOf('a', 64) + "  a\\b.txt\n",
	} {
		if _, err := parseManifest([]byte(input), "manifest.sha256"); err == nil {
			t.Fatalf("accepted unsafe manifest %q", input)
		}
	}
}

func assertProblemCode(t *testing.T, err error, code string) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("got %v, want validation error %s", err, code)
	}
	for _, problem := range validation.Problems {
		if problem.Code == code {
			return
		}
	}
	t.Fatalf("got problems %+v, want code %s", validation.Problems, code)
}
