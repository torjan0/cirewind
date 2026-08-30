package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/packreview"
)

func TestRunHelpAndUnknownOperation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "performs no") || !strings.Contains(stdout.String(), "factual") {
		t.Fatalf("help omits safety boundary: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"\x1b[31mevil"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown exit=%d", code)
	}
	if strings.Contains(stderr.String(), "\x1b") {
		t.Fatalf("terminal control reached stderr: %q", stderr.String())
	}
}

func TestRunRequiredFlagsAndCancellation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"validate-unit"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing flag exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "REQUIRED_FLAG") {
		t.Fatalf("missing typed validation output: %q", stderr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"validate-unit", "--root", t.TempDir(), "--candidate-commit", strings.Repeat("a", 40)}, &stdout, &stderr); code != 130 {
		t.Fatalf("canceled exit=%d stderr=%q", code, stderr.String())
	}
}

func TestRunBuildFixtureManifestProducesCanonicalJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "synthetic.txt"), []byte("inert synthetic fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "manifest.sha256")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"build-fixture-manifest", "--root", root, "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result commandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not JSON: %v (%q)", err, stdout.String())
	}
	if result.Operation != "build-fixture-manifest" || len(result.SHA256) != 64 || !strings.Contains(result.Statement, "not an authenticity signature") {
		t.Fatalf("unexpected result: %+v", result)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
}

func TestRunNormalizePlatformApprovals(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "reviews.json")
	output := filepath.Join(root, "platform-approvals.json")
	raw := []byte(`[{"id":42,"html_url":"https://github.com/example/cirewind/pull/7#pullrequestreview-42","user":{"login":"synthetic-reviewer","id":301,"type":"User"},"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","submitted_at":"2026-08-21T00:00:00Z","body":"CIRewind review assertion v1 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`)
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"normalize-platform-approvals", "--source", source, "--out", output,
		"--repository", "example/cirewind", "--pull-request", "7",
		"--candidate-commit", strings.Repeat("a", 40), "--observed-at", "2026-08-21T00:01:00Z",
		"--workflow-source-commit", strings.Repeat("b", 40),
		"--workflow-run-url", "https://github.com/example/cirewind/actions/runs/77",
		"--workflow-run-id", "77", "--workflow-run-attempt", "1"}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("normalize exit=%d stderr=%q", code, stderr.String())
	}
	var result commandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Operation != "normalize-platform-approvals" || !strings.Contains(result.Statement, "not a human approval") {
		t.Fatalf("unexpected result: %+v", result)
	}
	data, err := os.ReadFile(output)
	if err != nil || bytes.Contains(data, []byte("CIRewind review assertion")) || !bytes.Contains(data, []byte(`"bodySha256"`)) || !bytes.Contains(data, []byte(`"workflowSourceCommit"`)) {
		t.Fatalf("unexpected normalized snapshot: err=%v data=%s", err, data)
	}
}

func TestRunRenderReviewBodyEmitsExactFixedASCII(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "review-assertion.json")
	assertion := syntheticReviewAssertion()
	data, err := evidence.CanonicalJSON(assertion)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	validData := append([]byte(nil), data...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := packreview.ComputeReviewAssertionBody(assertion)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"render-review-body", "--review", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("render exit=%d stderr=%q", code, stderr.String())
	}
	if stdout.String() != want.Body || strings.HasSuffix(stdout.String(), "\n") || stderr.Len() != 0 {
		t.Fatalf("body output is not exact: got=%q want=%q stderr=%q", stdout.String(), want.Body, stderr.String())
	}

	assertion.ReviewID = "unsafe/review"
	data, err = evidence.CanonicalJSON(assertion)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"render-review-body", "--review", path}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "SAFE_ID") {
		t.Fatalf("invalid assertion result: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	unknown := bytes.Replace(validData, []byte("{"), []byte(`{"unexpected":true,`), 1)
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"render-review-body", "--review", path}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "STRICT_JSON") {
		t.Fatalf("unknown-field assertion result: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	if err := os.WriteFile(path, validData, 0o600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	stdout.Reset()
	stderr.Reset()
	if code := run(canceled, []string{"render-review-body", "--review", path}, &stdout, &stderr); code != 130 || stdout.Len() != 0 {
		t.Fatalf("canceled assertion result: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func syntheticReviewAssertion() packreview.ReviewAssertion {
	hash := strings.Repeat("a", 64)
	return packreview.ReviewAssertion{
		SchemaVersion: packreview.ReviewAssertionSchema, ReviewID: "synthetic-review", Reviewer: packreview.HumanIdentity{Login: "synthetic-reviewer", DatabaseID: 301},
		DeclaredRole: "outside-technical", Independent: true, ConflictDisclosure: "Synthetic assertion; no real approval.",
		IncidentID: "synthetic-incident", PackVersion: "1.0.0", CandidateCommit: strings.Repeat("b", 40),
		Bindings: packreview.ReviewBindings{CandidateManifestSHA256: hash, OriginalPackSHA256: hash, CanonicalPackSHA256: hash,
			ClaimsSHA256: hash, SourcesSHA256: hash, ConflictsSHA256: hash, FixtureManifestSHA256: hash,
			ValidatorPolicySHA256: hash, ReviewPolicySHA256: hash},
		Repository: "example/cirewind", PullRequestNumber: 7, Scopes: []string{"identity"}, Commands: []packreview.ReproductionCommand{},
		SourceObjectsChecked: []packreview.CheckedSourceObject{{SourceID: "synthetic-source", SHA256: hash}}, Decision: "approve",
		Rationale: "Synthetic assertion used only for offline command testing.", KnownLimitations: []string{"No factual review is represented."},
	}
}

func TestRunValidateCheckedInGovernance(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"validate-governance", "--repository-root", repositoryRoot}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var result commandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Operation != "validate-governance" || !strings.Contains(result.Statement, "no factual review") {
		t.Fatalf("unexpected governance result: %+v", result)
	}
}
