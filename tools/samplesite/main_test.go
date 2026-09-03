package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/cli"
)

func TestBuildThenVerifyRoundTrip(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "case")
	var demoOut, demoErr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"demo", "--out", caseDir}, &demoOut, &demoErr); code != 0 {
		t.Fatalf("demo failed: %d %s", code, demoErr.String())
	}
	site := filepath.Join(root, "site")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"build", "--case", caseDir, "--out", site, "--version", "0.2.0", "--source-commit", strings.Repeat("a", 40), "--go-version", "go1.25.13"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("build exit=%d stderr=%s", code, stderr.String())
	}
	var built commandResult
	if err := json.Unmarshal(stdout.Bytes(), &built); err != nil {
		t.Fatal(err)
	}
	if built.Operation != "build" || built.FindingTotal != 11 || len(built.SiteManifestSHA256) != 64 || built.SiteDir != site {
		t.Fatalf("build result=%+v", built)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"verify", "--site", site, "--version", "0.2.0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify exit=%d stderr=%s", code, stderr.String())
	}
	var verified commandResult
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.SiteManifestSHA256 != built.SiteManifestSHA256 || verified.ArchiveSHA256 != built.ArchiveSHA256 || verified.CaseManifestSHA256 != built.CaseManifestSHA256 {
		t.Fatalf("verify result %+v does not match build result %+v", verified, built)
	}

	landing := filepath.Join(site, "v0.2.0", "index.html")
	data, err := os.ReadFile(landing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(landing, append(data, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"verify", "--site", site, "--version", "0.2.0"}, &stdout, &stderr); code != 1 {
		t.Fatalf("tampered site verify exit=%d, want 1 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "manifest") {
		t.Fatalf("tamper diagnostic does not name the manifest: %s", stderr.String())
	}
}

func TestReadmeWriteThenCheck(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "case")
	var demoOut, demoErr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"demo", "--out", caseDir}, &demoOut, &demoErr); code != 0 {
		t.Fatalf("demo failed: %d %s", code, demoErr.String())
	}
	outDir := filepath.Join(root, "generated")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"readme", "--case", caseDir, "--out-dir", outDir, "--version", "0.2.0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("readme exit=%d stderr=%s", code, stderr.String())
	}
	var written readmeResult
	if err := json.Unmarshal(stdout.Bytes(), &written); err != nil {
		t.Fatal(err)
	}
	if !written.Candidate || written.Checked || len(written.Digests) != 4 {
		t.Fatalf("readme result=%+v", written)
	}
	for _, name := range []string{"README.candidate.md", "readme-preview.svg", "graph.svg", "README.slots.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("generated %s missing: %v", name, err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"readme", "--case", caseDir, "--out-dir", outDir, "--version", "0.2.0", "--check"}, &stdout, &stderr); code != 0 {
		t.Fatalf("readme --check exit=%d stderr=%s", code, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(outDir, "README.slots.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"readme", "--case", caseDir, "--out-dir", outDir, "--version", "0.2.0", "--check"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "differs") {
		t.Fatalf("drifted inventory check exit=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"readme", "--case", caseDir, "--out-dir", filepath.Join(root, "missing"), "--version", "0.2.0"}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing directory exit=%d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"build"},
		{"build", "--case", "x", "--out", "y", "--version", "0.2.0", "--source-commit", "abc"},
		{"verify", "--site", "x"},
		{"verify", "--site", "x", "--version", "0.2.0", "extra"},
		{"verify", "--site", "x", "--version", "0.2.0", "--prior", "0.1.0"},
		{"verify", "--site", "x", "--version", "0.2.0", "--prior", "0.1.0@abc@dir"},
		{"readme", "--case", "x", "--out-dir", "y"},
		{"readme", "--case", "x", "--out-dir", "y", "--version", "0.2.0", "extra"},
		{"build", "--case", "x", "--out", "y", "--version", "0.2.0", "--source-commit", strings.Repeat("a", 40), "--go-version", "go1.25.13", "--prior", "0.1.0@" + strings.Repeat("b", 64)},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
			t.Fatalf("args %v exit=%d, want 2", args, code)
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage:") {
			t.Fatalf("args %v stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help exit=%d stdout=%q", code, stdout.String())
	}
	if code := run(context.Background(), []string{"verify", "--site", filepath.Join(t.TempDir(), "missing"), "--version", "0.2.0"}, &stdout, &stderr); code != 1 {
		t.Fatalf("missing site exit=%d, want 1", code)
	}
}
