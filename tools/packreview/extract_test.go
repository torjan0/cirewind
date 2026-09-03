package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticTrivyAdvisory(t *testing.T) []byte {
	t.Helper()
	description := strings.Join([]string{
		"## Exposure Window", "",
		"| Component     | Start (UTC)            | End (UTC)         | Duration  |",
		"| ------------- | ---------------------- | ----------------- | --------- |",
		"| trivy v0.69.4 | 2026-03-19 18:22 [^1]  | 2026-03-19 ~21:42 | ~3 hours  |", "",
		"### Executable binaries", "",
		"| SHA256 | Filename |", "| --- | --- |",
		"| `" + strings.Repeat("a", 64) + "` | `trivy_0.69.4_Linux-64bit.tar.gz` |", "",
		"### Container images (v0.69.4)", "",
		"| Digest | Tag |", "| --- | --- |",
		"| `sha256:" + strings.Repeat("b", 64) + "` | `0.69.4` |", "",
		"### Network", "",
		"- `scan.example.invalid.test`", "- `192.0.2.10`", "",
	}, "\r\n")
	data, err := json.Marshal(map[string]any{"ghsa_id": "GHSA-xxxx-xxxx-xxxx", "description": description})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRunExtractIndicatorsWritesSealedRecords(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "advisory.json")
	if err := os.WriteFile(source, syntheticTrivyAdvisory(t), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "extraction.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"extract-indicators", "--extractor", "trivy-2026-advisory-tables", "--source", source, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Digests      []map[string]any `json:"digests"`
		OutputSHA256 string           `json:"outputSha256"`
	}
	if err := json.Unmarshal(first, &record); err != nil || len(record.Digests) != 2 || len(record.OutputSHA256) != 64 {
		t.Fatalf("record is wrong: %v %s", err, first)
	}
	if !strings.Contains(stdout.String(), `"operation":"extract-indicators"`) && !strings.Contains(stdout.String(), `"operation": "extract-indicators"`) {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	stdout.Reset()
	if code := run(context.Background(), []string{"extract-indicators", "--extractor", "trivy-2026-advisory-tables", "--source", source, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("second run exit %d: %s", code, stderr.String())
	}
	second, _ := os.ReadFile(out)
	if !bytes.Equal(first, second) {
		t.Fatal("repeated extraction is not byte-identical")
	}
	listing := filepath.Join(dir, "tags.json")
	if err := os.WriteFile(listing, []byte(`[{"ref":"refs/tags/v0.1.0","object":{"type":"commit","sha":"`+strings.Repeat("c", 40)+`"}},{"ref":"refs/tags/0.35.0","object":{"type":"commit","sha":"`+strings.Repeat("d", 40)+`"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(dir, "inventory.json")
	if code := run(context.Background(), []string{"extract-indicators", "--extractor", "trivy-2026-action-tag-inventory", "--source", listing, "--out", inventory, "--unrestored", "0.0.10"}, &stdout, &stderr); code != 0 {
		t.Fatalf("inventory exit %d: %s", code, stderr.String())
	}
	data, _ := os.ReadFile(inventory)
	if !strings.Contains(string(data), `"originalTags":["0.0.10","0.1.0"]`) {
		t.Fatalf("inventory is wrong: %s", data)
	}
	for name, args := range map[string][]string{
		"unknown extractor":    {"extract-indicators", "--extractor", "nope", "--source", source, "--out", out},
		"missing out":          {"extract-indicators", "--extractor", "trivy-2026-advisory-tables", "--source", source},
		"unrestored on tables": {"extract-indicators", "--extractor", "trivy-2026-advisory-tables", "--source", source, "--out", out, "--unrestored", "0.0.10"},
		"tables on listing":    {"extract-indicators", "--extractor", "trivy-2026-advisory-tables", "--source", listing, "--out", out},
	} {
		if code := run(context.Background(), args, &stdout, &stderr); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
