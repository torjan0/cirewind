package casefile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/cli"
)

func TestVerifyCaseRejectsDemoCaseKindSpoofWithRecomputedManifest(t *testing.T) {
	output := filepath.Join(t.TempDir(), "demo-case")
	var stdout, stderr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
	}

	metadataPath := filepath.Join(output, "collection-metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["caseKind"] != "synthetic" {
		t.Fatalf("demo caseKind=%v, want synthetic before tamper", metadata["caseKind"])
	}
	metadata["caseKind"] = "collected"
	data, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := casefile.BuildManifest(context.Background(), output)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "manifest.sha256"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = casefile.VerifyCase(context.Background(), output)
	if err == nil || !strings.Contains(err.Error(), "caseKind") || !strings.Contains(err.Error(), "persisted collection provenance") {
		t.Fatalf("recomputed-manifest demo spoof error=%v", err)
	}
}
