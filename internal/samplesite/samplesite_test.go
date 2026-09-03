package samplesite

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/torjan0/cirewind/internal/cli"
)

// sharedDemoCase is one synthetic case generated through the production demo
// command for the whole test binary. Tests never modify it.
var sharedDemoCase string

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "cirewind-samplesite-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sharedDemoCase = filepath.Join(root, "demo-case")
	var stdout, stderr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"demo", "--out", sharedDemoCase}, &stdout, &stderr); code != 0 {
		fmt.Fprintf(os.Stderr, "demo generation failed: code=%d stderr=%s\n", code, stderr.String())
		_ = os.RemoveAll(root)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

const (
	testVersion      = "0.2.0"
	testSourceCommit = "200fde2e8ef651545b6da1ab2b598ddb88820555"
	testGoVersion    = "go1.25.13"
)

func buildTestSite(t *testing.T, output string) Result {
	t.Helper()
	result, err := Build(context.Background(), Options{
		CaseDir: sharedDemoCase, Output: output, Version: testVersion,
		SourceCommit: testSourceCommit, GoVersion: testGoVersion,
	})
	if err != nil {
		t.Fatalf("build sample site: %v", err)
	}
	return result
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	names, err := listRegularFiles(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
