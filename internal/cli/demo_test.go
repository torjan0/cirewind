package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/livecollect"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func TestDemoProducesVerifiedOfflineSyntheticCase(t *testing.T) {
	for _, name := range []string{"CIREWIND_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		t.Setenv(name, "synthetic-token-must-never-be-observed")
	}
	// Any accidental conventional HTTP client use fails fast. The demo's
	// production path has no network boundary at all.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	output := filepath.Join(t.TempDir(), "synthetic-case")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-must-never-be-observed") {
		t.Fatal("demo printed authentication material")
	}
	for _, phrase := range []string{"SYNTHETIC DEMO", "PARTIAL COVERAGE", "findings: 11", "manifest: verified", "network requests: 0"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Errorf("demo summary omitted %q:\n%s", phrase, stdout.String())
		}
	}

	verification, err := casefile.VerifyCase(context.Background(), output)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Contract != casefile.ContractV1Alpha2 || len(verification.LegacyExtras) != 0 {
		t.Fatalf("verification = %#v", verification)
	}
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	gotFiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotFiles = append(gotFiles, entry.Name())
	}
	sort.Strings(gotFiles)
	wantFiles := append([]string(nil), bundle.Oracle.FinalFiles...)
	sort.Strings(wantFiles)
	if strings.Join(gotFiles, "\x00") != strings.Join(wantFiles, "\x00") {
		t.Fatalf("case files=%v, want %v", gotFiles, wantFiles)
	}
	if _, err := os.Lstat(filepath.Join(output, "raw")); !os.IsNotExist(err) {
		t.Fatalf("demo materialized raw directory: %v", err)
	}

	var metadata report.Metadata
	readJSONFile(t, filepath.Join(output, "collection-metadata.json"), &metadata)
	if metadata.SchemaVersion != report.MetadataSchemaV2 || metadata.CaseContractVersion != report.CaseContractV2 || metadata.CaseKind != report.CaseKindSynthetic || metadata.RawMaterialized == nil || *metadata.RawMaterialized || !metadata.Coverage.Partial {
		t.Fatalf("demo metadata lost v0.2 synthetic/partial contract: %#v", metadata)
	}
	var projected graph.GraphV2
	readJSONFile(t, filepath.Join(output, "graph.json"), &projected)
	if err := projected.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if len(projected.Edges) == 0 {
		t.Fatal("demo graph has no material edges")
	}
	for _, edge := range projected.Edges {
		if len(edge.EvidenceIDs) == 0 {
			t.Fatalf("graph edge %s lacks evidence", edge.ID)
		}
	}
	assertPendingEnvironmentGraph(t, projected)

	reportBytes, err := os.ReadFile(filepath.Join(output, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"Temporal evidence path", "synthetic", "UNKNOWN_EVIDENCE_GAP"} {
		if !bytes.Contains(reportBytes, []byte(phrase)) {
			t.Errorf("report omitted %q", phrase)
		}
	}
	summaryBytes, err := os.ReadFile(filepath.Join(output, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	summary := string(summaryBytes)
	synthetic := strings.Index(summary, "SYNTHETIC DEMONSTRATION: this case contains harmless fixture evidence, not a real incident or collected organization result.")
	partial := strings.Index(summary, "PARTIAL COVERAGE: some material evidence is unavailable. Totals and conclusions are limited to retained evidence.")
	findings := strings.Index(summary, "## Finding summary")
	if synthetic < 0 || partial < 0 || findings < 0 || synthetic >= findings || partial >= findings {
		t.Fatalf("demo Markdown summary does not lead with synthetic/partial classification: synthetic=%d partial=%d findings=%d\n%s", synthetic, partial, findings, summary)
	}
}

func TestDemoSummaryIsCompleteAndCanonicallyOrdered(t *testing.T) {
	output := filepath.Join(t.TempDir(), "synthetic-case")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful demo wrote stderr %q", stderr.String())
	}
	want := strings.Join([]string{
		"SYNTHETIC DEMO — PARTIAL COVERAGE",
		"findings: 11",
		"CONFIRMED_EXECUTED: 1",
		"CONFIRMED_DOWNLOADED: 1",
		"CONFIRMED_CALLED_WORKFLOW: 1",
		"DECLARED_AT_RUN_SHA: 1",
		"RUN_IN_WINDOW_MUTABLE_REF: 1",
		"POTENTIAL_TRANSITIVE: 2",
		"CURRENT_REFERENCE_ONLY: 1",
		"NO_MATCH_CONFIRMED: 1",
		"UNKNOWN_EVIDENCE_GAP: 1",
		"CONTRADICTORY_EVIDENCE: 1",
		"manifest: verified",
		"network requests: 0",
		"case: " + filepath.Clean(output),
		"report: " + filepath.Join(filepath.Clean(output), "report.html"),
		"",
	}, "\n")
	if stdout.String() != want {
		t.Fatalf("demo summary drifted:\ngot:\n%s\nwant:\n%s", stdout.String(), want)
	}
	if _, err := casefile.VerifyCase(context.Background(), output); err != nil {
		t.Fatalf("summary claimed verification for invalid case: %v", err)
	}
}

func TestDemoOutputIsByteDeterministic(t *testing.T) {
	parent := t.TempDir()
	outputs := []string{filepath.Join(parent, "first"), filepath.Join(parent, "second")}
	for _, output := range outputs {
		if code := Run(context.Background(), []string{"demo", "--out", output}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
			t.Fatalf("demo failed for %s", output)
		}
	}
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range bundle.Oracle.FinalFiles {
		left, err := os.ReadFile(filepath.Join(outputs[0], name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(outputs[1], name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Errorf("demo output %s differs across identical runs", name)
		}
	}
}

func TestDemoRefusesOverwriteAndHonorsCancellation(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "case")
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(output, "user-data")
		if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		if code := Run(context.Background(), []string{"demo", "--out", output}, &bytes.Buffer{}, &stderr); code != 1 {
			t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
		}
		data, err := os.ReadFile(sentinel)
		if err != nil || string(data) != "preserve" {
			t.Fatalf("existing output was modified: %q %v", data, err)
		}
	})

	t.Run("pre-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		output := filepath.Join(t.TempDir(), "case")
		if code := Run(ctx, []string{"demo", "--out", output}, &bytes.Buffer{}, &bytes.Buffer{}); code != 130 {
			t.Fatalf("canceled demo exit=%d", code)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("canceled demo published output: %v", err)
		}
	})
}

func TestDemoRefusesEveryExistingDestinationEntry(t *testing.T) {
	tests := []struct {
		name   string
		create func(*testing.T, string)
	}{
		{
			name: "regular file",
			create: func(t *testing.T, output string) {
				t.Helper()
				if err := os.WriteFile(output, []byte("preserve-file"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			create: func(t *testing.T, output string) {
				t.Helper()
				if err := os.Mkdir(output, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, "user-data"), []byte("preserve-directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			create: func(t *testing.T, output string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(output), "symlink-target")
				if err := os.WriteFile(target, []byte("preserve-target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, output); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
		},
		{
			name: "dangling symlink",
			create: func(t *testing.T, output string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(filepath.Dir(output), "missing-target"), output); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			output := filepath.Join(parent, "case")
			tc.create(t, output)
			before, err := snapshotDirectoryTree(parent)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 1 {
				t.Fatalf("demo exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "already exists") {
				t.Fatalf("unexpected overwrite diagnostic stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			after, err := snapshotDirectoryTree(parent)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("existing destination tree changed:\nbefore=%q\nafter=%q", before, after)
			}
			assertNoCaseStaging(t, parent)
		})
	}
}

func TestDemoRejectsFilesystemAndHomeRoots(t *testing.T) {
	t.Run("filesystem root", func(t *testing.T) {
		root := string(filepath.Separator)
		if volume := filepath.VolumeName(t.TempDir()); volume != "" {
			root = volume + string(filepath.Separator)
		}
		assertRejectedProtectedRoot(t, root)
	})
	t.Run("home root", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		assertRejectedProtectedRoot(t, home)
	})
}

func TestDemoRejectsSymlinkAndHostileAncestors(t *testing.T) {
	t.Run("symlink ancestor", func(t *testing.T) {
		parent := t.TempDir()
		target := t.TempDir()
		alias := filepath.Join(parent, "redirect")
		if err := os.Symlink(target, alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		output := filepath.Join(alias, "nested", "case")
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 1 {
			t.Fatalf("demo exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "symlink component") {
			t.Fatalf("unexpected symlink diagnostic stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		entries, err := os.ReadDir(target)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("symlink target mutated: %v", entries)
		}
	})

	t.Run("hostile parent label", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "parent\x1b[2J\nforged\u202e\u2066")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Skipf("filesystem does not support hostile fixture name: %v", err)
		}
		output := filepath.Join(parent, "case")
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Skipf("filesystem does not support hostile fixture name: %v", err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 1 {
			t.Fatalf("demo exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		diagnostic := stderr.String()
		if strings.ContainsAny(diagnostic, "\x1b\r") || strings.Contains(diagnostic, "\nforged") || strings.ContainsAny(diagnostic, "\u202e\u2066") {
			t.Fatalf("hostile output path reached terminal unsanitized: %q", diagnostic)
		}
		if strings.Count(diagnostic, "\n") != 1 {
			t.Fatalf("diagnostic is not one line: %q", diagnostic)
		}
	})
}

func TestDemoSanitizesSuccessfulOutputPath(t *testing.T) {
	parent := t.TempDir()
	component := "case\x1b[2J\nforged\u202e\u2066"
	if runtime.GOOS == "windows" {
		// Windows rejects ASCII control characters in path components. Bidi
		// controls remain a valid hostile terminal label and preserve the
		// successful-path sanitizer assertion on that platform.
		component = "case-forged\u202e\u2066"
	}
	output := filepath.Join(parent, component)
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful demo wrote stderr %q", stderr.String())
	}
	terminal := stdout.String()
	if strings.ContainsAny(terminal, "\x1b\r") || strings.Contains(terminal, "\nforged") || strings.ContainsAny(terminal, "\u202e\u2066") {
		t.Fatalf("hostile successful output path reached terminal unsanitized: %q", terminal)
	}
	if _, err := casefile.VerifyCase(context.Background(), output); err != nil {
		t.Fatalf("case at hostile source path failed verification: %v", err)
	}
}

func TestDemoConcurrentSameDestinationPublishesExactlyOneCase(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	start := make(chan struct{})
	results := make(chan int, 2)
	errorsOutput := make(chan string, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			var stdout, stderr bytes.Buffer
			results <- Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr)
			errorsOutput <- stderr.String()
		}()
	}
	ready.Wait()
	close(start)
	codes := []int{<-results, <-results}
	diagnostics := []string{<-errorsOutput, <-errorsOutput}
	sort.Ints(codes)
	if codes[0] != 0 || codes[1] != 1 {
		t.Fatalf("concurrent demo exits=%v stderr=%q", codes, diagnostics)
	}
	if _, err := casefile.VerifyCase(context.Background(), output); err != nil {
		t.Fatalf("winning case failed verification: %v", err)
	}
	assertNoCaseStaging(t, parent)
}

func TestDemoMidGenerationCancellationBeforePublicationIsDeterministic(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	result := make(chan int, 1)
	go func() {
		var stderr bytes.Buffer
		err := runDemoWithPipeline(ctx, []string{"--out", output}, &bytes.Buffer{}, &stderr, func(ctx context.Context, request casePipelineRequest) (report.Case, error) {
			close(entered)
			if request.Output != output {
				return report.Case{}, errors.New("demo pipeline received the wrong output")
			}
			<-ctx.Done()
			return report.Case{}, ctx.Err()
		})
		result <- writeCLIError(&stderr, err)
	}()
	<-entered
	cancel()
	if code := <-result; code != 130 {
		t.Fatalf("mid-generation canceled demo exit=%d, want 130", code)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled demo published destination: %v", err)
	}
	assertNoCaseStaging(t, parent)
}

func TestDemoDoesNotLaunchConventionalChildrenOrBrowsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable tripwires are not portable to Windows")
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "child-was-launched")
	for _, name := range []string{"curl", "wget", "git", "gh", "xdg-open", "open", "sensible-browser"} {
		script := []byte("#!/bin/sh\nprintf called >> \"$CIREWIND_DEMO_CHILD_MARKER\"\nexit 99\n")
		if err := os.WriteFile(filepath.Join(bin, name), script, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("BROWSER", filepath.Join(bin, "sensible-browser"))
	t.Setenv("CIREWIND_DEMO_CHILD_MARKER", marker)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	output := filepath.Join(t.TempDir(), "case")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("demo launched a conventional child or browser: %v", err)
	}
}

func TestDemoDoesNotConstructGitHubClient(t *testing.T) {
	output := filepath.Join(t.TempDir(), "case")
	constructions := 0
	dependencies := commandDependencies{newGitHubClient: func() (livecollect.API, error) {
		constructions++
		return nil, errors.New("demo attempted GitHub client construction")
	}}
	var stdout, stderr bytes.Buffer
	if code := runWithDependencies(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr, dependencies); code != 0 {
		t.Fatalf("demo exit=%d stderr=%q", code, stderr.String())
	}
	if constructions != 0 {
		t.Fatalf("demo constructed GitHub client %d times, want zero", constructions)
	}
	if _, err := casefile.VerifyCase(context.Background(), output); err != nil {
		t.Fatalf("credential-free demo case failed verification: %v", err)
	}
}

func assertRejectedProtectedRoot(t *testing.T, output string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--out", output}, &stdout, &stderr); code != 1 {
		t.Fatalf("demo --out %q exit=%d stdout=%q stderr=%q", output, code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "filesystem or home root") {
		t.Fatalf("unexpected protected-root diagnostic stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func assertNoCaseStaging(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cirewind-case-") {
			t.Errorf("private staging entry remains after demo: %s", entry.Name())
		}
	}
}

func snapshotDirectoryTree(root string) ([]byte, error) {
	var result bytes.Buffer
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		result.WriteString(filepath.ToSlash(relative))
		result.WriteByte(0)
		result.WriteString(info.Mode().String())
		result.WriteByte(0)
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result.Write(content)
		}
		result.WriteByte('\n')
		return nil
	})
	return result.Bytes(), err
}

func assertPendingEnvironmentGraph(t *testing.T, projected graph.GraphV2) {
	t.Helper()
	var pendingRevision string
	for _, finding := range projected.FindingIndex {
		if finding.RunID != nil && *finding.RunID == 1005 && finding.RunAttempt != nil && *finding.RunAttempt == 1 && finding.JobID != nil && *finding.JobID == 2005 && finding.State == model.RunInWindowMutableRef {
			pendingRevision = finding.FindingRevisionID
		}
	}
	if pendingRevision == "" {
		t.Fatal("pending environment finding is absent from graph index")
	}
	targeted, satisfied, eligible := false, false, false
	for _, edge := range projected.Edges {
		focus := false
		for _, revision := range edge.FocusFindingIDs {
			focus = focus || revision == pendingRevision
		}
		if !focus {
			continue
		}
		switch edge.Type {
		case graph.EdgeTargetedEnvironment:
			targeted = true
		case graph.EdgeEnvironmentGateSatisfied:
			satisfied = true
		case graph.EdgeEnvironmentSecretEligible:
			eligible = true
		}
	}
	if !targeted || satisfied || eligible {
		t.Fatalf("pending environment graph targeted/satisfied/eligible=%v/%v/%v", targeted, satisfied, eligible)
	}
}

func readJSONFile(t *testing.T, path string, destination any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatal(err)
	}
}
