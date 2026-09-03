package samplesite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/model"
)

func TestLoadVerifiedCaseDerivesOracleCounts(t *testing.T) {
	t.Parallel()
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	summary, err := LoadVerifiedCase(context.Background(), sharedDemoCase, bundle.Oracle)
	if err != nil {
		t.Fatalf("verified demo case rejected: %v", err)
	}
	if summary.Total != 11 || summary.CaseKind != "synthetic" || summary.Counts[model.ConfirmedExecuted] != 1 || summary.Counts[model.NoMatchConfirmed] != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	for _, metric := range []demodata.ExposureMetric{demodata.ExposureWriteTokenJob, demodata.ExposureNamedSecretFlow, demodata.ExposureOIDCMintingJob, demodata.ExposureSelfHostedRunnerJob, demodata.ExposureDeploymentAfter} {
		if summary.Exposures[metric] != 1 {
			t.Fatalf("relationship %s=%d, want 1", metric, summary.Exposures[metric])
		}
	}

	t.Run("finding count drift is rejected", func(t *testing.T) {
		copied := filepath.Join(t.TempDir(), "case")
		copyTree(t, sharedDemoCase, copied)
		data, err := os.ReadFile(filepath.Join(copied, "findings.json"))
		if err != nil {
			t.Fatal(err)
		}
		mutated := bytes.Replace(data, []byte(`"state": "CONFIRMED_DOWNLOADED"`), []byte(`"state": "CONFIRMED_EXECUTED"`), 1)
		if bytes.Equal(mutated, data) {
			t.Fatal("fixture did not contain the downloaded-only finding")
		}
		if err := os.WriteFile(filepath.Join(copied, "findings.json"), mutated, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVerifiedCase(context.Background(), copied, bundle.Oracle); err == nil {
			t.Fatal("promoted downloaded-only finding was accepted")
		}
	})
	t.Run("raw directory is rejected", func(t *testing.T) {
		copied := filepath.Join(t.TempDir(), "case")
		copyTree(t, sharedDemoCase, copied)
		if err := os.Mkdir(filepath.Join(copied, "raw"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVerifiedCase(context.Background(), copied, bundle.Oracle); err == nil {
			t.Fatal("case with a raw directory was accepted")
		}
	})
	t.Run("non-synthetic case kind is rejected", func(t *testing.T) {
		copied := filepath.Join(t.TempDir(), "case")
		copyTree(t, sharedDemoCase, copied)
		data, err := os.ReadFile(filepath.Join(copied, "collection-metadata.json"))
		if err != nil {
			t.Fatal(err)
		}
		mutated := bytes.Replace(data, []byte(`"caseKind": "synthetic"`), []byte(`"caseKind": "collected"`), 1)
		if bytes.Equal(mutated, data) {
			t.Fatal("fixture metadata did not declare the synthetic case kind")
		}
		if err := os.WriteFile(filepath.Join(copied, "collection-metadata.json"), mutated, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVerifiedCase(context.Background(), copied, bundle.Oracle); err == nil {
			t.Fatal("non-synthetic case was accepted for the public sample")
		}
	})
}

func TestBuildIsDeterministicAndVerifies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	first := buildTestSite(t, filepath.Join(root, "site-a"))
	second := buildTestSite(t, filepath.Join(root, "site-b"))
	if first.SiteManifestSHA256 != second.SiteManifestSHA256 || first.ArchiveSHA256 != second.ArchiveSHA256 {
		t.Fatalf("two builds differ: %+v vs %+v", first, second)
	}
	namesA, err := listRegularFiles(context.Background(), first.SiteDir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(namesA, "\n") != strings.Join(ExpectedFiles(testVersion, bundle.Oracle.FinalFiles), "\n") {
		t.Fatalf("published file set %v", namesA)
	}
	hostMarkers := []string{root, sharedDemoCase, os.TempDir()}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hostMarkers = append(hostMarkers, hostname)
	}
	for _, name := range namesA {
		a, err := os.ReadFile(filepath.Join(first.SiteDir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(second.SiteDir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("file %s differs between builds", name)
		}
		if !strings.HasSuffix(name, ".tar.gz") {
			for _, marker := range hostMarkers {
				if len(marker) > 3 && bytes.Contains(a, []byte(marker)) {
					t.Fatalf("file %s contains host marker %q", name, marker)
				}
			}
		}
	}
	if _, err := Verify(context.Background(), first.SiteDir, testVersion, nil); err != nil {
		t.Fatalf("verify published site: %v", err)
	}
	entries, err := ListArchiveEntries(mustRead(t, filepath.Join(first.SiteDir, "v"+testVersion, "downloads", ArchiveName(testVersion))), "cirewind-synthetic-case-v"+testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(bundle.Oracle.FinalFiles) {
		t.Fatalf("archive entries=%v", entries)
	}
	if _, err := Build(context.Background(), Options{CaseDir: sharedDemoCase, Output: first.SiteDir, Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion}); err == nil {
		t.Fatal("existing output was overwritten")
	}
	for _, bad := range []Options{
		{CaseDir: sharedDemoCase, Output: filepath.Join(root, "bad-1"), Version: "v0.2.0", SourceCommit: testSourceCommit, GoVersion: testGoVersion},
		{CaseDir: sharedDemoCase, Output: filepath.Join(root, "bad-2"), Version: testVersion, SourceCommit: "abc", GoVersion: testGoVersion},
		{CaseDir: sharedDemoCase, Output: filepath.Join(root, "bad-3"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: "1.25"},
	} {
		if _, err := Build(context.Background(), bad); err == nil {
			t.Fatalf("invalid options accepted: %+v", bad)
		}
		if _, err := os.Lstat(bad.Output); !os.IsNotExist(err) {
			t.Fatalf("rejected build left output %s", bad.Output)
		}
	}
	leftovers, err := filepath.Glob(filepath.Join(root, ".cirewind-site-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("staging leftovers=%v err=%v", leftovers, err)
	}
}

func TestVerifyRejectsTamperedOrUnsafeTrees(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	site := buildTestSite(t, filepath.Join(root, "site"))
	version := "v" + testVersion
	cases := map[string]func(t *testing.T, dir string){
		"landing tampered": func(t *testing.T, dir string) {
			path := filepath.Join(dir, version, "index.html")
			data := mustRead(t, path)
			mustWrite(t, path, bytes.Replace(data, []byte("experimental"), []byte("production"), 1))
		},
		"case file tampered": func(t *testing.T, dir string) {
			path := filepath.Join(dir, version, "sample-case", "summary.md")
			mustWrite(t, path, append(mustRead(t, path), '\n'))
		},
		"extra file": func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, version, "notes.txt"), []byte("x\n"))
		},
		"missing checksum": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, version, "downloads", "SHA256SUMS")); err != nil {
				t.Fatal(err)
			}
		},
		"raw directory": func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, version, "sample-case", "raw", "deadbeef.bin"), []byte("x"))
		},
		"credential shape": func(t *testing.T, dir string) {
			path := filepath.Join(dir, version, "summary.md")
			mustWrite(t, path, append(mustRead(t, path), []byte("\ntoken ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n")...))
			mustWrite(t, filepath.Join(dir, version, "sample-case", "summary.md"), mustRead(t, path))
		},
		"external script in landing": func(t *testing.T, dir string) {
			path := filepath.Join(dir, version, "index.html")
			mustWrite(t, path, bytes.Replace(mustRead(t, path), []byte("</main>"), []byte(`<script src="https://example.invalid/a.js"></script></main>`), 1))
		},
		"provenance drift": func(t *testing.T, dir string) {
			path := filepath.Join(dir, version, "provenance.json")
			mustWrite(t, path, bytes.Replace(mustRead(t, path), []byte(`"findingTotal": 11`), []byte(`"findingTotal": 12`), 1))
		},
	}
	if runtime.GOOS != "windows" {
		cases["executable bit"] = func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, version, "summary.md"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cases["symlink"] = func(t *testing.T, dir string) {
			target := filepath.Join(dir, version, "summary.md")
			link := filepath.Join(dir, version, "sample-case", "summary.md")
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "site")
			copyTree(t, site.SiteDir, dir)
			if _, err := Verify(context.Background(), dir, testVersion, nil); err != nil {
				t.Fatalf("clean copy rejected before mutation: %v", err)
			}
			mutate(t, dir)
			if _, err := Verify(context.Background(), dir, testVersion, nil); err == nil {
				t.Fatal("mutated site verified")
			}
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
