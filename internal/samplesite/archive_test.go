package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeterministicArchiveIsByteStableAndFixedHeaders(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files := map[string]string{"b.txt": "second\n", "a.txt": "first\n", "nested/c.json": "{}\n"}
	writeTree(t, root, files)
	names := []string{"b.txt", "nested/c.json", "a.txt"}
	first, err := BuildDeterministicTarGz(context.Background(), root, "cirewind-synthetic-case-v0.2.0", names)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDeterministicTarGz(context.Background(), root, "cirewind-synthetic-case-v0.2.0", []string{"a.txt", "nested/c.json", "b.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical inputs produced different archive bytes")
	}
	entries, err := ListArchiveEntries(first, "cirewind-synthetic-case-v0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(entries, ",") != "a.txt,b.txt,nested/c.json" {
		t.Fatalf("entries=%v", entries)
	}
	if bytes.Contains(first, []byte(root)) {
		t.Fatal("archive contains the host source path")
	}
	for _, bad := range [][]string{{"../escape"}, {"a.txt", "a.txt"}, {"/abs"}, {"with space"}} {
		if _, err := BuildDeterministicTarGz(context.Background(), root, "prefix", bad); err == nil {
			t.Fatalf("unsafe entry set %v was accepted", bad)
		}
	}
	if _, err := BuildDeterministicTarGz(context.Background(), root, "pre/fix", []string{"a.txt"}); err == nil {
		t.Fatal("multi-component prefix was accepted")
	}
	if _, err := ListArchiveEntries(first, "other-prefix"); err == nil {
		t.Fatal("archive with a different prefix was accepted")
	}
}

func TestTreeManifestBuildAndVerify(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTree(t, root, map[string]string{"index.html": "<p>x</p>\n", "sub/data.json": "{}\n"})
	manifest, err := BuildTreeManifest(context.Background(), root, "site-manifest.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("<p>x</p>\n"))
	if !strings.HasPrefix(string(manifest), hex.EncodeToString(sum[:])+"  index.html\n") {
		t.Fatalf("manifest=%q", manifest)
	}
	if err := os.WriteFile(filepath.Join(root, "site-manifest.sha256"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeManifest(context.Background(), root, "site-manifest.sha256"); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	t.Run("tampered file", func(t *testing.T) {
		copyRoot := t.TempDir()
		writeTree(t, copyRoot, map[string]string{"index.html": "<p>y</p>\n", "sub/data.json": "{}\n"})
		if err := os.WriteFile(filepath.Join(copyRoot, "site-manifest.sha256"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyTreeManifest(context.Background(), copyRoot, "site-manifest.sha256"); err == nil {
			t.Fatal("tampered file verified")
		}
	})
	t.Run("extra file", func(t *testing.T) {
		copyRoot := t.TempDir()
		writeTree(t, copyRoot, map[string]string{"index.html": "<p>x</p>\n", "sub/data.json": "{}\n", "extra.txt": "x"})
		if err := os.WriteFile(filepath.Join(copyRoot, "site-manifest.sha256"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyTreeManifest(context.Background(), copyRoot, "site-manifest.sha256"); err == nil {
			t.Fatal("unmanifested file verified")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		copyRoot := t.TempDir()
		writeTree(t, copyRoot, map[string]string{"index.html": "<p>x</p>\n"})
		if err := os.WriteFile(filepath.Join(copyRoot, "site-manifest.sha256"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyTreeManifest(context.Background(), copyRoot, "site-manifest.sha256"); err == nil {
			t.Fatal("missing file verified")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation is not portable on Windows runners")
		}
		copyRoot := t.TempDir()
		writeTree(t, copyRoot, map[string]string{"index.html": "<p>x</p>\n", "sub/data.json": "{}\n"})
		if err := os.WriteFile(filepath.Join(copyRoot, "site-manifest.sha256"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(copyRoot, "index.html"), filepath.Join(copyRoot, "link.html")); err != nil {
			t.Fatal(err)
		}
		if err := VerifyTreeManifest(context.Background(), copyRoot, "site-manifest.sha256"); err == nil {
			t.Fatal("symlinked tree verified")
		}
	})
	for _, malformed := range []string{"", "abc  index.html\n", strings.Repeat("a", 64) + " index.html\n", strings.Repeat("a", 64) + "  ../index.html\n", strings.Repeat("b", 64) + "  z.html\n" + strings.Repeat("a", 64) + "  a.html\n"} {
		if _, err := parseManifest([]byte(malformed)); err == nil {
			t.Fatalf("malformed manifest %q accepted", malformed)
		}
	}
}
