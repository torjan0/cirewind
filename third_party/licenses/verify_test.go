package licenses_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type licenseIndex struct {
	FormatVersion   int           `json:"format_version"`
	ReviewedAt      string        `json:"reviewed_at"`
	ReviewedTargets []string      `json:"reviewed_targets"`
	Files           []licenseFile `json:"files"`
}

type licenseFile struct {
	Component     string   `json:"component"`
	Version       string   `json:"version"`
	LinkedTargets []string `json:"linked_targets"`
	SourceFile    string   `json:"source_file"`
	LocalPath     string   `json:"local_path"`
	SHA256        string   `json:"sha256"`
}

type expectedFile struct {
	component string
	version   string
	source    string
	hash      string
}

var reviewedTargets = []string{
	"linux/amd64",
	"linux/arm64",
	"darwin/amd64",
	"darwin/arm64",
	"windows/amd64",
	"windows/arm64",
}

var expectedFiles = map[string]expectedFile{
	"github.com/dustin/go-humanize/v1.0.1/LICENSE": {
		"github.com/dustin/go-humanize", "v1.0.1", "$GOMODCACHE/github.com/dustin/go-humanize@v1.0.1/LICENSE", "a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71",
	},
	"github.com/google/uuid/v1.6.0/LICENSE": {
		"github.com/google/uuid", "v1.6.0", "$GOMODCACHE/github.com/google/uuid@v1.6.0/LICENSE", "0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d",
	},
	"github.com/mattn/go-isatty/v0.0.24/LICENSE": {
		"github.com/mattn/go-isatty", "v0.0.24", "$GOMODCACHE/github.com/mattn/go-isatty@v0.0.24/LICENSE", "08eab1118c80885fa1fa6a6dd7303f65a379fcb3733e063d20d1bbc2c76e6fa1",
	},
	"github.com/ncruces/go-strftime/v1.0.0/LICENSE": {
		"github.com/ncruces/go-strftime", "v1.0.0", "$GOMODCACHE/github.com/ncruces/go-strftime@v1.0.0/LICENSE", "38ae43959daf953a393a585b2988672cb65a5a541aca0d0be5e72595a0a16883",
	},
	"github.com/remyoudompheng/bigfft/v0.0.0-20230129092748-24d4a6f8daec/LICENSE": {
		"github.com/remyoudompheng/bigfft", "v0.0.0-20230129092748-24d4a6f8daec", "$GOMODCACHE/github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec/LICENSE", "dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d",
	},
	"go/1.25.13/LICENSE": {
		"go.dev/toolchain", "go1.25.13", "$GOROOT/LICENSE", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
	},
	"go/1.25.13/PATENTS": {
		"go.dev/toolchain", "go1.25.13", "$GOROOT/PATENTS", "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
	},
	"golang.org/x/sys/v0.47.0/LICENSE": {
		"golang.org/x/sys", "v0.47.0", "$GOMODCACHE/golang.org/x/sys@v0.47.0/LICENSE", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad",
	},
	"golang.org/x/sys/v0.47.0/PATENTS": {
		"golang.org/x/sys", "v0.47.0", "$GOMODCACHE/golang.org/x/sys@v0.47.0/PATENTS", "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc",
	},
	"gopkg.in/yaml.v3/v3.0.1/LICENSE": {
		"gopkg.in/yaml.v3", "v3.0.1", "$GOMODCACHE/gopkg.in/yaml.v3@v3.0.1/LICENSE", "d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b",
	},
	"gopkg.in/yaml.v3/v3.0.1/NOTICE": {
		"gopkg.in/yaml.v3", "v3.0.1", "$GOMODCACHE/gopkg.in/yaml.v3@v3.0.1/NOTICE", "f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00",
	},
	"modernc.org/libc/v1.74.4/LICENSE": {
		"modernc.org/libc", "v1.74.4", "$GOMODCACHE/modernc.org/libc@v1.74.4/LICENSE", "95ff867eb55a56935fa7492406cfa953fb7c13ca73f4c0a86ae05756b4605600",
	},
	"modernc.org/libc/v1.74.4/LICENSE-3RD-PARTY.md": {
		"modernc.org/libc", "v1.74.4", "$GOMODCACHE/modernc.org/libc@v1.74.4/LICENSE-3RD-PARTY.md", "f597097efe3d97021f89170746bd3a0fb9a8b6fb26b82043ed68a4e0283bee6c",
	},
	"modernc.org/mathutil/v1.7.1/LICENSE": {
		"modernc.org/mathutil", "v1.7.1", "$GOMODCACHE/modernc.org/mathutil@v1.7.1/LICENSE", "bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5",
	},
	"modernc.org/memory/v1.11.0/LICENSE": {
		"modernc.org/memory", "v1.11.0", "$GOMODCACHE/modernc.org/memory@v1.11.0/LICENSE", "59895e669f48f168b6b858358f6005779cdf40a265f7828813061b56af67b496",
	},
	"modernc.org/memory/v1.11.0/LICENSE-GO": {
		"modernc.org/memory", "v1.11.0", "$GOMODCACHE/modernc.org/memory@v1.11.0/LICENSE-GO", "2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067",
	},
	"modernc.org/memory/v1.11.0/LICENSE-MMAP-GO": {
		"modernc.org/memory", "v1.11.0", "$GOMODCACHE/modernc.org/memory@v1.11.0/LICENSE-MMAP-GO", "c2eba69f20d05414538c3a5df7694dde392e065ff70882e1625e90f5d6659fff",
	},
	"modernc.org/sqlite/v1.57.0/LICENSE": {
		"modernc.org/sqlite", "v1.57.0", "$GOMODCACHE/modernc.org/sqlite@v1.57.0/LICENSE", "c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822",
	},
	"modernc.org/sqlite/v1.57.0/LICENSE-SQLITE": {
		"modernc.org/sqlite", "v1.57.0", "$GOMODCACHE/modernc.org/sqlite@v1.57.0/LICENSE-SQLITE", "8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0",
	},
}

func TestBundledLicenseIntegrity(t *testing.T) {
	root := bundleRoot(t)
	index := readIndex(t, filepath.Join(root, "index.json"))

	if index.FormatVersion != 1 {
		t.Fatalf("format_version = %d, want 1", index.FormatVersion)
	}
	if index.ReviewedAt != "2026-08-21" {
		t.Fatalf("reviewed_at = %q, want 2026-08-21", index.ReviewedAt)
	}
	if !reflect.DeepEqual(index.ReviewedTargets, reviewedTargets) {
		t.Fatalf("reviewed_targets = %v, want %v", index.ReviewedTargets, reviewedTargets)
	}
	if len(index.Files) != len(expectedFiles) {
		t.Fatalf("index has %d files, want %d", len(index.Files), len(expectedFiles))
	}

	seen := make(map[string]bool, len(index.Files))
	previous := ""
	for _, entry := range index.Files {
		if entry.LocalPath <= previous {
			t.Fatalf("index files are not strictly sorted: %q follows %q", entry.LocalPath, previous)
		}
		previous = entry.LocalPath
		want, ok := expectedFiles[entry.LocalPath]
		if !ok {
			t.Fatalf("unexpected indexed file %q", entry.LocalPath)
		}
		if seen[entry.LocalPath] {
			t.Fatalf("duplicate indexed file %q", entry.LocalPath)
		}
		seen[entry.LocalPath] = true
		if entry.Component != want.component || entry.Version != want.version || entry.SourceFile != want.source || entry.SHA256 != want.hash {
			t.Errorf("index metadata differs for %q", entry.LocalPath)
		}
		if !reflect.DeepEqual(entry.LinkedTargets, targetsFor(entry.Component)) {
			t.Errorf("linked_targets for %q = %v, want %v", entry.LocalPath, entry.LinkedTargets, targetsFor(entry.Component))
		}
		verifyBundledFile(t, root, entry.LocalPath, want.hash)
	}

	for path := range expectedFiles {
		if !seen[path] {
			t.Errorf("required file %q is not indexed", path)
		}
	}
	verifyNoUnindexedFiles(t, root, seen)
	verifySelectedVersions(t, filepath.Join(root, "..", "..", "go.mod"))
}

func bundleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate license test source")
	}
	return filepath.Dir(file)
}

func readIndex(t *testing.T, path string) licenseIndex {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var index licenseIndex
	if err := decoder.Decode(&index); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("index has trailing JSON or could not be fully read: %v", err)
	}
	return index
}

func targetsFor(component string) []string {
	switch component {
	case "github.com/google/uuid":
		return reviewedTargets[:4]
	case "github.com/mattn/go-isatty", "github.com/ncruces/go-strftime":
		return reviewedTargets[2:]
	default:
		return reviewedTargets
	}
}

func verifyBundledFile(t *testing.T, root, relativePath, expectedHash string) {
	t.Helper()
	if relativePath == "" || strings.Contains(relativePath, "\\") || filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != filepath.FromSlash(relativePath) || strings.HasPrefix(relativePath, "../") {
		t.Fatalf("unsafe local_path %q", relativePath)
	}
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", relativePath, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%q is not a regular file", relativePath)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", relativePath, err)
	}
	digest := sha256.Sum256(data)
	got := hex.EncodeToString(digest[:])
	if got != expectedHash {
		t.Errorf("SHA-256 for %q = %s, want %s", relativePath, got, expectedHash)
	}
}

func verifyNoUnindexedFiles(t *testing.T, root string, indexed map[string]bool) {
	t.Helper()
	var actual []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular bundle entry %q", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative != "index.json" && relative != "verify_test.go" {
			actual = append(actual, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk license bundle: %v", err)
	}
	sort.Strings(actual)
	for _, path := range actual {
		if !indexed[path] {
			t.Errorf("unindexed file in license bundle: %q", path)
		}
	}
}

func verifySelectedVersions(t *testing.T, goModPath string) {
	t.Helper()
	data, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	required := []string{
		"go 1.25.13",
		"github.com/dustin/go-humanize v1.0.1",
		"github.com/google/uuid v1.6.0",
		"github.com/mattn/go-isatty v0.0.24",
		"github.com/ncruces/go-strftime v1.0.0",
		"github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec",
		"golang.org/x/sys v0.47.0",
		"gopkg.in/yaml.v3 v3.0.1",
		"modernc.org/libc v1.74.4",
		"modernc.org/mathutil v1.7.1",
		"modernc.org/memory v1.11.0",
		"modernc.org/sqlite v1.57.0",
	}
	for _, line := range required {
		if !bytes.Contains(data, []byte(line)) {
			t.Errorf("go.mod no longer selects %q; refresh the linked-module audit and license bundle", line)
		}
	}
}
