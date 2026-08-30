package releaseartifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

const (
	testVersion = "0.1.0-rc.1"
	testCommit  = "0123456789abcdef0123456789abcdef01234567"
	testEpoch   = int64(946684800)
	testGo      = "go1.25.13"
)

func TestNewBuildMetadataAndLDFlags(t *testing.T) {
	metadata, err := NewBuildMetadata(testVersion, testCommit, testGo, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.BuildDate != "2000-01-01T00:00:00Z" || metadata.Authenticated {
		t.Fatalf("unexpected build metadata: %+v", metadata)
	}
	wantFlags := "-s -w -buildid=" +
		" -X=github.com/torjan0/cirewind/internal/buildinfo.Version=0.1.0-rc.1" +
		" -X=github.com/torjan0/cirewind/internal/buildinfo.Commit=" + testCommit +
		" -X=github.com/torjan0/cirewind/internal/buildinfo.Date=2000-01-01T00:00:00Z" +
		" -X=github.com/torjan0/cirewind/internal/buildinfo.ReleaseStamp=" + ReleaseStamp(metadata)
	if got := LDFlags(metadata); got != wantFlags {
		t.Fatalf("LDFlags() = %q, want %q", got, wantFlags)
	}
}

func TestReleaseRepositoryAllowlistExcludesUnreviewedIncidentMaterial(t *testing.T) {
	for _, file := range repositoryReleaseFiles() {
		if strings.HasPrefix(file.Name, "incidents/candidates/") ||
			strings.HasPrefix(file.Name, "review-packets/") ||
			file.Name == "pack-review-policy.json" || file.Name == "review-registry.json" {
			t.Fatalf("unreviewed governance material entered the release allowlist: %s", file.Name)
		}
	}
}

func TestValidateReleaseStamp(t *testing.T) {
	metadata, err := NewBuildMetadata(testVersion, testCommit, testGo, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	stamp := []byte(ReleaseStamp(metadata))
	if err := validateReleaseStamp(append([]byte("prefix"), append(stamp, []byte("suffix")...)...), metadata); err != nil {
		t.Fatal(err)
	}
	if err := validateReleaseStamp([]byte("missing"), metadata); err == nil {
		t.Fatal("expected missing stamp rejection")
	}
	if err := validateReleaseStamp(append(append([]byte(nil), stamp...), stamp...), metadata); err == nil {
		t.Fatal("expected duplicate stamp rejection")
	}
}

func TestNewBuildMetadataRejectsAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name, version, commit, goVersion string
		epoch                            int64
	}{
		{name: "v prefix", version: "v0.1.0", commit: testCommit, goVersion: testGo, epoch: testEpoch},
		{name: "leading zero", version: "00.1.0", commit: testCommit, goVersion: testGo, epoch: testEpoch},
		{name: "prerelease leading zero", version: "1.0.0-01", commit: testCommit, goVersion: testGo, epoch: testEpoch},
		{name: "short commit", version: testVersion, commit: "0123456", goVersion: testGo, epoch: testEpoch},
		{name: "uppercase commit", version: testVersion, commit: strings.ToUpper(testCommit), goVersion: testGo, epoch: testEpoch},
		{name: "floating Go", version: testVersion, commit: testCommit, goVersion: "go1.25", epoch: testEpoch},
		{name: "pre ZIP epoch", version: testVersion, commit: testCommit, goVersion: testGo, epoch: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewBuildMetadata(test.version, test.commit, test.goVersion, test.epoch); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateBuildInfoAndSPDXAreTargetSpecific(t *testing.T) {
	metadata, err := NewBuildMetadata(testVersion, testCommit, testGo, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{OS: "linux", Arch: "amd64"}
	moduleSum := "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	info := &debug.BuildInfo{
		GoVersion: testGo,
		Path:      ModulePath + "/cmd/cirewind",
		Main:      debug.Module{Path: ModulePath, Version: "(devel)"},
		Deps:      []*debug.Module{{Path: "example.invalid/dependency", Version: "v1.2.3", Sum: moduleSum}},
		Settings: []debug.BuildSetting{
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "amd64"},
			{Key: "GOAMD64", Value: "v1"},
			{Key: "-trimpath", Value: "true"},
			{Key: "-ldflags", Value: LDFlags(metadata)},
		},
	}
	if err := ValidateBuildInfo(info, target, metadata); err != nil {
		t.Fatal(err)
	}
	first, err := GenerateSPDX(info, target, metadata, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSPDX(info, target, metadata, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("SPDX generation is not deterministic")
	}
	var document spdxDocument
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	if document.SPDXVersion != "SPDX-2.3" || len(document.Packages) != 3 || len(document.Relationships) != 3 {
		t.Fatalf("unexpected SPDX document: %+v", document)
	}

	info.Settings[1].Value = "darwin"
	if err := ValidateBuildInfo(info, target, metadata); err == nil {
		t.Fatal("expected target mismatch")
	}
	info.Settings[1].Value = "linux"
	info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.revision", Value: testCommit})
	if err := ValidateBuildInfo(info, target, metadata); err == nil {
		t.Fatal("expected embedded VCS setting rejection")
	}
}

func TestDeterministicArchivesRoundTrip(t *testing.T) {
	files := []ArchiveFile{
		{Name: "LICENSE", Data: []byte("license\n"), Mode: 0o644},
		{Name: "cirewind", Data: []byte("binary\n"), Mode: 0o755},
	}
	for _, target := range []Target{{OS: "linux", Arch: "amd64"}, {OS: "windows", Arch: "amd64"}} {
		t.Run(target.OS, func(t *testing.T) {
			first, err := DeterministicArchive(target, "cirewind_0.1.0_"+target.OS+"_amd64", testEpoch, files)
			if err != nil {
				t.Fatal(err)
			}
			second, err := DeterministicArchive(target, "cirewind_0.1.0_"+target.OS+"_amd64", testEpoch, files)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Fatal("archive bytes differ")
			}
			extracted, err := ReadArchive(target, first, 8, 1024)
			if err != nil {
				t.Fatal(err)
			}
			if len(extracted) != 2 {
				t.Fatalf("extracted %d files", len(extracted))
			}
			if target.OS == "windows" {
				reader, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range reader.File {
					if !file.Modified.Equal(time.Unix(testEpoch, 0).UTC()) {
						t.Fatalf("ZIP timestamp = %s, want source epoch", file.Modified)
					}
				}
			} else {
				gzipReader, err := gzip.NewReader(bytes.NewReader(first))
				if err != nil {
					t.Fatal(err)
				}
				header, err := tar.NewReader(gzipReader).Next()
				if err != nil {
					t.Fatal(err)
				}
				if header.Typeflag != tar.TypeReg {
					t.Fatalf("tar type = %d, want explicit regular-file type", header.Typeflag)
				}
				if err := gzipReader.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestArchiveReaderRejectsTraversalAndLinks(t *testing.T) {
	var zipBytes bytes.Buffer
	zipWriter := zip.NewWriter(&zipBytes)
	header := &zip.FileHeader{Name: "../escape", Method: zip.Store}
	header.SetMode(0o644)
	entry, err := zipWriter.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArchive(Target{OS: "windows", Arch: "amd64"}, zipBytes.Bytes(), 8, 1024); err == nil {
		t.Fatal("expected ZIP traversal rejection")
	}

	var tarBytes bytes.Buffer
	gzipWriter := gzip.NewWriter(&tarBytes)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "bundle/link", Typeflag: tar.TypeSymlink, Linkname: "/tmp/escape", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArchive(Target{OS: "linux", Arch: "amd64"}, tarBytes.Bytes(), 8, 1024); err == nil {
		t.Fatal("expected tar link rejection")
	}
}

func TestReleaseArchivePathsArePortable(t *testing.T) {
	target := Target{OS: "linux", Arch: "amd64"}
	tests := []string{
		"/absolute", "../escape", "directory/../escape", "directory\\escape",
		"C:/escape", "directory/trailing.", "directory/trailing ",
		"directory/NUL", "directory/con.txt", "directory/COM1", "directory/Lpt9.log",
		"directory/escape\x1bsequence",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			_, err := DeterministicArchive(target, "cirewind_0.1.0_linux_amd64", testEpoch, []ArchiveFile{{
				Name: path, Data: []byte("x"), Mode: 0o644,
			}})
			if err == nil {
				t.Fatalf("accepted nonportable archive path %q", path)
			}
		})
	}
}

func TestCheckedInLicenseIndexCoversReviewedTargets(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	common := []string{
		"github.com/dustin/go-humanize@v1.0.1",
		"github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec",
		"golang.org/x/sys@v0.47.0",
		"gopkg.in/yaml.v3@v3.0.1",
		"modernc.org/libc@v1.74.4",
		"modernc.org/mathutil@v1.7.1",
		"modernc.org/memory@v1.11.0",
		"modernc.org/sqlite@v1.57.0",
	}
	tests := []struct {
		target Target
		extra  []string
	}{
		{target: Target{OS: "linux", Arch: "amd64"}, extra: []string{"github.com/google/uuid@v1.6.0"}},
		{target: Target{OS: "linux", Arch: "arm64"}, extra: []string{"github.com/google/uuid@v1.6.0"}},
		{target: Target{OS: "darwin", Arch: "amd64"}, extra: []string{"github.com/google/uuid@v1.6.0", "github.com/mattn/go-isatty@v0.0.24", "github.com/ncruces/go-strftime@v1.0.0"}},
		{target: Target{OS: "darwin", Arch: "arm64"}, extra: []string{"github.com/google/uuid@v1.6.0", "github.com/mattn/go-isatty@v0.0.24", "github.com/ncruces/go-strftime@v1.0.0"}},
		{target: Target{OS: "windows", Arch: "amd64"}, extra: []string{"github.com/mattn/go-isatty@v0.0.24", "github.com/ncruces/go-strftime@v1.0.0"}},
		{target: Target{OS: "windows", Arch: "arm64"}, extra: []string{"github.com/mattn/go-isatty@v0.0.24", "github.com/ncruces/go-strftime@v1.0.0"}},
	}
	moduleSum := "h1:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, test := range tests {
		t.Run(test.target.String(), func(t *testing.T) {
			modules := append(append([]string(nil), common...), test.extra...)
			sortStrings(modules)
			info := &debug.BuildInfo{}
			for _, value := range modules {
				parts := strings.SplitN(value, "@", 2)
				info.Deps = append(info.Deps, &debug.Module{Path: parts[0], Version: parts[1], Sum: moduleSum})
			}
			bundle, err := LoadLicenseBundle(root, test.target, info, testGo)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.Files) == 0 || len(bundle.Index) == 0 {
				t.Fatal("empty license bundle")
			}
		})
	}
}

func TestCompareDistributions(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, directory := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(directory, "artifact"), []byte("same"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CompareDistributions(first, second); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "artifact"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CompareDistributions(first, second); err == nil {
		t.Fatal("expected changed distribution rejection")
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
