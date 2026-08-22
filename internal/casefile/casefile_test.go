package casefile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func writeRequired(t *testing.T, builder *Builder) {
	t.Helper()
	for _, name := range requiredFiles {
		f, err := builder.CreateFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(name); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFinalizeAndVerify(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "raw")); !os.IsNotExist(err) {
		t.Fatalf("raw directory exists by default: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "findings.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err == nil {
		t.Fatal("tampered case verified")
	}
}

func TestVerifyManifestDoesNotMutateCaseDirectory(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := directoryEntries(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	after, err := directoryEntries(target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("manifest verification mutated case directory: before=%v after=%v", before, after)
	}
}

func directoryEntries(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(entries))
	for index, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		result[index] = entry.Name() + ":" + info.Mode().String() + ":" + fmt.Sprint(info.Size())
	}
	return result, nil
}

func TestVerifyRejectsExtraFile(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, false)
	if err != nil {
		t.Fatal(err)
	}
	writeRequired(t, builder)
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err == nil {
		t.Fatal("unmanifested extra file accepted")
	}
}

func TestVerifyRejectsSelfConsistentIncompleteCase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "required case file") {
		t.Fatalf("empty case verification error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "report.html"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildManifest(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "required case file") {
		t.Fatalf("partial case verification error = %v", err)
	}
}

func TestRawSHA256FileIsOwnerOnlyAndManifested(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "case")
	builder, err := NewBuilder(target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	writeRequired(t, builder)
	digest := strings.Repeat("b", 64)
	file, err := builder.CreateRawFile(digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("raw bytes"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.RawSHA256Path("../../hostile"); err == nil {
		t.Fatal("hostile raw digest accepted")
	}
	if err := builder.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(target, "manifest.sha256"))
	if err != nil || !strings.Contains(string(manifest), "raw/"+digest+".bin") {
		t.Fatalf("raw object absent from manifest: err=%v manifest=%q", err, manifest)
	}
	if runtime.GOOS != "windows" {
		directory, _ := os.Stat(filepath.Join(target, "raw"))
		retained, _ := os.Stat(filepath.Join(target, "raw", digest+".bin"))
		if directory.Mode().Perm() != 0o700 || retained.Mode().Perm() != 0o600 {
			t.Fatalf("raw permissions directory=%o file=%o", directory.Mode().Perm(), retained.Mode().Perm())
		}
	}
}

func TestRawSHA256FileDisabledByDefault(t *testing.T) {
	t.Parallel()
	builder, err := NewBuilder(filepath.Join(t.TempDir(), "case"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	if _, err := builder.CreateRawFile(strings.Repeat("c", 64)); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled raw creation error=%v", err)
	}
}

func TestNewBuilderRejectsSymlinkAncestorBeforeCreatingParents(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	redirectTarget := t.TempDir()
	link := filepath.Join(base, "redirect")
	if err := os.Symlink(redirectTarget, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	target := filepath.Join(link, "must-not-be-created", "case")
	if _, err := NewBuilder(target, false); err == nil {
		t.Fatal("case path with a symlink ancestor was accepted")
	}
	if _, err := os.Lstat(filepath.Join(redirectTarget, "must-not-be-created")); !os.IsNotExist(err) {
		t.Fatalf("case builder mutated the symlink target before rejection: %v", err)
	}
}
