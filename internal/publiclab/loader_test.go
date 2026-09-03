package publiclab

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadArtifactUsesBoundedRegularFilesAndCrossBindsManifest(t *testing.T) {
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := WriteArtifact(context.Background(), directory, artifact); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadArtifact(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Bundle, artifact.Bundle) || !bytes.Equal(loaded.Manifest, artifact.Manifest) || loaded.Model.Bundle.SHA256 != artifact.Model.Bundle.SHA256 {
		t.Fatal("loaded artifact differs from generated artifact")
	}

	if err := os.WriteFile(filepath.Join(directory, ManifestFilename), append([]byte(nil), artifact.Manifest[:len(artifact.Manifest)/2]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtifact(context.Background(), directory); err == nil {
		t.Fatal("truncated object manifest was accepted")
	}
}

func TestLoadArtifactRejectsCancellationSymlinksAndUncleanPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadArtifact(ctx, t.TempDir()); err != context.Canceled {
		t.Fatalf("cancellation error=%v", err)
	}
	if _, err := LoadArtifact(context.Background(), filepath.Join(t.TempDir(), "..", "unclean")); err == nil {
		t.Fatal("unclean artifact path accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ManifestFilename), artifact.Manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "bundle")
	if err := os.WriteFile(target, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, BundleFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtifact(context.Background(), directory); err == nil {
		t.Fatal("symlinked bundle was accepted")
	}
}
