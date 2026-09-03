package publiclab

import (
	"context"
	"path/filepath"
	"testing"
)

// TestCheckedArtifactsMatchDeterministicRegeneration pins the checked-in
// public-lab bundle and sidecar manifest to deterministic regeneration from the
// reviewed source overlays. It runs under the ordinary hosted `go test ./...`
// matrix, so a source edit that is not accompanied by an intentional
// `make public-lab-build` regeneration fails on every CI target rather than
// only inside the Linux-local `make public-lab-check` gate.
func TestCheckedArtifactsMatchDeterministicRegeneration(t *testing.T) {
	artifactDir := filepath.Join("..", "..", "lab", "public", "artifacts")
	artifact, err := LoadArtifact(context.Background(), artifactDir)
	if err != nil {
		t.Fatalf("checked public-lab artifact is unreadable or inconsistent: %v", err)
	}
	if artifact.Model.Repository != RepositoryName {
		t.Fatalf("checked public-lab artifact is specialized for %q, want canonical %q", artifact.Model.Repository, RepositoryName)
	}
	if err := VerifyArtifact(context.Background(), sourceRoot(t), artifact.Bundle, artifact.Manifest); err != nil {
		t.Fatalf("checked public-lab artifact differs from deterministic source regeneration; regenerate with make public-lab-build only for an intentional reviewed source change: %v", err)
	}
}
