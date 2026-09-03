package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPriorTreesAreHashLockedAndCopiedVerbatim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	older, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "older"), Version: "0.1.0", SourceCommit: testSourceCommit, GoVersion: testGoVersion})
	if err != nil {
		t.Fatal(err)
	}
	priorDir := filepath.Join(older.SiteDir, "v0.1.0")
	prior := PriorTree{Version: "0.1.0", SiteManifestSHA256: older.SiteManifestSHA256, Dir: priorDir}

	// A tombstone is a prior tree that carries only a page and its manifest.
	tombstoneDir := filepath.Join(root, "tombstone")
	if err := os.Mkdir(tombstoneDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tombstonePage, err := RenderRoot("0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(tombstoneDir, "index.html"), tombstonePage)
	tombstoneManifest, err := BuildTreeManifest(ctx, tombstoneDir, siteManifestName)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(tombstoneDir, siteManifestName), tombstoneManifest)
	tombstoneSum := sha256.Sum256(tombstoneManifest)
	tombstone := PriorTree{Version: "0.0.1", SiteManifestSHA256: hex.EncodeToString(tombstoneSum[:]), Dir: tombstoneDir}

	result, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "current"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion, Priors: []PriorTree{prior, tombstone}})
	if err != nil {
		t.Fatalf("build with prior trees: %v", err)
	}
	locks := []PriorTree{{Version: "0.1.0", SiteManifestSHA256: prior.SiteManifestSHA256}, {Version: "0.0.1", SiteManifestSHA256: tombstone.SiteManifestSHA256}}
	if _, err := Verify(ctx, result.SiteDir, testVersion, locks); err != nil {
		t.Fatalf("verify with prior locks: %v", err)
	}
	if _, err := Verify(ctx, result.SiteDir, testVersion, nil); err == nil {
		t.Fatal("prior trees were accepted without their locks")
	}
	if _, err := Verify(ctx, result.SiteDir, testVersion, locks[:1]); err == nil {
		t.Fatal("an unlocked extra version tree was accepted")
	}
	names, err := listRegularFiles(ctx, priorDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append(names, siteManifestName) {
		if !bytes.Equal(mustRead(t, filepath.Join(priorDir, filepath.FromSlash(name))), mustRead(t, filepath.Join(result.SiteDir, "v0.1.0", filepath.FromSlash(name)))) {
			t.Fatalf("prior file %s was not copied verbatim", name)
		}
	}

	badLock := prior
	badLock.SiteManifestSHA256 = strings.Repeat("0", 64)
	if _, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "bad-lock"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion, Priors: []PriorTree{badLock}}); err == nil {
		t.Fatal("prior tree with a wrong hash lock was published")
	}
	tamperedDir := filepath.Join(root, "tampered-prior")
	copyTree(t, priorDir, tamperedDir)
	mustWrite(t, filepath.Join(tamperedDir, "summary.md"), append(mustRead(t, filepath.Join(tamperedDir, "summary.md")), '\n'))
	tampered := prior
	tampered.Dir = tamperedDir
	if _, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "tampered"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion, Priors: []PriorTree{tampered}}); err == nil {
		t.Fatal("prior tree that drifted from its manifest was published")
	}
	sameVersion := prior
	sameVersion.Version = testVersion
	if _, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "same"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion, Priors: []PriorTree{sameVersion}}); err == nil {
		t.Fatal("prior tree colliding with the current version was published")
	}
	activeDir := filepath.Join(root, "active-tombstone")
	if err := os.Mkdir(activeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(activeDir, "index.html"), bytes.Replace(tombstonePage, []byte("</main>"), []byte("<script>alert(1)</script></main>"), 1))
	activeManifest, err := BuildTreeManifest(ctx, activeDir, siteManifestName)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(activeDir, siteManifestName), activeManifest)
	activeSum := sha256.Sum256(activeManifest)
	if _, err := Build(ctx, Options{CaseDir: sharedDemoCase, Output: filepath.Join(root, "active"), Version: testVersion, SourceCommit: testSourceCommit, GoVersion: testGoVersion, Priors: []PriorTree{{Version: "0.0.2", SiteManifestSHA256: hex.EncodeToString(activeSum[:]), Dir: activeDir}}}); err == nil {
		t.Fatal("prior page with a script element was published")
	}
	for _, leftover := range []string{"bad-lock", "tampered", "same", "active"} {
		if _, err := os.Lstat(filepath.Join(root, leftover)); !os.IsNotExist(err) {
			t.Fatalf("rejected build left output %s", leftover)
		}
	}
}
