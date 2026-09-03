package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/demodata"
)

// testAssetsDir is the repository's fixed-asset directory seen from the package.
var testAssetsDir = filepath.Join("..", "..", "site", "assets")

func TestReadmeCandidateFirstScreenAndLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	candidate, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: testAssetsDir})
	if err != nil {
		t.Fatalf("build README candidate: %v", err)
	}
	again, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: testAssetsDir})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range candidate.Files {
		if !bytes.Equal(data, again.Files[name]) {
			t.Fatalf("README candidate file %s is not deterministic", name)
		}
	}
	page := string(candidate.Files[ReadmeCandidateName])
	if !strings.HasPrefix(page, "<!--\nSTAGED v0.2.0 README CANDIDATE.") || !strings.Contains(page, "Do not copy this file to README.md on the default branch.") {
		t.Fatal("candidate README lacks the staged-candidate banner")
	}
	banner := "![" + readmeBannerAlt + "](site/assets/" + ReadmeBannerName + "#gh-dark-mode-only)\n![" + readmeBannerAlt + "](site/assets/" + ReadmeBannerLightName + "#gh-light-mode-only)\n\n# CIRewind\n"
	if !strings.Contains(page, banner) || strings.Index(page, banner) > strings.Index(page, "# CIRewind") {
		t.Fatal("candidate README must show both fixed banner variants with their alt text immediately above the heading")
	}
	if strings.Count(page, "#gh-dark-mode-only") != 1 || strings.Count(page, "#gh-light-mode-only") != 1 {
		t.Fatal("each banner theme variant must be referenced exactly once")
	}
	order := []string{
		"# CIRewind",
		"Reconstruct which GitHub Action commit each historical run executed",
		"[![Temporal evidence path for the synthetic case",
		"](site/generated/readme-preview.svg)](" + VersionedPagesURL(testVersion) + "graph.svg)",
		"**SYNTHETIC — PARTIAL COVERAGE.**",
		"11 findings across the ten canonical states",
		"| `CONFIRMED_EXECUTED` | 1 |",
		"[Open the sample report](" + VersionedPagesURL(testVersion) + "sample-case/report.html)",
		"[Download the verified sample case](" + VersionedPagesURL(testVersion) + "downloads/" + ArchiveName(testVersion) + ")",
		"## Two-minute local run",
		"brew install torjan0/tap/cirewind\ncirewind demo --out cirewind-demo\ncirewind verify cirewind-demo",
		"go install github.com/torjan0/cirewind/cmd/cirewind@v0.2.0",
		"**Experimental v0.2.0:**",
		"## High-assurance installation",
		"[v0.2.0 release](" + ReleaseURL(testVersion) + ")",
		"`SHA256SUMS`, per-target SPDX",
		"## Why CIRewind exists",
		"## Evidence semantics",
		"## Contributing",
	}
	position := 0
	for _, marker := range order {
		index := strings.Index(page[position:], marker)
		if index < 0 {
			t.Fatalf("README candidate lacks %q after position %d", marker, position)
		}
		position += index
	}
	firstScreen := page[:strings.Index(page, "## High-assurance installation")]
	if !strings.Contains(firstScreen, "experimental") || strings.Count(firstScreen, "\n## ") != 1 {
		t.Fatalf("first screen must carry the experimental label and exactly one section heading before the high-assurance lane: %q", firstScreen)
	}
	for _, invariant := range Invariants {
		if !strings.Contains(page, invariant) {
			t.Fatalf("README candidate omits invariant %q", invariant)
		}
	}
	if strings.Contains(page, "{{") || strings.Contains(page, "}}") {
		t.Fatal("README candidate contains unresolved template text")
	}
	if err := CheckProhibitedLanguage([]byte(page)); err != nil {
		t.Fatal(err)
	}

	repositoryRoot := filepath.Join("..", "..")
	generated := map[string]bool{}
	for name := range candidate.Files {
		generated["site/generated/"+name] = true
	}
	external := map[string]bool{}
	for _, link := range ReadmeLinks([]byte(page)) {
		if strings.HasPrefix(link, "https://") {
			if link != ReleaseURL(testVersion) && !strings.HasPrefix(link, VersionedPagesURL(testVersion)) {
				t.Fatalf("README candidate links outside the fixed destinations: %s", link)
			}
			external[link] = true
			continue
		}
		if strings.Contains(link, "://") || strings.HasPrefix(link, "/") || strings.HasPrefix(link, "#") {
			t.Fatalf("README candidate link %q is not a repository-relative path", link)
		}
		if generated[link] {
			continue
		}
		// GitHub theme fragments select a variant; the file itself has no fragment.
		link, _, _ = strings.Cut(link, "#")
		if _, err := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(link))); err != nil {
			t.Fatalf("README candidate links to missing repository file %q: %v", link, err)
		}
	}
	for _, required := range []string{ReleaseURL(testVersion), VersionedPagesURL(testVersion) + "sample-case/report.html", VersionedPagesURL(testVersion) + "graph.svg"} {
		if !external[required] {
			t.Fatalf("README candidate does not link %s", required)
		}
	}

	var inventory ReadmeInventory
	decoder := json.NewDecoder(bytes.NewReader(candidate.Files[ReadmeSlotsName]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.SchemaVersion != readmeSlotsSchema || !inventory.Candidate || inventory.SiteVersion != testVersion || len(inventory.Slots) < 11 {
		t.Fatalf("inventory=%+v", inventory)
	}
	for slotName, asset := range map[string]string{"banner-image": ReadmeBannerName, "banner-image-light": ReadmeBannerLightName} {
		sum := sha256.Sum256(mustRead(t, filepath.Join(testAssetsDir, asset)))
		found := false
		for _, slot := range inventory.Slots {
			if slot.Name == slotName {
				found = true
				if slot.Value != "site/assets/"+asset || slot.Resolution != "resolved-now" || !strings.HasSuffix(slot.Note, hex.EncodeToString(sum[:])) {
					t.Fatalf("slot %s does not bind the asset digest: %+v", slotName, slot)
				}
			}
		}
		if !found {
			t.Fatalf("inventory lacks the %s slot", slotName)
		}
	}
	unresolved := 0
	for _, slot := range inventory.Slots {
		switch slot.Resolution {
		case "resolved-now":
		case "resolves-at-release", "resolves-at-deployment":
			unresolved++
			if !strings.Contains(page, slot.Value) {
				t.Fatalf("unresolved slot %s value %q is not the rendered text", slot.Name, slot.Value)
			}
		default:
			t.Fatalf("slot %s has unknown resolution %q", slot.Name, slot.Resolution)
		}
	}
	if unresolved == 0 {
		t.Fatal("inventory hides that release and deployment slots are unresolved")
	}

	final, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: testAssetsDir, Final: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final.Files[ReadmeFinalName]; !ok || bytes.Contains(final.Files[ReadmeFinalName], []byte("STAGED")) || !bytes.HasPrefix(final.Files[ReadmeFinalName], []byte("!["+readmeBannerAlt+"](site/assets/"+ReadmeBannerName+"#gh-dark-mode-only)\n!["+readmeBannerAlt+"](site/assets/"+ReadmeBannerLightName+"#gh-light-mode-only)\n\n# CIRewind\n")) {
		t.Fatal("final README rendering must drop the staged notice, keep the banner, and use README.md")
	}
	if !bytes.Equal(candidate.Files[ReadmeGraphName], mustRead(t, filepath.Join(sharedDemoCase, "graph.svg"))) {
		t.Fatal("graph copy is not byte-identical to the case graph")
	}
}

func TestReadmePreviewChangesOnlyTheViewport(t *testing.T) {
	t.Parallel()
	graph := mustRead(t, filepath.Join(sharedDemoCase, "graph.svg"))
	preview, err := RenderReadmePreviewSVG(graph)
	if err != nil {
		t.Fatal(err)
	}
	info, err := AuditSVG(preview)
	if err != nil {
		t.Fatal(err)
	}
	source, err := AuditSVG(graph)
	if err != nil {
		t.Fatal(err)
	}
	if info.Width != source.Width || info.Height != ReadmePreviewHeight || source.Height <= ReadmePreviewHeight {
		t.Fatalf("preview=%+v source=%+v", info, source)
	}
	if !bytes.Contains(preview, []byte(`viewBox="0 0 3000 1450"`)) || !bytes.Contains(preview, []byte("README preview viewport: the top 1450 of")) {
		t.Fatal("preview does not carry the expected viewport and description note")
	}
	rootDescriptionEnd := func(data []byte) int {
		start := bytes.Index(data, rootDescriptionStart)
		if start < 0 {
			t.Fatal("root description missing")
		}
		return start + bytes.Index(data[start:], []byte("</desc>"))
	}
	if !bytes.Equal(graph[rootDescriptionEnd(graph):], preview[rootDescriptionEnd(preview):]) {
		t.Fatal("preview alters bytes after the root accessible description")
	}
	if bytes.Count(preview, rootDescriptionStart) != 1 || len(preview) >= len(graph)+200 {
		t.Fatal("preview edit is not bounded to the root description note")
	}
	short := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="20" viewBox="0 0 10 20"><title>t</title><desc id="tep-desc">d</desc><rect width="1" height="1"/></svg>`)
	same, err := RenderReadmePreviewSVG(short)
	if err != nil || !bytes.Equal(same, short) {
		t.Fatalf("short graph must pass through unchanged: %v", err)
	}
	if _, err := RenderReadmePreviewSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="9000" viewBox="0 0 10 9000"><script>1</script></svg>`)); err == nil {
		t.Fatal("hostile graph accepted as preview source")
	}
}

func TestReadmeCandidateWriteAndCompare(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	candidate, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: testAssetsDir})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := candidate.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Compare(dir); err != nil {
		t.Fatalf("freshly written candidate does not compare clean: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ReadmeCandidateName), append(candidate.Files[ReadmeCandidateName], '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Compare(dir); err == nil {
		t.Fatal("drifted candidate compared clean")
	}
	if err := candidate.Write(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := LoadVerifiedCase(ctx, sharedDemoCase, bundle.Oracle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderReadme(summary, ReadmeSlots{Version: "v0.2.0"}); err == nil {
		t.Fatal("v-prefixed version accepted")
	}
	if _, err := RenderReadme(CaseSummary{}, ReadmeSlots{Version: testVersion, AssetsDir: testAssetsDir}); err == nil {
		t.Fatal("empty summary accepted")
	}
}

func TestReadmeCandidateRejectsBadBannerAssets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: t.TempDir()}); err == nil {
		t.Fatal("a missing banner asset was accepted")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ReadmeBannerName), []byte("not a png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: dir}); err == nil {
		t.Fatal("a non-PNG banner asset was accepted")
	}
	wrongSize := append([]byte("\x89PNG\r\n\x1a\n"), []byte{0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 100, 0, 0, 0, 50}...)
	if err := os.WriteFile(filepath.Join(dir, ReadmeBannerName), wrongSize, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: dir}); err == nil {
		t.Fatal("a banner asset with the wrong dimensions was accepted")
	}
	// A valid dark asset alone is not enough: the light variant is bound too.
	if err := os.WriteFile(filepath.Join(dir, ReadmeBannerName), mustRead(t, filepath.Join(testAssetsDir, ReadmeBannerName)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, AssetsDir: dir}); err == nil {
		t.Fatal("a missing light banner asset was accepted")
	}
}
