package samplesite

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/demodata"
)

func TestReadmeCandidateFirstScreenAndLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	candidate, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion})
	if err != nil {
		t.Fatalf("build README candidate: %v", err)
	}
	again, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion})
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
	order := []string{
		"# CIRewind",
		"Reconstruct which GitHub Action commit actually ran",
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
		"`SHA256SUMS`, per-target SPDX documents, and GitHub build-provenance",
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
	if inventory.SchemaVersion != readmeSlotsSchema || !inventory.Candidate || inventory.SiteVersion != testVersion || len(inventory.Slots) < 10 {
		t.Fatalf("inventory=%+v", inventory)
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

	final, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion, Final: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final.Files[ReadmeFinalName]; !ok || bytes.Contains(final.Files[ReadmeFinalName], []byte("STAGED")) || !bytes.HasPrefix(final.Files[ReadmeFinalName], []byte("# CIRewind\n")) {
		t.Fatal("final README rendering must drop the banner and use README.md")
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
	candidate, err := BuildReadmeCandidate(ctx, sharedDemoCase, ReadmeSlots{Version: testVersion})
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
	if _, err := RenderReadme(CaseSummary{}, ReadmeSlots{Version: testVersion}); err == nil {
		t.Fatal("empty summary accepted")
	}
}
