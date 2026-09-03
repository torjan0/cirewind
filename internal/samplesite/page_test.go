package samplesite

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func samplePageData() PageData {
	counts := make([]CountRow, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		counts = append(counts, CountRow{State: state, Count: 1})
	}
	return PageData{
		Version: "0.2.0", VersionPath: "v0.2.0", Counts: counts, Total: 11,
		WriteTokenJobs: 1, NamedSecretFlows: 1, OIDCJobs: 1, SelfHostedJobs: 1, DeploymentsAfter: 1,
		ArchiveName: ArchiveName("0.2.0"), ArchiveSHA256: strings.Repeat("a", 64), CaseManifestSHA256: strings.Repeat("b", 64),
		SourceCommit: strings.Repeat("c", 40), GoVersion: "go1.25.13", DemoBundleID: "cirewind.demo/v2", FixtureVersion: "2.0.0",
		SVGWidth: 1200, SVGHeight: 900,
	}
}

func TestContentSecurityPolicyIsExactAndHashBound(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte(Stylesheet))
	want := "default-src 'none'; img-src 'self'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; script-src 'none'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'"
	if ContentSecurityPolicy() != want {
		t.Fatalf("CSP=%q", ContentSecurityPolicy())
	}
	for _, forbidden := range []string{"url(", "@import", "http", "expression("} {
		if strings.Contains(strings.ToLower(Stylesheet), forbidden) {
			t.Fatalf("stylesheet contains %q", forbidden)
		}
	}
}

func TestLandingPageHierarchyAndSafety(t *testing.T) {
	t.Parallel()
	page, err := RenderLanding(samplePageData())
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	if policy, err := landingCSP(page); err != nil || policy != ContentSecurityPolicy() {
		t.Fatalf("landing page does not embed the exact policy: %q %v", policy, err)
	}
	if !strings.Contains(text, Headline) {
		t.Fatal("headline missing")
	}
	lower := strings.ToLower(text)
	for _, forbidden := range forbiddenMarkup {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("landing page contains %q", forbidden)
		}
	}
	for _, match := range urlPattern.FindAllString(text, -1) {
		if match != ProjectURL && match != ReleaseURL("0.2.0") && match != LabReproductionIndexURL {
			t.Fatalf("landing page links to %q", match)
		}
	}
	// The word experimental must appear in the first viewport, before the visual.
	if firstExperimental, firstVisual := strings.Index(text, "experimental"), strings.Index(text, "Temporal evidence path"); firstExperimental < 0 || firstVisual < 0 || firstExperimental > firstVisual {
		t.Fatal("experimental label is not in the first viewport")
	}
	order := []string{"<h1>", "Temporal evidence path", "SYNTHETIC — PARTIAL COVERAGE", "Open the sample report", "Two-minute local run", "What the A-to-B-to-A case demonstrates", "Mandatory distinctions", "Installation lanes", "Experimental qualification and limitations", "Privacy and provenance"}
	position := 0
	for _, marker := range order {
		index := strings.Index(text[position:], marker)
		if index < 0 {
			t.Fatalf("landing page lacks %q after position %d", marker, position)
		}
		position += index
	}
	for _, invariant := range Invariants {
		if !strings.Contains(text, invariant) {
			t.Fatalf("invariant %q missing", invariant)
		}
	}
	if err := CheckProhibitedLanguage(page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `<img src="./graph.svg"`) || !strings.Contains(text, `rel="noreferrer"`) || !strings.Contains(text, `<meta name="referrer" content="no-referrer">`) {
		t.Fatal("landing page embedding or referrer policy is not the reviewed shape")
	}
	if !strings.Contains(text, "go install github.com/torjan0/cirewind/cmd/cirewind@v0.2.0") || !strings.Contains(text, "brew install torjan0/tap/cirewind") {
		t.Fatal("installation lanes missing")
	}
	for _, evidenceModel := range []string{filepath.Join("..", "..", "docs", "EVIDENCE_MODEL.md"), filepath.Join("..", "..", "docs", "TEST_STRATEGY.md")} {
		data, err := os.ReadFile(evidenceModel)
		if err != nil {
			t.Fatal(err)
		}
		for _, invariant := range Invariants {
			if !strings.Contains(string(data), invariant) {
				t.Fatalf("%s does not contain invariant %q verbatim", evidenceModel, invariant)
			}
		}
	}
}

func TestRenderRejectsInconsistentData(t *testing.T) {
	t.Parallel()
	data := samplePageData()
	data.VersionPath = "v0.3.0"
	if _, err := RenderLanding(data); err == nil {
		t.Fatal("mismatched version path accepted")
	}
	data = samplePageData()
	data.Counts = data.Counts[:3]
	if _, err := RenderLanding(data); err == nil {
		t.Fatal("partial count rows accepted")
	}
	data = samplePageData()
	data.ArchiveSHA256 = "not-hex"
	if _, err := RenderLanding(data); err == nil {
		t.Fatal("non-hex digest accepted")
	}
	if _, err := RenderRoot("v0.2.0"); err == nil {
		t.Fatal("v-prefixed version accepted")
	}
	root, err := RenderRoot("0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(root), `href="./v0.2.0/"`) {
		t.Fatalf("root page=%s", root)
	}
	if err := CheckProhibitedLanguage([]byte("this visual is an attack path")); err == nil {
		t.Fatal("prohibited language accepted")
	}
}

func TestAuditSVGRejectsActiveContent(t *testing.T) {
	t.Parallel()
	valid := `<svg xmlns="http://www.w3.org/2000/svg" role="img" width="10" height="20" viewBox="0 0 10 20"><title>t</title><desc>d</desc><style>svg{forced-color-adjust:none}</style><defs><marker id="m"><path d="M0 0"/></marker></defs><g><rect x="0" y="0" width="1" height="1"/><line x1="0" y1="0" x2="1" y2="1" marker-end="url(#m)"/><text x="0" y="0"><tspan>a</tspan></text></g></svg>`
	info, err := AuditSVG([]byte(valid))
	if err != nil || info.Width != 10 || info.Height != 20 {
		t.Fatalf("valid SVG rejected: info=%+v err=%v", info, err)
	}
	for name, hostile := range map[string]string{
		"script element":   strings.Replace(valid, "<g>", "<g><script>alert(1)</script>", 1),
		"event handler":    strings.Replace(valid, "<rect ", "<rect onload=\"x\" ", 1),
		"image element":    strings.Replace(valid, "<g>", "<g><image href=\"https://example.invalid/x\"/>", 1),
		"anchor element":   strings.Replace(valid, "<g>", "<g><a href=\"https://example.invalid\"><text>x</text></a>", 1),
		"foreign object":   strings.Replace(valid, "<g>", "<g><foreignObject></foreignObject>", 1),
		"doctype":          "<!DOCTYPE svg>" + valid,
		"xml declaration":  "<?xml version=\"1.0\"?>" + valid,
		"external url":     strings.Replace(valid, `marker-end="url(#m)"`, `fill="url(https://example.invalid/p)"`, 1),
		"style attribute":  strings.Replace(valid, "<rect ", "<rect style=\"fill:red\" ", 1),
		"style import":     strings.Replace(valid, "svg{forced-color-adjust:none}", "@import url(x)", 1),
		"custom entity":    strings.Replace(valid, "<tspan>a</tspan>", "<tspan>&custom;</tspan>", 1),
		"missing size":     strings.Replace(valid, ` width="10" height="20"`, "", 1),
		"xlink namespace":  strings.Replace(valid, `xmlns="http://www.w3.org/2000/svg"`, `xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"`, 1),
		"processing instr": strings.Replace(valid, "<g>", "<?pi x?><g>", 1),
	} {
		if _, err := AuditSVG([]byte(hostile)); err == nil {
			t.Fatalf("hostile SVG %q accepted", name)
		}
	}
}
