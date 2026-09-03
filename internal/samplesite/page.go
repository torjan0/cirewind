package samplesite

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"regexp"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
)

//go:embed templates/landing.html.tmpl templates/root.html.tmpl templates/readme.md.tmpl
var templateFiles embed.FS

// Stylesheet is the only style on the site. Its SHA-256 is the sole style
// source the policy permits; the bytes are versioned renderer constants.
const Stylesheet = `:root{color-scheme:light}html,body{background:#FFFFFF;color:#111827;margin:0;font-family:ui-monospace,monospace;font-size:16px;line-height:1.5}main{max-width:64rem;margin:0 auto;padding:1rem}h1{font-size:1.75rem;line-height:1.25;margin:0.5rem 0}h2{font-size:1.25rem;margin-top:2rem;border-top:1px solid #334155;padding-top:1rem}img{max-width:100%;height:auto;border:1px solid #334155}table{border-collapse:collapse}th,td{border:1px solid #334155;padding:0.25rem 0.5rem;text-align:left}caption{text-align:left;font-weight:bold;margin-bottom:0.25rem}pre{overflow-x:auto;border:1px solid #334155;padding:0.375rem 0.5rem;margin:0.5rem 0}code{font-family:ui-monospace,monospace;overflow-wrap:anywhere}a{color:#005A9C;overflow-wrap:anywhere}a:focus{outline:3px solid #B42318;outline-offset:2px}.label{font-weight:bold;border:2px solid #B42318;display:inline-block;padding:0.125rem 0.5rem;margin:0 0 0.25rem}.lede{font-size:1.1rem;margin:0.5rem 0}.hero{display:grid;grid-template-columns:minmax(0,1fr);gap:0 1.5rem}.hero h2{font-size:1.1rem;margin-top:0.25rem;border-top:0;padding-top:0}.hero p,.hero ul{margin:0.25rem 0}.scroll{overflow-x:auto}.scroll:focus{outline:3px solid #B42318;outline-offset:2px}.visual{max-height:44vh;overflow:auto;border:1px solid #334155}.visual:focus{outline:3px solid #B42318;outline-offset:2px}.visual img{display:block;width:100%;height:auto;border:0}.counts th,.counts td{padding:0.125rem 0.5rem}@media(min-width:60rem){.hero{grid-template-columns:minmax(0,3fr) minmax(0,4fr)}}`

// ProjectURL and LabReproductionIndexURL are the only external navigation
// targets. They are build-time constants that no report, pack, or label can
// alter.
const (
	ProjectURL              = "https://github.com/torjan0/cirewind"
	LabReproductionIndexURL = "https://github.com/torjan0/cirewind-lab/tree/main/reproductions"
	Headline                = "Reconstruct which GitHub Action commit actually ran—even after a mutable tag was restored."
)

// Invariants are the eight mandatory evidence-model sentences, unedited.
var Invariants = []string{
	"Action downloaded != Action executed",
	"Repository possesses a secret != affected step could read that secret",
	"id-token: write != cloud role assumed",
	"Workflow ran during incident window != compromised SHA executed",
	"Current tag points to a safe commit != historical runs were safe",
	"No retained logs != no compromise",
	"Deployment followed an affected step != attacker caused the deployment",
	"Present-day workflow YAML != historical workflow definition",
}

var canonicalSemVer = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

// ContentSecurityPolicy is the exact serialized landing-page policy. Only the
// fixed stylesheet hash and same-origin images are permitted.
func ContentSecurityPolicy() string {
	sum := sha256.Sum256([]byte(Stylesheet))
	return "default-src 'none'; img-src 'self'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; script-src 'none'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'"
}

// CountRow is one canonical state count in fixed state order.
type CountRow struct {
	State model.FindingState
	Count int
}

// PageData is the typed input to the landing template. No field is parsed as
// markup; html/template escapes every value at its sink.
type PageData struct {
	Version            string
	VersionPath        string
	Counts             []CountRow
	Total              int
	WriteTokenJobs     int
	NamedSecretFlows   int
	OIDCJobs           int
	SelfHostedJobs     int
	DeploymentsAfter   int
	ArchiveName        string
	ArchiveSHA256      string
	CaseManifestSHA256 string
	SourceCommit       string
	GoVersion          string
	DemoBundleID       string
	FixtureVersion     string
	SVGWidth           int
	SVGHeight          int
}

// CountPair places two canonical states side by side in the compact table.
type CountPair struct {
	Left  CountRow
	Right CountRow
}

type landingView struct {
	PageData
	CountPairs  []CountPair
	CSP         string
	Stylesheet  template.CSS
	Invariants  []string
	ProjectURL  string
	ReleaseURL  string
	LabIndexURL string
}

type rootView struct {
	Version     string
	VersionPath string
	CSP         string
	Stylesheet  template.CSS
}

var (
	landingTemplate = template.Must(template.ParseFS(templateFiles, "templates/landing.html.tmpl"))
	rootTemplate    = template.Must(template.ParseFS(templateFiles, "templates/root.html.tmpl"))
)

// ValidateVersion accepts only canonical SemVer without a v prefix.
func ValidateVersion(version string) error {
	if len(version) > 64 || !canonicalSemVer.MatchString(version) {
		return fmt.Errorf("site version %q is not canonical SemVer without a v prefix", version)
	}
	return nil
}

// ReleaseURL is the predictable versioned release page for a version.
func ReleaseURL(version string) string {
	return ProjectURL + "/releases/tag/v" + version
}

// RenderLanding renders the versioned landing page from typed data.
func RenderLanding(data PageData) ([]byte, error) {
	if err := ValidateVersion(data.Version); err != nil {
		return nil, err
	}
	if data.VersionPath != "v"+data.Version {
		return nil, errors.New("version path does not match the site version")
	}
	if len(data.Counts) != len(model.FindingStates()) {
		return nil, errors.New("landing data must carry one row per canonical state")
	}
	for index, row := range data.Counts {
		if row.State != model.FindingStates()[index] || row.Count < 0 {
			return nil, errors.New("landing count rows are not in canonical state order")
		}
	}
	if !hexToken(data.ArchiveSHA256, 64) || !hexToken(data.CaseManifestSHA256, 64) || !hexToken(data.SourceCommit, 40) {
		return nil, errors.New("landing data digests must be lowercase hexadecimal")
	}
	if data.ArchiveName != ArchiveName(data.Version) || data.SVGWidth <= 0 || data.SVGHeight <= 0 || data.Total <= 0 {
		return nil, errors.New("landing data is incomplete")
	}
	if len(data.Counts)%2 != 0 {
		return nil, errors.New("canonical state count is not even; the compact table needs pairs")
	}
	pairs := make([]CountPair, 0, len(data.Counts)/2)
	for index := 0; index < len(data.Counts); index += 2 {
		pairs = append(pairs, CountPair{Left: data.Counts[index], Right: data.Counts[index+1]})
	}
	view := landingView{
		PageData:    data,
		CountPairs:  pairs,
		CSP:         ContentSecurityPolicy(),
		Stylesheet:  template.CSS(Stylesheet),
		Invariants:  append([]string(nil), Invariants...),
		ProjectURL:  ProjectURL,
		ReleaseURL:  ReleaseURL(data.Version),
		LabIndexURL: LabReproductionIndexURL,
	}
	var buffer bytes.Buffer
	if err := landingTemplate.Execute(&buffer, view); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// RenderRoot renders the mutable root landing link page.
func RenderRoot(version string) ([]byte, error) {
	if err := ValidateVersion(version); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := rootTemplate.Execute(&buffer, rootView{Version: version, VersionPath: "v" + version, CSP: ContentSecurityPolicy(), Stylesheet: template.CSS(Stylesheet)}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ArchiveName is the fixed download name for a version.
func ArchiveName(version string) string {
	return "cirewind-synthetic-case-v" + version + ".tar.gz"
}

func hexToken(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// prohibitedPhrases must not appear in generated page text. They are the
// overclaims the evidence model forbids.
var prohibitedPhrases = []string{
	"attack path", "compromise path", "blast radius", "exfiltrat", "cloud role assumed", "role assumed",
	"runner compromised", "runner persistent", "caused by the attacker", "not compromised", "independently verified",
	"secret accessed", "secret stolen", "secret leaked",
}

// CheckProhibitedLanguage reports the first forbidden phrase in page text.
func CheckProhibitedLanguage(page []byte) error {
	text := string(page)
	// The eight invariant sentences are quoted verbatim and contain negated
	// forms of otherwise prohibited claims; they are exempt as exact strings.
	for _, invariant := range Invariants {
		text = strings.ReplaceAll(text, invariant, " ")
	}
	lower := strings.ToLower(text)
	for _, phrase := range prohibitedPhrases {
		if strings.Contains(lower, phrase) {
			return fmt.Errorf("page contains prohibited language %q", phrase)
		}
	}
	return nil
}
