package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	texttemplate "text/template"

	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/model"
)

// PagesURL is the predictable project Pages origin for the sample site. It is
// a trusted build-time constant; nothing in a case, pack, or label can alter it.
const PagesURL = "https://torjan0.github.io/cirewind/"

const (
	// ReadmePreviewHeight is the number of top pixels of graph.svg shown by the
	// README preview viewport: the title, legend, and first finding lane.
	ReadmePreviewHeight = 1450
	ReadmeCandidateName = "README.candidate.md"
	ReadmeFinalName     = "README.md"
	ReadmePreviewName   = "readme-preview.svg"
	ReadmeGraphName     = "graph.svg"
	ReadmeSlotsName     = "README.slots.json"
	readmeSlotsSchema   = "cirewind.readme-slots/v1alpha1"
	readmeGeneratedDir  = "site/generated"
	// ReadmeBannerName is the maintainer-owned fixed banner shown above the
	// heading on GitHub's dark theme. It is not generated; its digest is
	// recorded in the slot inventory so the drift check binds its exact bytes.
	ReadmeBannerName      = "cirewind-banner-dark.png"
	ReadmeBannerLightName = "cirewind-banner-light.png"
	readmeAssetsDir       = "site/assets"
	// readmeBannerAlt names every element whose meaning the banner encodes by
	// shape and color, so the image adds nothing a screen reader cannot hear.
	readmeBannerAlt = "CIRewind wordmark over a schematic GitHub Actions run: blue job nodes in a chain, an orange dashed node with a question mark where evidence is missing, a red node where a compromised action ran, a green node where a verified action ran, and a green dashed arrow from the red node back to the start, showing the run reconstructed from evidence"
	maxBannerBytes  = 512 << 10
	bannerWidth     = 1800
	bannerHeight    = 600
)

var (
	// rootDescriptionStart is the graph's root accessible description, referenced
	// by the root aria-labelledby attribute; lanes carry their own descriptions.
	rootDescriptionStart = []byte(`<desc id="tep-desc">`)
	readmeTemplate       = texttemplate.Must(texttemplate.New("readme").Parse(mustReadTemplate("templates/readme.md.tmpl")))
	// readmeLinkPattern matches Markdown link and image destinations.
	readmeLinkPattern = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

func mustReadTemplate(name string) string {
	data, err := templateFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// ReadmeSlots are the trusted typed inputs of the README candidate. Final
// omits the staged-candidate banner and is reserved for the release-candidate
// materialization step, never for the default branch before activation.
type ReadmeSlots struct {
	Version string
	Final   bool
	// AssetsDir is the directory holding the fixed banner asset; empty means
	// site/assets relative to the working directory.
	AssetsDir string
}

// ReadmeSlot documents one typed slot, its rendered value, and when it resolves.
type ReadmeSlot struct {
	Name       string `json:"name"`
	Value      string `json:"value"`
	Resolution string `json:"resolution"`
	Note       string `json:"note,omitempty"`
}

// ReadmeInventory is the explicit final-slot inventory published beside the
// candidate so that no unresolved slot is implicit.
type ReadmeInventory struct {
	SchemaVersion string       `json:"schemaVersion"`
	SiteVersion   string       `json:"siteVersion"`
	Candidate     bool         `json:"candidate"`
	Slots         []ReadmeSlot `json:"slots"`
}

type readmeView struct {
	Version          string
	Candidate        bool
	Total            int
	CountPairs       []CountPair
	PreviewPath      string
	BannerPath       string
	BannerLightPath  string
	BannerAlt        string
	GraphPath        string
	GraphURL         string
	ReportURL        string
	ArchiveURL       string
	ManifestURL      string
	SampleURL        string
	ReleaseURL       string
	GoInstallCommand string
	Invariants       []string
	States           []model.FindingState
}

// VersionedPagesURL is the immutable Pages tree for one version.
func VersionedPagesURL(version string) string {
	return PagesURL + "v" + version + "/"
}

func readmeInventory(slots ReadmeSlots, bannerSHA256, bannerLightSHA256 string) ReadmeInventory {
	pages := VersionedPagesURL(slots.Version)
	return ReadmeInventory{
		SchemaVersion: readmeSlotsSchema,
		SiteVersion:   slots.Version,
		Candidate:     !slots.Final,
		Slots: []ReadmeSlot{
			{Name: "version", Value: slots.Version, Resolution: "resolved-now", Note: "canonical SemVer without a v prefix; also fixes every versioned URL and install command below"},
			{Name: "banner-image", Value: readmeAssetsDir + "/" + ReadmeBannerName, Resolution: "resolved-now", Note: "maintainer-owned fixed asset, 1800 by 600 palette PNG shown on GitHub's dark theme; sha256 " + bannerSHA256},
			{Name: "banner-image-light", Value: readmeAssetsDir + "/" + ReadmeBannerLightName, Resolution: "resolved-now", Note: "maintainer-owned fixed asset, 1800 by 600 palette PNG shown on GitHub's light theme; sha256 " + bannerLightSHA256},
			{Name: "preview-image", Value: readmeGeneratedDir + "/" + ReadmePreviewName, Resolution: "resolved-now", Note: "viewport crop of the generated graph.svg from the verified demo case, regenerated and drift-checked"},
			{Name: "graph-copy", Value: readmeGeneratedDir + "/" + ReadmeGraphName, Resolution: "resolved-now", Note: "byte-identical copy of the demo graph.svg"},
			{Name: "counts", Value: "from findings.json of the verified demo case, compared with the embedded oracle", Resolution: "resolved-now"},
			{Name: "sample-graph-url", Value: pages + "graph.svg", Resolution: "resolves-at-deployment", Note: "predictable Pages location; exists only after the authorized deployment"},
			{Name: "sample-report-url", Value: pages + "sample-case/report.html", Resolution: "resolves-at-deployment"},
			{Name: "sample-archive-url", Value: pages + "downloads/" + ArchiveName(slots.Version), Resolution: "resolves-at-deployment"},
			{Name: "sample-manifest-url", Value: pages + "sample-case/manifest.sha256", Resolution: "resolves-at-deployment"},
			{Name: "release-url", Value: ReleaseURL(slots.Version), Resolution: "resolves-at-release", Note: "predictable release page; exists only after the authorized publication"},
			{Name: "go-install-command", Value: "go install github.com/torjan0/cirewind/cmd/cirewind@v" + slots.Version, Resolution: "resolves-at-release", Note: "the tag must exist and pass release qualification before this command is qualified"},
			{Name: "brew-install-command", Value: "brew install torjan0/tap/cirewind", Resolution: "resolves-at-release", Note: "the maintainer-owned tap formula is prepared under DIST-003 and published only after release"},
		},
	}
}

// RenderReadme renders the README candidate from a verified case summary and
// trusted slots. It fails on unresolved template text, prohibited language, or
// an external link outside the fixed release and Pages destinations.
func RenderReadme(summary CaseSummary, slots ReadmeSlots) ([]byte, error) {
	if err := ValidateVersion(slots.Version); err != nil {
		return nil, err
	}
	if summary.Total <= 0 || len(summary.Counts) == 0 {
		return nil, errors.New("case summary carries no finding counts")
	}
	states := model.FindingStates()
	if len(states)%2 != 0 {
		return nil, errors.New("canonical state count is not even; the compact table needs pairs")
	}
	pairs := make([]CountPair, 0, len(states)/2)
	for index := 0; index < len(states); index += 2 {
		pairs = append(pairs, CountPair{
			Left:  CountRow{State: states[index], Count: summary.Counts[states[index]]},
			Right: CountRow{State: states[index+1], Count: summary.Counts[states[index+1]]},
		})
	}
	pages := VersionedPagesURL(slots.Version)
	view := readmeView{
		Version:          slots.Version,
		Candidate:        !slots.Final,
		Total:            summary.Total,
		CountPairs:       pairs,
		PreviewPath:      readmeGeneratedDir + "/" + ReadmePreviewName,
		BannerPath:       readmeAssetsDir + "/" + ReadmeBannerName,
		BannerLightPath:  readmeAssetsDir + "/" + ReadmeBannerLightName,
		BannerAlt:        readmeBannerAlt,
		GraphPath:        readmeGeneratedDir + "/" + ReadmeGraphName,
		GraphURL:         pages + "graph.svg",
		ReportURL:        pages + "sample-case/report.html",
		ArchiveURL:       pages + "downloads/" + ArchiveName(slots.Version),
		ManifestURL:      pages + "sample-case/manifest.sha256",
		SampleURL:        pages,
		ReleaseURL:       ReleaseURL(slots.Version),
		GoInstallCommand: "go install github.com/torjan0/cirewind/cmd/cirewind@v" + slots.Version,
		Invariants:       append([]string(nil), Invariants...),
		States:           states,
	}
	var buffer bytes.Buffer
	if err := readmeTemplate.Execute(&buffer, view); err != nil {
		return nil, err
	}
	page := buffer.Bytes()
	if bytes.Contains(page, []byte("{{")) || bytes.Contains(page, []byte("}}")) {
		return nil, errors.New("rendered README still contains template text")
	}
	if err := CheckProhibitedLanguage(page); err != nil {
		return nil, err
	}
	for _, match := range urlPattern.FindAllString(string(page), -1) {
		if match != view.ReleaseURL && !strings.HasPrefix(match, pages) {
			return nil, fmt.Errorf("README links to a URL outside the fixed release and Pages destinations: %s", match)
		}
	}
	return page, nil
}

// ReadmeLinks returns every Markdown link or image destination in a README.
func ReadmeLinks(page []byte) []string {
	matches := readmeLinkPattern.FindAllSubmatch(page, -1)
	links := make([]string, 0, len(matches))
	for _, match := range matches {
		links = append(links, string(match[1]))
	}
	return links
}

// RenderReadmePreviewSVG derives the README preview from graph.svg by changing
// only the root viewport (height and viewBox) and appending one sentence to the
// accessible description. Every other byte is identical; no content is
// regenerated. A graph no taller than the preview height is returned as is.
func RenderReadmePreviewSVG(graph []byte) ([]byte, error) {
	info, err := AuditSVG(graph)
	if err != nil {
		return nil, fmt.Errorf("source graph: %w", err)
	}
	if info.Height <= ReadmePreviewHeight {
		return append([]byte(nil), graph...), nil
	}
	end := bytes.IndexByte(graph, '>')
	if end < 0 {
		return nil, errors.New("graph root element is unterminated")
	}
	root := graph[:end+1]
	oldHeight := []byte(` height="` + strconv.Itoa(info.Height) + `"`)
	oldViewBox := []byte(` viewBox="0 0 ` + strconv.Itoa(info.Width) + ` ` + strconv.Itoa(info.Height) + `"`)
	if bytes.Count(root, oldHeight) != 1 || bytes.Count(root, oldViewBox) != 1 {
		return nil, errors.New("graph root does not carry the expected single height and viewBox")
	}
	newRoot := bytes.Replace(root, oldHeight, []byte(` height="`+strconv.Itoa(ReadmePreviewHeight)+`"`), 1)
	newRoot = bytes.Replace(newRoot, oldViewBox, []byte(` viewBox="0 0 `+strconv.Itoa(info.Width)+` `+strconv.Itoa(ReadmePreviewHeight)+`"`), 1)
	rest := graph[end+1:]
	descStart := bytes.Index(rest, rootDescriptionStart)
	if descStart < 0 || bytes.Count(rest, rootDescriptionStart) != 1 {
		return nil, errors.New("graph does not carry exactly one root accessible description")
	}
	descEnd := bytes.Index(rest[descStart:], []byte("</desc>"))
	if descEnd < 0 {
		return nil, errors.New("graph root accessible description is unterminated")
	}
	descEnd += descStart
	note := fmt.Sprintf(" README preview viewport: the top %d of %d pixels; the complete visual is graph.svg.", ReadmePreviewHeight, info.Height)
	preview := make([]byte, 0, len(graph)+len(note))
	preview = append(preview, newRoot...)
	preview = append(preview, rest[:descEnd]...)
	preview = append(preview, note...)
	preview = append(preview, rest[descEnd:]...)
	if _, err := AuditSVG(preview); err != nil {
		return nil, fmt.Errorf("derived preview: %w", err)
	}
	return preview, nil
}

// ReadmeCandidate is the complete generated set for the staged README.
type ReadmeCandidate struct {
	Files map[string][]byte
}

// BuildReadmeCandidate renders every generated README file in memory from a
// verified demo case: the candidate (or final) README, the preview viewport,
// the graph copy, and the slot inventory.
func BuildReadmeCandidate(ctx context.Context, caseDir string, slots ReadmeSlots) (ReadmeCandidate, error) {
	if err := ctx.Err(); err != nil {
		return ReadmeCandidate{}, err
	}
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	summary, err := LoadVerifiedCase(ctx, caseDir, bundle.Oracle)
	if err != nil {
		return ReadmeCandidate{}, fmt.Errorf("load verified case: %w", err)
	}
	graph, err := readBoundedRegular(filepath.Join(caseDir, "graph.svg"), maxSVGBytes)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	preview, err := RenderReadmePreviewSVG(graph)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	page, err := RenderReadme(summary, slots)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	bannerSHA256, err := loadReadmeBanner(slots.AssetsDir, ReadmeBannerName)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	bannerLightSHA256, err := loadReadmeBanner(slots.AssetsDir, ReadmeBannerLightName)
	if err != nil {
		return ReadmeCandidate{}, err
	}
	inventory, err := json.MarshalIndent(readmeInventory(slots, bannerSHA256, bannerLightSHA256), "", "  ")
	if err != nil {
		return ReadmeCandidate{}, err
	}
	readmeName := ReadmeCandidateName
	if slots.Final {
		readmeName = ReadmeFinalName
	}
	return ReadmeCandidate{Files: map[string][]byte{
		readmeName:        page,
		ReadmePreviewName: preview,
		ReadmeGraphName:   graph,
		ReadmeSlotsName:   append(inventory, '\n'),
	}}, nil
}

// loadReadmeBanner checks one fixed banner asset (a regular, bounded PNG with
// the fixed 3:1 dimensions) and returns its SHA-256 for the slot inventory.
func loadReadmeBanner(assetsDir, name string) (string, error) {
	if assetsDir == "" {
		assetsDir = readmeAssetsDir
	}
	path := filepath.Join(assetsDir, name)
	data, err := readBoundedRegular(path, maxBannerBytes)
	if err != nil {
		return "", fmt.Errorf("README banner asset %s: %w", name, err)
	}
	if len(data) < 24 || !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) || string(data[12:16]) != "IHDR" {
		return "", fmt.Errorf("README banner asset %s is not a PNG image", name)
	}
	width := int(data[16])<<24 | int(data[17])<<16 | int(data[18])<<8 | int(data[19])
	height := int(data[20])<<24 | int(data[21])<<16 | int(data[22])<<8 | int(data[23])
	if width != bannerWidth || height != bannerHeight {
		return "", fmt.Errorf("README banner asset must be %d by %d pixels, got %d by %d", bannerWidth, bannerHeight, width, height)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Write replaces the generated files in dir; dir must already exist and be a
// real directory. Other files in dir are left untouched.
func (c ReadmeCandidate) Write(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("README candidate directory must be an existing real directory")
	}
	for name, data := range c.Files {
		path := filepath.Join(dir, name)
		if existing, err := os.Lstat(path); err == nil && (!existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0) {
			return fmt.Errorf("refusing to replace non-regular file %s", name)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Compare reports the first generated file whose committed bytes differ.
func (c ReadmeCandidate) Compare(dir string) error {
	for name, data := range c.Files {
		existing, err := readBoundedRegular(filepath.Join(dir, name), maxSVGBytes)
		if err != nil {
			return fmt.Errorf("committed %s: %w", name, err)
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("committed %s differs from the regenerated bytes", name)
		}
	}
	return nil
}

// Digests returns the SHA-256 of every generated file.
func (c ReadmeCandidate) Digests() map[string]string {
	digests := make(map[string]string, len(c.Files))
	for name, data := range c.Files {
		sum := sha256.Sum256(data)
		digests[name] = hex.EncodeToString(sum[:])
	}
	return digests
}
