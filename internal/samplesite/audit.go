package samplesite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/casefile"
)

const (
	// AggregateBudget is the tighter initial Pages artifact budget from the
	// specification; GitHub's platform maximum is far larger.
	AggregateBudget   = 64 << 20
	maxSVGBytes       = 8 << 20
	maxHTMLBytes      = 4 << 20
	maxTextBytes      = 32 << 20
	maxDatabaseBytes  = 48 << 20
	maxChecksumBytes  = 1 << 20
	siteManifestName  = "site-manifest.sha256"
	provenanceName    = "provenance.json"
	sumsName          = "SHA256SUMS"
	sampleCaseDir     = "sample-case"
	downloadsDir      = "downloads"
	rootIndexName     = "index.html"
	versionedIndexTop = "index.html"
)

var allowedSVGElements = map[string]bool{
	"svg": true, "title": true, "desc": true, "style": true, "defs": true, "marker": true, "g": true,
	"rect": true, "line": true, "polyline": true, "path": true, "polygon": true, "circle": true, "text": true, "tspan": true,
}

var (
	urlPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>)]+`)
	// forbiddenBytes are credential shapes and host-path forms that must never
	// appear in any published byte. They are rejection controls, not proof of
	// complete privacy.
	forbiddenBytes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)github_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`(?i)\bgh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`(?i)authorization:\s*(?:bearer|basic)\s+\S+`),
		regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])/home/[A-Za-z0-9._-]+/`),
		regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])/Users/[A-Za-z0-9._-]+/`),
		regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])/tmp/[A-Za-z0-9._-]+`),
		regexp.MustCompile(`(?i)[A-Z]:\\Users\\`),
	}
	forbiddenMarkup = []string{
		"<script", "<form", "<iframe", "<object", "<embed", "<link", "<video", "<audio", "<base", "<applet", "<frame", "<canvas",
		`href="javascript:`, `src="javascript:`, `href="data:`, `src="data:`, "url(data:", "url(javascript:",
		"target=", "srcdoc", " onload", " onerror", " onclick", " onmouse", " onfocus", " onkey",
	}
)

// SVGInfo carries the intrinsic size of the audited standalone SVG.
type SVGInfo struct {
	Width  int
	Height int
}

// AuditSVG parses a standalone SVG strictly and rejects anything outside the
// inert renderer vocabulary: active or external elements, event handlers,
// links, external or data references, entities, processing instructions, and
// document type declarations. It returns the intrinsic size.
func AuditSVG(data []byte) (SVGInfo, error) {
	if len(data) == 0 || len(data) > maxSVGBytes {
		return SVGInfo{}, errors.New("SVG is empty or exceeds its byte budget")
	}
	if !bytes.HasPrefix(data, []byte("<svg")) {
		return SVGInfo{}, errors.New("SVG must begin with the fixed root element and no declaration")
	}
	lower := bytes.ToLower(data)
	for _, forbidden := range []string{"<!doctype", "<!entity", "<?xml", "<![cdata[", "@import", "expression(", "http://www.w3.org/1999/xlink"} {
		if bytes.Contains(lower, []byte(forbidden)) {
			return SVGInfo{}, fmt.Errorf("SVG contains forbidden construct %q", forbidden)
		}
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	decoder.Entity = map[string]string{}
	var info SVGInfo
	depth := 0
	inStyle := false
	seenRoot := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return SVGInfo{}, fmt.Errorf("SVG is not strict XML: %w", err)
		}
		switch typed := token.(type) {
		case xml.ProcInst, xml.Directive:
			return SVGInfo{}, errors.New("SVG contains a processing instruction or directive")
		case xml.StartElement:
			depth++
			name := typed.Name.Local
			if !allowedSVGElements[name] {
				return SVGInfo{}, fmt.Errorf("SVG contains element %q outside the inert vocabulary", name)
			}
			if typed.Name.Space != "" && typed.Name.Space != "http://www.w3.org/2000/svg" {
				return SVGInfo{}, fmt.Errorf("SVG element %q uses namespace %q", name, typed.Name.Space)
			}
			if depth == 1 {
				if name != "svg" || seenRoot {
					return SVGInfo{}, errors.New("SVG root must be a single svg element")
				}
				seenRoot = true
			}
			inStyle = name == "style"
			for _, attribute := range typed.Attr {
				attributeName := strings.ToLower(attribute.Name.Local)
				value := strings.ToLower(attribute.Value)
				if strings.HasPrefix(attributeName, "on") || attributeName == "href" || attributeName == "src" || attributeName == "style" {
					return SVGInfo{}, fmt.Errorf("SVG attribute %q is not permitted", attributeName)
				}
				trimmed := strings.TrimSpace(value)
				if strings.HasPrefix(trimmed, "javascript:") || strings.HasPrefix(trimmed, "data:") || strings.Contains(trimmed, "url(data:") || strings.Contains(trimmed, "url(javascript:") {
					return SVGInfo{}, fmt.Errorf("SVG attribute %q carries an active or data URL", attributeName)
				}
				if attribute.Name.Space != "" && attribute.Name.Space != "xmlns" && attribute.Name.Space != "http://www.w3.org/2000/svg" {
					return SVGInfo{}, fmt.Errorf("SVG attribute %q uses namespace %q", attributeName, attribute.Name.Space)
				}
				if strings.Contains(value, "url(") && !(strings.HasPrefix(attributeName, "marker") && strings.HasPrefix(value, "url(#")) {
					return SVGInfo{}, fmt.Errorf("SVG attribute %q references a URL", attributeName)
				}
				if depth == 1 && (attributeName == "width" || attributeName == "height") {
					size, err := strconv.Atoi(attribute.Value)
					if err != nil || size <= 0 || size > 1_000_000 {
						return SVGInfo{}, fmt.Errorf("SVG %s %q is not a bounded integer", attributeName, attribute.Value)
					}
					if attributeName == "width" {
						info.Width = size
					} else {
						info.Height = size
					}
				}
			}
		case xml.EndElement:
			depth--
			inStyle = false
		case xml.CharData:
			if inStyle {
				text := strings.ToLower(string(typed))
				if strings.Contains(text, "url(") || strings.Contains(text, "@") || strings.Contains(text, "http") {
					return SVGInfo{}, errors.New("SVG stylesheet references an external resource")
				}
			}
		}
	}
	if !seenRoot || info.Width == 0 || info.Height == 0 {
		return SVGInfo{}, errors.New("SVG root lacks integer width and height")
	}
	return info, nil
}

// PriorTree is a reviewed, hash-locked earlier version tree or tombstone that
// is published verbatim beside the current version. Dir is the local source
// directory for Build and is ignored by Verify. Prior trees are never fetched
// from the deployed site.
type PriorTree struct {
	Version            string
	SiteManifestSHA256 string
	Dir                string
}

func validatePriors(version string, priors []PriorTree) error {
	seen := map[string]bool{version: true}
	for _, prior := range priors {
		if err := ValidateVersion(prior.Version); err != nil {
			return err
		}
		if seen[prior.Version] {
			return fmt.Errorf("prior version %s duplicates another tree", prior.Version)
		}
		seen[prior.Version] = true
		if !hexToken(prior.SiteManifestSHA256, 64) {
			return fmt.Errorf("prior version %s lacks a lowercase hexadecimal site-manifest lock", prior.Version)
		}
	}
	return nil
}

// lockedManifestFiles reads a prior tree's site manifest below root, checks it
// against the supplied hash lock, and returns the relative files it covers.
func lockedManifestFiles(root string, prior PriorTree) ([]string, error) {
	manifest, err := readBoundedRegular(filepath.Join(root, siteManifestName), maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("prior version %s manifest: %w", prior.Version, err)
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != prior.SiteManifestSHA256 {
		return nil, fmt.Errorf("prior version %s manifest does not match its hash lock", prior.Version)
	}
	entries, err := parseManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("prior version %s manifest: %w", prior.Version, err)
	}
	files := make([]string, 0, len(entries))
	for name := range entries {
		files = append(files, name)
	}
	sort.Strings(files)
	return files, nil
}

// ExpectedFiles lists every regular file of a published site tree for one
// version, relative to the site root, in sorted order.
func ExpectedFiles(version string, caseFiles []string) []string {
	prefix := "v" + version + "/"
	files := []string{
		rootIndexName,
		prefix + versionedIndexTop,
		prefix + siteManifestName,
		prefix + "graph.svg",
		prefix + "findings.json",
		prefix + "summary.md",
		prefix + downloadsDir + "/" + ArchiveName(version),
		prefix + downloadsDir + "/" + sumsName,
		prefix + provenanceName,
	}
	for _, name := range caseFiles {
		files = append(files, prefix+sampleCaseDir+"/"+name)
	}
	sort.Strings(files)
	return files
}

func budgetFor(name string) int64 {
	switch {
	case strings.HasSuffix(name, ".html"):
		return maxHTMLBytes
	case strings.HasSuffix(name, ".svg"):
		return maxSVGBytes
	case strings.HasSuffix(name, ".db"):
		return maxDatabaseBytes
	case strings.HasSuffix(name, ".tar.gz"):
		return maxArchiveBytes
	case strings.HasSuffix(name, ".sha256") || strings.HasSuffix(name, sumsName):
		return maxChecksumBytes
	default:
		return maxTextBytes
	}
}

// AuditTree checks a staged or published site tree against the exact file
// allowlist, link, mode, size, privacy, inert-SVG, manifest, checksum, and
// provenance rules. It never parses case content as markup.
func AuditTree(ctx context.Context, siteDir, version string, caseFiles []string, priors []PriorTree) (Provenance, error) {
	if err := ValidateVersion(version); err != nil {
		return Provenance{}, err
	}
	if err := validatePriors(version, priors); err != nil {
		return Provenance{}, err
	}
	names, err := listRegularFiles(ctx, siteDir)
	if err != nil {
		return Provenance{}, err
	}
	expected := ExpectedFiles(version, caseFiles)
	for _, prior := range priors {
		priorRoot := filepath.Join(siteDir, "v"+prior.Version)
		files, err := lockedManifestFiles(priorRoot, prior)
		if err != nil {
			return Provenance{}, err
		}
		if err := VerifyTreeManifest(ctx, priorRoot, siteManifestName); err != nil {
			return Provenance{}, fmt.Errorf("prior version %s: %w", prior.Version, err)
		}
		expected = append(expected, "v"+prior.Version+"/"+siteManifestName)
		for _, name := range files {
			expected = append(expected, "v"+prior.Version+"/"+name)
		}
	}
	sort.Strings(expected)
	if strings.Join(names, "\n") != strings.Join(expected, "\n") {
		return Provenance{}, fmt.Errorf("site tree %v differs from the exact allowlist %v", names, expected)
	}
	prefix := "v" + version + "/"
	contents := make(map[string][]byte, len(names))
	var aggregate int64
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return Provenance{}, err
		}
		path := filepath.Join(siteDir, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil {
			return Provenance{}, err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 != 0 {
			return Provenance{}, fmt.Errorf("site file %q carries an executable bit", name)
		}
		data, err := readBoundedRegular(path, budgetFor(name))
		if err != nil {
			return Provenance{}, fmt.Errorf("site file %s: %w", name, err)
		}
		aggregate += int64(len(data))
		if aggregate > AggregateBudget {
			return Provenance{}, errors.New("site tree exceeds the aggregate byte budget")
		}
		if !strings.HasSuffix(name, ".tar.gz") {
			for _, pattern := range forbiddenBytes {
				if pattern.Match(data) {
					return Provenance{}, fmt.Errorf("site file %q contains a credential shape or host path", name)
				}
			}
		}
		contents[name] = data
	}
	allowedURLs := map[string]bool{ProjectURL: true, ReleaseURL(version): true, LabReproductionIndexURL: true}
	for _, name := range []string{rootIndexName, prefix + versionedIndexTop} {
		page := contents[name]
		lower := strings.ToLower(string(page))
		for _, forbidden := range forbiddenMarkup {
			if strings.Contains(lower, forbidden) {
				return Provenance{}, fmt.Errorf("page %q contains forbidden markup %q", name, forbidden)
			}
		}
		for _, match := range urlPattern.FindAllString(string(page), -1) {
			if !allowedURLs[match] {
				return Provenance{}, fmt.Errorf("page %q links to non-allowlisted URL %q", name, match)
			}
		}
		if !strings.Contains(string(page), `<meta http-equiv="Content-Security-Policy" content="`+escapedCSP()+`">`) {
			return Provenance{}, fmt.Errorf("page %q does not carry the exact content security policy", name)
		}
		if err := CheckProhibitedLanguage(page); err != nil {
			return Provenance{}, fmt.Errorf("page %q: %w", name, err)
		}
	}
	if !strings.Contains(string(contents[prefix+versionedIndexTop]), "experimental") {
		return Provenance{}, errors.New("landing page omits the experimental label")
	}
	for _, prior := range priors {
		page, ok := contents["v"+prior.Version+"/"+rootIndexName]
		if !ok {
			continue
		}
		lower := strings.ToLower(string(page))
		for _, forbidden := range forbiddenMarkup {
			if strings.Contains(lower, forbidden) {
				return Provenance{}, fmt.Errorf("prior version %s page contains forbidden markup %q", prior.Version, forbidden)
			}
		}
		for _, match := range urlPattern.FindAllString(string(page), -1) {
			if match != ProjectURL && match != ReleaseURL(prior.Version) && match != LabReproductionIndexURL {
				return Provenance{}, fmt.Errorf("prior version %s page links to non-allowlisted URL %q", prior.Version, match)
			}
		}
		if err := CheckProhibitedLanguage(page); err != nil {
			return Provenance{}, fmt.Errorf("prior version %s page: %w", prior.Version, err)
		}
	}
	for _, copied := range []string{"graph.svg", "findings.json", "summary.md"} {
		if !bytes.Equal(contents[prefix+copied], contents[prefix+sampleCaseDir+"/"+copied]) {
			return Provenance{}, fmt.Errorf("top-level %s is not a byte-identical copy of the case file", copied)
		}
	}
	if _, err := AuditSVG(contents[prefix+"graph.svg"]); err != nil {
		return Provenance{}, err
	}
	for _, name := range names {
		if strings.HasSuffix(name, ".svg") && strings.Contains(string(contents[name]), "http://www.w3.org/1999/xlink") {
			return Provenance{}, fmt.Errorf("SVG %q declares the xlink namespace", name)
		}
	}
	if _, err := casefile.VerifyCase(ctx, filepath.Join(siteDir, filepath.FromSlash(prefix+sampleCaseDir))); err != nil {
		return Provenance{}, fmt.Errorf("verify published sample case: %w", err)
	}
	if err := VerifyTreeManifest(ctx, filepath.Join(siteDir, filepath.FromSlash("v"+version)), siteManifestName); err != nil {
		return Provenance{}, fmt.Errorf("verify site manifest: %w", err)
	}
	archiveName := ArchiveName(version)
	archive := contents[prefix+downloadsDir+"/"+archiveName]
	archiveSum := sha256.Sum256(archive)
	archiveDigest := hex.EncodeToString(archiveSum[:])
	if string(contents[prefix+downloadsDir+"/"+sumsName]) != archiveDigest+"  "+archiveName+"\n" {
		return Provenance{}, errors.New("SHA256SUMS does not bind the archive bytes")
	}
	entries, err := ListArchiveEntries(archive, "cirewind-synthetic-case-v"+version)
	if err != nil {
		return Provenance{}, fmt.Errorf("audit archive: %w", err)
	}
	sortedCase := append([]string(nil), caseFiles...)
	sort.Strings(sortedCase)
	if strings.Join(entries, "\n") != strings.Join(sortedCase, "\n") {
		return Provenance{}, fmt.Errorf("archive entries %v differ from the case files %v", entries, sortedCase)
	}
	var provenance Provenance
	decoder := json.NewDecoder(bytes.NewReader(contents[prefix+provenanceName]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&provenance); err != nil {
		return Provenance{}, fmt.Errorf("decode provenance: %w", err)
	}
	if err := provenance.validate(version); err != nil {
		return Provenance{}, err
	}
	caseManifestSum := sha256.Sum256(contents[prefix+sampleCaseDir+"/manifest.sha256"])
	if provenance.CaseManifestSHA256 != hex.EncodeToString(caseManifestSum[:]) || provenance.ArchiveSHA256 != archiveDigest || provenance.ArchiveByteLength != len(archive) || provenance.ArchiveName != archiveName {
		return Provenance{}, errors.New("provenance digests do not bind the published bytes")
	}
	if !strings.Contains(string(contents[prefix+versionedIndexTop]), archiveDigest) || !strings.Contains(string(contents[prefix+versionedIndexTop]), provenance.CaseManifestSHA256) {
		return Provenance{}, errors.New("landing page does not display the archive and case manifest digests")
	}
	return provenance, nil
}

func escapedCSP() string {
	return strings.ReplaceAll(ContentSecurityPolicy(), "'", "&#39;")
}
