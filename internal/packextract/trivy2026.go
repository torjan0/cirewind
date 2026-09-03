// Package packextract mechanically transforms reviewed, byte-pinned primary
// sources into typed, sorted candidate indicator records. Every extraction
// records the input bytes it consumed by length and SHA-256, the extractor
// identity and version, every normalization it applied, and the SHA-256 of
// its own canonical output, so a reviewer who retrieves the same bytes can
// reproduce the record byte for byte. Extractors never use the network, never
// guess a digest namespace from context, and reject inputs they cannot parse
// exactly rather than skipping rows.
package packextract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// ExtractionSchema names the record format produced by every extractor.
const ExtractionSchema = "cirewind.extraction/v1alpha1"

// Trivy2026 identifies the extractor for the March 2026 Trivy ecosystem
// maintainer advisory (GHSA-69fq-xp46-6x23). Bump the version whenever the
// parsing rules or the output shape change.
const (
	Trivy2026Extractor        = "trivy-2026-advisory-tables"
	Trivy2026ExtractorVersion = "1"
)

// Exact section titles and table headers of the advisory. The extractor
// refuses to run when any of them is absent or altered.
const (
	trivy2026WindowHeading     = "## Exposure Window"
	trivy2026ExecutableHeading = "### Executable binaries"
	trivy2026ImageHeading      = "### Container images (v0.69.4)"
	trivy2026NetworkHeading    = "### Network"
	trivy2026NetworkIntro      = "C2/sinks:"
)

var (
	trivy2026WindowHeader     = []string{"Component", "Start (UTC)", "End (UTC)", "Duration"}
	trivy2026ExecutableHeader = []string{"SHA256", "Filename"}
	trivy2026ImageHeader      = []string{"Digest", "Tag"}
)

var (
	hex64Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex64AnyCase       = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)
	assetNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}$`)
	imageTagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$`)
	domainNamePattern  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	whitespacePattern  = regexp.MustCompile(`\s+`)
	trailingBreakToken = "<br>"
)

// Extraction is the reproducible record of one mechanical extraction.
type Extraction struct {
	SchemaVersion    string          `json:"schemaVersion"`
	Extractor        string          `json:"extractor"`
	ExtractorVersion string          `json:"extractorVersion"`
	InputSHA256      string          `json:"inputSha256"`
	InputByteLength  int             `json:"inputByteLength"`
	InputField       string          `json:"inputField"`
	Windows          []WindowRow     `json:"windows"`
	Digests          []DigestRecord  `json:"digests"`
	Network          NetworkRecord   `json:"network"`
	Normalizations   []Normalization `json:"normalizations"`
	OutputSHA256     string          `json:"outputSha256"`
}

// WindowRow preserves one row of the advisory's exposure-window table
// verbatim, footnote markers and approximation tildes included. Windows are
// authored by a reviewer from these cells; the extractor never turns them into
// instants.
type WindowRow struct {
	Row       int    `json:"row"`
	Component string `json:"component"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Duration  string `json:"duration"`
}

// DigestRecord is one typed digest. Subject is the pack digest namespace the
// table itself denotes (release assets or OCI manifests); a digest value is
// never matched across namespaces.
type DigestRecord struct {
	Subject            string `json:"subject"`
	Algorithm          string `json:"algorithm"`
	Digest             string `json:"digest"`
	Label              string `json:"label"`
	Section            string `json:"section"`
	Row                int    `json:"row"`
	OriginalDigestCell string `json:"originalDigestCell"`
	OriginalLabelCell  string `json:"originalLabelCell"`
}

// NetworkRecord holds the literal network indicators of the Network section.
type NetworkRecord struct {
	Section     string   `json:"section"`
	Domains     []string `json:"domains"`
	IPAddresses []string `json:"ipAddresses"`
}

// Normalization records one mechanical change to a cell so the reviewer can
// see exactly how the record differs from the source text.
type Normalization struct {
	Record string `json:"record"`
	Field  string `json:"field"`
	Rule   string `json:"rule"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// ExtractTrivy2026 parses the GitHub REST representation of the maintainer
// advisory (the bytes a reviewer pins) and returns the typed indicator record.
func ExtractTrivy2026(input []byte) (*Extraction, error) {
	if len(input) > maxInputBytes {
		return nil, fmt.Errorf("input is %d bytes, more than the %d allowed", len(input), maxInputBytes)
	}
	var advisory struct {
		Description *string `json:"description"`
	}
	if err := json.Unmarshal(input, &advisory); err != nil {
		return nil, fmt.Errorf("input is not a JSON advisory object: %w", err)
	}
	if advisory.Description == nil {
		return nil, fmt.Errorf("input has no description field")
	}
	if len(*advisory.Description) > maxDescriptionBytes {
		return nil, fmt.Errorf("description is %d bytes, more than the %d allowed", len(*advisory.Description), maxDescriptionBytes)
	}
	lines, err := splitLines(*advisory.Description)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(input)
	result := &Extraction{
		SchemaVersion: ExtractionSchema, Extractor: Trivy2026Extractor, ExtractorVersion: Trivy2026ExtractorVersion,
		InputSHA256: hex.EncodeToString(sum[:]), InputByteLength: len(input), InputField: "/description",
		Windows: []WindowRow{}, Digests: []DigestRecord{}, Normalizations: []Normalization{},
	}
	if err := extractTrivy2026Windows(lines, result); err != nil {
		return nil, err
	}
	if err := extractTrivy2026Digests(lines, result, trivy2026ExecutableHeading, trivy2026ExecutableHeader, "release-asset"); err != nil {
		return nil, err
	}
	if err := extractTrivy2026Digests(lines, result, trivy2026ImageHeading, trivy2026ImageHeader, "oci-manifest"); err != nil {
		return nil, err
	}
	if err := extractTrivy2026Network(lines, result); err != nil {
		return nil, err
	}
	sort.SliceStable(result.Digests, func(i, j int) bool {
		if result.Digests[i].Subject != result.Digests[j].Subject {
			return result.Digests[i].Subject < result.Digests[j].Subject
		}
		return result.Digests[i].Digest < result.Digests[j].Digest
	})
	sort.SliceStable(result.Normalizations, func(i, j int) bool {
		if result.Normalizations[i].Record != result.Normalizations[j].Record {
			return result.Normalizations[i].Record < result.Normalizations[j].Record
		}
		return result.Normalizations[i].Field < result.Normalizations[j].Field
	})
	if err := seal(result); err != nil {
		return nil, err
	}
	return result, nil
}

func extractTrivy2026Windows(lines []string, result *Extraction) error {
	start, err := findHeading(lines, trivy2026WindowHeading)
	if err != nil {
		return err
	}
	rows, err := parseTable(lines, start, trivy2026WindowHeader)
	if err != nil {
		return err
	}
	for _, row := range rows {
		result.Windows = append(result.Windows, WindowRow{Row: row.Number, Component: row.Cells[0], Start: row.Cells[1], End: row.Cells[2], Duration: row.Cells[3]})
	}
	return nil
}

func extractTrivy2026Digests(lines []string, result *Extraction, heading string, header []string, subject string) error {
	start, err := findHeading(lines, heading)
	if err != nil {
		return err
	}
	rows, err := parseTable(lines, start, header)
	if err != nil {
		return err
	}
	section := strings.TrimLeft(heading, "# ")
	seenDigest := make(map[string]int)
	seenLabel := make(map[string]int)
	for _, row := range rows {
		digestCell, labelCell := row.Cells[0], row.Cells[1]
		digestText, quoted := unquoteCode(digestCell)
		if !quoted {
			return fmt.Errorf("%s row %d: digest cell %q is not code-quoted", section, row.Number, digestCell)
		}
		algorithm := "sha256"
		switch subject {
		case "oci-manifest":
			if !strings.HasPrefix(digestText, "sha256:") {
				return fmt.Errorf("%s row %d: digest %q lacks the sha256: prefix", section, row.Number, digestText)
			}
			digestText = strings.TrimPrefix(digestText, "sha256:")
		case "release-asset":
			if strings.Contains(digestText, ":") {
				return fmt.Errorf("%s row %d: digest %q carries an unexpected algorithm prefix", section, row.Number, digestText)
			}
		}
		if !hex64AnyCase.MatchString(digestText) {
			return fmt.Errorf("%s row %d: digest %q is not 64 hexadecimal characters", section, row.Number, digestText)
		}
		record := subject + "/" + strings.ToLower(digestText)
		if !hex64Pattern.MatchString(digestText) {
			result.Normalizations = append(result.Normalizations, Normalization{Record: record, Field: "digest", Rule: "lowercase-hex", Before: digestText, After: strings.ToLower(digestText)})
			digestText = strings.ToLower(digestText)
		}
		labelText, quoted := unquoteCode(labelCell)
		if !quoted {
			trimmed := strings.TrimSuffix(labelCell, trailingBreakToken)
			if trimmed == labelCell {
				return fmt.Errorf("%s row %d: label cell %q is not code-quoted", section, row.Number, labelCell)
			}
			result.Normalizations = append(result.Normalizations, Normalization{Record: record, Field: "label", Rule: "drop-trailing-line-break-tag", Before: labelCell, After: trimmed})
			labelText, quoted = unquoteCode(trimmed)
			if !quoted {
				return fmt.Errorf("%s row %d: label cell %q is not code-quoted", section, row.Number, labelCell)
			}
		}
		if collapsed := whitespacePattern.ReplaceAllString(labelText, ""); collapsed != labelText {
			result.Normalizations = append(result.Normalizations, Normalization{Record: record, Field: "label", Rule: "remove-whitespace", Before: labelText, After: collapsed})
			labelText = collapsed
		}
		switch subject {
		case "release-asset":
			if !assetNamePattern.MatchString(labelText) {
				return fmt.Errorf("%s row %d: asset name %q is not a plain file name", section, row.Number, labelText)
			}
		case "oci-manifest":
			if !imageTagPattern.MatchString(labelText) {
				return fmt.Errorf("%s row %d: image tag %q is malformed", section, row.Number, labelText)
			}
		}
		if previous, dup := seenDigest[digestText]; dup {
			return fmt.Errorf("%s rows %d and %d repeat digest %s", section, previous, row.Number, digestText)
		}
		if previous, dup := seenLabel[labelText]; dup {
			return fmt.Errorf("%s rows %d and %d repeat label %q", section, previous, row.Number, labelText)
		}
		seenDigest[digestText], seenLabel[labelText] = row.Number, row.Number
		result.Digests = append(result.Digests, DigestRecord{Subject: subject, Algorithm: algorithm, Digest: digestText, Label: labelText, Section: section, Row: row.Number, OriginalDigestCell: digestCell, OriginalLabelCell: labelCell})
	}
	return nil
}

func extractTrivy2026Network(lines []string, result *Extraction) error {
	start, err := findHeading(lines, trivy2026NetworkHeading)
	if err != nil {
		return err
	}
	items, err := listItems(lines, start, trivy2026NetworkIntro)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("%s lists no literals", trivy2026NetworkHeading)
	}
	network := NetworkRecord{Section: strings.TrimLeft(trivy2026NetworkHeading, "# "), Domains: []string{}, IPAddresses: []string{}}
	for _, item := range items {
		literal, quoted := unquoteCode(item)
		if !quoted {
			return fmt.Errorf("network literal %q is not code-quoted", item)
		}
		if address, err := netip.ParseAddr(literal); err == nil {
			network.IPAddresses = append(network.IPAddresses, address.String())
			continue
		}
		if domainNamePattern.MatchString(literal) {
			network.Domains = append(network.Domains, literal)
			continue
		}
		return fmt.Errorf("network literal %q is neither an IP address nor a bare domain name", literal)
	}
	sort.Strings(network.Domains)
	sort.Strings(network.IPAddresses)
	result.Network = network
	return nil
}

// FindDigest looks up a record by its exact namespace and digest. A digest
// under another subject is deliberately not found.
func (e *Extraction) FindDigest(subject, digest string) (DigestRecord, bool) {
	for _, record := range e.Digests {
		if record.Subject == subject && record.Digest == strings.ToLower(digest) {
			return record, true
		}
	}
	return DigestRecord{}, false
}
