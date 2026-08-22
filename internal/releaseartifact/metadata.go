// Package releaseartifact implements deterministic release-archive metadata and
// packaging. It is internal maintainer tooling and is not part of the CIRewind
// evidence model or product runtime.
package releaseartifact

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	runtimedebug "runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ModulePath    = "github.com/torjan0/cirewind"
	ToolName      = "CIRewind release tooling"
	FormatVersion = 1
)

var (
	semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	hexPattern    = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// Target identifies one supported release build.
type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

func (t Target) String() string { return t.OS + "/" + t.Arch }

// ArchiveExtension returns the deterministic archive format used for a target.
func (t Target) ArchiveExtension() string {
	if t.OS == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

// BinaryName returns the platform-specific executable filename.
func (t Target) BinaryName() string {
	if t.OS == "windows" {
		return "cirewind.exe"
	}
	return "cirewind"
}

// Validate restricts release output to the reviewed v0.1 target matrix.
func (t Target) Validate() error {
	switch t.OS {
	case "linux", "darwin", "windows":
	default:
		return fmt.Errorf("unsupported release operating system %q", t.OS)
	}
	switch t.Arch {
	case "amd64", "arm64":
	default:
		return fmt.Errorf("unsupported release architecture %q", t.Arch)
	}
	return nil
}

// ParseTarget parses an exact GOOS/GOARCH target.
func ParseTarget(value string) (Target, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Target{}, fmt.Errorf("target must use GOOS/GOARCH syntax: %q", value)
	}
	target := Target{OS: parts[0], Arch: parts[1]}
	return target, target.Validate()
}

// BuildMetadata is the exact deterministic metadata injected into and recorded
// beside release binaries. It is not an authenticity signature.
type BuildMetadata struct {
	FormatVersion   int    `json:"formatVersion"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	SourceDateEpoch int64  `json:"sourceDateEpoch"`
	BuildDate       string `json:"buildDate"`
	GoVersion       string `json:"goVersion"`
	CGOEnabled      bool   `json:"cgoEnabled"`
	Trimpath        bool   `json:"trimpath"`
	BuildVCS        bool   `json:"buildVCS"`
	BuildID         string `json:"buildID"`
	Authenticated   bool   `json:"authenticated"`
}

// LDFlags returns the one canonical linker-flag string for release binaries.
// Its values contain no whitespace or shell metacharacters after validation.
func LDFlags(metadata BuildMetadata) string {
	prefix := ModulePath + "/internal/buildinfo."
	return "-s -w -buildid=" +
		" -X=" + prefix + "Version=" + metadata.Version +
		" -X=" + prefix + "Commit=" + metadata.Commit +
		" -X=" + prefix + "Date=" + metadata.BuildDate +
		" -X=" + prefix + "ReleaseStamp=" + ReleaseStamp(metadata)
}

// ReleaseStamp is an exact non-secret metadata marker embedded in each binary.
func ReleaseStamp(metadata BuildMetadata) string {
	return "cirewind-release-stamp:v1|" + metadata.Version + "|" + metadata.Commit + "|" + metadata.BuildDate
}

// NewBuildMetadata validates the immutable inputs to a reproducible build.
func NewBuildMetadata(version, commit, goVersion string, epoch int64) (BuildMetadata, error) {
	if !canonicalSemVer(version) {
		return BuildMetadata{}, fmt.Errorf("version must be canonical SemVer without a v prefix: %q", version)
	}
	if !hexPattern.MatchString(commit) {
		return BuildMetadata{}, errors.New("commit must be a lowercase full 40- or 64-hex Git object ID")
	}
	if !regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(goVersion) {
		return BuildMetadata{}, fmt.Errorf("Go version must include an exact patch release: %q", goVersion)
	}
	instant := time.Unix(epoch, 0).UTC()
	if instant.Year() < 1980 || instant.Year() > 9999 {
		return BuildMetadata{}, errors.New("source date epoch must be representable by ZIP timestamps (1980..9999)")
	}
	return BuildMetadata{
		FormatVersion:   FormatVersion,
		Version:         version,
		Commit:          commit,
		SourceDateEpoch: epoch,
		BuildDate:       instant.Format(time.RFC3339),
		GoVersion:       goVersion,
		CGOEnabled:      false,
		Trimpath:        true,
		BuildVCS:        false,
		BuildID:         "",
		Authenticated:   false,
	}, nil
}

func canonicalSemVer(version string) bool {
	if !semverPattern.MatchString(version) {
		return false
	}
	withoutBuild := strings.SplitN(version, "+", 2)[0]
	parts := strings.SplitN(withoutBuild, "-", 2)
	if len(parts) != 2 {
		return true
	}
	for _, identifier := range strings.Split(parts[1], ".") {
		if len(identifier) > 1 && identifier[0] == '0' {
			numeric := true
			for _, character := range identifier {
				if character < '0' || character > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				return false
			}
		}
	}
	return true
}

// ValidateBinary proves that the executable's embedded Go build graph and
// settings match the requested target and release recipe.
func ValidateBinary(path string, target Target, metadata BuildMetadata) (*buildinfo.BuildInfo, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Go build information from %q: %w", path, err)
	}
	if err := ValidateBuildInfo(info, target, metadata); err != nil {
		return nil, err
	}
	return info, nil
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// GenerateSPDX creates a target-specific SPDX 2.3 JSON module inventory from
// the exact build graph embedded in a binary.
func GenerateSPDX(info *buildinfo.BuildInfo, target Target, metadata BuildMetadata, binarySHA256 string) ([]byte, error) {
	if info == nil {
		return nil, errors.New("build information is nil")
	}
	if len(binarySHA256) != sha256.Size*2 {
		return nil, errors.New("binary SHA-256 must be 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(binarySHA256); err != nil || strings.ToLower(binarySHA256) != binarySHA256 {
		return nil, errors.New("binary SHA-256 must be 64 lowercase hex characters")
	}
	rootID := "SPDXRef-Package-CIRewind"
	packages := []spdxPackage{{
		Name:             ModulePath,
		SPDXID:           rootID,
		VersionInfo:      metadata.Version,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "Apache-2.0",
		LicenseDeclared:  "Apache-2.0",
		CopyrightText:    "NOASSERTION",
		Checksums:        []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: binarySHA256}},
		ExternalRefs:     []spdxExternalRef{purlReference(ModulePath, metadata.Version)},
	}}
	relationships := []spdxRelationship{{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: rootID,
	}}
	toolchainID := "SPDXRef-Package-GoToolchain"
	packages = append(packages, spdxPackage{
		Name:             "go.dev/toolchain",
		SPDXID:           toolchainID,
		VersionInfo:      metadata.GoVersion,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "BSD-3-Clause",
		CopyrightText:    "NOASSERTION",
		ExternalRefs:     []spdxExternalRef{purlReference("go.dev/toolchain", metadata.GoVersion)},
	})
	relationships = append(relationships, spdxRelationship{
		SPDXElementID:      rootID,
		RelationshipType:   "DEPENDS_ON",
		RelatedSPDXElement: toolchainID,
	})

	dependencies := append([]*runtimedebug.Module(nil), info.Deps...)
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Path != dependencies[j].Path {
			return dependencies[i].Path < dependencies[j].Path
		}
		return dependencies[i].Version < dependencies[j].Version
	})
	seenIDs := map[string]bool{rootID: true, toolchainID: true}
	for position, dependency := range dependencies {
		id := spdxModuleID(position, dependency.Path, dependency.Version)
		if seenIDs[id] {
			return nil, fmt.Errorf("duplicate SPDX package ID %q", id)
		}
		seenIDs[id] = true
		checksum, err := moduleChecksum(dependency.Sum)
		if err != nil {
			return nil, fmt.Errorf("module %s@%s: %w", dependency.Path, dependency.Version, err)
		}
		packages = append(packages, spdxPackage{
			Name:             dependency.Path,
			SPDXID:           id,
			VersionInfo:      dependency.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			Checksums:        []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: checksum}},
			ExternalRefs:     []spdxExternalRef{purlReference(dependency.Path, dependency.Version)},
		})
		relationships = append(relationships, spdxRelationship{
			SPDXElementID:      rootID,
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: id,
		})
	}

	namespaceSeed := strings.Join([]string{metadata.Version, metadata.Commit, target.String(), binarySHA256}, "\x00")
	namespaceHash := sha256.Sum256([]byte(namespaceSeed))
	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              fmt.Sprintf("cirewind-%s-%s-%s", metadata.Version, target.OS, target.Arch),
		DocumentNamespace: "https://github.com/torjan0/cirewind/sbom/" + hex.EncodeToString(namespaceHash[:]),
		CreationInfo: spdxCreationInfo{
			Created:  time.Unix(metadata.SourceDateEpoch, 0).UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Tool: " + ToolName},
		},
		Packages:      packages,
		Relationships: relationships,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SPDX document: %w", err)
	}
	return append(encoded, '\n'), nil
}

func spdxModuleID(position int, path, version string) string {
	sum := sha256.Sum256([]byte(path + "\x00" + version))
	return "SPDXRef-Package-GoModule-" + strconv.Itoa(position+1) + "-" + hex.EncodeToString(sum[:8])
}

func moduleChecksum(sum string) (string, error) {
	if !strings.HasPrefix(sum, "h1:") {
		return "", fmt.Errorf("unsupported Go module sum %q", sum)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, "h1:"))
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("invalid Go module sum %q", sum)
	}
	return hex.EncodeToString(decoded), nil
}

func purlReference(path, version string) spdxExternalRef {
	segments := strings.Split(path, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return spdxExternalRef{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:golang/" + strings.Join(segments, "/") + "@" + url.PathEscape(version),
	}
}
