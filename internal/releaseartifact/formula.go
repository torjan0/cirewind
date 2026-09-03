package releaseartifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

// Homebrew formula generation. The formula is an evaluation lane: it installs
// the exact upstream release archive for the host platform and checks its
// SHA-256, but it does not verify build-provenance attestations and never
// rebuilds, patches, or downloads anything else. It is rendered only from
// verified release subjects, so a formula for a tag that has not been built
// cannot exist.

const (
	// ReleaseDownloadBase is the immutable upstream asset location shape.
	ReleaseDownloadBase = "https://github.com/" + repositoryOwner + "/" + repositoryName + "/releases/download/"
	repositoryOwner     = "torjan0"
	repositoryName      = "cirewind"
	formulaHomepage     = "https://github.com/torjan0/cirewind"
	maxMetadataBytes    = 4 << 20
)

var (
	formulaTargets = []Target{
		{OS: "darwin", Arch: "arm64"},
		{OS: "darwin", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "linux", Arch: "amd64"},
	}
	downloadBasePattern = regexp.MustCompile(`^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*/$`)
	formulaTemplate     = template.Must(template.New("formula").Parse(`class Cirewind < Formula
  desc "Evidence-first reconstruction of historical GitHub Actions execution"
  homepage "{{.Homepage}}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "{{.DarwinArm64.URL}}"
      sha256 "{{.DarwinArm64.SHA256}}"
    end
    on_intel do
      url "{{.DarwinAmd64.URL}}"
      sha256 "{{.DarwinAmd64.SHA256}}"
    end
  end

  on_linux do
    on_arm do
      url "{{.LinuxArm64.URL}}"
      sha256 "{{.LinuxArm64.SHA256}}"
    end
    on_intel do
      url "{{.LinuxAmd64.URL}}"
      sha256 "{{.LinuxAmd64.SHA256}}"
    end
  end

  def install
    bin.install "cirewind"
    pkgshare.install "incidents", "build-metadata.json", "sbom.spdx.json", "licenses"
    doc.install "README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md"
  end

  def caveats
    <<~EOS
      Homebrew is an evaluation lane for CIRewind. It installs the upstream
      release archive for this platform and checks its SHA-256, but it does not
      verify GitHub build-provenance attestations and is not an attestation
      equivalent. For forensic use, download the complete release set and
      verify it as described in the release process documentation.
    EOS
  end

  test do
    assert_match "cirewind {{.Version}} (commit ", shell_output("#{bin}/cirewind version")
    system bin/"cirewind", "demo", "--out", testpath/"demo"
    system bin/"cirewind", "verify", testpath/"demo"
    assert_path_exists testpath/"demo/manifest.sha256"
  end
end
`))
)

// FormulaOptions control rendering. DownloadBase defaults to the immutable
// upstream release location for the subjects' version; a fixture override is
// accepted only so synthetic subjects can be served locally during
// qualification, and the rendered text then records that it is a fixture.
type FormulaOptions struct {
	DownloadBase string
}

type formulaSubject struct {
	URL    string
	SHA256 string
}

type formulaView struct {
	Homepage    string
	Version     string
	DarwinArm64 formulaSubject
	DarwinAmd64 formulaSubject
	LinuxArm64  formulaSubject
	LinuxAmd64  formulaSubject
}

// LoadDistributionMetadata reads release-metadata.json strictly. It does not
// verify the subjects; callers that render anything must verify first.
func LoadDistributionMetadata(directory string) (DistributionMetadata, error) {
	raw, err := readBoundedRegular(filepath.Join(directory, "release-metadata.json"), maxMetadataBytes)
	if err != nil {
		return DistributionMetadata{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var metadata DistributionMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return DistributionMetadata{}, fmt.Errorf("decode release metadata: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return DistributionMetadata{}, fmt.Errorf("decode release metadata: %w", err)
	}
	return metadata, nil
}

// RenderFormula renders the formula from distribution metadata. Every Unix
// target must have exactly one archive whose name follows the release layout
// and whose SHA-256 is a lowercase digest; Windows subjects are ignored
// because Homebrew does not target them.
func RenderFormula(metadata DistributionMetadata, options FormulaOptions) ([]byte, error) {
	if metadata.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported distribution format version %d", metadata.FormatVersion)
	}
	version := metadata.Build.Version
	if !canonicalSemVer(version) {
		return nil, fmt.Errorf("release version %q is not canonical SemVer", version)
	}
	base := options.DownloadBase
	if base == "" {
		base = ReleaseDownloadBase + "v" + version + "/"
	}
	if !downloadBasePattern.MatchString(base) {
		return nil, fmt.Errorf("download base %q is not an absolute directory URL", base)
	}
	subjects := make(map[Target]formulaSubject, len(formulaTargets))
	for _, descriptor := range metadata.Artifacts {
		if descriptor.Target.OS == "windows" {
			continue
		}
		if _, duplicate := subjects[descriptor.Target]; duplicate {
			return nil, fmt.Errorf("duplicate release subject for %s", descriptor.Target)
		}
		want := fmt.Sprintf("cirewind_%s_%s_%s.tar.gz", version, descriptor.Target.OS, descriptor.Target.Arch)
		if descriptor.Archive.Name != want {
			return nil, fmt.Errorf("release subject for %s is named %q, want %q", descriptor.Target, descriptor.Archive.Name, want)
		}
		if !sha256Pattern.MatchString(descriptor.Archive.SHA256) || descriptor.Archive.Bytes <= 0 {
			return nil, fmt.Errorf("release subject for %s lacks a lowercase SHA-256 and byte length", descriptor.Target)
		}
		if descriptor.Build.Version != version {
			return nil, fmt.Errorf("release subject for %s carries version %q, want %q", descriptor.Target, descriptor.Build.Version, version)
		}
		subjects[descriptor.Target] = formulaSubject{URL: base + descriptor.Archive.Name, SHA256: descriptor.Archive.SHA256}
	}
	for _, target := range formulaTargets {
		if _, ok := subjects[target]; !ok {
			return nil, fmt.Errorf("release subject for %s is missing", target)
		}
	}
	if len(subjects) != len(formulaTargets) {
		return nil, errors.New("release subjects include an unsupported platform")
	}
	view := formulaView{
		Homepage:    formulaHomepage,
		Version:     version,
		DarwinArm64: subjects[Target{OS: "darwin", Arch: "arm64"}],
		DarwinAmd64: subjects[Target{OS: "darwin", Arch: "amd64"}],
		LinuxArm64:  subjects[Target{OS: "linux", Arch: "arm64"}],
		LinuxAmd64:  subjects[Target{OS: "linux", Arch: "amd64"}],
	}
	var buffer bytes.Buffer
	if options.DownloadBase != "" {
		buffer.WriteString("# FIXTURE FORMULA: subjects are served from a local qualification address, not the upstream release.\n")
	}
	if err := formulaTemplate.Execute(&buffer, view); err != nil {
		return nil, err
	}
	if strings.Contains(buffer.String(), "{{") {
		return nil, errors.New("formula rendering left template text")
	}
	return buffer.Bytes(), nil
}

// RenderFormulaFromDistribution verifies a release distribution directory and
// renders the formula from its exact subjects.
func RenderFormulaFromDistribution(directory string, options FormulaOptions) ([]byte, error) {
	if err := VerifyDistribution(directory); err != nil {
		return nil, fmt.Errorf("verify release subjects: %w", err)
	}
	metadata, err := LoadDistributionMetadata(directory)
	if err != nil {
		return nil, err
	}
	return RenderFormula(metadata, options)
}
