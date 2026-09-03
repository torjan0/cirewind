package releaseartifact

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const maxReleaseBinaryBytes = 256 << 20

// FileRecord describes one independently verifiable release file.
type FileRecord struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// ArtifactDescriptor describes one target archive and its external SBOM.
type ArtifactDescriptor struct {
	FormatVersion int           `json:"formatVersion"`
	Target        Target        `json:"target"`
	TopDirectory  string        `json:"topDirectory"`
	Archive       FileRecord    `json:"archive"`
	Binary        FileRecord    `json:"binary"`
	SBOM          FileRecord    `json:"sbom"`
	Build         BuildMetadata `json:"build"`
	// ReviewedPacks lists the registry-marked reviewed incident packs bundled
	// by exact bytes; an empty list states that no reviewed real pack shipped.
	ReviewedPacks []ReviewedPack `json:"reviewedPacks"`
}

type targetBuildMetadata struct {
	Build        BuildMetadata `json:"build"`
	Target       Target        `json:"target"`
	BinarySHA256 string        `json:"binarySHA256"`
	BinaryBytes  int64         `json:"binaryBytes"`
	SBOMPath     string        `json:"sbomPath"`
	LicenseIndex string        `json:"licenseIndex"`
}

// PackageOptions controls one target package operation.
type PackageOptions struct {
	Root       string
	BinaryPath string
	OutputDir  string
	Target     Target
	Build      BuildMetadata
}

// PackageTarget constructs one deterministic archive and its external SPDX
// file, using the exact dependency graph embedded in the binary.
func PackageTarget(options PackageOptions) (ArtifactDescriptor, error) {
	if err := options.Target.Validate(); err != nil {
		return ArtifactDescriptor{}, err
	}
	binary, err := readBoundedRegular(options.BinaryPath, maxReleaseBinaryBytes)
	if err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("read release binary: %w", err)
	}
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("read embedded Go build information: %w", err)
	}
	if err := ValidateBuildInfo(info, options.Target, options.Build); err != nil {
		return ArtifactDescriptor{}, err
	}
	if err := validateReleaseStamp(binary, options.Build); err != nil {
		return ArtifactDescriptor{}, err
	}
	binaryDigest := digestHex(binary)
	sbom, err := GenerateSPDX(info, options.Target, options.Build, binaryDigest)
	if err != nil {
		return ArtifactDescriptor{}, err
	}
	licenses, err := LoadLicenseBundle(options.Root, options.Target, info, options.Build.GoVersion)
	if err != nil {
		return ArtifactDescriptor{}, err
	}

	base := fmt.Sprintf("cirewind_%s_%s_%s", options.Build.Version, options.Target.OS, options.Target.Arch)
	buildRecord := targetBuildMetadata{
		Build:        options.Build,
		Target:       options.Target,
		BinarySHA256: binaryDigest,
		BinaryBytes:  int64(len(binary)),
		SBOMPath:     "sbom.spdx.json",
		LicenseIndex: "licenses/index.json",
	}
	buildJSON, err := json.MarshalIndent(buildRecord, "", "  ")
	if err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("encode target build metadata: %w", err)
	}
	files := []ArchiveFile{
		{Name: options.Target.BinaryName(), Data: binary, Mode: 0o755},
		{Name: "build-metadata.json", Data: append(buildJSON, '\n'), Mode: 0o644},
		{Name: "licenses/index.json", Data: licenses.Index, Mode: 0o644},
		{Name: "sbom.spdx.json", Data: sbom, Mode: 0o644},
	}
	files = append(files, repositoryReleaseFiles()...)
	reviewedPacks, reviewedFiles, err := reviewedArchiveFiles(options.Root)
	if err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("reviewed-pack release contract: %w", err)
	}
	files = append(files, reviewedFiles...)
	for i := range files {
		if files[i].Data != nil {
			continue
		}
		contents, err := readBoundedRegular(filepath.Join(options.Root, filepath.FromSlash(files[i].Name)), maxLicenseFileBytes)
		if err != nil {
			return ArtifactDescriptor{}, fmt.Errorf("read release file %q: %w", files[i].Name, err)
		}
		files[i].Data = contents
	}
	files = append(files, licenses.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	archive, err := DeterministicArchive(options.Target, base, options.Build.SourceDateEpoch, files)
	if err != nil {
		return ArtifactDescriptor{}, err
	}

	archiveName := base + options.Target.ArchiveExtension()
	sbomName := base + ".spdx.json"
	if err := writeNewRegular(filepath.Join(options.OutputDir, archiveName), archive, 0o644); err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("write release archive: %w", err)
	}
	if err := writeNewRegular(filepath.Join(options.OutputDir, sbomName), sbom, 0o644); err != nil {
		return ArtifactDescriptor{}, fmt.Errorf("write external SPDX: %w", err)
	}
	return ArtifactDescriptor{
		FormatVersion: FormatVersion,
		Target:        options.Target,
		TopDirectory:  base,
		Archive:       FileRecord{Name: archiveName, SHA256: digestHex(archive), Bytes: int64(len(archive))},
		Binary:        FileRecord{Name: options.Target.BinaryName(), SHA256: binaryDigest, Bytes: int64(len(binary))},
		SBOM:          FileRecord{Name: sbomName, SHA256: digestHex(sbom), Bytes: int64(len(sbom))},
		Build:         options.Build,
		ReviewedPacks: reviewedPacks,
	}, nil
}

// repositoryReleaseFiles is the closed checked-in distribution allowlist.
// Candidate packs and review packets are deliberately absent. Reviewed real
// packs enter only through the registry-bound reviewed-pack contract in
// reviewedpacks.go, never through this list.
func repositoryReleaseFiles() []ArchiveFile {
	return []ArchiveFile{
		{Name: "README.md", Mode: 0o644},
		{Name: "LICENSE", Mode: 0o644},
		{Name: "SECURITY.md", Mode: 0o644},
		{Name: "THIRD_PARTY_NOTICES.md", Mode: 0o644},
		{Name: "incidents/synthetic/mutable-tag.yaml", Mode: 0o644},
	}
}

func writeNewRegular(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(contents)
	if writeErr == nil && written != len(contents) {
		writeErr = errors.New("short write")
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

// ValidateBuildInfo checks already-decoded Go build information.
func ValidateBuildInfo(info *buildinfo.BuildInfo, target Target, metadata BuildMetadata) error {
	if info == nil {
		return errors.New("build information is nil")
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if info.Path != ModulePath+"/cmd/cirewind" {
		return fmt.Errorf("unexpected command import path %q", info.Path)
	}
	if info.Main.Path != ModulePath {
		return fmt.Errorf("unexpected main module %q", info.Main.Path)
	}
	if info.GoVersion != metadata.GoVersion {
		return fmt.Errorf("binary Go version %q does not match %q", info.GoVersion, metadata.GoVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return fmt.Errorf("duplicate build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	required := map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        target.OS,
		"GOARCH":      target.Arch,
		"-trimpath":   "true",
	}
	if target.Arch == "amd64" {
		required["GOAMD64"] = "v1"
	} else {
		required["GOARM64"] = "v8.0"
	}
	for key, want := range required {
		if got := settings[key]; got != want {
			return fmt.Errorf("binary build setting %s=%q, want %q", key, got, want)
		}
	}
	for _, dependency := range info.Deps {
		if dependency.Replace != nil {
			return fmt.Errorf("release binary contains a replaced module %s => %s", dependency.Path, dependency.Replace.Path)
		}
		if dependency.Path == "" || dependency.Version == "" || dependency.Sum == "" {
			return fmt.Errorf("release binary contains incomplete dependency metadata for %q", dependency.Path)
		}
	}
	for key := range settings {
		if len(key) >= 4 && key[:4] == "vcs." {
			return fmt.Errorf("release binary unexpectedly embeds VCS setting %q", key)
		}
	}
	return nil
}

func validateReleaseStamp(binary []byte, metadata BuildMetadata) error {
	stamp := []byte(ReleaseStamp(metadata))
	if count := bytes.Count(binary, stamp); count != 1 {
		return fmt.Errorf("binary contains %d exact release metadata stamps, want 1", count)
	}
	return nil
}
