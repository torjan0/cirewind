package releaseartifact

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var supportedTargets = []Target{
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "windows", Arch: "amd64"},
	{OS: "windows", Arch: "arm64"},
}

// DistributionMetadata describes a complete six-target candidate. The
// authenticated=false field is deliberate: hashes and reproducibility do not
// authenticate who produced an artifact.
type DistributionMetadata struct {
	FormatVersion  int                        `json:"formatVersion"`
	Build          BuildMetadata              `json:"build"`
	Recipe         DistributionRecipe         `json:"recipe"`
	Integrity      DistributionIntegrity      `json:"integrity"`
	Authentication DistributionAuthentication `json:"authentication"`
	Artifacts      []ArtifactDescriptor       `json:"artifacts"`
}

// DistributionRecipe records deterministic build controls.
type DistributionRecipe struct {
	Command      string   `json:"command"`
	Targets      []string `json:"targets"`
	ArchiveRules string   `json:"archiveRules"`
	SBOMSource   string   `json:"sbomSource"`
}

// DistributionIntegrity documents the checksum contract.
type DistributionIntegrity struct {
	Algorithm string `json:"algorithm"`
	File      string `json:"file"`
}

// DistributionAuthentication accurately bounds unsigned local output.
type DistributionAuthentication struct {
	Authenticated bool   `json:"authenticated"`
	Status        string `json:"status"`
	RequiredStep  string `json:"requiredStep"`
}

// FinalizeDistribution writes deterministic metadata and SHA256SUMS after
// verifying every descriptor against the exact output bytes.
func FinalizeDistribution(outputDir string, descriptors []ArtifactDescriptor) error {
	ordered, build, err := validateDescriptors(outputDir, descriptors)
	if err != nil {
		return err
	}
	metadata := newDistributionMetadata(ordered, build)
	encoded, err := encodeDistributionMetadata(metadata)
	if err != nil {
		return err
	}
	metadataPath := filepath.Join(outputDir, "release-metadata.json")
	if err := writeNewRegular(metadataPath, encoded, 0o644); err != nil {
		return fmt.Errorf("write release metadata: %w", err)
	}

	files := []string{"release-metadata.json"}
	for _, descriptor := range ordered {
		files = append(files, descriptor.Archive.Name, descriptor.SBOM.Name)
	}
	sums, err := checksumManifest(outputDir, files)
	if err != nil {
		return err
	}
	if err := writeNewRegular(filepath.Join(outputDir, "SHA256SUMS"), sums, 0o644); err != nil {
		return fmt.Errorf("write SHA256SUMS: %w", err)
	}
	return nil
}

func newDistributionMetadata(ordered []ArtifactDescriptor, build BuildMetadata) DistributionMetadata {
	targetNames := make([]string, len(ordered))
	for i := range ordered {
		targetNames[i] = ordered[i].Target.String()
	}
	return DistributionMetadata{
		FormatVersion: FormatVersion,
		Build:         build,
		Recipe: DistributionRecipe{
			Command:      "scripts/release.sh",
			Targets:      targetNames,
			ArchiveRules: "sorted regular files; fixed source-date timestamp; uid/gid 0 for tar; normalized 0644/0755 modes; Go archive writers",
			SBOMSource:   "SPDX 2.3 JSON generated from debug/buildinfo in each exact binary",
		},
		Integrity: DistributionIntegrity{Algorithm: "SHA-256", File: "SHA256SUMS"},
		Authentication: DistributionAuthentication{
			Authenticated: false,
			Status:        "unsigned-local-build-metadata",
			RequiredStep:  "A release maintainer must verify this candidate and attach an independently authenticated signature or platform provenance before publication.",
		},
		Artifacts: ordered,
	}
}

func encodeDistributionMetadata(metadata DistributionMetadata) ([]byte, error) {
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode release metadata: %w", err)
	}
	return append(encoded, '\n'), nil
}

func checksumManifest(outputDir string, files []string) ([]byte, error) {
	files = append([]string(nil), files...)
	sort.Strings(files)
	var sums strings.Builder
	for _, name := range files {
		contents, err := readBoundedRegular(filepath.Join(outputDir, name), maxReleaseBinaryBytes*2)
		if err != nil {
			return nil, fmt.Errorf("hash release file %q: %w", name, err)
		}
		fmt.Fprintf(&sums, "%s  %s\n", digestHex(contents), name)
	}
	return []byte(sums.String()), nil
}

func validateDescriptors(outputDir string, descriptors []ArtifactDescriptor) ([]ArtifactDescriptor, BuildMetadata, error) {
	if len(descriptors) != len(supportedTargets) {
		return nil, BuildMetadata{}, fmt.Errorf("release requires %d target descriptors, got %d", len(supportedTargets), len(descriptors))
	}
	ordered := append([]ArtifactDescriptor(nil), descriptors...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Target.String() < ordered[j].Target.String() })
	var build BuildMetadata
	for i, descriptor := range ordered {
		if descriptor.FormatVersion != FormatVersion {
			return nil, BuildMetadata{}, fmt.Errorf("unsupported artifact descriptor version %d", descriptor.FormatVersion)
		}
		if descriptor.Target != supportedTargets[i] {
			return nil, BuildMetadata{}, fmt.Errorf("target %d is %s, want %s", i, descriptor.Target, supportedTargets[i])
		}
		base := fmt.Sprintf("cirewind_%s_%s_%s", descriptor.Build.Version, descriptor.Target.OS, descriptor.Target.Arch)
		if descriptor.TopDirectory != base || descriptor.Archive.Name != base+descriptor.Target.ArchiveExtension() ||
			descriptor.SBOM.Name != base+".spdx.json" || descriptor.Binary.Name != descriptor.Target.BinaryName() {
			return nil, BuildMetadata{}, fmt.Errorf("target %s descriptor filenames do not follow the canonical release layout", descriptor.Target)
		}
		if i == 0 {
			build = descriptor.Build
		} else if descriptor.Build != build {
			return nil, BuildMetadata{}, fmt.Errorf("target %s build metadata differs from other targets", descriptor.Target)
		}
		if i > 0 {
			first, err := EncodeReviewedIndex(ordered[0].ReviewedPacks)
			if err != nil {
				return nil, BuildMetadata{}, err
			}
			current, err := EncodeReviewedIndex(descriptor.ReviewedPacks)
			if err != nil {
				return nil, BuildMetadata{}, err
			}
			if !bytes.Equal(first, current) {
				return nil, BuildMetadata{}, fmt.Errorf("target %s reviewed-pack set differs from other targets", descriptor.Target)
			}
		}
		for label, record := range map[string]FileRecord{"archive": descriptor.Archive, "SBOM": descriptor.SBOM} {
			if _, err := safeDistributionName(record.Name); err != nil {
				return nil, BuildMetadata{}, fmt.Errorf("target %s %s name: %w", descriptor.Target, label, err)
			}
			contents, err := readBoundedRegular(filepath.Join(outputDir, record.Name), maxReleaseBinaryBytes*2)
			if err != nil {
				return nil, BuildMetadata{}, fmt.Errorf("read target %s %s: %w", descriptor.Target, label, err)
			}
			if int64(len(contents)) != record.Bytes || digestHex(contents) != record.SHA256 {
				return nil, BuildMetadata{}, fmt.Errorf("target %s %s descriptor does not match exact bytes", descriptor.Target, label)
			}
		}
	}
	validated, err := NewBuildMetadata(build.Version, build.Commit, build.GoVersion, build.SourceDateEpoch)
	if err != nil {
		return nil, BuildMetadata{}, fmt.Errorf("invalid descriptor build metadata: %w", err)
	}
	if build != validated {
		return nil, BuildMetadata{}, errors.New("descriptor build metadata contains noncanonical derived fields")
	}
	return ordered, build, nil
}

func safeDistributionName(name string) (string, error) {
	clean, err := safeRelativeSlashPath(name)
	if err != nil {
		return "", err
	}
	if strings.Contains(clean, "/") {
		return "", errors.New("distribution files must be at its root")
	}
	return clean, nil
}

// VerifyDistribution verifies the exact file set, checksums, descriptor
// metadata, archive entries, embedded build graph, license hashes, and SPDX for
// a local release candidate. It does not authenticate a publisher.
func VerifyDistribution(directory string) error {
	metadataBytes, err := readBoundedRegular(filepath.Join(directory, "release-metadata.json"), maxLicenseFileBytes)
	if err != nil {
		return fmt.Errorf("read release metadata: %w", err)
	}
	var metadata DistributionMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return fmt.Errorf("decode release metadata: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode release metadata: %w", err)
	}
	if metadata.FormatVersion != FormatVersion || metadata.Build.FormatVersion != FormatVersion {
		return errors.New("unsupported release metadata format")
	}
	if metadata.Authentication.Authenticated || metadata.Build.Authenticated {
		return errors.New("local release metadata must not claim unaudited authentication")
	}
	ordered, build, err := validateDescriptors(directory, metadata.Artifacts)
	if err != nil {
		return err
	}
	if build != metadata.Build {
		return errors.New("release build metadata disagrees with artifact descriptors")
	}
	wantMetadata, err := encodeDistributionMetadata(newDistributionMetadata(ordered, build))
	if err != nil {
		return err
	}
	if !bytes.Equal(metadataBytes, wantMetadata) {
		return errors.New("release metadata contains noncanonical recipe or authentication fields")
	}

	wantFiles := map[string]bool{"SHA256SUMS": true, "release-metadata.json": true}
	for _, descriptor := range ordered {
		wantFiles[descriptor.Archive.Name] = true
		wantFiles[descriptor.SBOM.Name] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	if len(entries) != len(wantFiles) {
		return fmt.Errorf("release directory contains %d entries, want exactly %d", len(entries), len(wantFiles))
	}
	for _, entry := range entries {
		if entry.IsDir() || !wantFiles[entry.Name()] {
			return fmt.Errorf("unexpected release directory entry %q", entry.Name())
		}
	}

	checksums, err := parseChecksums(filepath.Join(directory, "SHA256SUMS"))
	if err != nil {
		return err
	}
	delete(wantFiles, "SHA256SUMS")
	if len(checksums) != len(wantFiles) {
		return fmt.Errorf("SHA256SUMS contains %d records, want %d", len(checksums), len(wantFiles))
	}
	for name := range wantFiles {
		want, exists := checksums[name]
		if !exists {
			return fmt.Errorf("SHA256SUMS omits %q", name)
		}
		contents, err := readBoundedRegular(filepath.Join(directory, name), maxReleaseBinaryBytes*2)
		if err != nil {
			return err
		}
		if digestHex(contents) != want {
			return fmt.Errorf("SHA-256 mismatch for %q", name)
		}
	}
	manifestNames := make([]string, 0, len(wantFiles))
	for name := range wantFiles {
		manifestNames = append(manifestNames, name)
	}
	wantManifest, err := checksumManifest(directory, manifestNames)
	if err != nil {
		return err
	}
	actualManifest, err := readBoundedRegular(filepath.Join(directory, "SHA256SUMS"), maxLicenseFileBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualManifest, wantManifest) {
		return errors.New("SHA256SUMS is not the canonical sorted manifest")
	}

	for _, descriptor := range ordered {
		if err := verifyTargetArchive(directory, descriptor); err != nil {
			return fmt.Errorf("verify %s: %w", descriptor.Target, err)
		}
	}
	return nil
}

func parseChecksums(path string) (map[string]string, error) {
	contents, err := readBoundedRegular(path, maxLicenseFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	result := make(map[string]string)
	for lineNumber, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " {
			return nil, fmt.Errorf("invalid SHA256SUMS line %d", lineNumber+1)
		}
		digest, name := line[:64], line[66:]
		if decoded, err := hex.DecodeString(digest); err != nil || len(decoded) != sha256.Size || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("invalid digest on SHA256SUMS line %d", lineNumber+1)
		}
		if _, err := safeDistributionName(name); err != nil {
			return nil, fmt.Errorf("invalid filename on SHA256SUMS line %d: %w", lineNumber+1, err)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("duplicate SHA256SUMS filename %q", name)
		}
		result[name] = digest
	}
	return result, nil
}

func verifyTargetArchive(directory string, descriptor ArtifactDescriptor) error {
	archive, err := readBoundedRegular(filepath.Join(directory, descriptor.Archive.Name), maxReleaseBinaryBytes*2)
	if err != nil {
		return err
	}
	files, err := ReadArchive(descriptor.Target, archive, 128, maxReleaseBinaryBytes*2)
	if err != nil {
		return err
	}
	prefix := descriptor.TopDirectory + "/"
	required := []string{
		descriptor.Target.BinaryName(), "README.md", "LICENSE", "SECURITY.md",
		"THIRD_PARTY_NOTICES.md", "build-metadata.json",
		"incidents/synthetic/mutable-tag.yaml", "licenses/index.json", "sbom.spdx.json",
	}
	wantArchiveEntries := make(map[string]bool)
	for _, name := range required {
		fullName := prefix + name
		wantArchiveEntries[fullName] = true
		if _, exists := files[fullName]; !exists {
			return fmt.Errorf("archive omits %q", prefix+name)
		}
	}
	binary := files[prefix+descriptor.Target.BinaryName()]
	if int64(len(binary)) != descriptor.Binary.Bytes || digestHex(binary) != descriptor.Binary.SHA256 {
		return errors.New("archive binary does not match descriptor")
	}
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return fmt.Errorf("read archived binary build information: %w", err)
	}
	if err := ValidateBuildInfo(info, descriptor.Target, descriptor.Build); err != nil {
		return err
	}
	if err := validateReleaseStamp(binary, descriptor.Build); err != nil {
		return err
	}
	wantSPDX, err := GenerateSPDX(info, descriptor.Target, descriptor.Build, descriptor.Binary.SHA256)
	if err != nil {
		return err
	}
	embeddedSPDX := files[prefix+"sbom.spdx.json"]
	externalSPDX, err := readBoundedRegular(filepath.Join(directory, descriptor.SBOM.Name), maxLicenseFileBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(embeddedSPDX, externalSPDX) || !bytes.Equal(embeddedSPDX, wantSPDX) {
		return errors.New("embedded, external, and regenerated SPDX documents differ")
	}

	wantBuildRecord := targetBuildMetadata{
		Build: descriptor.Build, Target: descriptor.Target,
		BinarySHA256: descriptor.Binary.SHA256, BinaryBytes: descriptor.Binary.Bytes,
		SBOMPath: "sbom.spdx.json", LicenseIndex: "licenses/index.json",
	}
	wantBuildJSON, err := json.MarshalIndent(wantBuildRecord, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(files[prefix+"build-metadata.json"], append(wantBuildJSON, '\n')) {
		return errors.New("archived build metadata differs from descriptor")
	}
	licenseEntries, err := verifyArchivedLicenses(files, prefix, descriptor.Target, info, descriptor.Build.GoVersion)
	if err != nil {
		return err
	}
	for name := range licenseEntries {
		wantArchiveEntries[name] = true
	}
	reviewedEntries, err := verifyReviewedEntries(files, prefix, descriptor.ReviewedPacks)
	if err != nil {
		return err
	}
	for name := range reviewedEntries {
		wantArchiveEntries[name] = true
	}
	if len(files) != len(wantArchiveEntries) {
		return fmt.Errorf("archive contains %d files, want exactly %d", len(files), len(wantArchiveEntries))
	}
	canonicalFiles := make([]ArchiveFile, 0, len(files))
	for name, contents := range files {
		if !wantArchiveEntries[name] {
			return fmt.Errorf("archive contains unexpected file %q", name)
		}
		mode := os.FileMode(0o644)
		if name == prefix+descriptor.Target.BinaryName() {
			mode = 0o755
		}
		canonicalFiles = append(canonicalFiles, ArchiveFile{
			Name: strings.TrimPrefix(name, prefix), Data: contents, Mode: mode,
		})
	}
	wantArchive, err := DeterministicArchive(descriptor.Target, descriptor.TopDirectory, descriptor.Build.SourceDateEpoch, canonicalFiles)
	if err != nil {
		return err
	}
	if !bytes.Equal(archive, wantArchive) {
		return errors.New("archive bytes do not follow the canonical order, timestamp, mode, owner, or compression recipe")
	}
	return nil
}

func verifyArchivedLicenses(files map[string][]byte, prefix string, target Target, info *buildinfo.BuildInfo, goVersion string) (map[string]bool, error) {
	var index licenseIndex
	decoder := json.NewDecoder(bytes.NewReader(files[prefix+"licenses/index.json"]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return nil, fmt.Errorf("decode archived license index: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode archived license index: %w", err)
	}
	if index.FormatVersion != 1 || len(index.ReviewedTargets) != 1 || index.ReviewedTargets[0] != target.String() {
		return nil, errors.New("archived license index has invalid target metadata")
	}
	requiredModules := map[string]string{"go.dev/toolchain": goVersion}
	for _, dependency := range info.Deps {
		requiredModules[dependency.Path] = dependency.Version
	}
	seenModules := make(map[string]int)
	wantEntries := make(map[string]bool)
	for _, entry := range index.Files {
		version, exists := requiredModules[entry.Component]
		if !exists || version != entry.Version || len(entry.LinkedTargets) != 1 || entry.LinkedTargets[0] != target.String() {
			return nil, fmt.Errorf("archived license entry for %s does not match embedded modules", entry.Component)
		}
		clean, err := safeRelativeSlashPath(entry.LocalPath)
		if err != nil {
			return nil, err
		}
		name := prefix + "licenses/" + clean
		if wantEntries[name] {
			return nil, fmt.Errorf("archived license index repeats %q", name)
		}
		contents, exists := files[name]
		if !exists || digestHex(contents) != entry.SHA256 {
			return nil, fmt.Errorf("archived license %q is missing or hash-mismatched", name)
		}
		wantEntries[name] = true
		seenModules[entry.Component]++
	}
	for module := range requiredModules {
		if seenModules[module] == 0 {
			return nil, fmt.Errorf("archived licenses omit embedded module %s", module)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, prefix+"licenses/") && name != prefix+"licenses/index.json" && !wantEntries[name] {
			return nil, fmt.Errorf("archive contains unindexed license %q", name)
		}
	}
	return wantEntries, nil
}

// CompareDistributions requires byte-for-byte equality of two release trees.
func CompareDistributions(first, second string) error {
	left, err := distributionFiles(first)
	if err != nil {
		return err
	}
	right, err := distributionFiles(second)
	if err != nil {
		return err
	}
	if len(left) != len(right) {
		return fmt.Errorf("distribution file counts differ: %d != %d", len(left), len(right))
	}
	for name, leftDigest := range left {
		if rightDigest, exists := right[name]; !exists || rightDigest != leftDigest {
			return fmt.Errorf("distribution differs at %q", name)
		}
	}
	return nil
}

func distributionFiles(directory string) (map[string]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("distribution contains directory %q", entry.Name())
		}
		contents, err := readBoundedRegular(filepath.Join(directory, entry.Name()), maxReleaseBinaryBytes*2)
		if err != nil {
			return nil, err
		}
		result[entry.Name()] = digestHex(contents) + ":" + strconv.FormatInt(int64(len(contents)), 10)
	}
	return result, nil
}
