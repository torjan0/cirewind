package releaseartifact

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const maxLicenseFileBytes = 4 << 20

type licenseIndex struct {
	FormatVersion   int            `json:"format_version"`
	ReviewedAt      string         `json:"reviewed_at"`
	ReviewedTargets []string       `json:"reviewed_targets"`
	Files           []licenseEntry `json:"files"`
}

type licenseEntry struct {
	Component     string   `json:"component"`
	Version       string   `json:"version"`
	LinkedTargets []string `json:"linked_targets"`
	SourceFile    string   `json:"source_file"`
	LocalPath     string   `json:"local_path"`
	SHA256        string   `json:"sha256"`
}

// LicenseBundle contains the target-filtered, hash-verified license files and
// its deterministic index.
type LicenseBundle struct {
	Index []byte
	Files []ArchiveFile
}

// LoadLicenseBundle verifies that each module embedded in the binary has at
// least one reviewed target-specific license entry and reads only indexed,
// hash-matching regular files.
func LoadLicenseBundle(root string, target Target, info *buildinfo.BuildInfo, goVersion string) (LicenseBundle, error) {
	if info == nil {
		return LicenseBundle{}, errors.New("build information is nil")
	}
	indexPath := filepath.Join(root, "third_party", "licenses", "index.json")
	encoded, err := readBoundedRegular(indexPath, maxLicenseFileBytes)
	if err != nil {
		return LicenseBundle{}, fmt.Errorf("read license index: %w", err)
	}
	var index licenseIndex
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&index); err != nil {
		return LicenseBundle{}, fmt.Errorf("decode license index: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return LicenseBundle{}, fmt.Errorf("decode license index: %w", err)
	}
	if index.FormatVersion != 1 || index.ReviewedAt == "" {
		return LicenseBundle{}, errors.New("unsupported or incomplete license index metadata")
	}

	required := make(map[string]string, len(info.Deps)+1)
	required["go.dev/toolchain"] = goVersion
	for _, dependency := range info.Deps {
		if existing, duplicate := required[dependency.Path]; duplicate && existing != dependency.Version {
			return LicenseBundle{}, fmt.Errorf("conflicting embedded module versions for %s", dependency.Path)
		}
		required[dependency.Path] = dependency.Version
	}

	targetName := target.String()
	matched := make(map[string]int, len(required))
	filtered := licenseIndex{
		FormatVersion:   index.FormatVersion,
		ReviewedAt:      index.ReviewedAt,
		ReviewedTargets: []string{targetName},
	}
	var files []ArchiveFile
	seenPaths := make(map[string]bool)
	for _, entry := range index.Files {
		if !contains(entry.LinkedTargets, targetName) {
			continue
		}
		wantVersion, needed := required[entry.Component]
		if !needed {
			return LicenseBundle{}, fmt.Errorf("license index claims %s is linked for %s but the exact binary does not", entry.Component, targetName)
		}
		if entry.Version != wantVersion {
			return LicenseBundle{}, fmt.Errorf("license version for %s is %q, binary uses %q", entry.Component, entry.Version, wantVersion)
		}
		clean, err := safeRelativeSlashPath(entry.LocalPath)
		if err != nil {
			return LicenseBundle{}, fmt.Errorf("license path for %s: %w", entry.Component, err)
		}
		if seenPaths[clean] {
			return LicenseBundle{}, fmt.Errorf("duplicate license path %q", clean)
		}
		seenPaths[clean] = true
		contents, err := readBoundedRegular(filepath.Join(root, "third_party", "licenses", filepath.FromSlash(clean)), maxLicenseFileBytes)
		if err != nil {
			return LicenseBundle{}, fmt.Errorf("read indexed license %q: %w", clean, err)
		}
		if digestHex(contents) != entry.SHA256 {
			return LicenseBundle{}, fmt.Errorf("indexed license %q failed SHA-256 verification", clean)
		}
		entry.LinkedTargets = []string{targetName}
		filtered.Files = append(filtered.Files, entry)
		files = append(files, ArchiveFile{Name: "licenses/" + clean, Data: contents, Mode: 0o644})
		matched[entry.Component]++
	}
	for module, version := range required {
		if matched[module] == 0 {
			return LicenseBundle{}, fmt.Errorf("no reviewed license file for embedded module %s@%s on %s", module, version, targetName)
		}
	}
	sort.Slice(filtered.Files, func(i, j int) bool { return filtered.Files[i].LocalPath < filtered.Files[j].LocalPath })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	filteredJSON, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return LicenseBundle{}, fmt.Errorf("encode filtered license index: %w", err)
	}
	return LicenseBundle{Index: append(filteredJSON, '\n'), Files: files}, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func safeRelativeSlashPath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", errors.New("path must be a nonempty relative slash path")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if err := validatePortablePathComponent(part); err != nil {
			return "", err
		}
	}
	return strings.Join(parts, "/"), nil
}

func validatePortablePathComponent(part string) error {
	if part == "" || part == "." || part == ".." {
		return errors.New("path contains an empty or dot component")
	}
	if strings.ContainsRune(part, ':') || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
		return errors.New("path contains a component unsafe on Windows")
	}
	for _, character := range part {
		if character == 0 || unicode.IsControl(character) {
			return errors.New("path contains a control character")
		}
	}
	base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
		(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
		return errors.New("path contains a reserved Windows device component")
	}
	return nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d-byte release limit", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte release limit", limit)
	}
	return contents, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
