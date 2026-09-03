// Package samplesite builds and audits the deterministic synthetic sample site
// described in docs/SAMPLE_SITE_SPEC.md. It copies allowlisted files from one
// verified synthetic case, renders fixed HTML from typed data, and never parses
// case content as markup. It performs no network or process operation.
package samplesite

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxManifestBytes = 1 << 20
	maxManifestFiles = 4096
	maxArchiveBytes  = 48 << 20
)

// BuildDeterministicTarGz archives the named regular files below sourceDir
// under prefix with sorted entries, epoch timestamps, numeric owner and group
// zero, mode 0644, no links, and no host path. Identical inputs produce
// identical bytes.
func BuildDeterministicTarGz(ctx context.Context, sourceDir, prefix string, names []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validRelativePath(prefix) || strings.Contains(prefix, "/") {
		return nil, fmt.Errorf("archive prefix %q is not a single safe path component", prefix)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for index, name := range sorted {
		if !validRelativePath(name) {
			return nil, fmt.Errorf("archive entry %q is not a safe relative path", name)
		}
		if index > 0 && sorted[index-1] == name {
			return nil, fmt.Errorf("archive entry %q is duplicated", name)
		}
	}
	var buffer bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	compressor.Header = gzip.Header{OS: 255}
	writer := tar.NewWriter(compressor)
	var total int64
	for _, name := range sorted {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readBoundedRegular(filepath.Join(sourceDir, filepath.FromSlash(name)), maxArchiveBytes)
		if err != nil {
			return nil, fmt.Errorf("read archive input %s: %w", name, err)
		}
		total += int64(len(data))
		if total > maxArchiveBytes {
			return nil, errors.New("archive inputs exceed the accepted byte budget")
		}
		header := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     prefix + "/" + name,
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write archive header %s: %w", name, err)
		}
		if _, err := writer.Write(data); err != nil {
			return nil, fmt.Errorf("write archive entry %s: %w", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := compressor.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxArchiveBytes {
		return nil, errors.New("archive exceeds the accepted byte budget")
	}
	return buffer.Bytes(), nil
}

// ListArchiveEntries returns the entry names of a deterministic archive after
// checking that every entry is a regular file with the expected fixed header.
func ListArchiveEntries(data []byte, prefix string) ([]string, error) {
	if len(data) == 0 || len(data) > maxArchiveBytes {
		return nil, errors.New("archive is empty or oversized")
	}
	decompressor, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(io.LimitReader(decompressor, maxArchiveBytes+1))
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || header.Mode != 0o644 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(time.Unix(0, 0)) || header.Linkname != "" {
			return nil, fmt.Errorf("archive entry %q does not have the fixed deterministic header", header.Name)
		}
		name, ok := strings.CutPrefix(header.Name, prefix+"/")
		if !ok || !validRelativePath(name) {
			return nil, fmt.Errorf("archive entry %q is outside the expected prefix", header.Name)
		}
		if len(names) > 0 && names[len(names)-1] >= name {
			return nil, fmt.Errorf("archive entries are not strictly sorted at %q", header.Name)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// BuildTreeManifest returns sorted GNU-style SHA-256 lines for every regular
// file below dir except the entry named exclude. Symlinks and non-regular
// entries are rejected.
func BuildTreeManifest(ctx context.Context, dir, exclude string) ([]byte, error) {
	names, err := listRegularFiles(ctx, dir)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	count := 0
	for _, name := range names {
		if name == exclude {
			continue
		}
		count++
		if count > maxManifestFiles {
			return nil, errors.New("tree exceeds the accepted manifest file count")
		}
		digest, err := hashFile(ctx, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&output, "%s  %s\n", digest, name)
	}
	if count == 0 {
		return nil, errors.New("tree contains no manifested file")
	}
	return []byte(output.String()), nil
}

// VerifyTreeManifest checks that the manifest named manifestName below dir
// covers exactly the other regular files below dir and that every digest
// matches. It rejects links, non-regular entries, unmanifested files, missing
// files, malformed lines, and unsorted or duplicate entries.
func VerifyTreeManifest(ctx context.Context, dir, manifestName string) error {
	manifest, err := readBoundedRegular(filepath.Join(dir, filepath.FromSlash(manifestName)), maxManifestBytes)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", manifestName, err)
	}
	expected, err := parseManifest(manifest)
	if err != nil {
		return fmt.Errorf("parse manifest %s: %w", manifestName, err)
	}
	names, err := listRegularFiles(ctx, dir)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if name == manifestName {
			continue
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("file %q is not covered by %s", name, manifestName)
		}
		digest, err := hashFile(ctx, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		if digest != want {
			return fmt.Errorf("file %q does not match %s", name, manifestName)
		}
		seen[name] = true
	}
	for name := range expected {
		if !seen[name] {
			return fmt.Errorf("manifested file %q is missing", name)
		}
	}
	return nil
}

func parseManifest(data []byte) (map[string]string, error) {
	if len(data) == 0 || !bytes.HasSuffix(data, []byte("\n")) {
		return nil, errors.New("manifest is empty or lacks a final newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > maxManifestFiles {
		return nil, errors.New("manifest exceeds the accepted file count")
	}
	result := make(map[string]string, len(lines))
	previous := ""
	for _, line := range lines {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || len(digest) != sha256.Size*2 || !validRelativePath(name) {
			return nil, fmt.Errorf("malformed manifest line %q", line)
		}
		if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("malformed manifest digest for %q", name)
		}
		if previous != "" && name <= previous {
			return nil, fmt.Errorf("manifest entries are not strictly sorted at %q", name)
		}
		previous = name
		result[name] = digest
	}
	return result, nil
}

func listRegularFiles(ctx context.Context, dir string) ([]string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("tree root must be a real directory")
	}
	var names []string
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("tree contains symlink %q", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("tree contains non-regular entry %q", path)
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if !validRelativePath(name) {
			return fmt.Errorf("unsafe tree path %q", name)
		}
		names = append(names, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func hashFile(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := readBoundedRegular(path, maxArchiveBytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", filepath.Base(path))
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%q exceeds the accepted byte limit", filepath.Base(path))
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q grew beyond the accepted byte limit", filepath.Base(path))
	}
	return data, nil
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, character := range part {
			switch {
			case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9':
			case character == '.', character == '_', character == '-':
			default:
				return false
			}
		}
	}
	return true
}
