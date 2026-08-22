// Package casefile safely stages, manifests, verifies, and publishes CIRewind
// case directories. Source-derived names never become filesystem paths.
package casefile

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var requiredFiles = []string{
	"affected-runs.csv",
	"case.db",
	"collection-metadata.json",
	"evidence.jsonl",
	"findings.json",
	"graph.json",
	"report.html",
	"summary.md",
}

// Builder stages fixed case outputs in an owner-only sibling directory.
type Builder struct {
	target  string
	staging string
	raw     bool
	closed  bool
}

func NewBuilder(target string, raw bool) (*Builder, error) {
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("case output path is empty")
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve case output: %w", err)
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) || abs == filepath.Clean(os.Getenv("HOME")) {
		return nil, errors.New("case output cannot be a filesystem or home root")
	}
	abs, err = canonicalizeTrustedTempPath(abs)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(abs); err == nil {
		return nil, fmt.Errorf("case output already exists: %s", abs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect case output: %w", err)
	}
	parent := filepath.Dir(abs)
	// Check existing ancestors before MkdirAll so an attacker-controlled
	// symlink cannot redirect creation outside the requested case parent. Check
	// again afterwards to narrow the remaining rename/create race.
	if err := rejectLinks(parent); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create case parent: %w", err)
	}
	if err := rejectLinks(parent); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(parent, ".cirewind-case-")
	if err != nil {
		return nil, fmt.Errorf("create case staging directory: %w", err)
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		_ = os.Remove(staging)
		return nil, fmt.Errorf("protect case staging directory: %w", err)
	}
	if raw {
		if err := os.Mkdir(filepath.Join(staging, "raw"), 0o700); err != nil {
			_ = os.Remove(staging)
			return nil, fmt.Errorf("create raw evidence directory: %w", err)
		}
	}
	return &Builder{target: abs, staging: staging, raw: raw}, nil
}

func (b *Builder) StagingPath() string { return b.staging }

// Path returns the controlled staging path for a fixed case file.
func (b *Builder) Path(name string) (string, error) {
	if b.closed {
		return "", errors.New("case builder is closed")
	}
	if name == "manifest.sha256" || !contains(requiredFiles, name) {
		return "", fmt.Errorf("unsupported case filename %q", name)
	}
	return filepath.Join(b.staging, name), nil
}

// CreateFile exclusively creates one fixed owner-only case file.
func (b *Builder) CreateFile(name string) (*os.File, error) {
	path, err := b.Path(name)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create case file %s: %w", name, err)
	}
	return f, nil
}

// RawSHA256Path returns a controlled content-addressed filename for exact raw
// bytes. It never uses repository, workflow, job, step, or archive entry names.
func (b *Builder) RawSHA256Path(digest string) (string, error) {
	if b.closed {
		return "", errors.New("case builder is closed")
	}
	if !b.raw {
		return "", errors.New("raw evidence retention is disabled")
	}
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		return "", errors.New("invalid raw SHA-256 length or case")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", errors.New("invalid raw SHA-256 encoding")
	}
	return filepath.Join(b.staging, "raw", digest+".bin"), nil
}

// CreateRawFile exclusively creates one owner-only content-addressed raw file.
func (b *Builder) CreateRawFile(digest string) (*os.File, error) {
	path, err := b.RawSHA256Path(digest)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create raw evidence object: %w", err)
	}
	return file, nil
}

// Finalize checks the fixed case contract, writes its manifest, and atomically
// renames the staging directory into place.
func (b *Builder) Finalize(ctx context.Context) error {
	if b.closed {
		return errors.New("case builder is closed")
	}
	for _, name := range requiredFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(filepath.Join(b.staging, name))
		if err != nil {
			return fmt.Errorf("required case file %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("required case file %s is not regular", name)
		}
		if err := os.Chmod(filepath.Join(b.staging, name), 0o600); err != nil {
			return fmt.Errorf("protect case file %s: %w", name, err)
		}
	}
	manifest, err := BuildManifest(ctx, b.staging)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(b.staging, "manifest.sha256")
	f, err := os.OpenFile(manifestPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create case manifest: %w", err)
	}
	if _, err := f.Write(manifest); err != nil {
		_ = f.Close()
		return fmt.Errorf("write case manifest: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync case manifest: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close case manifest: %w", err)
	}
	if _, err := os.Lstat(b.target); err == nil {
		return fmt.Errorf("case output appeared during finalization: %s", b.target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect final case output: %w", err)
	}
	if err := os.Rename(b.staging, b.target); err != nil {
		return fmt.Errorf("publish case directory: %w", err)
	}
	b.closed = true
	return nil
}

// Abort removes only the unique staging directory created by this Builder.
func (b *Builder) Abort() error {
	if b.closed || b.staging == "" {
		return nil
	}
	b.closed = true
	return os.RemoveAll(b.staging)
}

// BuildManifest returns sorted GNU-style SHA-256 entries for all regular files
// except the manifest itself. Symlinks and non-regular entries are rejected.
func BuildManifest(ctx context.Context, dir string) ([]byte, error) {
	var names []string
	err := filepath.WalkDir(dir, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, filePath)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("case contains symlink %s", relative)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("case contains non-regular file %s", relative)
		}
		relative = filepath.ToSlash(relative)
		if relative == "manifest.sha256" {
			return nil
		}
		if !validRelative(relative) {
			return fmt.Errorf("unsafe manifest path %q", relative)
		}
		names = append(names, relative)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enumerate case files: %w", err)
	}
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		digest, err := hashFile(ctx, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&output, "%s  %s\n", digest, name)
	}
	return []byte(output.String()), nil
}

// VerifyManifest detects changed, missing, and unmanifested regular files.
func VerifyManifest(ctx context.Context, dir string) error {
	manifestPath := filepath.Join(dir, "manifest.sha256")
	f, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	expected := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(f, 16<<20))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return errors.New("malformed manifest line")
		}
		digest, name := line[:64], line[66:]
		if _, err := hex.DecodeString(digest); err != nil || !validRelative(name) || name == "manifest.sha256" {
			return errors.New("malformed manifest entry")
		}
		if _, duplicate := expected[name]; duplicate {
			return fmt.Errorf("duplicate manifest entry %q", name)
		}
		expected[name] = strings.ToLower(digest)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	for _, name := range requiredFiles {
		if _, present := expected[name]; !present {
			return fmt.Errorf("manifest omits required case file %s", name)
		}
	}
	actualBytes, err := BuildManifest(ctx, dir)
	if err != nil {
		return err
	}
	actual := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(actualBytes)), "\n") {
		if line == "" {
			continue
		}
		actual[line[66:]] = line[:64]
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("manifest file set differs: expected %d files, found %d", len(expected), len(actual))
	}
	for name, digest := range expected {
		if actual[name] != digest {
			return fmt.Errorf("manifest verification failed for %s", name)
		}
	}
	return nil
}

func hashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open case file for hashing: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := f.Read(buffer)
		if n > 0 {
			_, _ = h.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("hash case file: %w", readErr)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validRelative(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.ContainsRune(name, 0) && !strings.HasPrefix(name, "/") && name == filepath.ToSlash(filepath.Clean(name)) && name != "." && name != ".." && !strings.HasPrefix(name, "../")
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

// canonicalizeTrustedTempPath resolves links in the process-selected temporary
// root, but not in any caller-controlled path below that root. This admits
// operating-system aliases such as macOS /var -> /private/var without turning
// an arbitrary symlink ancestor into an accepted output location. Callers must
// still apply rejectLinks to the returned path before and after creating
// missing directories.
func canonicalizeTrustedTempPath(path string) (string, error) {
	return canonicalizeUnderTrustedRoot(path, os.TempDir())
}

func canonicalizeUnderTrustedRoot(path, trustedRoot string) (string, error) {
	cleanPath := filepath.Clean(path)
	root, err := filepath.Abs(trustedRoot)
	if err != nil {
		return "", fmt.Errorf("resolve trusted temporary root: %w", err)
	}
	root = filepath.Clean(root)
	relative, err := filepath.Rel(root, cleanPath)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return cleanPath, nil
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize trusted temporary root: %w", err)
	}
	info, err := os.Stat(canonicalRoot)
	if err != nil {
		return "", fmt.Errorf("inspect trusted temporary root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("trusted temporary root is not a directory")
	}
	if relative == "." {
		return filepath.Clean(canonicalRoot), nil
	}
	return filepath.Clean(filepath.Join(canonicalRoot, relative)), nil
}

func rejectLinks(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("case path contains symlink component: %s", current)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
