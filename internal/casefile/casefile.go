// Package casefile safely stages, manifests, verifies, and publishes CIRewind
// case directories. Source-derived names never become filesystem paths.
package casefile

import (
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

// CaseContract identifies the fixed material-file contract selected by
// collection-metadata.json after its manifest entry has been authenticated.
type CaseContract string

const (
	ContractV1Alpha1 CaseContract = "cirewind.case/v1alpha1"
	ContractV1Alpha2 CaseContract = "cirewind.case/v1alpha2"
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

var requiredFilesV2 = []string{
	"affected-runs.csv",
	"case.db",
	"collection-metadata.json",
	"evidence.jsonl",
	"findings.json",
	"graph.json",
	"graph.svg",
	"report.html",
	"summary.md",
}

// manifestTreeLimits bound filesystem work before any case payload is hashed.
// The production values admit the documented raw-evidence limits while making
// sparse-file and entry-storm denial of service finite. Tests use smaller
// limits through buildManifestWithLimits rather than mutable package globals.
type manifestTreeLimits struct {
	maxEntries       uint64
	maxDepth         int
	maxFileBytes     uint64
	maxAggregateByte uint64
}

var defaultManifestTreeLimits = manifestTreeLimits{
	maxEntries:       100_128,
	maxDepth:         64,
	maxFileBytes:     16 << 30,
	maxAggregateByte: 32 << 30,
}

// Builder stages fixed case outputs in an owner-only sibling directory.
type Builder struct {
	target      string
	staging     string
	stagingInfo os.FileInfo
	raw         bool
	contract    CaseContract
	closed      bool
}

// NewBuilder preserves the v0.1 case contract. New v0.2 generators must use
// NewBuilderV2 so graph.svg and the strict raw-materialization policy cannot be
// omitted accidentally.
func NewBuilder(target string, raw bool) (*Builder, error) {
	return newBuilder(target, raw, ContractV1Alpha1)
}

// NewBuilderV2 stages a strict v0.2 case. rawMaterialized controls whether the
// one optional raw/ directory is created; collection metadata and evidence
// descriptors are checked against it before publication.
func NewBuilderV2(target string, rawMaterialized bool) (*Builder, error) {
	return newBuilder(target, rawMaterialized, ContractV1Alpha2)
}

func newBuilder(target string, raw bool, contract CaseContract) (*Builder, error) {
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("case output path is empty")
	}
	if contract != ContractV1Alpha1 && contract != ContractV1Alpha2 {
		return nil, fmt.Errorf("unsupported case contract %q", contract)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve case output: %w", err)
	}
	abs = filepath.Clean(abs)
	if protectedOutputRoot(abs) {
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
	stagingInfo, err := stableDirectoryInfo(staging)
	if err != nil {
		_ = os.Remove(staging)
		return nil, fmt.Errorf("inspect case staging directory: %w", err)
	}
	if raw {
		if err := os.Mkdir(filepath.Join(staging, "raw"), 0o700); err != nil {
			_ = os.Remove(staging)
			return nil, fmt.Errorf("create raw evidence directory: %w", err)
		}
	}
	return &Builder{target: abs, staging: staging, stagingInfo: stagingInfo, raw: raw, contract: contract}, nil
}

func protectedOutputRoot(path string) bool {
	clean := filepath.Clean(path)
	// filepath.Dir(root) == root on both POSIX roots and Windows volume/UNC
	// roots; comparing only with filepath.Separator misses drive roots.
	if filepath.Dir(clean) == clean {
		return true
	}
	homes := []string{os.Getenv("HOME")}
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	for _, home := range homes {
		if strings.TrimSpace(home) == "" {
			continue
		}
		resolved, err := filepath.Abs(home)
		if err == nil && clean == filepath.Clean(resolved) {
			return true
		}
	}
	return false
}

func (b *Builder) StagingPath() string { return b.staging }

// Path returns the controlled staging path for a fixed case file.
func (b *Builder) Path(name string) (string, error) {
	if b.closed {
		return "", errors.New("case builder is closed")
	}
	if name == "manifest.sha256" || !contains(b.requiredFiles(), name) {
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
	if err := b.validateStagingIdentity(); err != nil {
		return err
	}
	for _, name := range b.requiredFiles() {
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
	verification, err := VerifyCase(ctx, b.staging)
	if err != nil {
		return fmt.Errorf("verify staged case: %w", err)
	}
	if verification.Contract != b.contract {
		return fmt.Errorf("staged case selected contract %q, builder requires %q", verification.Contract, b.contract)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(b.target); err == nil {
		return fmt.Errorf("case output appeared during finalization: %s", b.target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect final case output: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.validateStagingIdentity(); err != nil {
		return err
	}
	if err := publishDirectoryNoReplace(b.staging, b.target); err != nil {
		return fmt.Errorf("publish case directory: %w", err)
	}
	b.closed = true
	return nil
}

func (b *Builder) requiredFiles() []string {
	if b.contract == ContractV1Alpha2 {
		return requiredFilesV2
	}
	return requiredFiles
}

// Abort removes only the unique staging directory created by this Builder.
func (b *Builder) Abort() error {
	if b.closed || b.staging == "" {
		return nil
	}
	b.closed = true
	info, err := stableDirectoryInfo(b.staging)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect case staging directory before cleanup: %w", err)
	}
	if b.stagingInfo == nil || !os.SameFile(b.stagingInfo, info) {
		return errors.New("refuse to remove replaced case staging directory")
	}
	return os.RemoveAll(b.staging)
}

func (b *Builder) validateStagingIdentity() error {
	info, err := stableDirectoryInfo(b.staging)
	if err != nil {
		return fmt.Errorf("inspect case staging directory: %w", err)
	}
	if b.stagingInfo == nil || !os.SameFile(b.stagingInfo, info) {
		return errors.New("case staging directory identity changed")
	}
	return nil
}

// stableDirectoryInfo returns identity information captured from an open
// directory handle. On Windows, os.Lstat defers loading the file ID until
// os.SameFile is called; retaining that lazy FileInfo would let a replacement
// at the same path be mistaken for the original directory. File.Stat binds the
// identity to the opened handle on every supported platform.
func stableDirectoryInfo(path string) (os.FileInfo, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !linkInfo.IsDir() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("case staging path is not a directory")
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || !os.SameFile(linkInfo, info) {
		return nil, errors.New("case staging directory identity changed while inspecting it")
	}
	return info, nil
}

// BuildManifest returns sorted GNU-style SHA-256 entries for all regular files
// except the manifest itself. Symlinks and non-regular entries are rejected.
func BuildManifest(ctx context.Context, dir string) ([]byte, error) {
	return buildManifestWithLimits(ctx, dir, defaultManifestTreeLimits)
}

func buildManifestWithLimits(ctx context.Context, dir string, limits manifestTreeLimits) ([]byte, error) {
	if limits.maxEntries == 0 || limits.maxDepth < 1 || limits.maxFileBytes == 0 || limits.maxAggregateByte == 0 {
		return nil, errors.New("invalid case manifest traversal limits")
	}
	type plannedFile struct {
		name string
		size uint64
	}
	var files []plannedFile
	var entries, aggregateBytes uint64
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
		entries++
		if entries > limits.maxEntries {
			return fmt.Errorf("case tree exceeds %d entries", limits.maxEntries)
		}
		if depth := relativePathDepth(relative); depth > limits.maxDepth {
			return fmt.Errorf("case path %q exceeds depth limit %d", filepath.ToSlash(relative), limits.maxDepth)
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
		if info.Size() < 0 || uint64(info.Size()) > limits.maxFileBytes {
			return fmt.Errorf("case file %q exceeds per-file limit %d", filepath.ToSlash(relative), limits.maxFileBytes)
		}
		fileBytes := uint64(info.Size())
		if fileBytes > limits.maxAggregateByte || aggregateBytes > limits.maxAggregateByte-fileBytes {
			return fmt.Errorf("case tree exceeds aggregate byte limit %d", limits.maxAggregateByte)
		}
		aggregateBytes += fileBytes
		relative = filepath.ToSlash(relative)
		if relative == "manifest.sha256" {
			return nil
		}
		if !validRelative(relative) {
			return fmt.Errorf("unsafe manifest path %q", relative)
		}
		files = append(files, plannedFile{name: relative, size: fileBytes})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("enumerate case files: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	var output strings.Builder
	for _, file := range files {
		digest, err := hashFileAtExpectedSize(ctx, filepath.Join(dir, filepath.FromSlash(file.name)), file.size)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&output, "%s  %s\n", digest, file.name)
	}
	return []byte(output.String()), nil
}

func relativePathDepth(relative string) int {
	clean := filepath.Clean(relative)
	if clean == "." {
		return 0
	}
	return strings.Count(clean, string(filepath.Separator)) + 1
}

// VerifyManifest detects changed, missing, and unmanifested files while
// preserving the legacy error-only API. Call VerifyCase when compatibility
// notices or the selected case contract are needed.
func VerifyManifest(ctx context.Context, dir string) error {
	_, err := VerifyCase(ctx, dir)
	return err
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

func hashFileAtExpectedSize(ctx context.Context, path string, expected uint64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open case file for bounded hashing: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 128*1024)
	var observed uint64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		remaining := expected + 1 - observed
		readSize := len(buffer)
		if remaining < uint64(readSize) {
			readSize = int(remaining)
		}
		n, readErr := f.Read(buffer[:readSize])
		if n > 0 {
			observed += uint64(n)
			if observed > expected {
				return "", fmt.Errorf("case file %q grew during bounded manifest hashing", path)
			}
			_, _ = h.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("hash bounded case file: %w", readErr)
		}
	}
	if observed != expected {
		return "", fmt.Errorf("case file %q changed size during bounded manifest hashing", path)
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
