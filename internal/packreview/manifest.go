package packreview

import (
	"bytes"
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
)

const (
	CandidateManifestName = "candidate-content-manifest.sha256"
	FixtureManifestName   = "manifest.sha256"
	ReviewManifestName    = "review-record-manifest.sha256"
	maxReviewFiles        = 2000
	maxReviewEntries      = 4000
	maxReviewDepth        = 16
	maxReviewFileBytes    = int64(64 << 20)
	maxReviewTotalBytes   = int64(256 << 20)
)

type manifestEntry struct {
	Path   string
	SHA256 string
}

var candidateFixedFiles = map[string]struct{}{
	"claims.json": {}, "conflicts.json": {}, "expected-findings.json": {},
	"pack.yaml": {}, "packet.json": {}, "review-policy.json": {}, "sources.json": {}, "validation.json": {},
	"fixtures/manifest.sha256": {},
}

// BuildCandidateManifest deterministically hashes every allowlisted immutable
// candidate file except the manifest itself and atomically writes the result.
func BuildCandidateManifest(ctx context.Context, candidateContent, output string) ([]byte, error) {
	root, err := safeRoot(candidateContent)
	if err != nil {
		return nil, err
	}
	wantOutput := filepath.Join(root, CandidateManifestName)
	if !sameCleanPath(output, wantOutput) {
		return nil, &ValidationError{Problems: []Problem{{Code: "MANIFEST_PATH", Path: output, Message: "candidate manifest output must be inside candidate-content with the fixed filename"}}}
	}
	entries, err := scanTree(ctx, root, func(name string) bool { return name == CandidateManifestName }, validateCandidateDirectory, validateCandidateEntry)
	if err != nil {
		return nil, err
	}
	data := encodeManifest(entries)
	if err := writeAtomicRegular(wantOutput, data, 0o600); err != nil {
		return nil, fmt.Errorf("write candidate manifest: %w", err)
	}
	return data, nil
}

func BuildFixtureManifest(ctx context.Context, fixturesRoot, output string) ([]byte, error) {
	root, err := safeRoot(fixturesRoot)
	if err != nil {
		return nil, err
	}
	wantOutput := filepath.Join(root, FixtureManifestName)
	if !sameCleanPath(output, wantOutput) {
		return nil, &ValidationError{Problems: []Problem{{Code: "MANIFEST_PATH", Path: output, Message: "fixture manifest output must use fixtures/manifest.sha256"}}}
	}
	entries, err := scanTree(ctx, root, func(name string) bool { return name == FixtureManifestName }, validateFixtureDirectory, validateFixtureEntry)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, &ValidationError{Problems: []Problem{{Code: "EMPTY_FIXTURES", Path: root, Message: "fixture directory must contain material files"}}}
	}
	data := encodeManifest(entries)
	if err := writeAtomicRegular(wantOutput, data, 0o600); err != nil {
		return nil, fmt.Errorf("write fixture manifest: %w", err)
	}
	return data, nil
}

func VerifyCandidateManifest(ctx context.Context, candidateContent string) ([]byte, string, error) {
	root, err := safeRoot(candidateContent)
	if err != nil {
		return nil, "", err
	}
	manifestPath := filepath.Join(root, CandidateManifestName)
	data, err := readBoundedRegularContext(ctx, manifestPath, 4<<20)
	if err != nil {
		return nil, "", fmt.Errorf("read candidate manifest: %w", err)
	}
	expected, err := parseManifest(data, CandidateManifestName)
	if err != nil {
		return nil, "", err
	}
	actual, err := scanTree(ctx, root, func(name string) bool { return name == CandidateManifestName }, validateCandidateDirectory, validateCandidateEntry)
	if err != nil {
		return nil, "", err
	}
	if !manifestEntriesEqual(expected, actual) {
		return nil, "", &ValidationError{Problems: []Problem{{Code: "MANIFEST_MISMATCH", Path: manifestPath, Message: "candidate manifest does not match the exact allowlisted file set and hashes"}}}
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func VerifyFixtureManifest(ctx context.Context, fixturesRoot string) ([]byte, string, error) {
	root, err := safeRoot(fixturesRoot)
	if err != nil {
		return nil, "", err
	}
	manifestPath := filepath.Join(root, FixtureManifestName)
	data, err := readBoundedRegularContext(ctx, manifestPath, 4<<20)
	if err != nil {
		return nil, "", fmt.Errorf("read fixture manifest: %w", err)
	}
	expected, err := parseManifest(data, "fixtures/"+FixtureManifestName)
	if err != nil {
		return nil, "", err
	}
	actual, err := scanTree(ctx, root, func(name string) bool { return name == FixtureManifestName }, validateFixtureDirectory, validateFixtureEntry)
	if err != nil {
		return nil, "", err
	}
	if len(actual) == 0 || !manifestEntriesEqual(expected, actual) {
		return nil, "", &ValidationError{Problems: []Problem{{Code: "FIXTURE_MANIFEST_MISMATCH", Path: manifestPath, Message: "fixture manifest does not match the exact fixture file set and hashes"}}}
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func buildReviewManifest(ctx context.Context, reviewUnitRoot string) ([]byte, error) {
	root, err := safeRoot(reviewUnitRoot)
	if err != nil {
		return nil, err
	}
	entries, err := scanTree(ctx, root, func(name string) bool {
		return name == ReviewManifestName || name == CandidateManifestName || name == "candidate-content" || strings.HasPrefix(name, "candidate-content/")
	}, validateReviewRecordDirectory, validateReviewRecordEntry)
	if err != nil {
		return nil, err
	}
	if len(entries) < 3 {
		return nil, &ValidationError{Problems: []Problem{{Code: "REVIEW_RECORD_SET", Path: root, Message: "review record manifest requires approvals and promotion-record.json"}}}
	}
	return encodeManifest(entries), nil
}

func buildReviewManifestWithPromotion(ctx context.Context, reviewUnitRoot string, promotion []byte) ([]byte, error) {
	root, err := safeRoot(reviewUnitRoot)
	if err != nil {
		return nil, err
	}
	approvalsRoot := filepath.Join(root, "approvals")
	if err := ensureReviewDirectory(approvalsRoot); err != nil {
		return nil, err
	}
	entries, err := scanTree(ctx, approvalsRoot, func(string) bool { return false }, validateApprovalDirectory, func(name string, data []byte) error {
		parts := strings.Split(name, "/")
		if len(parts) != 2 || !stableIDRE.MatchString(parts[0]) || (parts[1] != "review.json" && parts[1] != "REVIEW.md") {
			return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_FILE", Path: name, Message: "approval tree must contain only REVIEW.md and review.json under safe review IDs"}}}
		}
		return rejectActiveOrSensitiveFixture(name, data)
	})
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Path = "approvals/" + entries[i].Path
	}
	digest := sha256.Sum256(promotion)
	entries = append(entries, manifestEntry{Path: "promotion-record.json", SHA256: hex.EncodeToString(digest[:])})
	platform, err := readBoundedRegularContext(ctx, filepath.Join(root, "platform-approvals.json"), maxReviewFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read platform approval snapshot: %w", err)
	}
	platformDigest := sha256.Sum256(platform)
	entries = append(entries, manifestEntry{Path: "platform-approvals.json", SHA256: hex.EncodeToString(platformDigest[:])})
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return encodeManifest(entries), nil
}

func verifyReviewManifest(ctx context.Context, reviewUnitRoot string) ([]byte, string, error) {
	root, err := safeRoot(reviewUnitRoot)
	if err != nil {
		return nil, "", err
	}
	data, err := readBoundedRegularContext(ctx, filepath.Join(root, ReviewManifestName), 4<<20)
	if err != nil {
		return nil, "", err
	}
	expected, err := parseManifest(data, ReviewManifestName)
	if err != nil {
		return nil, "", err
	}
	actualBytes, err := buildReviewManifest(ctx, root)
	if err != nil {
		return nil, "", err
	}
	actual, err := parseManifest(actualBytes, ReviewManifestName)
	if err != nil || !manifestEntriesEqual(expected, actual) {
		return nil, "", &ValidationError{Problems: []Problem{{Code: "REVIEW_MANIFEST_MISMATCH", Path: filepath.Join(root, ReviewManifestName), Message: "review-record manifest does not match exact approval/promotion files"}}}
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func scanTree(ctx context.Context, root string, exclude func(string) bool, validateDirectory func(string) error, validateFile func(string, []byte) error) ([]manifestEntry, error) {
	var entries []manifestEntry
	var infos []os.FileInfo
	caseFold := map[string]string{}
	var total int64
	entryCount := 0
	fileCount := 0
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if filePath == root {
			return nil
		}
		entryCount++
		if entryCount > maxReviewEntries {
			return &ValidationError{Problems: []Problem{{Code: "ENTRY_COUNT", Path: root, Message: "review path entry count exceeds 4000"}}}
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if err := validateManifestPath(name); err != nil {
			return err
		}
		if depth := strings.Count(name, "/") + 1; depth > maxReviewDepth {
			return &ValidationError{Problems: []Problem{{Code: "PATH_DEPTH", Path: name, Message: "review path exceeds maximum depth"}}}
		}
		folded := strings.ToLower(name)
		if first, ok := caseFold[folded]; ok && first != name {
			return &ValidationError{Problems: []Problem{{Code: "CASE_COLLISION", Path: name, Message: "path collides case-insensitively with " + first}}}
		}
		caseFold[folded] = name
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() && !info.IsDir() {
			return &ValidationError{Problems: []Problem{{Code: "NON_REGULAR_ENTRY", Path: name, Message: "only regular files and directories are allowed"}}}
		}
		if exclude(name) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			if validateDirectory != nil {
				if err := validateDirectory(name); err != nil {
					return err
				}
			}
			children, err := os.ReadDir(filePath)
			if err != nil {
				return err
			}
			if len(children) == 0 {
				return &ValidationError{Problems: []Problem{{Code: "EMPTY_DIRECTORY", Path: name, Message: "empty directories are forbidden because manifests cannot bind them"}}}
			}
			return nil
		}
		fileCount++
		if fileCount > maxReviewFiles {
			return &ValidationError{Problems: []Problem{{Code: "FILE_COUNT", Path: root, Message: "review file count exceeds 2000"}}}
		}
		if info.Size() < 0 || info.Size() > maxReviewFileBytes || total+info.Size() > maxReviewTotalBytes {
			return &ValidationError{Problems: []Problem{{Code: "FILE_SIZE", Path: name, Message: "review file size limits exceeded"}}}
		}
		for _, previous := range infos {
			if os.SameFile(previous, info) {
				return &ValidationError{Problems: []Problem{{Code: "HARD_LINK", Path: name, Message: "hard-linked review files are forbidden"}}}
			}
		}
		data, stableInfo, err := readStableRegularContext(ctx, filePath, info, maxReviewFileBytes)
		if err != nil {
			return err
		}
		if validateFile != nil {
			if err := validateFile(name, data); err != nil {
				return err
			}
		}
		total += int64(len(data))
		infos = append(infos, stableInfo)
		digest := sha256.Sum256(data)
		entries = append(entries, manifestEntry{Path: name, SHA256: hex.EncodeToString(digest[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func validateCandidateDirectory(name string) error {
	if name == "fixtures" || strings.HasPrefix(name, "fixtures/") {
		return nil
	}
	return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_CANDIDATE_DIRECTORY", Path: name, Message: "directory is outside the closed candidate-content layout"}}}
}

func validateFixtureDirectory(string) error { return nil }

func validateReviewRecordDirectory(name string) error {
	parts := strings.Split(name, "/")
	if name == "approvals" || len(parts) == 2 && parts[0] == "approvals" && stableIDRE.MatchString(parts[1]) && safeFilenameComponent(parts[1]) {
		return nil
	}
	return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_DIRECTORY", Path: name, Message: "directory is outside the closed review-record layout"}}}
}

func validateApprovalDirectory(name string) error {
	if !strings.Contains(name, "/") && stableIDRE.MatchString(name) && safeFilenameComponent(name) {
		return nil
	}
	return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_DIRECTORY", Path: name, Message: "approval directory must use one safe review ID"}}}
}

func validateCandidateEntry(name string, data []byte) error {
	if _, fixed := candidateFixedFiles[name]; fixed {
		return rejectActiveOrSensitiveFixture(name, data)
	}
	if !strings.HasPrefix(name, "fixtures/") {
		return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_CANDIDATE_FILE", Path: name, Message: "file is not in the closed candidate-content allowlist"}}}
	}
	return validateFixtureEntry(strings.TrimPrefix(name, "fixtures/"), data)
}

func validateFixtureEntry(name string, data []byte) error {
	if name == "" || name == FixtureManifestName {
		return nil
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".jsonl", ".yaml", ".yml", ".txt", ".log", ".sha256", ".md":
	default:
		return &ValidationError{Problems: []Problem{{Code: "FIXTURE_FORMAT", Path: name, Message: "fixture uses a non-allowlisted inert data extension"}}}
	}
	return rejectActiveOrSensitiveFixture(name, data)
}

func validateReviewRecordEntry(name string, data []byte) error {
	if name == "promotion-record.json" || name == "platform-approvals.json" {
		return rejectActiveOrSensitiveFixture(name, data)
	}
	parts := strings.Split(name, "/")
	if len(parts) == 3 && parts[0] == "approvals" && stableIDRE.MatchString(parts[1]) && (parts[2] == "review.json" || parts[2] == "REVIEW.md") {
		return rejectActiveOrSensitiveFixture(name, data)
	}
	return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_FILE", Path: name, Message: "file is not in the closed review-record allowlist"}}}
}

func rejectActiveOrSensitiveFixture(name string, data []byte) error {
	if bytes.IndexByte(data, 0) >= 0 || bytes.HasPrefix(data, []byte("#!")) || bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) || bytes.HasPrefix(data, []byte{'M', 'Z'}) {
		return &ValidationError{Problems: []Problem{{Code: "ACTIVE_FIXTURE", Path: name, Message: "fixture appears executable or binary"}}}
	}
	lower := bytes.ToLower(data)
	// gitleaks:allow -- these public marker fragments detect prohibited fixture content; they are not credentials.
	for _, marker := range [][]byte{
		[]byte("-----begin private key-----"),         //gitleaks:allow
		[]byte("-----begin rsa private key-----"),     //gitleaks:allow
		[]byte("-----begin ec private key-----"),      //gitleaks:allow
		[]byte("-----begin openssh private key-----"), //gitleaks:allow
		[]byte("ghp_"), []byte("gho_"), []byte("ghu_"), []byte("ghs_"), []byte("ghr_"), []byte("github_pat_"),
	} {
		if bytes.Contains(lower, marker) {
			return &ValidationError{Problems: []Problem{{Code: "SENSITIVE_FIXTURE", Path: name, Message: "fixture contains prohibited credential-like material"}}}
		}
	}
	return nil
}

func encodeManifest(entries []manifestEntry) []byte {
	var output bytes.Buffer
	for _, entry := range entries {
		fmt.Fprintf(&output, "%s  %s\n", entry.SHA256, entry.Path)
	}
	return output.Bytes()
}

func parseManifest(data []byte, manifestPath string) ([]manifestEntry, error) {
	if len(data) == 0 || len(data) > 4<<20 || !bytes.HasSuffix(data, []byte("\n")) || bytes.Contains(data, []byte("\r")) {
		return nil, &ValidationError{Problems: []Problem{{Code: "MANIFEST_FORMAT", Path: manifestPath, Message: "manifest must be non-empty canonical LF-terminated text"}}}
	}
	var entries []manifestEntry
	previous := ""
	err := scanLines(data, 8192, func(line string) error {
		if len(line) < 67 || line[64:66] != "  " {
			return &ValidationError{Problems: []Problem{{Code: "MANIFEST_LINE", Path: manifestPath, Message: "manifest line must use lowercase SHA-256, two spaces, and path"}}}
		}
		digest, name := line[:64], line[66:]
		if !sha256RE.MatchString(digest) {
			return &ValidationError{Problems: []Problem{{Code: "MANIFEST_HASH", Path: manifestPath, Message: "manifest hash is not lowercase SHA-256"}}}
		}
		if err := validateManifestPath(name); err != nil {
			return err
		}
		if name == manifestPath || filepath.Base(name) == CandidateManifestName || filepath.Base(name) == ReviewManifestName {
			return &ValidationError{Problems: []Problem{{Code: "MANIFEST_SELF_REFERENCE", Path: name, Message: "manifest may not include itself or another enclosing manifest"}}}
		}
		if previous >= name {
			return &ValidationError{Problems: []Problem{{Code: "MANIFEST_ORDER", Path: name, Message: "manifest paths must be strictly sorted and unique"}}}
		}
		previous = name
		entries = append(entries, manifestEntry{Path: name, SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func validateManifestPath(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))) != name {
		return &ValidationError{Problems: []Problem{{Code: "MANIFEST_PATH", Path: name, Message: "manifest path must be canonical, relative, and slash-separated"}}}
	}
	for _, component := range strings.Split(name, "/") {
		if !safeFilenameComponent(component) {
			return &ValidationError{Problems: []Problem{{Code: "MANIFEST_PATH", Path: name, Message: "manifest path contains an unsafe or reserved component"}}}
		}
	}
	return nil
}

func safeFilenameComponent(component string) bool {
	if component == "" || component == "." || component == ".." || len(component) > 120 || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
		return false
	}
	for _, char := range component {
		if char < 0x21 || char > 0x7e || strings.ContainsRune(`<>:"/\|?*`, char) {
			return false
		}
	}
	base := strings.ToUpper(component)
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return false
	}
	return true
}

func safeRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("review root is empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", &ValidationError{Problems: []Problem{{Code: "REVIEW_ROOT", Path: abs, Message: "review root must be a real directory, not a link"}}}
	}
	return filepath.Clean(abs), nil
}

func readStableRegularContext(ctx context.Context, path string, before os.FileInfo, limit int64) ([]byte, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, &ValidationError{Problems: []Problem{{Code: "FILE_REPLACED", Path: path, Message: "file identity changed while opening"}}}
	}
	data, readErr := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, limit+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit || after.Size() != int64(len(data)) || !os.SameFile(opened, after) {
		return nil, nil, &ValidationError{Problems: []Problem{{Code: "FILE_CHANGED", Path: path, Message: "file changed or exceeded limits while hashing"}}}
	}
	return data, after, nil
}

func readStableRegular(path string, before os.FileInfo, limit int64) ([]byte, os.FileInfo, error) {
	return readStableRegularContext(context.Background(), path, before, limit)
}

func readBoundedRegularContext(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, &ValidationError{Problems: []Problem{{Code: "REGULAR_FILE", Path: path, Message: "must be a regular file"}}}
	}
	data, _, err := readStableRegularContext(ctx, path, info, limit)
	return data, err
}

func readBoundedRegular(path string, limit int64) ([]byte, error) {
	return readBoundedRegularContext(context.Background(), path, limit)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func writeAtomicRegular(path string, data []byte, mode os.FileMode) error {
	if current, err := readBoundedRegular(path, int64(len(data))+1); err == nil && bytes.Equal(current, data) {
		return os.Chmod(path, mode)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		var validation *ValidationError
		if errors.As(err, &validation) {
			return err
		}
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".cirewind-packreview-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryName) }
	defer cleanup()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return nil
}

func manifestEntriesEqual(left, right []manifestEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameCleanPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}
