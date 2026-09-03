package publiclab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// LocalGitBoundary invokes one resolved Git executable without a shell. It
// disables repository hooks and environment overrides that could redirect Git
// away from the validated worktree. Authentication remains the operator's
// normal Git/SSH responsibility; command output is bounded and never included
// by MoveV1 in a returned diagnostic.
type LocalGitBoundary struct {
	executable string
}

// NewLocalGitBoundary resolves Git once so PATH cannot select a different
// executable between tag-protocol preconditions and mutation.
func NewLocalGitBoundary(executable string) (*LocalGitBoundary, error) {
	if executable == "" {
		executable = "git"
	}
	resolved, err := exec.LookPath(executable)
	if err != nil {
		return nil, errors.New("Git executable is unavailable")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, errors.New("Git executable path could not be fixed")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("Git executable is not a regular file")
	}
	return &LocalGitBoundary{executable: resolved}, nil
}

// RunGit implements GitCommandBoundary. Arguments are passed directly, never
// interpreted by a shell.
func (boundary *LocalGitBoundary) RunGit(ctx context.Context, worktree string, arguments ...string) ([]byte, error) {
	if boundary == nil || !filepath.IsAbs(boundary.executable) || !filepath.IsAbs(worktree) || filepath.Clean(worktree) != worktree {
		return nil, errors.New("Git command boundary is not initialized with absolute paths")
	}
	if len(arguments) == 0 || len(arguments) > 32 {
		return nil, errors.New("Git argument count is outside the accepted range")
	}
	for _, argument := range arguments {
		if len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 || strings.ContainsAny(argument, "\r\n") {
			return nil, errors.New("Git argument is malformed")
		}
	}
	if !allowedGitInvocation(arguments) {
		return nil, errors.New("Git operation is outside the public-lab allowlist")
	}
	// An empty core.hooksPath resolves hooks relative to the filesystem root
	// rather than disabling them; a null-device path can never contain a hook.
	gitArguments := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "core.untrackedCache=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=user",
	}
	environment := safeGitEnvironment(os.Environ())
	cleanup := func() {}
	if arguments[0] != "--version" {
		if _, err := validatedLocalObjectDirectory(worktree); err != nil {
			return nil, err
		}
	}
	if networkGitOperation(arguments[0]) {
		isolatedGitDir, objectDirectory, remove, err := isolatedNetworkGitDirectory(worktree)
		if err != nil {
			return nil, err
		}
		cleanup = remove
		gitArguments = append(gitArguments, "--git-dir="+isolatedGitDir)
		environment = append(environment, "GIT_OBJECT_DIRECTORY="+objectDirectory)
	} else {
		gitArguments = append(gitArguments, "-C", worktree)
	}
	defer cleanup()
	gitArguments = append(gitArguments, arguments...)
	command := exec.CommandContext(ctx, boundary.executable, gitArguments...)
	command.Env = environment
	output := &boundedCommandOutput{limit: maxGitCommandOutput}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.overflow {
		return nil, errors.New("Git command output exceeded the accepted bound")
	}
	return output.bytes(), err
}

func safeGitEnvironment(input []string) []string {
	blocked := map[string]struct{}{
		"GIT_DIR": {}, "GIT_WORK_TREE": {}, "GIT_INDEX_FILE": {},
		"GIT_COMMON_DIR": {}, "GIT_OBJECT_DIRECTORY": {}, "GIT_ALTERNATE_OBJECT_DIRECTORIES": {},
		"GIT_CONFIG_COUNT": {}, "GIT_CONFIG_PARAMETERS": {}, "GIT_CONFIG_SYSTEM": {}, "GIT_CONFIG_GLOBAL": {},
		"GIT_CONFIG_NOSYSTEM": {}, "GIT_SSH_COMMAND": {}, "GIT_PROXY_COMMAND": {},
		"GIT_SSH": {}, "GIT_SSH_VARIANT": {}, "GIT_EXEC_PATH": {},
		"GIT_ASKPASS": {}, "SSH_ASKPASS": {}, "GIT_PAGER": {}, "PAGER": {},
		"GIT_EDITOR": {}, "GIT_SEQUENCE_EDITOR": {}, "GIT_EXTERNAL_DIFF": {}, "GIT_DIFF_OPTS": {},
		"GIT_TRACE": {}, "GIT_TRACE_PACKET": {},
		"GIT_TRACE_CURL": {}, "GIT_CURL_VERBOSE": {},
		"GIT_NAMESPACE": {}, "GIT_REPLACE_REF_BASE": {}, "GIT_SHALLOW_FILE": {},
		"GIT_CEILING_DIRECTORIES": {}, "GIT_DISCOVERY_ACROSS_FILESYSTEM": {},
		"GIT_ALLOW_PROTOCOL": {}, "GIT_PROTOCOL": {}, "GIT_PROTOCOL_FROM_USER": {}, "GIT_ATTR_NOSYSTEM": {},
	}
	result := make([]string, 0, len(input)+8)
	for _, item := range input {
		name, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		canonicalName := strings.ToUpper(name)
		if _, denied := blocked[canonicalName]; denied || strings.HasPrefix(canonicalName, "GIT_CONFIG_KEY_") || strings.HasPrefix(canonicalName, "GIT_CONFIG_VALUE_") ||
			strings.HasPrefix(canonicalName, "GIT_SSL_") || strings.HasPrefix(canonicalName, "GIT_HTTP_") || strings.HasPrefix(canonicalName, "GIT_TRACE") {
			continue
		}
		result = append(result, item)
	}
	result = append(result,
		"LC_ALL=C", "LANG=C", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_PAGER=cat",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM="+os.DevNull, "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_ATTR_NOSYSTEM=1",
	)
	return result
}

func allowedGitInvocation(arguments []string) bool {
	if len(arguments) == 1 && arguments[0] == "--version" {
		return true
	}
	if len(arguments) == 3 && arguments[0] == "symbolic-ref" && arguments[1] == "--quiet" && arguments[2] == "HEAD" {
		return true
	}
	if len(arguments) == 3 && arguments[0] == "rev-parse" && arguments[1] == "--verify" &&
		(arguments[2] == "HEAD" || arguments[2] == "refs/heads/main" || arguments[2] == ObservationsRef) {
		return true
	}
	if len(arguments) == 3 && arguments[0] == "cat-file" && arguments[1] == "-t" && isSHA1(arguments[2]) {
		return true
	}
	if len(arguments) == 3 && arguments[0] == "cat-file" && arguments[1] == "-p" && validObservationObjectSpec(arguments[2]) {
		return true
	}
	if len(arguments) == 4 && arguments[0] == "merge-base" && arguments[1] == "--is-ancestor" && isSHA1(arguments[2]) && isSHA1(arguments[3]) {
		return true
	}
	if len(arguments) == 4 && arguments[0] == "remote" && arguments[1] == "get-url" && arguments[2] == "--all" && arguments[3] == tagRemoteName {
		return true
	}
	if len(arguments) == 5 && arguments[0] == "remote" && arguments[1] == "get-url" && arguments[2] == "--push" && arguments[3] == "--all" && arguments[4] == tagRemoteName {
		return true
	}
	if len(arguments) == 8 && arguments[0] == "ls-remote" && remoteArgumentShape(arguments[1]) &&
		arguments[2] == "refs/heads/main" && arguments[3] == "refs/tags/fixture-a" && arguments[4] == "refs/tags/fixture-a^{}" &&
		arguments[5] == "refs/tags/fixture-b" && arguments[6] == "refs/tags/fixture-b^{}" && arguments[7] == MutableV1Ref {
		return true
	}
	if len(arguments) == 6 && arguments[0] == "push" && arguments[1] == "--porcelain" && arguments[2] == "--no-verify" &&
		strings.HasPrefix(arguments[3], "--force-with-lease="+MutableV1Ref+":") && remoteArgumentShape(arguments[4]) {
		oldTarget := strings.TrimPrefix(arguments[3], "--force-with-lease="+MutableV1Ref+":")
		newTarget, ref, ok := strings.Cut(arguments[5], ":")
		return ok && isSHA1(oldTarget) && isSHA1(newTarget) && ref == MutableV1Ref
	}
	return false
}

// remoteArgumentShape rejects an empty or option-shaped remote argument so the
// boundary cannot be steered into --upload-pack, --receive-pack, or a similar
// transport option even if a caller bypassed policy-level remote validation.
func remoteArgumentShape(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-")
}

func validObservationObjectSpec(value string) bool {
	revision, path, ok := strings.Cut(value, ":")
	if !ok || !isSHA1(revision) || !strings.HasPrefix(path, "observations/") || !strings.HasSuffix(path, ".json") {
		return false
	}
	recordID := strings.TrimSuffix(strings.TrimPrefix(path, "observations/"), ".json")
	if len(recordID) < 1 || len(recordID) > 100 || strings.HasSuffix(recordID, ".") || windowsReservedName(recordID) {
		return false
	}
	for index, character := range recordID {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func networkGitOperation(operation string) bool {
	return operation == "ls-remote" || operation == "push"
}

// isolatedNetworkGitDirectory keeps URL rewrite, credential, include, proxy,
// and transport settings from the operator worktree out of ls-remote and push.
// The temporary repository has no refs or configurable remotes; it borrows only
// the already-reviewed object database needed for an object-ID refspec push.
func isolatedNetworkGitDirectory(worktree string) (string, string, func(), error) {
	objects, err := validatedLocalObjectDirectory(worktree)
	if err != nil {
		return "", "", func() {}, err
	}
	root, err := os.MkdirTemp("", "cirewind-public-lab-git-")
	if err != nil {
		return "", "", func() {}, errors.New("create isolated Git command directory")
	}
	remove := func() { _ = os.RemoveAll(root) }
	if err := os.Chmod(root, 0o700); err != nil {
		remove()
		return "", "", func() {}, errors.New("restrict isolated Git command directory")
	}
	for _, path := range []string{filepath.Join(root, "objects"), filepath.Join(root, "refs"), filepath.Join(root, "refs", "heads")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			remove()
			return "", "", func() {}, errors.New("initialize isolated Git command directory")
		}
	}
	if err := os.WriteFile(filepath.Join(root, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		remove()
		return "", "", func() {}, errors.New("initialize isolated Git HEAD")
	}
	config := []byte("[core]\n\trepositoryformatversion = 0\n\tbare = true\n")
	if err := os.WriteFile(filepath.Join(root, "config"), config, 0o600); err != nil {
		remove()
		return "", "", func() {}, errors.New("initialize isolated Git configuration")
	}
	return root, objects, remove, nil
}

func validatedLocalObjectDirectory(worktree string) (string, error) {
	gitDir := filepath.Join(worktree, ".git")
	for _, path := range []string{worktree, gitDir, filepath.Join(gitDir, "objects")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("tag-control worktree must use real worktree, .git, and object directories")
		}
	}
	for _, forbidden := range []string{filepath.Join(gitDir, "info", "grafts"), filepath.Join(gitDir, "shallow")} {
		if _, err := os.Lstat(forbidden); err == nil || !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("reviewed Git worktree uses grafted or shallow history")
		}
	}
	objects, err := filepath.Abs(filepath.Join(gitDir, "objects"))
	if err != nil || !filepath.IsAbs(objects) {
		return "", errors.New("resolve reviewed object directory")
	}
	if err := validateBorrowedObjectDirectory(objects); err != nil {
		return "", err
	}
	return objects, nil
}

func validateBorrowedObjectDirectory(objects string) error {
	entries := 0
	err := filepath.WalkDir(objects, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 16384 {
			return errors.New("reviewed Git object directory exceeds the accepted entry bound")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("reviewed Git object directory contains a link or special file")
		}
		if filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(objects, "info", "alternates")) {
			return errors.New("reviewed Git object directory uses an alternate object store")
		}
		return nil
	})
	if err != nil {
		return errors.New("reviewed Git object directory is not a closed regular-file tree")
	}
	return nil
}

type boundedCommandOutput struct {
	mu       sync.Mutex
	limit    int
	data     []byte
	overflow bool
}

func (output *boundedCommandOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.limit - len(output.data)
	if remaining > 0 {
		keep := len(data)
		if keep > remaining {
			keep = remaining
		}
		output.data = append(output.data, data[:keep]...)
	}
	if len(data) > remaining {
		output.overflow = true
	}
	return len(data), nil
}

func (output *boundedCommandOutput) bytes() []byte {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data...)
}
