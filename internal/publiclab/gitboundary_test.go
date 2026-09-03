package publiclab

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLocalGitBoundaryRunsResolvedGitWithoutEnvironmentRedirect(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	boundary, err := NewLocalGitBoundary(git)
	if err != nil {
		t.Fatal(err)
	}
	worktree := t.TempDir()
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "redirect.git"))
	t.Setenv("GIT_TRACE", "1")
	output, err := boundary.RunGit(context.Background(), worktree, "--version")
	if err != nil || !strings.HasPrefix(string(output), "git version ") || strings.Contains(string(output), "trace:") {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestSafeGitEnvironmentRemovesTLSAndHTTPTransportOverrides(t *testing.T) {
	input := []string{
		"PATH=/synthetic/bin",
		"GIT_SSL_NO_VERIFY=true",
		"GIT_SSL_CAINFO=/synthetic/ca.pem",
		"GIT_SSL_CAPATH=/synthetic/certs",
		"GIT_SSL_CERT=/synthetic/client.pem",
		"GIT_HTTP_PROXY_AUTHMETHOD=basic",
		"GIT_HTTP_USER_AGENT=hostile-agent",
		"GIT_PROTOCOL=version=0",
		"GIT_TRACE2_EVENT=/synthetic/trace.json",
		"git_trace2_performance=/synthetic/performance.json",
		"git_ssl_no_verify=true",
		"git_config_count=1",
		"Git_Http_Proxy_AuthMethod=basic",
	}
	got := safeGitEnvironment(input)
	joined := "\n" + strings.Join(got, "\n") + "\n"
	for _, name := range []string{
		"GIT_SSL_NO_VERIFY", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_CERT",
		"GIT_HTTP_PROXY_AUTHMETHOD", "GIT_HTTP_USER_AGENT", "GIT_PROTOCOL",
		"GIT_TRACE2_EVENT", "git_trace2_performance",
		"git_ssl_no_verify", "git_config_count", "Git_Http_Proxy_AuthMethod",
	} {
		if strings.Contains(joined, "\n"+name+"=") {
			t.Fatalf("transport override %s survived environment isolation: %q", name, got)
		}
	}
	if !strings.Contains(joined, "\nPATH=/synthetic/bin\n") || !strings.Contains(joined, "\nGIT_CONFIG_NOSYSTEM=1\n") {
		t.Fatalf("safe baseline environment was not retained: %q", got)
	}
}

func TestAllowedGitInvocationRejectsOptionShapedRemotes(t *testing.T) {
	oldTarget := strings.Repeat("a", 40)
	newTarget := strings.Repeat("b", 40)
	readback := func(remote string) []string {
		return []string{"ls-remote", remote,
			"refs/heads/main",
			"refs/tags/fixture-a", "refs/tags/fixture-a^{}",
			"refs/tags/fixture-b", "refs/tags/fixture-b^{}",
			MutableV1Ref,
		}
	}
	for _, remote := range []string{"/synthetic/allowed-remote.git", "https://github.com/example/cirewind-lab.git", "git@github.com:example/cirewind-lab.git"} {
		if !allowedGitInvocation(readback(remote)) || !allowedGitInvocation(exactPushArguments(oldTarget, newTarget, remote)) {
			t.Fatalf("policy-shaped remote %q was rejected by the boundary allowlist", remote)
		}
	}
	for _, remote := range []string{"", "-", "--upload-pack=/synthetic/exploit", "--receive-pack=/synthetic/exploit", "-oProxyCommand=/synthetic/exploit"} {
		if allowedGitInvocation(readback(remote)) || allowedGitInvocation(exactPushArguments(oldTarget, newTarget, remote)) {
			t.Fatalf("option-shaped remote %q passed the boundary allowlist", remote)
		}
	}
}

func TestLocalGitBoundaryBoundsOutputAndDoesNotInterpretShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper is a POSIX shell script")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "synthetic-git")
	script := []byte("#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 70000 ]; do printf x; i=$((i + 1)); done\n")
	if err := os.WriteFile(helper, script, 0o700); err != nil {
		t.Fatal(err)
	}
	boundary, err := NewLocalGitBoundary(helper)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := boundary.RunGit(context.Background(), root, "--version"); err == nil || output != nil {
		t.Fatalf("oversized output=%d err=%v", len(output), err)
	}

	gitBoundary, err := NewLocalGitBoundary("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	sentinel := filepath.Join(root, "must-not-exist")
	_, _ = gitBoundary.RunGit(context.Background(), root, "; touch "+sentinel)
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("Git argument was interpreted by a shell")
	}
}

func TestLocalGitBoundaryIsolatesGlobalAndRepositoryURLRewrites(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bundle := filepath.Join(root, BundleFilename)
	if err := os.WriteFile(bundle, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	intended := filepath.Join(root, "intended.git")
	redirect := filepath.Join(root, "redirect.git")
	worktree := filepath.Join(root, "worktree")
	runGit(t, git, "clone", "--quiet", "--bare", bundle, intended)
	runGit(t, git, "clone", "--quiet", "--bare", bundle, redirect)
	runGit(t, git, "clone", "--quiet", intended, worktree)
	runGit(t, git, "--git-dir", redirect, "update-ref", MutableV1Ref, artifact.Model.Commits[2].ObjectID)
	runGit(t, git, "-C", worktree, "config", "--local", "url."+redirect+".insteadOf", intended)

	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	global := []byte("[url \"" + redirect + "\"]\n\tinsteadOf = " + intended + "\n")
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), global, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("GIT_EXEC_PATH", filepath.Join(root, "missing-exec-path"))

	boundary, err := NewLocalGitBoundary(git)
	if err != nil {
		t.Fatal(err)
	}
	output, err := boundary.RunGit(context.Background(), worktree, "ls-remote", intended,
		"refs/heads/main",
		"refs/tags/fixture-a", "refs/tags/fixture-a^{}",
		"refs/tags/fixture-b", "refs/tags/fixture-b^{}",
		MutableV1Ref,
	)
	if err != nil {
		t.Fatalf("isolated ls-remote failed: %v", err)
	}
	refs, err := parseRemoteRefs(output)
	if err != nil || refs[MutableV1Ref] != artifact.Model.Commits[1].ObjectID {
		t.Fatalf("URL rewrite escaped the isolated Git boundary: refs=%v err=%v", refs, err)
	}
}

func TestLocalGitBoundaryDisablesRepositoryFSMonitorExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses the POSIX touch utility as an inert execution sentinel")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	sentinel := filepath.Join(root, "fsmonitor-must-not-run")
	runGit(t, git, "init", "--quiet", "--initial-branch=main", worktree)
	runGit(t, git, "-C", worktree, "config", "user.name", "Synthetic Test")
	runGit(t, git, "-C", worktree, "config", "user.email", "synthetic@example.invalid")
	if err := os.WriteFile(filepath.Join(worktree, "tracked"), []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, git, "-C", worktree, "add", "tracked")
	runGit(t, git, "-C", worktree, "commit", "--quiet", "-m", "synthetic fixture")
	runGit(t, git, "-C", worktree, "config", "core.fsmonitor", "/usr/bin/touch "+sentinel)

	boundary, err := NewLocalGitBoundary(git)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.RunGit(context.Background(), worktree, "status", "--porcelain=v1", "--untracked-files=normal"); err == nil {
		t.Fatal("worktree-inspecting status operation was accepted")
	}
	if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
		t.Fatal("repository-local core.fsmonitor executed inside the Git boundary")
	}
}

func TestMoveV1DoesNotExecuteRepositoryAttributeFilters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX shell command as an inert execution sentinel")
	}
	fixture := newTagMoveFixture(t)
	sentinel := filepath.Join(fixture.root, "filter-must-not-run")
	filterCommand := "touch " + sentinel + "; cat"
	if err := os.WriteFile(filepath.Join(fixture.worktree, ".gitattributes"), []byte("README.md filter=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	infoAttributes := filepath.Join(fixture.worktree, ".git", "info", "attributes")
	if err := os.MkdirAll(filepath.Dir(infoAttributes), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoAttributes, []byte("* filter=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, fixture.git, "-C", fixture.worktree, "config", "filter.evil.clean", filterCommand)
	if err := os.WriteFile(filepath.Join(fixture.worktree, "README.md"), []byte("modified but irrelevant to exact-object push\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	boundary, err := NewLocalGitBoundary(fixture.git)
	if err != nil {
		t.Fatal(err)
	}
	result, err := MoveV1(context.Background(), boundary, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
	if err != nil || !result.Verified || fixture.remoteV1(t) != fixture.policy.CommitB {
		t.Fatalf("exact-object move failed: result=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
		t.Fatal("repository-controlled clean filter executed")
	}
}

func TestLocalGitBoundaryRejectsAlternateOrLinkedObjectStores(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	for _, test := range []struct {
		name string
		make func(*testing.T, string)
	}{
		{
			name: "alternate object store",
			make: func(t *testing.T, worktree string) {
				t.Helper()
				info := filepath.Join(worktree, ".git", "objects", "info")
				if err := os.MkdirAll(info, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(info, "alternates"), []byte(filepath.Join(t.TempDir(), "objects")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "linked object entry",
			make: func(t *testing.T, worktree string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(worktree, ".git", "objects", "synthetic-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			worktree := filepath.Join(t.TempDir(), "worktree")
			runGit(t, git, "init", "--quiet", "--initial-branch=main", worktree)
			test.make(t, worktree)
			boundary, err := NewLocalGitBoundary(git)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := boundary.RunGit(context.Background(), worktree,
				"ls-remote", filepath.Join(t.TempDir(), "remote.git"),
				"refs/heads/main", "refs/tags/fixture-a", "refs/tags/fixture-a^{}",
				"refs/tags/fixture-b", "refs/tags/fixture-b^{}", MutableV1Ref,
			); err == nil {
				t.Fatal("non-closed object directory was accepted for a network Git operation")
			}
		})
	}
}
