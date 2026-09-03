// Package buildinfo exposes release metadata injected by the build, with a
// bounded fallback to Go module build information for unstamped builds.
package buildinfo

import (
	"runtime/debug"
	"strings"
	"sync"
)

// Linker-injected release metadata. Release tooling sets every value through
// -X flags; the defaults below identify an unstamped build.
var (
	Version      = "dev"
	Commit       = "unknown"
	Date         = "unknown"
	ReleaseStamp = "cirewind-release-stamp:v1|dev|unknown|unknown"
)

const (
	defaultVersion      = "dev"
	defaultCommit       = "unknown"
	defaultDate         = "unknown"
	defaultReleaseStamp = "cirewind-release-stamp:v1|dev|unknown|unknown"
	developmentVersion  = "(devel)"
	dirtySuffix         = "+dirty"
	maxVersionLength    = 128
	maxRevisionLength   = 64
	minRevisionLength   = 7
)

// Info is the effective version report for this executable. Every field is a
// bounded token that is safe for a terminal line or an HTTP header value.
type Info struct {
	// Version is the release version, the Go module version without its "v"
	// prefix, or "dev".
	Version string
	// Commit is the release source revision, the VCS revision embedded by the Go
	// toolchain, or "unknown". A module version alone never implies a commit.
	Commit string
	// Date is the release build time or "unknown". Embedded VCS time is a commit
	// time, not a build time, and is deliberately not reported here.
	Date string
}

var (
	currentOnce sync.Once
	currentInfo Info
)

// Current resolves the effective build information once. Linker-injected
// release metadata is authoritative and is never mixed with module data. An
// unstamped build reports the Go module version and the embedded VCS revision
// only when the toolchain actually recorded them; otherwise the values stay
// "dev" and "unknown" rather than being invented.
func Current() Info {
	currentOnce.Do(func() {
		build, ok := debug.ReadBuildInfo()
		currentInfo = resolve(Version, Commit, Date, ReleaseStamp, build, ok)
	})
	return currentInfo
}

// UserAgent returns a stable, non-sensitive GitHub API user agent.
func UserAgent() string {
	// Keep the release stamp linked into every command binary. Release tooling
	// verifies it without executing a foreign-platform executable.
	if ReleaseStamp == "" {
		return "cirewind/invalid-build"
	}
	return userAgentFor(Current())
}

func userAgentFor(info Info) string {
	return "cirewind/" + info.Version
}

func resolve(stampedVersion, stampedCommit, stampedDate, stampedReleaseStamp string, build *debug.BuildInfo, ok bool) Info {
	stamped := Info{Version: stampedVersion, Commit: stampedCommit, Date: stampedDate}
	if stampedVersion != defaultVersion || stampedCommit != defaultCommit || stampedDate != defaultDate || stampedReleaseStamp != defaultReleaseStamp {
		// Any injected value identifies a deliberate release build whose
		// metadata was validated by release tooling.
		return stamped
	}
	if !ok || build == nil {
		return stamped
	}
	result := stamped
	if version := moduleVersion(build.Main.Version); version != "" {
		result.Version = version
	}
	revision, modified := vcsSettings(build.Settings)
	if revision != "" {
		result.Commit = revision
	}
	if modified && !strings.Contains(result.Version, "dirty") {
		result.Version += dirtySuffix
	}
	return result
}

// moduleVersion accepts only a toolchain-shaped module version such as
// "v0.2.0", "v0.2.1-rc.1", or a pseudo-version, and returns it without the
// "v" prefix. Development placeholders and anything outside the bounded token
// grammar yield an empty string so the caller keeps "dev".
func moduleVersion(value string) string {
	if value == "" || value == developmentVersion || !strings.HasPrefix(value, "v") {
		return ""
	}
	trimmed := value[1:]
	if len(trimmed) == 0 || len(trimmed) > maxVersionLength || trimmed[0] < '0' || trimmed[0] > '9' || !safeToken(trimmed) {
		return ""
	}
	return trimmed
}

// vcsSettings returns the embedded VCS revision when it is a bounded lowercase
// hexadecimal object ID, and whether the toolchain recorded a modified worktree.
// No other build setting is read, so flags and paths never reach the output.
func vcsSettings(settings []debug.BuildSetting) (string, bool) {
	revision := ""
	modified := false
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			if hexToken(setting.Value) {
				revision = setting.Value
			}
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	return revision, modified
}

func safeToken(value string) bool {
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9', character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z':
		case character == '.', character == '-', character == '+':
		default:
			return false
		}
	}
	return true
}

func hexToken(value string) bool {
	if len(value) < minRevisionLength || len(value) > maxRevisionLength {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
