// Package buildinfo exposes release metadata injected by the build.
package buildinfo

var (
	Version      = "dev"
	Commit       = "unknown"
	Date         = "unknown"
	ReleaseStamp = "cirewind-release-stamp:v1|dev|unknown|unknown"
)

// UserAgent returns a stable, non-sensitive GitHub API user agent.
func UserAgent() string {
	// Keep the release stamp linked into every command binary. Release tooling
	// verifies it without executing a foreign-platform executable.
	if ReleaseStamp == "" {
		return "cirewind/invalid-build"
	}
	return "cirewind/" + Version
}
