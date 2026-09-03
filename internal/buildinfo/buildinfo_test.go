package buildinfo

import (
	"runtime/debug"
	"strings"
	"testing"
)

const (
	testRevision = "cf8fc95cd47af03b9d43a534103f0531107b96f6"
	testPseudo   = "v0.1.2-0.20260903021538-cf8fc95cd47a"
)

func buildWith(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main:     debug.Module{Path: "github.com/torjan0/cirewind", Version: version},
		Settings: settings,
	}
}

func setting(key, value string) debug.BuildSetting {
	return debug.BuildSetting{Key: key, Value: value}
}

func TestResolveMatrix(t *testing.T) {
	t.Parallel()
	releaseStamp := "cirewind-release-stamp:v1|0.2.0|" + testRevision + "|2026-01-01T00:00:00Z"
	tests := []struct {
		name    string
		version string
		commit  string
		date    string
		stamp   string
		build   *debug.BuildInfo
		ok      bool
		want    Info
	}{
		{
			name:    "linker stamps stay authoritative over module data",
			version: "0.2.0", commit: testRevision, date: "2026-01-01T00:00:00Z", stamp: releaseStamp,
			build: buildWith("v9.9.9", setting("vcs.revision", strings.Repeat("a", 40)), setting("vcs.modified", "true")),
			ok:    true,
			want:  Info{Version: "0.2.0", Commit: testRevision, Date: "2026-01-01T00:00:00Z"},
		},
		{
			name:    "release stamp alone still disables the fallback",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: releaseStamp,
			build: buildWith("v0.2.0"),
			ok:    true,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "versioned go install reports the module version and no invented commit",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("v0.2.0"),
			ok:    true,
			want:  Info{Version: "0.2.0", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "prerelease module version is reported verbatim",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("v0.2.0-rc.1"),
			ok:    true,
			want:  Info{Version: "0.2.0-rc.1", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "pseudo-version install keeps the pseudo-version and unknown commit",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith(testPseudo),
			ok:    true,
			want:  Info{Version: testPseudo[1:], Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "checkout build reports the embedded revision without a build time",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith(testPseudo, setting("vcs", "git"), setting("vcs.revision", testRevision), setting("vcs.time", "2026-09-03T02:15:38Z"), setting("vcs.modified", "false")),
			ok:    true,
			want:  Info{Version: testPseudo[1:], Commit: testRevision, Date: "unknown"},
		},
		{
			name:    "toolchain dirty marker is preserved once",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith(testPseudo+"+dirty", setting("vcs.revision", testRevision), setting("vcs.modified", "true")),
			ok:    true,
			want:  Info{Version: testPseudo[1:] + "+dirty", Commit: testRevision, Date: "unknown"},
		},
		{
			name:    "development placeholder with a modified worktree is marked dirty",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("(devel)", setting("vcs.revision", testRevision), setting("vcs.modified", "true")),
			ok:    true,
			want:  Info{Version: "dev+dirty", Commit: testRevision, Date: "unknown"},
		},
		{
			name:    "development placeholder without VCS stays dev and unknown",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("(devel)"),
			ok:    true,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "absent build information keeps the compiled defaults",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: nil,
			ok:    false,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "hostile module version and revision are not reported",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("v0.2.0\r\nX-Injected: yes", setting("vcs.revision", "../etc/passwd"), setting("vcs.modified", "maybe")),
			ok:    true,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "overlong module version and uppercase revision are not reported",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("v"+strings.Repeat("9", 200), setting("vcs.revision", strings.ToUpper(testRevision))),
			ok:    true,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "non-version placeholder and short revision are not reported",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("main", setting("vcs.revision", "abc")),
			ok:    true,
			want:  Info{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
		{
			name:    "build flags and paths are never consulted",
			version: defaultVersion, commit: defaultCommit, date: defaultDate, stamp: defaultReleaseStamp,
			build: buildWith("v0.2.0", setting("-ldflags", "-X synthetic=/home/synthetic-user/secret"), setting("GOFLAGS", "-mod=vendor"), setting("vcs.time", "2026-09-03T02:15:38Z")),
			ok:    true,
			want:  Info{Version: "0.2.0", Commit: "unknown", Date: "unknown"},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolve(tc.version, tc.commit, tc.date, tc.stamp, tc.build, tc.ok)
			if got != tc.want {
				t.Fatalf("resolve() = %+v, want %+v", got, tc.want)
			}
			for _, value := range []string{got.Version, got.Commit, got.Date} {
				if strings.ContainsAny(value, " \t\r\n\x00/\\") {
					t.Fatalf("resolved value %q is not a safe token", value)
				}
			}
			if agent := userAgentFor(got); !strings.HasPrefix(agent, "cirewind/") || strings.ContainsAny(agent, " \t\r\n") {
				t.Fatalf("user agent %q is not header safe", agent)
			}
		})
	}
}

func TestCurrentIsStableAndMatchesUserAgent(t *testing.T) {
	t.Parallel()
	first := Current()
	second := Current()
	if first != second {
		t.Fatalf("Current() changed between calls: %+v then %+v", first, second)
	}
	// Test binaries are built without VCS stamping and carry the "(devel)"
	// module version, so the unstamped defaults must survive resolution.
	if first.Version != "dev" || first.Commit != "unknown" || first.Date != "unknown" {
		t.Fatalf("test binary resolved to %+v, want unstamped defaults", first)
	}
	if UserAgent() != "cirewind/"+first.Version {
		t.Fatalf("UserAgent() = %q does not follow the resolved version %q", UserAgent(), first.Version)
	}
}
