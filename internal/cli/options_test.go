package cli

import (
	"io"
	"testing"
)

func TestInvestigateOptions(t *testing.T) {
	got, err := parseInvestigate([]string{"--repo", "acme/a", "--repo", "acme/b", "--incident", "pack.yaml", "--from", "2026-01-01T00:00:00Z", "--to", "2026-01-02T00:00:00Z", "--out", "case"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets.Repositories) != 2 || got.Concurrent != 4 {
		t.Fatalf("unexpected options: %#v", got)
	}
}

func TestInvestigateRejectsAmbiguousScopeAndNonUTC(t *testing.T) {
	for _, args := range [][]string{
		{"--org", "acme", "--repo", "acme/a", "--incident", "x", "--from", "2026-01-01T00:00:00Z", "--to", "2026-01-02T00:00:00Z", "--out", "case"},
		{"--org", "acme", "--incident", "x", "--from", "2026-01-01T00:00:00-08:00", "--to", "2026-01-02T00:00:00Z", "--out", "case"},
	} {
		if _, err := parseInvestigate(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
}

func TestArchiveFixtureIsOfflineAndExclusive(t *testing.T) {
	got, err := parseArchive([]string{"--import-fixture", "fixture.json", "--store", "archive.db"}, io.Discard)
	if err != nil || got.ImportFixture == "" {
		t.Fatalf("fixture options: %#v, %v", got, err)
	}
	if _, err := parseArchive([]string{"--import-fixture", "fixture.json", "--org", "acme", "--store", "archive.db"}, io.Discard); err == nil {
		t.Fatal("fixture import accepted network scope")
	}
}

func TestReplayRequiresAllFiles(t *testing.T) {
	if _, err := parseReplay([]string{"--archive", "a.db"}, io.Discard); err == nil {
		t.Fatal("accepted incomplete replay")
	}
}

func TestReplayRawCopyIsExplicit(t *testing.T) {
	without, err := parseReplay([]string{"--archive", "a.db", "--incident", "pack.yaml", "--out", "case"}, io.Discard)
	if err != nil || without.RawLogs {
		t.Fatalf("default replay raw option=%v err=%v", without.RawLogs, err)
	}
	with, err := parseReplay([]string{"--archive", "a.db", "--incident", "pack.yaml", "--out", "case", "--raw-logs"}, io.Discard)
	if err != nil || !with.RawLogs {
		t.Fatalf("opted-in replay raw option=%v err=%v", with.RawLogs, err)
	}
}
