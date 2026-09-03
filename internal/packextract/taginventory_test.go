package packextract

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureListing(t *testing.T, refs ...string) []byte {
	t.Helper()
	entries := make([]map[string]any, 0, len(refs))
	for index, ref := range refs {
		sha := strings.Repeat(string(rune('a'+index%6)), 40)
		entries = append(entries, map[string]any{"ref": ref, "node_id": "x", "url": "https://api.example.test/" + ref, "object": map[string]any{"type": "commit", "sha": sha, "url": "https://api.example.test/o"}})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDeriveTrivy2026TagInventoryStripsPrefixAndAddsUnrestored(t *testing.T) {
	listing := fixtureListing(t, "refs/tags/v0.0.9", "refs/tags/v0.0.11", "refs/tags/v0.34.0", "refs/tags/0.35.0", "refs/tags/v0.35.0", "refs/tags/v0.36.0", "refs/tags/latest", "refs/tags/v1.0")
	got, err := DeriveTrivy2026TagInventory(listing, []string{"0.34.2", "0.0.10", "0.34.1"})
	if err != nil {
		t.Fatal(err)
	}
	wantOriginal := []string{"0.0.9", "0.0.10", "0.0.11", "0.34.0", "0.34.1", "0.34.2"}
	if strings.Join(got.OriginalTags, ",") != strings.Join(wantOriginal, ",") {
		t.Fatalf("original tags are %v, want %v", got.OriginalTags, wantOriginal)
	}
	if strings.Join(got.Unrestored, ",") != "0.0.10,0.34.1,0.34.2" {
		t.Fatalf("unrestored tags are %v", got.Unrestored)
	}
	wantSkipped := []string{"refs/tags/0.35.0", "refs/tags/latest", "refs/tags/v0.35.0", "refs/tags/v0.36.0", "refs/tags/v1.0"}
	if strings.Join(got.Skipped, ",") != strings.Join(wantSkipped, ",") {
		t.Fatalf("skipped refs are %v, want %v", got.Skipped, wantSkipped)
	}
	if got.Counts != (InventoryCounts{ListingRefs: 8, Restored: 3, Unrestored: 3, Skipped: 5, Original: 6}) {
		t.Fatalf("counts are wrong: %+v", got.Counts)
	}
	if got.Restored[0].Ref != "refs/tags/v0.0.9" || got.Restored[0].OriginalName != "0.0.9" || got.Restored[0].ObjectSHA != strings.Repeat("a", 40) {
		t.Fatalf("restored record is wrong: %+v", got.Restored[0])
	}
	if len(got.OutputSHA256) != 64 || got.FirstSafeTag != "0.35.0" || got.InputByteLength != len(listing) {
		t.Fatalf("provenance fields are wrong: %+v", got)
	}
	again, err := DeriveTrivy2026TagInventory(listing, []string{"0.0.10", "0.34.1", "0.34.2"})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := Canonical(got)
	second, _ := Canonical(again)
	if !bytes.Equal(first, second) {
		t.Fatal("the derivation depends on the order of the supplied unrestored names")
	}
}

func TestDeriveTrivy2026TagInventoryRejectsBadInput(t *testing.T) {
	good := fixtureListing(t, "refs/tags/v0.1.0")
	cases := map[string]struct {
		listing    []byte
		unrestored []string
	}{
		"not an array":         {[]byte(`{"ref":"x"}`), nil},
		"empty ref":            {[]byte(`[{"ref":"","object":{"type":"commit","sha":"` + strings.Repeat("a", 40) + `"}}]`), nil},
		"repeated ref":         {[]byte(`[{"ref":"refs/tags/v0.1.0","object":{"type":"commit","sha":"` + strings.Repeat("a", 40) + `"}},{"ref":"refs/tags/v0.1.0","object":{"type":"commit","sha":"` + strings.Repeat("b", 40) + `"}}]`), nil},
		"malformed object":     {[]byte(`[{"ref":"refs/tags/v0.1.0","object":{"type":"blob","sha":"zz"}}]`), nil},
		"unrestored not plain": {good, []string{"v0.2.0"}},
		"unrestored too new":   {good, []string{"0.35.0"}},
		"unrestored present":   {good, []string{"0.1.0"}},
	}
	for name, item := range cases {
		if _, err := DeriveTrivy2026TagInventory(item.listing, item.unrestored); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
