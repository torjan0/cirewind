package packextract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// fixtureRows are synthetic digests; none is a real artifact hash.
var fixtureAssets = [][2]string{
	{strings.Repeat("a", 64), "trivy_0.69.4_Linux-64bit.tar.gz"},
	{strings.Repeat("b", 64), "trivy_0.69.4_macOS-ARM64.tar.gz"},
	{strings.Repeat("c", 64), "trivy_0.69.4_linux_amd64"},
}

var fixtureImages = [][2]string{
	{"sha256:" + strings.Repeat("d", 64), "`0.69.4`"},
	{"sha256:" + strings.Repeat("e", 64), "`0.69.4- linux/s390x`"},
	{"sha256:" + strings.Repeat("f", 64), "`0.69.5-linux/arm64`<br>"},
	{"sha256:" + strings.Repeat("a", 64), "`0.69.6`"},
}

func fixtureDescription(assets, images [][2]string, network []string, newline string) string {
	var b strings.Builder
	line := func(text string) { b.WriteString(text); b.WriteString(newline) }
	line("## Summary")
	line("")
	line("Synthetic advisory text.")
	line("")
	line("## Exposure Window")
	line("")
	line("| Component     | Start (UTC)            | End (UTC)         | Duration  |")
	line("| ------------- | ---------------------- | ----------------- | --------- |")
	line("| trivy v0.69.4 | 2026-03-19 18:22 [^1]  | 2026-03-19 ~21:42 | ~3 hours  |")
	line("| trivy-action  | 2026-03-19 ~17:43 [^2] | 2026-03-20 ~05:40 | ~12 hours |")
	line("")
	line("## Indicators of Compromise")
	line("")
	line("### Executable binaries")
	line("")
	line("| SHA256                                                             | Filename                            |")
	line("| ------------------------------------------------------------------ | ----------------------------------- |")
	for _, row := range assets {
		line(fmt.Sprintf("| `%s` | `%s` |", row[0], row[1]))
	}
	line("")
	line("### Container images (v0.69.4)")
	line("")
	line("| Digest                                                                    | Tag                      |")
	line("| ------------------------------------------------------------------------- | ------------------------ |")
	for _, row := range images {
		line(fmt.Sprintf("| `%s` | %s |", row[0], row[1]))
	}
	line("")
	line("### Network")
	line("C2/sinks:")
	for _, item := range network {
		line("- `" + item + "`")
	}
	line("")
	line("### GitHub Repositories")
	line("")
	line("Public repo with `tpcp-docs-` prefix.")
	return b.String()
}

func fixtureInput(t *testing.T, description string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"ghsa_id": "GHSA-xxxx-xxxx-xxxx", "description": description})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestExtractTrivy2026ParsesTablesAndRecordsNormalizations(t *testing.T) {
	input := fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, []string{"scan.example.invalid.test", "192.0.2.10"}, "\r\n"))
	got, err := ExtractTrivy2026(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Windows) != 2 || got.Windows[0].Start != "2026-03-19 18:22 [^1]" || got.Windows[1].End != "2026-03-20 ~05:40" {
		t.Fatalf("window rows are wrong: %+v", got.Windows)
	}
	if len(got.Digests) != 7 {
		t.Fatalf("want 7 digests, got %d", len(got.Digests))
	}
	for index := 1; index < len(got.Digests); index++ {
		prev, cur := got.Digests[index-1], got.Digests[index]
		if prev.Subject > cur.Subject || (prev.Subject == cur.Subject && prev.Digest >= cur.Digest) {
			t.Fatalf("digests are not sorted by subject then digest at %d", index)
		}
	}
	if _, ok := got.FindDigest("oci-manifest", strings.Repeat("A", 64)); !ok {
		t.Fatal("image digest shared with an asset must be found under its own namespace")
	}
	if _, ok := got.FindDigest("workflow-artifact", strings.Repeat("a", 64)); ok {
		t.Fatal("a digest must never be found under a namespace the table did not denote")
	}
	asset, ok := got.FindDigest("release-asset", strings.Repeat("a", 64))
	if !ok || asset.Label != "trivy_0.69.4_Linux-64bit.tar.gz" || asset.Algorithm != "sha256" || asset.Row != 1 {
		t.Fatalf("asset record is wrong: %+v", asset)
	}
	spaced, _ := got.FindDigest("oci-manifest", strings.Repeat("e", 64))
	broken, _ := got.FindDigest("oci-manifest", strings.Repeat("f", 64))
	if spaced.Label != "0.69.4-linux/s390x" || broken.Label != "0.69.5-linux/arm64" {
		t.Fatalf("labels were not normalized: %q %q", spaced.Label, broken.Label)
	}
	if spaced.OriginalLabelCell != "`0.69.4- linux/s390x`" || broken.OriginalLabelCell != "`0.69.5-linux/arm64`<br>" {
		t.Fatalf("original cells were not retained: %q %q", spaced.OriginalLabelCell, broken.OriginalLabelCell)
	}
	rules := make(map[string]int)
	for _, item := range got.Normalizations {
		rules[item.Rule]++
	}
	if rules["remove-whitespace"] != 1 || rules["drop-trailing-line-break-tag"] != 1 || len(got.Normalizations) != 2 {
		t.Fatalf("normalizations are wrong: %+v", got.Normalizations)
	}
	if len(got.Network.Domains) != 1 || got.Network.Domains[0] != "scan.example.invalid.test" || len(got.Network.IPAddresses) != 1 || got.Network.IPAddresses[0] != "192.0.2.10" {
		t.Fatalf("network record is wrong: %+v", got.Network)
	}
	if got.InputByteLength != len(input) || len(got.InputSHA256) != 64 || len(got.OutputSHA256) != 64 || got.Extractor != Trivy2026Extractor {
		t.Fatalf("provenance fields are wrong: %+v", got)
	}
	if ok, err := VerifyExtraction(got); err != nil || !ok {
		t.Fatalf("sealed record must verify: %v %v", ok, err)
	}
	got.Digests[0].Label = "tampered"
	if ok, _ := VerifyExtraction(got); ok {
		t.Fatal("a tampered record must not verify")
	}
}

func TestExtractTrivy2026IsDeterministicAcrossRunsAndLineEndings(t *testing.T) {
	crlf := fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, []string{"192.0.2.10"}, "\r\n"))
	lf := fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, []string{"192.0.2.10"}, "\n"))
	first, err := ExtractTrivy2026(crlf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExtractTrivy2026(crlf)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := Canonical(first)
	secondBytes, _ := Canonical(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("two extractions of the same bytes differ")
	}
	third, err := ExtractTrivy2026(lf)
	if err != nil {
		t.Fatal(err)
	}
	if third.InputSHA256 == first.InputSHA256 {
		t.Fatal("different input bytes must carry different input hashes")
	}
	third.InputSHA256, third.InputByteLength = first.InputSHA256, first.InputByteLength
	if err := seal(third); err != nil {
		t.Fatal(err)
	}
	thirdBytes, _ := Canonical(third)
	if !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatal("line endings must not change the extracted records")
	}
}

func TestExtractTrivy2026RowOrderDoesNotChangeRecordsExceptRowNumbers(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	assets := append([][2]string{}, fixtureAssets...)
	base, err := ExtractTrivy2026(fixtureInput(t, fixtureDescription(assets, fixtureImages, []string{"192.0.2.10"}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	for trial := 0; trial < 20; trial++ {
		rng.Shuffle(len(assets), func(i, j int) { assets[i], assets[j] = assets[j], assets[i] })
		got, err := ExtractTrivy2026(fixtureInput(t, fixtureDescription(assets, fixtureImages, []string{"192.0.2.10"}, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		for index := range got.Digests {
			want, have := base.Digests[index], got.Digests[index]
			want.Row, have.Row = 0, 0
			if want != have {
				t.Fatalf("trial %d: record %d differs: %+v vs %+v", trial, index, want, have)
			}
		}
	}
}

func TestExtractTrivy2026RejectsMalformedInput(t *testing.T) {
	network := []string{"192.0.2.10"}
	cases := map[string][]byte{
		"not json":             []byte("not json"),
		"no description":       []byte(`{"ghsa_id":"x"}`),
		"missing section":      fixtureInput(t, strings.Replace(fixtureDescription(fixtureAssets, fixtureImages, network, "\n"), "### Network", "### Networks", 1)),
		"duplicate heading":    fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, network, "\n")+"\n### Network\n\n- `198.51.100.1`\n"),
		"altered header":       fixtureInput(t, strings.Replace(fixtureDescription(fixtureAssets, fixtureImages, network, "\n"), "| SHA256 ", "| SHA-256 ", 1)),
		"duplicate digest":     fixtureInput(t, fixtureDescription(append(append([][2]string{}, fixtureAssets...), [2]string{strings.Repeat("a", 64), "other.tar.gz"}), fixtureImages, network, "\n")),
		"duplicate label":      fixtureInput(t, fixtureDescription(append(append([][2]string{}, fixtureAssets...), [2]string{strings.Repeat("9", 64), "trivy_0.69.4_linux_amd64"}), fixtureImages, network, "\n")),
		"short digest":         fixtureInput(t, fixtureDescription([][2]string{{strings.Repeat("a", 63), "x.tar.gz"}}, fixtureImages, network, "\n")),
		"non hex digest":       fixtureInput(t, fixtureDescription([][2]string{{strings.Repeat("g", 64), "x.tar.gz"}}, fixtureImages, network, "\n")),
		"asset with prefix":    fixtureInput(t, fixtureDescription([][2]string{{"sha256:" + strings.Repeat("a", 64), "x.tar.gz"}}, fixtureImages, network, "\n")),
		"image without prefix": fixtureInput(t, fixtureDescription(fixtureAssets, [][2]string{{strings.Repeat("d", 64), "`0.69.4`"}}, network, "\n")),
		"unquoted digest":      fixtureInput(t, strings.Replace(fixtureDescription(fixtureAssets, fixtureImages, network, "\n"), "| `"+strings.Repeat("a", 64)+"`", "| "+strings.Repeat("a", 64), 1)),
		"unquoted label":       fixtureInput(t, fixtureDescription(fixtureAssets, [][2]string{{"sha256:" + strings.Repeat("d", 64), "0.69.4"}}, network, "\n")),
		"path in asset name":   fixtureInput(t, fixtureDescription([][2]string{{strings.Repeat("a", 64), "../x.tar.gz"}}, fixtureImages, network, "\n")),
		"unknown network":      fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, []string{"http://example.test/path"}, "\n")),
		"empty network":        fixtureInput(t, fixtureDescription(fixtureAssets, fixtureImages, nil, "\n")),
		"prose in network":     fixtureInput(t, strings.Replace(fixtureDescription(fixtureAssets, fixtureImages, network, "\n"), "C2/sinks:", "Sinks observed:", 1)),
		"ragged row":           fixtureInput(t, strings.Replace(fixtureDescription(fixtureAssets, fixtureImages, network, "\n"), "| `trivy_0.69.4_linux_amd64` |", "|", 1)),
	}
	for name, input := range cases {
		if _, err := ExtractTrivy2026(input); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExtractTrivy2026EnforcesLimits(t *testing.T) {
	many := make([][2]string, 0, maxTableRows+1)
	for index := 0; index <= maxTableRows; index++ {
		many = append(many, [2]string{fmt.Sprintf("%064x", index+1), fmt.Sprintf("asset-%d.tar.gz", index)})
	}
	if _, err := ExtractTrivy2026(fixtureInput(t, fixtureDescription(many, fixtureImages, []string{"192.0.2.10"}, "\n"))); err == nil {
		t.Fatal("a table beyond the row limit was accepted")
	}
	if _, err := ExtractTrivy2026(fixtureInput(t, strings.Repeat("x\n", maxLines+1))); err == nil {
		t.Fatal("a description beyond the line limit was accepted")
	}
	if _, err := ExtractTrivy2026(bytes.Repeat([]byte(" "), maxInputBytes+1)); err == nil {
		t.Fatal("an oversize input was accepted")
	}
}
