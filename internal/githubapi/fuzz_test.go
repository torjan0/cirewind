package githubapi

import (
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzResponseSanitizers(f *testing.F) {
	f.Add([]byte("safe\r\n\x1b[2J\u202e"))
	f.Add([]byte{0xff, 0xfe, '\n'})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			body = body[:64<<10]
		}
		const token = "CIREWIND_FUZZ_TOKEN_SENTINEL_4f88f850"
		withToken := append(append([]byte(nil), body...), []byte(token)...)
		first := sanitizeResponseMessage(withToken, token)
		second := sanitizeResponseMessage(withToken, token)
		if first != second || len(first) > maxDiagnosticBytes || !utf8.ValidString(first) {
			t.Fatalf("diagnostic violated determinism/limit/UTF-8: len=%d", len(first))
		}
		if strings.Contains(first, token) {
			t.Fatal("diagnostic retained authentication sentinel")
		}
		for _, r := range first {
			if r == '\x1b' || unicode.IsControl(r) || isBidiControl(r) {
				t.Fatalf("diagnostic retained control %U", r)
			}
		}
	})
}

func FuzzDecodeGitHubJSON(f *testing.F) {
	f.Add([]byte(`{"id":1,"run_attempt":2,"head_sha":"abc"}`), "application/json")
	f.Add([]byte(`{} trailing`), "application/vnd.github+json")
	f.Add([]byte{0xff}, "application/json")
	f.Fuzz(func(t *testing.T, body []byte, mediaType string) {
		if len(body) > 256<<10 {
			body = body[:256<<10]
		}
		if len(mediaType) > 256 {
			mediaType = mediaType[:256]
		}
		response := rawResponse{body: body, meta: ResponseMeta{StatusCode: 200, MediaType: mediaType}}
		var first, second WorkflowRun
		firstErr := decodeJSON(response, &first, "fuzz decode")
		secondErr := decodeJSON(response, &second, "fuzz decode")
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("JSON decoder acceptance is nondeterministic")
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatal("JSON decoder diagnostic is nondeterministic")
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("JSON decoder result is nondeterministic")
		}
	})
}

func TestDiagnosticByteCeilingDoesNotSplitRuneOrEscape(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"💥", "\x1b", "\u202e"} {
		got := sanitizeDiagnostic(strings.Repeat("a", maxDiagnosticBytes-1) + suffix)
		if len(got) > maxDiagnosticBytes || !utf8.ValidString(got) || got != strings.Repeat("a", maxDiagnosticBytes-1) {
			t.Fatalf("boundary diagnostic=%q len=%d", got[len(got)-min(8, len(got)):], len(got))
		}
	}
}
