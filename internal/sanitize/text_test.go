package sanitize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestTerminalRemovesActiveControls(t *testing.T) {
	t.Parallel()
	input := "safe\x1b[2J\x1b]8;;https://evil.invalid\aevil\x1b]8;;\a\r\nnext\u202e"
	if got, want := Terminal(input, 1024), "safeevil next"; got != want {
		t.Fatalf("Terminal() = %q, want %q", got, want)
	}
}

func TestCSVCell(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"=1+1", " +cmd", "\t@SUM(A1)", "\u202e-2"} {
		if got := CSVCell(input); len(got) == 0 || got[0] != '\'' {
			t.Errorf("CSVCell(%q) = %q", input, got)
		}
	}
	if got := CSVCell("normal"); got != "normal" {
		t.Fatalf("CSVCell(normal) = %q", got)
	}
}

func TestTerminalHonorsExactByteLimitForInvalidUTF8(t *testing.T) {
	t.Parallel()
	input := string([]byte{0xff})
	for limit := 1; limit <= 3; limit++ {
		got := Terminal(input, limit)
		if len(got) > limit || !utf8.ValidString(got) {
			t.Fatalf("Terminal(invalid,%d)=%q (%d bytes)", limit, got, len(got))
		}
	}
}

func FuzzTerminalAndCSVCell(f *testing.F) {
	f.Add([]byte("safe\x1b[2J\r\nnext\u202e"), 64)
	f.Add([]byte{0xff, '=', '1', '+', '1'}, 3)
	f.Fuzz(func(t *testing.T, input []byte, limit int) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		if limit < 0 {
			limit = -limit
		}
		limit %= 4097
		value := string(input)
		first := Terminal(value, limit)
		second := Terminal(value, limit)
		if first != second || len(first) > limit || !utf8.ValidString(first) {
			t.Fatalf("terminal sanitizer violated determinism/limit/UTF-8: len=%d limit=%d", len(first), limit)
		}
		for _, r := range first {
			if r == '\x1b' || unicode.IsControl(r) || isUnsafeRune(r) {
				t.Fatalf("terminal sanitizer retained control %U", r)
			}
		}
		csvFirst, csvSecond := CSVCell(value), CSVCell(value)
		if csvFirst != csvSecond || (!strings.HasPrefix(csvFirst, "'") && csvFirst != value) {
			t.Fatal("CSV sanitizer is nondeterministic or rewrote a non-prefixed cell")
		}
	})
}
