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
	prefixes := []string{
		"",
		" ",
		"\x00",     // NUL
		"\x01\v\f", // other C0 controls
		"\x7f",     // DEL
		"\u0085",   // C1 next-line control
		"\u00a0",   // no-break space
		"\u1680",   // Ogham space mark
		"\u2009",   // thin space
		"\u2028",   // line separator
		"\u202f",   // narrow no-break space
		"\u3000",   // ideographic space
		"\u00ad",   // soft hyphen (format)
		"\u200b",   // zero-width space (format)
		"\u2060",   // word joiner (format)
		"\ufeff",   // zero-width no-break space / BOM (format)
		"\u202e",   // bidi override (format)
		" \x00\u200b\u00a0",
		string([]byte{0xff}), // invalid UTF-8 may be discarded on import
	}
	for _, prefix := range prefixes {
		for _, marker := range []rune{'=', '+', '-', '@'} {
			input := prefix + string(marker) + "payload"
			if got, want := CSVCell(input), "'"+input; got != want {
				t.Errorf("CSVCell(%q) = %q, want %q", input, got, want)
			}
		}
	}

	for _, input := range []string{
		"",
		"normal",
		"1+1",
		" x=1",
		"\x00\u200bnormal",
		"\u00a0text",
		"'=1+1",
		" \u200b'=1+1",
		"\x00\u200b\u00a0",
	} {
		if got := CSVCell(input); got != input {
			t.Errorf("CSVCell(%q) = %q, want unchanged", input, got)
		}
	}

	for _, input := range []string{"=formula", "\x00@formula", "\u200b-formula", "normal"} {
		first := CSVCell(input)
		if second := CSVCell(first); second != first {
			t.Errorf("CSVCell is not idempotent: first=%q second=%q", first, second)
		}
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

func TestPresentationRemovesBidiTerminalAndXMLControls(t *testing.T) {
	t.Parallel()
	input := "left\x1b[31mred\x1b[0m\r\nright\u202e-hidden\u061c-alm\ufdd0"
	got, truncated := Presentation(input, 1024)
	if truncated || got != "leftred right-hidden-alm" {
		t.Fatalf("Presentation()=%q truncated=%v", got, truncated)
	}
	if input != "left\x1b[31mred\x1b[0m\r\nright\u202e-hidden\u061c-alm\ufdd0" {
		t.Fatal("presentation sanitization changed retained input")
	}
}

func TestDisplayWrappingConservativelyBoundsWideText(t *testing.T) {
	t.Parallel()
	lines, truncated := WrapDisplay(strings.Repeat("証", 80), 96, 30, 3)
	if !truncated || len(lines) != 3 || !strings.HasSuffix(lines[2], "…") {
		t.Fatalf("WrapDisplay() lines=%q truncated=%v", lines, truncated)
	}
	for _, line := range lines {
		if got := displayTextUnits(line); got > 30 {
			t.Fatalf("wide line consumes %d display units: %q", got, line)
		}
		if len([]rune(line)) > 16 { // fifteen wide runes, or fourteen plus the wide ellipsis.
			t.Fatalf("wide line exceeds its conservative rune bound: %q", line)
		}
	}

	visible, truncated := TruncateDisplay(strings.Repeat("界", 100), 192, 160)
	if !truncated || displayTextUnits(visible) > 160 || !strings.HasSuffix(visible, "…") {
		t.Fatalf("TruncateDisplay()=%q units=%d truncated=%v", visible, displayTextUnits(visible), truncated)
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
		if CSVCell(csvFirst) != csvFirst {
			t.Fatal("CSV sanitizer is not idempotent")
		}
		presentationFirst, presentationTruncated := Presentation(value, limit)
		presentationSecond, secondTruncated := Presentation(value, limit)
		if presentationFirst != presentationSecond || presentationTruncated != secondTruncated || len(presentationFirst) > limit || !utf8.ValidString(presentationFirst) {
			t.Fatal("presentation sanitizer violated determinism, byte limit, or UTF-8")
		}
		for _, r := range presentationFirst {
			if unicode.IsControl(r) || isUnsafeRune(r) || !presentationSafeRune(r) {
				t.Fatalf("presentation sanitizer retained unsafe rune %U", r)
			}
		}
	})
}
