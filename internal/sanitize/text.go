// Package sanitize contains output-sink-specific hostile-text handling.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// Terminal returns a single-line, bounded terminal-safe rendering. It removes
// ANSI CSI/OSC/DCS sequences, C0/C1 controls, bidi controls, and converts line
// boundaries to visible spaces. It never changes retained source evidence.
func Terminal(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(value); {
		if b.Len() >= maxBytes {
			break
		}
		c := value[i]
		if c == 0x1b {
			i = skipEscape(value, i)
			continue
		}
		if c < 0x20 || c == 0x7f {
			if c == '\n' || c == '\r' || c == '\t' {
				if b.Len() == 0 || b.String()[b.Len()-1] != ' ' {
					b.WriteByte(' ')
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			const replacement = "�"
			if b.Len()+len(replacement) > maxBytes {
				break
			}
			b.WriteString(replacement)
			i++
			continue
		}
		if isUnsafeRune(r) {
			i += size
			continue
		}
		if b.Len()+size > maxBytes {
			break
		}
		b.WriteRune(r)
		i += size
	}
	return strings.TrimSpace(b.String())
}

// CSVCell neutralizes spreadsheet formula prefixes after trimming only for
// detection. The original cell text remains otherwise intact.
func CSVCell(value string) string {
	probe := value
	for len(probe) > 0 {
		r, size := utf8.DecodeRuneInString(probe)
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || isUnsafeRune(r) {
			probe = probe[size:]
			continue
		}
		break
	}
	if probe != "" && strings.ContainsRune("=+-@", []rune(probe)[0]) {
		return "'" + value
	}
	return value
}

func skipEscape(value string, start int) int {
	if start+1 >= len(value) {
		return len(value)
	}
	next := value[start+1]
	switch next {
	case '[': // CSI: final byte 0x40..0x7e.
		for i := start + 2; i < len(value); i++ {
			if value[i] >= 0x40 && value[i] <= 0x7e {
				return i + 1
			}
		}
	case ']', 'P', 'X', '^', '_': // OSC/DCS/SOS/PM/APC: BEL or ST.
		for i := start + 2; i < len(value); i++ {
			if value[i] == 0x07 {
				return i + 1
			}
			if value[i] == 0x1b && i+1 < len(value) && value[i+1] == '\\' {
				return i + 2
			}
		}
	default:
		return start + 2
	}
	return len(value)
}

func isUnsafeRune(r rune) bool {
	return (r >= 0x80 && r <= 0x9f) ||
		r == 0x202a || r == 0x202b || r == 0x202c || r == 0x202d || r == 0x202e ||
		r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x2069 || r == 0x200e || r == 0x200f
}
