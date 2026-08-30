// Package sanitize contains output-sink-specific hostile-text handling.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const truncationSuffix = " … [truncated]"

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

// Presentation returns deterministic, single-line hostile text suitable for
// human-facing HTML, XML, and SVG text nodes. It removes terminal escapes,
// controls (including bidirectional overrides and isolates), XML-invalid code
// points, and line-boundary spoofing without changing retained source evidence.
// The returned boolean reports byte-limit truncation.
func Presentation(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", value != ""
	}
	var builder strings.Builder
	truncated, pendingSpace := false, false
	for index := 0; index < len(value); {
		if value[index] == 0x1b {
			index = skipEscape(value, index)
			continue
		}
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			r, size = utf8.RuneError, 1
		}
		index += size
		if r == '\n' || r == '\r' || r == '\t' || r == '\u2028' || r == '\u2029' {
			pendingSpace = builder.Len() > 0
			continue
		}
		if !presentationSafeRune(r) {
			continue
		}
		if pendingSpace {
			if builder.Len()+1 > maxBytes {
				truncated = true
				break
			}
			builder.WriteByte(' ')
			pendingSpace = false
		}
		encoded := string(r)
		if builder.Len()+len(encoded) > maxBytes {
			truncated = true
			break
		}
		builder.WriteString(encoded)
	}
	result := strings.TrimSpace(builder.String())
	if truncated {
		result = appendByteTruncationSuffix(result, maxBytes)
	}
	return strings.TrimSpace(result), truncated
}

// TruncateDisplay bounds already presentation-safe text by both rune count and
// conservative monospace display units. ASCII occupies one unit; non-ASCII
// code points occupy two. This deliberately overestimates combining marks so
// fixed SVG boxes remain safe without runtime font measurement.
func TruncateDisplay(value string, maxRunes, maxUnits int) (string, bool) {
	if maxRunes <= 0 || maxUnits <= 0 {
		return "", value != ""
	}
	var builder strings.Builder
	runes, units := 0, 0
	truncated := false
	for _, r := range value {
		width := displayUnits(r)
		if runes >= maxRunes || units+width > maxUnits {
			truncated = true
			break
		}
		builder.WriteRune(r)
		runes++
		units += width
	}
	result := strings.TrimSpace(builder.String())
	if truncated {
		result = appendDisplayEllipsis(result, maxUnits)
	}
	return result, truncated
}

// WrapDisplay splits already presentation-safe text into a bounded number of
// deterministic fixed-width lines. Word boundaries are preferred, but hostile
// unbroken strings are split at the display-unit limit. The last line receives
// a visible truncation marker when content is omitted.
func WrapDisplay(value string, maxRunes, maxUnits, maxLines int) ([]string, bool) {
	if maxRunes <= 0 || maxUnits <= 0 || maxLines <= 0 {
		return []string{"[unavailable]"}, value != ""
	}
	runes := []rune(value)
	if len(runes) > maxRunes {
		runes = runes[:maxRunes]
	}
	truncated := len([]rune(value)) > len(runes)
	lines := make([]string, 0, maxLines)
	for len(runes) > 0 && len(lines) < maxLines {
		limit, units, lastSpace := 0, 0, -1
		for limit < len(runes) {
			width := displayUnits(runes[limit])
			if units+width > maxUnits {
				break
			}
			units += width
			if unicode.IsSpace(runes[limit]) {
				lastSpace = limit
			}
			limit++
		}
		if limit == 0 {
			limit = 1
		}
		cut := limit
		if limit < len(runes) && lastSpace > 0 {
			cut = lastSpace
		}
		line := strings.TrimSpace(string(runes[:cut]))
		if line == "" {
			line = string(runes[:limit])
			cut = limit
		}
		lines = append(lines, line)
		runes = runes[cut:]
		for len(runes) > 0 && unicode.IsSpace(runes[0]) {
			runes = runes[1:]
		}
	}
	if len(runes) > 0 {
		truncated = true
	}
	if len(lines) == 0 {
		lines = []string{"[unavailable]"}
	}
	if truncated {
		lines[len(lines)-1] = appendDisplayEllipsis(lines[len(lines)-1], maxUnits)
	}
	return lines, truncated
}

// CSVCell neutralizes spreadsheet formula prefixes after ignoring leading
// invalid UTF-8, controls, Unicode format characters, and whitespace only for
// detection.
// Spreadsheet importers can discard or normalize these characters before
// interpreting a cell. The original cell text remains otherwise intact.
func CSVCell(value string) string {
	probe := value
	for len(probe) > 0 {
		r, size := utf8.DecodeRuneInString(probe)
		if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			probe = probe[size:]
			continue
		}
		break
	}
	first, _ := utf8.DecodeRuneInString(probe)
	if probe != "" && strings.ContainsRune("=+-@", first) {
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
	return (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Bidi_Control, r)
}

func presentationSafeRune(r rune) bool {
	if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f || isUnsafeRune(r) {
		return false
	}
	if r > utf8.MaxRune || r >= 0xd800 && r <= 0xdfff {
		return false
	}
	if r >= 0xfdd0 && r <= 0xfdef || r&0xffff == 0xfffe || r&0xffff == 0xffff {
		return false
	}
	return r >= 0x20 && (r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000)
}

func displayUnits(r rune) int {
	if r <= 0x7f {
		return 1
	}
	return 2
}

func appendByteTruncationSuffix(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	for value != "" && len(value)+len(truncationSuffix) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(value)
		value = strings.TrimSpace(value[:len(value)-size])
	}
	if len(truncationSuffix) > maxBytes {
		return ""
	}
	return strings.TrimSpace(value) + truncationSuffix
}

func displayTextUnits(value string) int {
	units := 0
	for _, r := range value {
		units += displayUnits(r)
	}
	return units
}

func appendDisplayEllipsis(value string, maxUnits int) string {
	value = strings.TrimSpace(value)
	const suffix = "…"
	for value != "" && displayTextUnits(value)+displayTextUnits(suffix) > maxUnits {
		_, size := utf8.DecodeLastRuneInString(value)
		value = strings.TrimSpace(value[:len(value)-size])
	}
	if displayTextUnits(suffix) > maxUnits {
		return ""
	}
	return value + suffix
}
