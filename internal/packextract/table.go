package packextract

import (
	"fmt"
	"strings"
)

// Bounds that keep the parser from doing unbounded work on hostile input.
const (
	maxInputBytes       = 4 << 20
	maxDescriptionBytes = 1 << 20
	maxLines            = 50000
	maxTableRows        = 1000
)

// tableRow is one data row of a Markdown pipe table with its 1-based row
// number inside the table.
type tableRow struct {
	Number int
	Cells  []string
}

// splitLines splits text on LF and drops one trailing CR per line so CRLF and
// LF inputs parse identically. The difference is recorded by the input hash,
// never by the extracted records.
func splitLines(text string) ([]string, error) {
	lines := strings.Split(text, "\n")
	if len(lines) > maxLines {
		return nil, fmt.Errorf("input has %d lines, more than the %d allowed", len(lines), maxLines)
	}
	for index, line := range lines {
		lines[index] = strings.TrimSuffix(line, "\r")
	}
	return lines, nil
}

// findHeading returns the index of the line whose trimmed text equals heading.
// The heading must occur exactly once so a second table cannot be smuggled in
// under a duplicated title.
func findHeading(lines []string, heading string) (int, error) {
	found := -1
	for index, line := range lines {
		if strings.TrimSpace(line) != heading {
			continue
		}
		if found >= 0 {
			return 0, fmt.Errorf("heading %q occurs more than once", heading)
		}
		found = index
	}
	if found < 0 {
		return 0, fmt.Errorf("heading %q is absent", heading)
	}
	return found, nil
}

// parseTable reads the first pipe table after the heading at index start. The
// header cells must equal header exactly; the separator row must consist of
// dashes; data rows end at the first line that is not a pipe row. Every data
// row must carry exactly len(header) cells.
func parseTable(lines []string, start int, header []string) ([]tableRow, error) {
	index := start + 1
	for index < len(lines) && strings.TrimSpace(lines[index]) == "" {
		index++
	}
	if index >= len(lines) {
		return nil, fmt.Errorf("table after %q is absent", strings.TrimSpace(lines[start]))
	}
	headerCells, ok := pipeCells(lines[index])
	if !ok {
		return nil, fmt.Errorf("line %d after %q is not a table header", index+1, strings.TrimSpace(lines[start]))
	}
	if len(headerCells) != len(header) {
		return nil, fmt.Errorf("table header after %q has %d cells, want %d", strings.TrimSpace(lines[start]), len(headerCells), len(header))
	}
	for position, cell := range headerCells {
		if cell != header[position] {
			return nil, fmt.Errorf("table header cell %d after %q is %q, want %q", position+1, strings.TrimSpace(lines[start]), cell, header[position])
		}
	}
	index++
	if index >= len(lines) {
		return nil, fmt.Errorf("table after %q lacks a separator row", strings.TrimSpace(lines[start]))
	}
	separator, ok := pipeCells(lines[index])
	if !ok || len(separator) != len(header) {
		return nil, fmt.Errorf("table after %q lacks a separator row", strings.TrimSpace(lines[start]))
	}
	for _, cell := range separator {
		if strings.Trim(cell, "-: ") != "" {
			return nil, fmt.Errorf("table after %q has a malformed separator row", strings.TrimSpace(lines[start]))
		}
	}
	index++
	rows := make([]tableRow, 0)
	for index < len(lines) {
		cells, ok := pipeCells(lines[index])
		if !ok {
			break
		}
		if len(cells) != len(header) {
			return nil, fmt.Errorf("table row %d after %q has %d cells, want %d", len(rows)+1, strings.TrimSpace(lines[start]), len(cells), len(header))
		}
		rows = append(rows, tableRow{Number: len(rows) + 1, Cells: cells})
		if len(rows) > maxTableRows {
			return nil, fmt.Errorf("table after %q has more than %d rows", strings.TrimSpace(lines[start]), maxTableRows)
		}
		index++
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("table after %q has no rows", strings.TrimSpace(lines[start]))
	}
	return rows, nil
}

// pipeCells splits a `| a | b |` row into trimmed cells. Lines that do not
// start and end with a pipe are not rows.
func pipeCells(line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 2 || !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
		return nil, false
	}
	inner := trimmed[1 : len(trimmed)-1]
	parts := strings.Split(inner, "|")
	cells := make([]string, len(parts))
	for index, part := range parts {
		cells[index] = strings.TrimSpace(part)
	}
	return cells, true
}

// listItems returns the `- item` lines that follow the heading at index
// start. Blank lines and the one exact intro line are allowed before the first
// item; any other prose ends the list, and prose before the first item is an
// error because it would mean the section is not the one the extractor was
// written for.
func listItems(lines []string, start int, intro string) ([]string, error) {
	items := make([]string, 0)
	for index := start + 1; index < len(lines); index++ {
		trimmed := strings.TrimSpace(lines[index])
		if trimmed == "" {
			if len(items) > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "- ") {
			if len(items) == 0 && intro != "" && trimmed == intro {
				continue
			}
			if len(items) == 0 {
				return nil, fmt.Errorf("unexpected text %q before the list under %q", trimmed, strings.TrimSpace(lines[start]))
			}
			break
		}
		items = append(items, strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
	}
	return items, nil
}

// unquoteCode strips one pair of surrounding backticks. The boolean reports
// whether the cell was code-quoted, which the Trivy tables always are.
func unquoteCode(cell string) (string, bool) {
	if len(cell) >= 2 && strings.HasPrefix(cell, "`") && strings.HasSuffix(cell, "`") {
		return cell[1 : len(cell)-1], true
	}
	return cell, false
}
