package incident

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const maxDiagnostics = 256

type Diagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

func (d Diagnostic) String() string {
	where := d.Path
	if where == "" {
		where = "$"
	}
	if d.Line > 0 {
		where = fmt.Sprintf("%s:%d:%d", where, d.Line, d.Column)
	}
	return fmt.Sprintf("%s [%s]: %s", where, d.Code, d.Message)
}

// ValidationError contains stable source-ordered diagnostics. Messages are
// produced by the validator and quote hostile scalar values rather than
// interpolating them as terminal control data.
type ValidationError struct {
	Diagnostics []Diagnostic
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Diagnostics) == 0 {
		return "incident pack validation failed"
	}
	if len(e.Diagnostics) == 1 {
		return e.Diagnostics[0].String()
	}
	return fmt.Sprintf("incident pack validation failed with %d diagnostics; first: %s", len(e.Diagnostics), e.Diagnostics[0])
}

type diagnosticSet struct {
	items     []Diagnostic
	truncated bool
}

func (s *diagnosticSet) add(code, path string, line, column int, format string, args ...any) {
	if len(s.items) >= maxDiagnostics {
		s.truncated = true
		return
	}
	message := sanitizeDiagnosticText(fmt.Sprintf(format, args...), 4096)
	path = sanitizeDiagnosticText(path, 1024)
	s.items = append(s.items, Diagnostic{Code: code, Path: path, Line: line, Column: column, Message: message})
}

func sanitizeDiagnosticText(value string, max int) string {
	var out strings.Builder
	for _, r := range value {
		if out.Len() >= max {
			out.WriteString("...")
			break
		}
		switch {
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == 0x1b:
			out.WriteString(`\u001b`)
		case unicode.IsControl(r) || isBidiControl(r):
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func (s *diagnosticSet) err() error {
	if s.truncated {
		s.items = append(s.items, Diagnostic{
			Code:    "DIAGNOSTIC_LIMIT",
			Path:    "$",
			Message: fmt.Sprintf("additional diagnostics omitted after the compiled limit of %d", maxDiagnostics),
		})
	}
	if len(s.items) == 0 {
		return nil
	}
	sort.SliceStable(s.items, func(i, j int) bool {
		a, b := s.items[i], s.items[j]
		if a.Line != b.Line {
			if a.Line == 0 {
				return false
			}
			if b.Line == 0 {
				return true
			}
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Code < b.Code
	})
	return &ValidationError{Diagnostics: append([]Diagnostic(nil), s.items...)}
}

type position struct {
	line   int
	column int
}

type locations map[string]position

func (l locations) at(path string) position {
	for candidate := path; candidate != ""; {
		if p, ok := l[candidate]; ok {
			return p
		}
		if i := strings.LastIndexAny(candidate, ".[ "); i >= 0 {
			candidate = strings.TrimSuffix(candidate[:i], "[")
		} else {
			break
		}
	}
	return l["$"]
}

func addAt(ds *diagnosticSet, loc locations, code, path, format string, args ...any) {
	p := loc.at(path)
	ds.add(code, path, p.line, p.column, format, args...)
}
