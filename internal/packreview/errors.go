package packreview

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ValidationError is a bounded policy/schema failure. Maintainer tooling maps
// it to exit status 2, separate from operational failures.
type ValidationError struct {
	Problems []Problem `json:"problems"`
}

type Problem struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Problems) == 0 {
		return "review validation failed"
	}
	return fmt.Sprintf("review validation failed at %s: %s", e.Problems[0].Path, e.Problems[0].Message)
}

func IsValidation(err error) bool {
	var target *ValidationError
	return errors.As(err, &target)
}

type problems struct {
	items []Problem
}

func (p *problems) add(code, path, format string, args ...any) {
	if len(p.items) >= 100 {
		return
	}
	message := fmt.Sprintf(format, args...)
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, message)
	if len(message) > 1024 {
		message = message[:1024]
	}
	p.items = append(p.items, Problem{Code: code, Path: path, Message: message})
}

func (p *problems) err() error {
	if len(p.items) == 0 {
		return nil
	}
	sort.SliceStable(p.items, func(i, j int) bool {
		if p.items[i].Path != p.items[j].Path {
			return p.items[i].Path < p.items[j].Path
		}
		if p.items[i].Code != p.items[j].Code {
			return p.items[i].Code < p.items[j].Code
		}
		return p.items[i].Message < p.items[j].Message
	})
	return &ValidationError{Problems: append([]Problem(nil), p.items...)}
}
