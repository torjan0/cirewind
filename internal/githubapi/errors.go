package githubapi

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type ErrorClass string

const (
	ErrorUnauthorized        ErrorClass = "UNAUTHORIZED"
	ErrorForbidden           ErrorClass = "FORBIDDEN"
	ErrorNotFound            ErrorClass = "NOT_FOUND"
	ErrorRetentionOrDeletion ErrorClass = "RETENTION_OR_DELETION"
	ErrorAPIVersion          ErrorClass = "API_VERSION_UNSUPPORTED"
	ErrorValidation          ErrorClass = "VALIDATION_FAILED"
	ErrorRateLimited         ErrorClass = "RATE_LIMITED"
	ErrorSecondaryLimit      ErrorClass = "SECONDARY_LIMIT"
	ErrorTransient           ErrorClass = "TRANSIENT_NETWORK"
	ErrorRedirectExpired     ErrorClass = "REDIRECT_EXPIRED"
	ErrorUnsafeRedirect      ErrorClass = "UNSAFE_REDIRECT"
	ErrorSizeLimit           ErrorClass = "SIZE_LIMIT"
	ErrorMalformedResponse   ErrorClass = "MALFORMED_RESPONSE"
	ErrorUnexpectedMedia     ErrorClass = "UNEXPECTED_MEDIA_TYPE"
	ErrorPagination          ErrorClass = "PAGINATION_FAILURE"
	ErrorCancelled           ErrorClass = "CANCELLED"
	ErrorUnsupportedTarget   ErrorClass = "UNSUPPORTED_TARGET"
	ErrorInvalidRequest      ErrorClass = "INVALID_REQUEST"
	ErrorRetryBudget         ErrorClass = "RETRY_BUDGET_EXHAUSTED"
	ErrorLocalIO             ErrorClass = "LOCAL_IO"
)

const maxDiagnosticBytes = 4 << 10

// Error is safe for terminal, JSON, and evidence diagnostics. Message never
// contains a raw URL, request headers, or an unsanitized response body.
type Error struct {
	Class      ErrorClass
	Operation  string
	StatusCode int
	Message    string
	Retryable  bool
	Responses  []ResponseMeta
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{"github read"}
	if e.Operation != "" {
		parts = append(parts, e.Operation)
	}
	if e.Class != "" {
		parts = append(parts, string(e.Class))
	}
	if e.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("status %d", e.StatusCode))
	}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	return strings.Join(parts, ": ")
}

func (e *Error) Unwrap() error { return e.Cause }

func IsClass(err error, class ErrorClass) bool {
	var target *Error
	return errors.As(err, &target) && target.Class == class
}

func sanitizeDiagnostic(value string) string {
	var b strings.Builder
	b.Grow(min(len(value), maxDiagnosticBytes))
	for _, r := range value {
		var rendered string
		switch {
		case r == '\r':
			rendered = `\r`
		case r == '\n':
			rendered = `\n`
		case r == '\t':
			rendered = `\t`
		case r == 0x1b:
			rendered = `\u001b`
		case unicode.IsControl(r) || isBidiControl(r):
			rendered = fmt.Sprintf(`\u%04x`, r)
		default:
			rendered = string(r)
		}
		// Keep the byte ceiling exact and never emit a partial UTF-8 rune or
		// escape sequence. Diagnostics are persisted and rendered in several
		// sinks, so the advertised byte budget must not be an approximation.
		if len(rendered) > maxDiagnosticBytes-b.Len() {
			break
		}
		b.WriteString(rendered)
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}
