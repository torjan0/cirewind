// Package collect contains deterministic, coverage-aware collection planning.
// It depends on typed GitHub operations but not on presentation or findings.
package collect

import (
	"errors"

	"github.com/torjan0/cirewind/internal/githubapi"
)

type GapReason string

const (
	GapUnauthorized         GapReason = "UNAUTHORIZED"
	GapForbidden            GapReason = "FORBIDDEN"
	GapNotFound             GapReason = "NOT_FOUND"
	GapRetentionOrDeletion  GapReason = "RETENTION_OR_DELETION"
	GapRateLimited          GapReason = "RATE_LIMITED"
	GapTransient            GapReason = "TRANSIENT_NETWORK"
	GapMalformedResponse    GapReason = "MALFORMED_RESPONSE"
	GapPagination           GapReason = "PAGINATION_FAILURE"
	GapAPIVersion           GapReason = "API_VERSION_UNSUPPORTED"
	GapValidation           GapReason = "VALIDATION_FAILED"
	GapRedirectExpired      GapReason = "REDIRECT_EXPIRED"
	GapUnsafeRedirect       GapReason = "UNSAFE_REDIRECT"
	GapSizeLimit            GapReason = "SIZE_LIMIT"
	GapLocalIO              GapReason = "LOCAL_IO"
	GapDensityCeiling       GapReason = "DENSITY_CEILING"
	GapPartitionLimit       GapReason = "PARTITION_LIMIT"
	GapLiveStateRace        GapReason = "LIVE_STATE_RACE"
	GapAmbiguousCorrelation GapReason = "AMBIGUOUS_CORRELATION"
	GapCancelled            GapReason = "CANCELLED"
	GapUnknown              GapReason = "UNKNOWN"
)

type Gap struct {
	Reason       GapReason                `json:"reason"`
	Scope        string                   `json:"scope"`
	RepositoryID int64                    `json:"repository_id,omitempty"`
	RunID        int64                    `json:"run_id,omitempty"`
	Attempt      int                      `json:"attempt,omitempty"`
	JobID        int64                    `json:"job_id,omitempty"`
	Material     bool                     `json:"material"`
	Retryable    bool                     `json:"retryable"`
	Diagnostic   string                   `json:"diagnostic,omitempty"`
	Responses    []githubapi.ResponseMeta `json:"responses,omitempty"`
}

func GapFromError(scope string, repositoryID, runID int64, attempt int, err error) Gap {
	gap := Gap{Reason: GapUnknown, Scope: scope, RepositoryID: repositoryID, RunID: runID, Attempt: attempt, Material: true}
	var apiErr *githubapi.Error
	if !errors.As(err, &apiErr) {
		if err != nil {
			gap.Diagnostic = "collection operation failed"
		}
		return gap
	}
	gap.Retryable = apiErr.Retryable
	gap.Diagnostic = apiErr.Error()
	gap.Responses = append([]githubapi.ResponseMeta(nil), apiErr.Responses...)
	switch apiErr.Class {
	case githubapi.ErrorUnauthorized:
		gap.Reason = GapUnauthorized
	case githubapi.ErrorForbidden:
		gap.Reason = GapForbidden
	case githubapi.ErrorNotFound:
		gap.Reason = GapNotFound
	case githubapi.ErrorRetentionOrDeletion:
		gap.Reason = GapRetentionOrDeletion
	case githubapi.ErrorAPIVersion:
		gap.Reason = GapAPIVersion
	case githubapi.ErrorValidation, githubapi.ErrorInvalidRequest:
		gap.Reason = GapValidation
	case githubapi.ErrorRateLimited, githubapi.ErrorSecondaryLimit:
		gap.Reason = GapRateLimited
	case githubapi.ErrorTransient, githubapi.ErrorRetryBudget:
		gap.Reason = GapTransient
	case githubapi.ErrorRedirectExpired:
		gap.Reason = GapRedirectExpired
	case githubapi.ErrorUnsafeRedirect:
		gap.Reason = GapUnsafeRedirect
	case githubapi.ErrorSizeLimit:
		gap.Reason = GapSizeLimit
	case githubapi.ErrorLocalIO:
		gap.Reason = GapLocalIO
	case githubapi.ErrorMalformedResponse, githubapi.ErrorUnexpectedMedia:
		gap.Reason = GapMalformedResponse
	case githubapi.ErrorPagination:
		gap.Reason = GapPagination
	case githubapi.ErrorCancelled:
		gap.Reason = GapCancelled
	}
	return gap
}
