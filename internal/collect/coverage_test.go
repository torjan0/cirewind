package collect

import (
	"testing"

	"github.com/torjan0/cirewind/internal/githubapi"
)

func TestGapFromErrorPreservesStableClassificationAndSafeEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		class githubapi.ErrorClass
		want  GapReason
	}{
		{githubapi.ErrorUnauthorized, GapUnauthorized},
		{githubapi.ErrorForbidden, GapForbidden},
		{githubapi.ErrorNotFound, GapNotFound},
		{githubapi.ErrorRetentionOrDeletion, GapRetentionOrDeletion},
		{githubapi.ErrorAPIVersion, GapAPIVersion},
		{githubapi.ErrorValidation, GapValidation},
		{githubapi.ErrorRateLimited, GapRateLimited},
		{githubapi.ErrorSecondaryLimit, GapRateLimited},
		{githubapi.ErrorTransient, GapTransient},
		{githubapi.ErrorRedirectExpired, GapRedirectExpired},
		{githubapi.ErrorUnsafeRedirect, GapUnsafeRedirect},
		{githubapi.ErrorSizeLimit, GapSizeLimit},
		{githubapi.ErrorLocalIO, GapLocalIO},
		{githubapi.ErrorMalformedResponse, GapMalformedResponse},
		{githubapi.ErrorPagination, GapPagination},
		{githubapi.ErrorCancelled, GapCancelled},
	}
	for _, test := range tests {
		t.Run(string(test.class), func(t *testing.T) {
			err := &githubapi.Error{
				Class: test.class, Operation: "fixture", Message: "bounded diagnostic", Retryable: true,
				Responses: []githubapi.ResponseMeta{{RouteTemplate: "/fixture", StatusCode: 403}},
			}
			gap := GapFromError("attempt_logs", 10, 20, 2, err)
			if gap.Reason != test.want || gap.RepositoryID != 10 || gap.RunID != 20 || gap.Attempt != 2 || !gap.Material || !gap.Retryable || len(gap.Responses) != 1 {
				t.Fatalf("gap = %+v", gap)
			}
		})
	}
}
