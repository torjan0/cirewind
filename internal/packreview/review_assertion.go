package packreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

const reviewBodyPrefix = "CIRewind review assertion v1 sha256:"

// ReviewAssertion contains every reviewer-controlled field that can affect a
// qualifying decision. Platform-assigned identifiers and timestamps are
// deliberately excluded because they do not exist until GitHub records the
// review. The known repository and pull request remain in the assertion so a
// body cannot be replayed onto a different review surface.
type ReviewAssertion struct {
	SchemaVersion        string                `json:"schemaVersion"`
	ReviewID             string                `json:"reviewId"`
	Reviewer             HumanIdentity         `json:"reviewer"`
	DeclaredRole         string                `json:"declaredRole"`
	Independent          bool                  `json:"independent"`
	ConflictDisclosure   string                `json:"conflictDisclosure"`
	IncidentID           string                `json:"incidentId"`
	PackVersion          string                `json:"packVersion"`
	CandidateCommit      string                `json:"candidateCommit"`
	Bindings             ReviewBindings        `json:"bindings"`
	Repository           string                `json:"repository"`
	PullRequestNumber    int64                 `json:"pullRequestNumber"`
	Scopes               []string              `json:"scopes"`
	Commands             []ReproductionCommand `json:"commands"`
	SourceObjectsChecked []CheckedSourceObject `json:"sourceObjectsChecked"`
	Decision             string                `json:"decision"`
	Rationale            string                `json:"rationale"`
	KnownLimitations     []string              `json:"knownLimitations"`
}

// ReviewBodyBinding is the deterministic, non-secret binding a reviewer places
// in the GitHub review body. Only hashes are retained in governance records;
// arbitrary review-body content is discarded by the normalizer.
type ReviewBodyBinding struct {
	AssertionSHA256 string
	BodySHA256      string
	Body            string
}

// ComputeReviewBodyBinding hashes canonical material review assertions and
// derives the exact fixed ASCII GitHub review body. Validation separately
// checks the review fields; this function is intentionally pure and performs no
// network or process operation.
func ComputeReviewBodyBinding(review Review) (ReviewBodyBinding, error) {
	return ComputeReviewAssertionBody(ReviewAssertionFromReview(review))
}

// ReviewAssertionFromReview projects a finalized review onto exactly the
// fields that had to exist before its GitHub review was submitted.
func ReviewAssertionFromReview(review Review) ReviewAssertion {
	return ReviewAssertion{
		SchemaVersion:        ReviewAssertionSchema,
		ReviewID:             review.ReviewID,
		Reviewer:             review.Reviewer,
		DeclaredRole:         review.DeclaredRole,
		Independent:          review.Independent,
		ConflictDisclosure:   review.ConflictDisclosure,
		IncidentID:           review.IncidentID,
		PackVersion:          review.PackVersion,
		CandidateCommit:      review.CandidateCommit,
		Bindings:             review.Bindings,
		Repository:           review.PlatformReview.Repository,
		PullRequestNumber:    review.PlatformReview.PullRequestNumber,
		Scopes:               review.Scopes,
		Commands:             review.Commands,
		SourceObjectsChecked: review.SourceObjectsChecked,
		Decision:             review.Decision,
		Rationale:            review.Rationale,
		KnownLimitations:     review.KnownLimitations,
	}
}

// ComputeReviewAssertionBody returns the exact fixed ASCII body for one draft
// assertion. Callers must validate the assertion before treating the result as
// suitable for a review workflow.
func ComputeReviewAssertionBody(assertion ReviewAssertion) (ReviewBodyBinding, error) {
	canonical, err := marshalCanonical(assertion)
	if err != nil {
		return ReviewBodyBinding{}, err
	}
	assertionDigest := sha256.Sum256(canonical)
	assertionSHA256 := hex.EncodeToString(assertionDigest[:])
	body := reviewBodyPrefix + assertionSHA256
	bodyDigest := sha256.Sum256([]byte(body))
	return ReviewBodyBinding{
		AssertionSHA256: assertionSHA256,
		BodySHA256:      hex.EncodeToString(bodyDigest[:]),
		Body:            body,
	}, nil
}

// RenderReviewBodyFile strict-decodes and validates a canonical human-authored
// draft assertion, then returns only its deterministic fixed review-body
// binding. It does not create an approval or synthesize any assertion field.
func RenderReviewBodyFile(ctx context.Context, assertionJSON string) (ReviewBodyBinding, error) {
	assertion, raw, err := readStrictJSON[ReviewAssertion](ctx, assertionJSON)
	if err != nil {
		return ReviewBodyBinding{}, err
	}
	if err := requireCanonicalJSONFile(filepath.Base(assertionJSON), raw, assertion); err != nil {
		return ReviewBodyBinding{}, err
	}
	var validation problems
	validateReviewAssertion(assertion, &validation)
	if err := validation.err(); err != nil {
		return ReviewBodyBinding{}, err
	}
	return ComputeReviewAssertionBody(assertion)
}
