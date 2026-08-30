package packreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxPlatformSourceBytes = int64(8 << 20)

// PlatformSnapshotOptions is caller-supplied GitHub Actions run context for a
// normalized REST observation. The raw response remains hostile input.
type PlatformSnapshotOptions struct {
	Repository           string
	PullRequestNumber    int64
	CandidateCommit      string
	ObservedAt           string
	WorkflowSourceCommit string
	WorkflowRunURL       string
	WorkflowRunID        int64
	WorkflowRunAttempt   int64
}

type githubReviewObservation struct {
	ID      int64  `json:"id"`
	HTMLURL string `json:"html_url"`
	User    *struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Type  string `json:"type"`
	} `json:"user"`
	State       string  `json:"state"`
	CommitID    string  `json:"commit_id"`
	SubmittedAt *string `json:"submitted_at"`
	Body        *string `json:"body"`
}

// NormalizePlatformSnapshot converts a bounded GitHub list-reviews response
// (one array or an array of paginated arrays) into the closed offline record.
// It performs no network request and does not treat the result as an approval.
func NormalizePlatformSnapshot(ctx context.Context, raw []byte, options PlatformSnapshotOptions) (PlatformApprovalSnapshot, []byte, error) {
	if err := ctx.Err(); err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	if len(raw) == 0 || int64(len(raw)) > maxPlatformSourceBytes {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_SIZE", Path: "/source", Message: "GitHub review response must be 1-8388608 bytes"}}}
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "INVALID_JSON_ENCODING", Path: "/source", Message: "GitHub review response must be UTF-8 without a byte-order mark"}}}
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: strictJSONProblemCode(err), Path: "/source", Message: boundedError(err)}}}
	}
	reviews, err := decodeGitHubReviewPages(raw)
	if err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	if len(reviews) == 0 || len(reviews) > 2000 {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_COUNT", Path: "/source", Message: "GitHub review response must contain 1-2000 bounded observations"}}}
	}
	approvals := make([]PlatformApproval, 0, len(reviews))
	for index, review := range reviews {
		if err := ctx.Err(); err != nil {
			return PlatformApprovalSnapshot{}, nil, err
		}
		base := fmt.Sprintf("/source/%d", index)
		state := strings.ToUpper(review.State)
		switch state {
		case "APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED":
		case "PENDING":
			continue
		default:
			return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_STATE", Path: base + "/state", Message: "unsupported GitHub review state"}}}
		}
		if review.User == nil || review.SubmittedAt == nil {
			return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_REVIEW", Path: base, Message: "submitted review requires user and submitted_at"}}}
		}
		body := ""
		if review.Body != nil {
			body = *review.Body
		}
		bodyDigest := sha256.Sum256([]byte(body))
		approvals = append(approvals, PlatformApproval{
			ReviewDatabaseID: review.ID,
			ReviewURL:        review.HTMLURL,
			Reviewer:         PlatformActor{Login: strings.ToLower(review.User.Login), DatabaseID: review.User.ID},
			AccountType:      review.User.Type,
			State:            state,
			CommitID:         strings.ToLower(review.CommitID),
			SubmittedAt:      *review.SubmittedAt,
			BodySHA256:       hex.EncodeToString(bodyDigest[:]),
			Dismissed:        state == "DISMISSED",
		})
	}
	if len(approvals) == 0 || len(approvals) > 100 {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_APPROVAL_COUNT", Path: "/source", Message: "GitHub response must yield 1-100 submitted review observations"}}}
	}
	sort.Slice(approvals, func(left, right int) bool {
		return approvals[left].ReviewDatabaseID < approvals[right].ReviewDatabaseID
	})
	digest := sha256.Sum256(raw)
	snapshot := PlatformApprovalSnapshot{
		SchemaVersion: PlatformSnapshotSchema, Repository: options.Repository, PullRequestNumber: options.PullRequestNumber,
		CandidateCommit: options.CandidateCommit, ObservedAt: options.ObservedAt, ObservationSource: "github-rest-api",
		WorkflowSourceCommit: options.WorkflowSourceCommit, WorkflowRunURL: options.WorkflowRunURL, WorkflowRunID: options.WorkflowRunID, WorkflowRunAttempt: options.WorkflowRunAttempt,
		ResponseSHA256: hex.EncodeToString(digest[:]), Approvals: approvals,
	}
	var validation problems
	validatePlatformSnapshot(snapshot, &validation)
	if err := validation.err(); err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	canonical, err := marshalCanonical(snapshot)
	if err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	return snapshot, canonical, nil
}

// WritePlatformSnapshot reads a hostile bounded response and atomically writes
// only the fixed normalized snapshot filename. It returns exact output bytes.
func WritePlatformSnapshot(ctx context.Context, sourcePath, outputPath string, options PlatformSnapshotOptions) (PlatformApprovalSnapshot, []byte, error) {
	if filepath.Base(outputPath) != "platform-approvals.json" || sameCleanPath(sourcePath, outputPath) {
		return PlatformApprovalSnapshot{}, nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SNAPSHOT_PATH", Path: outputPath, Message: "output must be a distinct fixed platform-approvals.json path"}}}
	}
	raw, err := readBoundedRegularContext(ctx, sourcePath, maxPlatformSourceBytes)
	if err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	snapshot, canonical, err := NormalizePlatformSnapshot(ctx, raw, options)
	if err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	if err := writeAtomicRegular(outputPath, canonical, 0o600); err != nil {
		return PlatformApprovalSnapshot{}, nil, err
	}
	return snapshot, canonical, nil
}

func decodeGitHubReviewPages(raw []byte) ([]githubReviewObservation, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review response must be a JSON array"}}}
	}
	result := make([]githubReviewObservation, 0, 100)
	shape := byte(0)
	for decoder.More() {
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review response is malformed"}}}
		}
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 {
			return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review response contains an empty value"}}}
		}
		currentShape := byte('{')
		if trimmed[0] == '[' {
			currentShape = '['
		}
		if shape == 0 {
			shape = currentShape
		} else if shape != currentShape {
			return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_SHAPE", Path: "/source", Message: "response cannot mix page arrays and reviews"}}}
		}
		if currentShape == '[' {
			if err := appendGitHubReviewPage(trimmed, &result); err != nil {
				return nil, err
			}
		} else {
			if trimmed[0] != '{' {
				return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_SHAPE", Path: "/source", Message: "response values must be review objects or page arrays"}}}
			}
			var review githubReviewObservation
			if err := json.Unmarshal(trimmed, &review); err != nil {
				return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review object is malformed"}}}
			}
			result = append(result, review)
		}
		if len(result) > 2000 {
			return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_COUNT", Path: "/source", Message: "GitHub review response exceeds 2000 observations"}}}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review response is malformed"}}}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review response has trailing JSON"}}}
	}
	return result, nil
}

func appendGitHubReviewPage(raw []byte, result *[]githubReviewObservation) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review page is malformed"}}}
	}
	for decoder.More() {
		if len(*result) >= 2000 {
			return &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_COUNT", Path: "/source", Message: "GitHub review response exceeds 2000 observations"}}}
		}
		var review githubReviewObservation
		if err := decoder.Decode(&review); err != nil {
			return &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review page is malformed"}}}
		}
		*result = append(*result, review)
	}
	if _, err := decoder.Token(); err != nil {
		return &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review page is malformed"}}}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return &ValidationError{Problems: []Problem{{Code: "PLATFORM_SOURCE_JSON", Path: "/source", Message: "GitHub review page has trailing JSON"}}}
	}
	return nil
}
