package packreview

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

const reviewDisclaimer = "This record documents reviewer-supplied provenance. It does not certify itself, prove that incident facts are true, or replace a matching human GitHub pull-request approval against the exact candidate commit."

// RenderReview deterministically derives inert Markdown from one already
// validated human-supplied review record.
func RenderReview(review Review) ([]byte, error) {
	var validation problems
	validateReview(review, &validation)
	if err := validation.err(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "# Review record %s\n\n", markdownText(review.ReviewID))
	fmt.Fprintf(&output, "> %s\n\n", markdownText(reviewDisclaimer))
	fmt.Fprintf(&output, "- Decision: `%s`\n", review.Decision)
	fmt.Fprintf(&output, "- Reviewer: `%s` (GitHub database ID `%d`)\n", markdownText(review.Reviewer.Login), review.Reviewer.DatabaseID)
	fmt.Fprintf(&output, "- Declared role: `%s`\n", review.DeclaredRole)
	fmt.Fprintf(&output, "- Reviewer declares independence: `%t`\n", review.Independent)
	fmt.Fprintf(&output, "- Reviewed at: `%s`\n", review.ReviewedAt)
	fmt.Fprintf(&output, "- Incident / pack: `%s` / `%s`\n", markdownText(review.IncidentID), markdownText(review.PackVersion))
	fmt.Fprintf(&output, "- Candidate commit: `%s`\n\n", review.CandidateCommit)

	output.WriteString("## Conflict disclosure\n\n")
	writeQuoted(&output, review.ConflictDisclosure)
	output.WriteString("\n## Exact bindings\n\n")
	for _, binding := range []struct{ label, value string }{
		{"Candidate-content manifest", review.Bindings.CandidateManifestSHA256},
		{"Original pack", review.Bindings.OriginalPackSHA256},
		{"Canonical pack", review.Bindings.CanonicalPackSHA256},
		{"Claims", review.Bindings.ClaimsSHA256},
		{"Sources", review.Bindings.SourcesSHA256},
		{"Conflicts", review.Bindings.ConflictsSHA256},
		{"Fixture manifest", review.Bindings.FixtureManifestSHA256},
		{"Validator policy", review.Bindings.ValidatorPolicySHA256},
		{"Review policy", review.Bindings.ReviewPolicySHA256},
	} {
		fmt.Fprintf(&output, "- %s SHA-256: `%s`\n", binding.label, binding.value)
	}

	output.WriteString("\n## GitHub review reference\n\n")
	fmt.Fprintf(&output, "- Repository: `%s`\n", markdownText(review.PlatformReview.Repository))
	fmt.Fprintf(&output, "- Pull request: `%d`\n", review.PlatformReview.PullRequestNumber)
	fmt.Fprintf(&output, "- Review database ID: `%d`\n", review.PlatformReview.ReviewDatabaseID)
	fmt.Fprintf(&output, "- Review URL: `%s`\n", markdownText(review.PlatformReview.ReviewURL))
	fmt.Fprintf(&output, "- Material assertion SHA-256: `%s`\n", review.PlatformReview.AssertionSHA256)
	fmt.Fprintf(&output, "- Exact review-body SHA-256: `%s`\n", review.PlatformReview.BodySHA256)

	output.WriteString("\n## Review scope\n\n")
	for _, scope := range review.Scopes {
		fmt.Fprintf(&output, "- `%s`\n", scope)
	}

	output.WriteString("\n## Offline reproduction record\n\n")
	if len(review.Commands) == 0 {
		output.WriteString("No reproduction command was recorded.\n")
	} else {
		for index, command := range review.Commands {
			fmt.Fprintf(&output, "%d. Tool `%s`, version `%s`\n", index+1, markdownText(command.Tool), markdownText(command.Version))
			for _, argument := range command.Arguments {
				fmt.Fprintf(&output, "   - Argument: `%s`\n", markdownText(argument))
			}
		}
	}

	output.WriteString("\n## Source objects checked\n\n")
	if len(review.SourceObjectsChecked) == 0 {
		output.WriteString("No source-object hash was recorded.\n")
	} else {
		for _, object := range review.SourceObjectsChecked {
			fmt.Fprintf(&output, "- `%s`: `%s`\n", markdownText(object.SourceID), object.SHA256)
		}
	}

	output.WriteString("\n## Rationale\n\n")
	writeQuoted(&output, review.Rationale)
	output.WriteString("\n## Known limitations accepted\n\n")
	if len(review.KnownLimitations) == 0 {
		output.WriteString("None recorded.\n")
	} else {
		for _, limitation := range review.KnownLimitations {
			fmt.Fprintf(&output, "- %s\n", markdownText(limitation))
		}
	}
	return output.Bytes(), nil
}

// RenderReviewFile validates canonical review.json and writes only its fixed
// sibling REVIEW.md. It never changes the review decision or any JSON field.
func RenderReviewFile(ctx context.Context, reviewJSON, output string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	review, raw, err := readStrictJSON[Review](ctx, reviewJSON)
	if err != nil {
		return err
	}
	if err := requireCanonicalJSONFile(filepath.Base(reviewJSON), raw, review); err != nil {
		return err
	}
	if filepath.Base(reviewJSON) != "review.json" || filepath.Base(output) != "REVIEW.md" || filepath.Dir(reviewJSON) != filepath.Dir(output) {
		return &ValidationError{Problems: []Problem{{Code: "REVIEW_PATH", Path: output, Message: "REVIEW.md must be the fixed sibling of review.json"}}}
	}
	if filepath.Base(filepath.Dir(reviewJSON)) != review.ReviewID {
		return &ValidationError{Problems: []Problem{{Code: "REVIEW_PATH", Path: reviewJSON, Message: "approval directory name must equal reviewId"}}}
	}
	markdown, err := RenderReview(review)
	if err != nil {
		return err
	}
	return writeAtomicRegular(output, markdown, 0o600)
}

func readReviewDirectory(ctx context.Context, directory string) (Review, []byte, error) {
	review, raw, err := readStrictJSON[Review](ctx, filepath.Join(directory, "review.json"))
	if err != nil {
		return Review{}, nil, err
	}
	if err := requireCanonicalJSONFile("review.json", raw, review); err != nil {
		return Review{}, nil, err
	}
	if filepath.Base(directory) != review.ReviewID {
		return Review{}, nil, &ValidationError{Problems: []Problem{{Code: "REVIEW_PATH", Path: directory, Message: "approval directory name must equal reviewId"}}}
	}
	markdown, err := RenderReview(review)
	if err != nil {
		return Review{}, nil, err
	}
	retained, err := readBoundedRegularContext(ctx, filepath.Join(directory, "REVIEW.md"), 1<<20)
	if err != nil {
		return Review{}, nil, err
	}
	if !bytes.Equal(retained, markdown) {
		return Review{}, nil, &ValidationError{Problems: []Problem{{Code: "REVIEW_MARKDOWN_DRIFT", Path: filepath.Join(directory, "REVIEW.md"), Message: "REVIEW.md does not match deterministic rendering of review.json"}}}
	}
	return review, raw, nil
}

func markdownText(value string) string {
	value = html.EscapeString(value)
	replacer := strings.NewReplacer(
		"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "#", "\\#", "+", "\\+", "-", "\\-", "!", "\\!", "|", "\\|",
	)
	return replacer.Replace(value)
}

func writeQuoted(output *bytes.Buffer, value string) {
	for _, line := range strings.Split(value, "\n") {
		fmt.Fprintf(output, "> %s\n", markdownText(line))
	}
}

func ensureReviewDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &ValidationError{Problems: []Problem{{Code: "REVIEW_DIRECTORY", Path: path, Message: "approval path must be a real directory"}}}
	}
	return nil
}
