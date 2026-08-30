package packreview

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxGovernanceTreeEntries = 100_000
	maxGovernanceTreeFiles   = 75_000
	maxGovernanceTreeDepth   = maxReviewDepth + 3
	maxRegistryTreeIncidents = 10_000
	maxVersionsPerIncident   = 1_000
	maxCandidateCopies       = 10_000
	maxReviewedPacks         = 10_000
)

type governanceTreeLimits struct {
	entries int
	files   int
	depth   int
}

// governanceDirectory follows only repository-relative, fixed path
// components. Every existing component must be a real directory. This keeps a
// review-packets or incidents subtree from escaping through a symlinked
// ancestor while allowing an optional governance subtree to be absent.
func governanceDirectory(repositoryRoot string, components ...string) (string, bool, error) {
	current := repositoryRoot
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return current, false, nil
		}
		if err != nil {
			return current, false, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return current, false, &ValidationError{Problems: []Problem{{
				Code: "GOVERNANCE_TREE_ROOT", Path: current,
				Message: "governance tree root and repository-relative ancestors must be real directories, not links",
			}}}
		}
	}
	return current, true, nil
}

// validateBoundedGovernanceTree performs a bounded, non-following structural
// walk before semantic validation. It is intentionally independent of file
// contents, and therefore also protects baseline governance validation where
// an unregistered candidate commit C is not yet available.
func validateBoundedGovernanceTree(ctx context.Context, root string, limits governanceTreeLimits, allowEmpty func(string) bool) error {
	entries := 0
	files := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		entries++
		if entries > limits.entries {
			return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_ENTRY_COUNT", Path: root, Message: "governance tree entry count exceeds its global bound"}}}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if strings.Count(name, "/")+1 > limits.depth {
			return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_PATH_DEPTH", Path: name, Message: "governance tree path exceeds its depth bound"}}}
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_TREE_ENTRY", Path: name, Message: "governance tree permits only real directories and regular files"}}}
		}
		if info.IsDir() {
			children, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(children) == 0 && (allowEmpty == nil || !allowEmpty(name)) {
				return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_EMPTY_DIRECTORY", Path: name, Message: "empty governance directories are outside the closed tree layout"}}}
			}
			return nil
		}
		files++
		if files > limits.files {
			return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_FILE_COUNT", Path: root, Message: "governance tree file count exceeds its global bound"}}}
		}
		return nil
	})
}

func allowEmptyReviewPacketDirectory(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 3 && parts[2] == "approvals"
}

func allowEmptyCandidateIncidentDirectory(name string) bool {
	return !strings.Contains(name, "/")
}

func validateCandidateCopyCount(count int, path string) error {
	if count <= maxCandidateCopies {
		return nil
	}
	return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_COUNT", Path: path, Message: "candidate copy count exceeds the global bound of 10000"}}}
}

// validateReviewUnitTreeShape closes the portions of a review unit that are
// outside candidate-content's manifest. A pre-review candidate may omit the
// approvals root because Git cannot retain an empty directory. Once review has
// begun, or review/promotion material exists, approvals must be a real
// directory. Any individual approval directory must already have its complete
// two-file shape.
func validateReviewUnitTreeShape(ctx context.Context, root string, preReviewCandidate bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	foundCandidate := false
	foundApprovals := false
	foundReviewMaterial := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(root, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: path, Message: "review-unit entries must not be links"}}}
		}
		switch entry.Name() {
		case "candidate-content":
			foundCandidate = info.IsDir()
			if !foundCandidate {
				return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: path, Message: "candidate-content must be a real directory"}}}
			}
		case "approvals":
			foundApprovals = info.IsDir()
			if !foundApprovals {
				return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: path, Message: "approvals must be a real directory"}}}
			}
		case "promotion-record.json", ReviewManifestName, "platform-approvals.json":
			if !info.Mode().IsRegular() {
				return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: path, Message: "review-unit record entries must be regular files"}}}
			}
			foundReviewMaterial = true
		default:
			return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_UNIT_ENTRY", Path: path, Message: "entry is outside the closed review-unit layout"}}}
		}
	}
	if !foundCandidate {
		return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: root, Message: "review unit requires a real candidate-content directory"}}}
	}
	if !foundApprovals {
		if !preReviewCandidate {
			return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: root, Message: "review unit requires a real approvals directory once review begins"}}}
		}
		if foundReviewMaterial {
			return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_SHAPE", Path: root, Message: "review or promotion material requires a real approvals directory"}}}
		}
	}
	if _, _, err := VerifyCandidateManifest(ctx, filepath.Join(root, "candidate-content")); err != nil {
		return err
	}
	if !foundApprovals {
		return nil
	}
	approvalEntries, err := os.ReadDir(filepath.Join(root, "approvals"))
	if err != nil {
		return err
	}
	if len(approvalEntries) > maxReviewApprovalCount {
		return &ValidationError{Problems: []Problem{{Code: "APPROVAL_COUNT", Path: filepath.Join(root, "approvals"), Message: "approval directory must contain at most 100 review directories"}}}
	}
	for _, approval := range approvalEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		approvalRoot := filepath.Join(root, "approvals", approval.Name())
		if approval.Type()&os.ModeSymlink != 0 || !approval.IsDir() || !stableIDRE.MatchString(approval.Name()) || !safeFilenameComponent(approval.Name()) {
			return &ValidationError{Problems: []Problem{{Code: "APPROVAL_PATH", Path: approvalRoot, Message: "approval entry must be a safe real directory"}}}
		}
		children, err := os.ReadDir(approvalRoot)
		if err != nil {
			return err
		}
		if len(children) != 2 || children[0].Name() != "REVIEW.md" || children[1].Name() != "review.json" {
			return &ValidationError{Problems: []Problem{{Code: "APPROVAL_FILE_SET", Path: approvalRoot, Message: "approval directory must contain exactly REVIEW.md and review.json"}}}
		}
		for _, child := range children {
			info, err := child.Info()
			if err != nil {
				return err
			}
			if child.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return &ValidationError{Problems: []Problem{{Code: "APPROVAL_FILE_SET", Path: filepath.Join(approvalRoot, child.Name()), Message: "approval records must be regular files"}}}
			}
		}
	}
	return nil
}
