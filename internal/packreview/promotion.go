package packreview

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// maxRecordedPromotionInterval is a structural chronology bound between two
// retained record fields. It is not a trusted wall-clock freshness proof: the
// external workflow/run review remains the authenticity and timeliness gate.
const maxRecordedPromotionInterval = 15 * time.Minute

// Promote copies exact approved bytes and writes deterministic promotion
// records. It does not edit Git, commit, push, tag, or mutate the registry.
func Promote(ctx context.Context, options PromotionOptions) (PromotionRecord, error) {
	if err := ctx.Err(); err != nil {
		return PromotionRecord{}, err
	}
	repositoryRoot, err := safeRoot(options.RepositoryRoot)
	if err != nil {
		return PromotionRecord{}, err
	}
	currentPolicy, currentPolicyRaw, err := readStrictJSON[ReviewPolicy](ctx, filepath.Join(repositoryRoot, "pack-review-policy.json"))
	if err != nil {
		return PromotionRecord{}, err
	}
	if err := requireCanonicalJSONFile("pack-review-policy.json", currentPolicyRaw, currentPolicy); err != nil {
		return PromotionRecord{}, err
	}
	var currentPolicyValidation problems
	validateReviewPolicy(currentPolicy, &currentPolicyValidation)
	if err := currentPolicyValidation.err(); err != nil {
		return PromotionRecord{}, err
	}
	unit, err := ValidateUnit(ctx, options.ReviewUnitRoot, options.CandidateCommit)
	if err != nil {
		return PromotionRecord{}, err
	}
	wantRoot := reviewUnitPath(repositoryRoot, unit.Pack.IncidentID, unit.Pack.PackVersion)
	if !sameCleanPath(unit.Root, wantRoot) {
		return PromotionRecord{}, &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_PATH", Path: unit.Root, Message: "review unit is not below the explicit repository root"}}}
	}
	fixedPlatformSnapshot := filepath.Join(unit.Root, "platform-approvals.json")
	if !sameCleanPath(options.PlatformSnapshot, fixedPlatformSnapshot) {
		return PromotionRecord{}, &ValidationError{Problems: []Problem{{Code: "PLATFORM_SNAPSHOT_PATH", Path: options.PlatformSnapshot, Message: "promotion requires the retained review-unit platform-approvals.json"}}}
	}
	if digestHex(currentPolicyRaw) != unit.Pack.ReviewPolicySHA256 {
		return PromotionRecord{}, &ValidationError{Problems: []Problem{{
			Code: "PROMOTION_POLICY_STALE", Path: "/reviewPolicySha256",
			Message: "promotion requires the candidate to retain the exact current repository review policy",
		}}}
	}
	result, err := CheckApprovals(ctx, options.ReviewUnitRoot, options.CandidateCommit, options.CandidateManifest, options.PlatformSnapshot)
	if err != nil {
		return PromotionRecord{}, err
	}
	platformRecord, platformSnapshot, err := readStrictJSON[PlatformApprovalSnapshot](ctx, options.PlatformSnapshot)
	if err != nil {
		return PromotionRecord{}, err
	}
	if err := requireCanonicalJSONFile("platform-approvals.json", platformSnapshot, platformRecord); err != nil {
		return PromotionRecord{}, err
	}
	platformSnapshotHash := digestHex(platformSnapshot)
	var validation problems
	validateTime(options.PromotedAt, "/promotedAt", &validation)
	validatePromotionSnapshotChronology(platformRecord.ObservedAt, options.PromotedAt, &validation)
	record := PromotionRecord{
		SchemaVersion:           PromotionSchema,
		IncidentID:              unit.Pack.IncidentID,
		PackVersion:             unit.Pack.PackVersion,
		Status:                  "reviewed",
		CandidateCommit:         options.CandidateCommit,
		CandidateManifestSHA256: unit.CandidateManifestSHA256,
		OriginalPackSHA256:      unit.Pack.OriginalPackSHA256,
		CanonicalPackSHA256:     unit.Pack.CanonicalPackSHA256,
		ReviewedPath:            slashReviewedPackPath(unit.Pack.IncidentID, unit.Pack.PackVersion),
		ApprovalIDs:             append([]string(nil), result.QualifyingApprovalIDs...),
		PlatformSnapshotSHA256:  platformSnapshotHash,
		ReviewPolicyProfile:     unit.Pack.ReviewPolicyProfile,
		ReviewPolicySHA256:      unit.Pack.ReviewPolicySHA256,
		PromotedAt:              options.PromotedAt,
	}
	validatePromotion(record, &validation)
	if err := validation.err(); err != nil {
		return PromotionRecord{}, err
	}
	recordBytes, err := marshalCanonical(record)
	if err != nil {
		return PromotionRecord{}, err
	}
	reviewManifest, err := buildReviewManifestWithPromotion(ctx, unit.Root, recordBytes)
	if err != nil {
		return PromotionRecord{}, err
	}
	packBytes, err := readBoundedRegularContext(ctx, filepath.Join(unit.CandidateContent, "pack.yaml"), maxReviewFileBytes)
	if err != nil {
		return PromotionRecord{}, err
	}

	reviewedPath := reviewedPackPath(repositoryRoot, unit.Pack.IncidentID, unit.Pack.PackVersion)
	promotionPath := filepath.Join(unit.Root, "promotion-record.json")
	manifestPath := filepath.Join(unit.Root, ReviewManifestName)
	for _, sourcePath := range []string{
		filepath.Join(unit.CandidateContent, "pack.yaml"),
		candidatePackPath(repositoryRoot, unit.Pack.IncidentID, unit.Pack.PackVersion),
	} {
		if err := rejectExistingFileAlias(reviewedPath, sourcePath); err != nil {
			return PromotionRecord{}, err
		}
	}
	for _, target := range []struct {
		path string
		data []byte
	}{{reviewedPath, packBytes}, {promotionPath, recordBytes}, {manifestPath, reviewManifest}} {
		if err := preflightNewOrExact(target.path, target.data); err != nil {
			return PromotionRecord{}, err
		}
	}
	if err := mkdirRelativeNoLinks(repositoryRoot, filepath.Join("incidents", "reviewed", unit.Pack.IncidentID)); err != nil {
		return PromotionRecord{}, err
	}

	var created []string
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			_ = os.Remove(created[index])
		}
	}
	for _, target := range []struct {
		path string
		data []byte
	}{{reviewedPath, packBytes}, {promotionPath, recordBytes}, {manifestPath, reviewManifest}} {
		wasCreated, err := writeNewOrExact(target.path, target.data, 0o644)
		if err != nil {
			rollback()
			return PromotionRecord{}, err
		}
		if wasCreated {
			created = append(created, target.path)
		}
	}
	if _, manifestHash, err := verifyReviewManifest(ctx, unit.Root); err != nil {
		rollback()
		return PromotionRecord{}, err
	} else if manifestHash == "" {
		rollback()
		return PromotionRecord{}, errors.New("review-record manifest hash is empty")
	}
	retainedPack, err := readBoundedRegularContext(ctx, reviewedPath, maxReviewFileBytes)
	if err != nil || !bytes.Equal(retainedPack, packBytes) {
		rollback()
		return PromotionRecord{}, errors.New("reviewed pack copy changed during promotion verification")
	}
	for _, sourcePath := range []string{
		filepath.Join(unit.CandidateContent, "pack.yaml"),
		candidatePackPath(repositoryRoot, unit.Pack.IncidentID, unit.Pack.PackVersion),
	} {
		if err := rejectExistingFileAlias(reviewedPath, sourcePath); err != nil {
			rollback()
			return PromotionRecord{}, err
		}
	}
	return record, nil
}

func validatePromotionSnapshotChronology(observedAt, promotedAt string, p *problems) {
	observed, observeErr := time.Parse(time.RFC3339Nano, observedAt)
	promoted, promoteErr := time.Parse(time.RFC3339Nano, promotedAt)
	if observeErr != nil || promoteErr != nil {
		return
	}
	if promoted.Before(observed) {
		p.add("PROMOTION_TIME_ORDER", "/promotedAt", "promotion cannot predate the platform observation")
		return
	}
	if promoted.Sub(observed) > maxRecordedPromotionInterval {
		p.add("PROMOTION_INTERVAL", "/promotedAt", "recorded promotion time must be within %s of recorded platform observation time; this is not a wall-clock freshness proof", maxRecordedPromotionInterval)
	}
}

func preflightNewOrExact(path string, want []byte) error {
	got, err := readBoundedRegular(path, int64(len(want))+1)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return &ValidationError{Problems: []Problem{{Code: "IMMUTABLE_OUTPUT_EXISTS", Path: path, Message: "existing promotion output differs; refusing overwrite"}}}
	}
	return nil
}

func rejectExistingFileAlias(path, sourcePath string) error {
	target, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	source, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if os.SameFile(target, source) {
		return &ValidationError{Problems: []Problem{{
			Code: "PROMOTION_OUTPUT_ALIAS", Path: path,
			Message: "reviewed pack must be a physically distinct file from candidate inputs",
		}}}
	}
	return nil
}

func writeNewOrExact(path string, data []byte, mode os.FileMode) (bool, error) {
	if err := preflightNewOrExact(path, data); err != nil {
		return false, err
	}
	if got, err := readBoundedRegular(path, int64(len(data))+1); err == nil && bytes.Equal(got, data) {
		return false, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return false, err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = errors.New("short write")
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return false, err
	}
	return true, nil
}

func mkdirRelativeNoLinks(root, relative string) error {
	current := root
	for _, component := range splitPath(relative) {
		if !safeFilenameComponent(component) {
			return &ValidationError{Problems: []Problem{{Code: "DIRECTORY_PATH", Path: relative, Message: "unsafe directory component"}}}
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &ValidationError{Problems: []Problem{{Code: "DIRECTORY_LINK", Path: current, Message: "promotion directory ancestor is not a real directory"}}}
		}
	}
	return nil
}

func splitPath(value string) []string {
	clean := filepath.Clean(value)
	if clean == "." {
		return nil
	}
	var result []string
	for clean != "." && clean != string(filepath.Separator) {
		directory, base := filepath.Split(clean)
		result = append([]string{base}, result...)
		clean = filepath.Clean(directory)
	}
	return result
}
