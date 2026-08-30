package packreview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/incident"
)

// VerifyRegistry validates append-only status history and exact promoted
// content. promotionContentCommit is the externally supplied P being checked;
// the registry never names its own containing commit.
func VerifyRegistry(ctx context.Context, repositoryRoot, promotionContentCommit string) error {
	var initial problems
	validateCommit(promotionContentCommit, "/promotionContentCommit", &initial)
	if err := initial.err(); err != nil {
		return err
	}
	return validateGovernance(ctx, repositoryRoot, promotionContentCommit, "")
}

// ValidateGovernance validates the checked-in policy, append-only registry,
// and reviewed tree even when no reviewed pack exists yet. It does not assert
// an external Git commit or any factual review.
func ValidateGovernance(ctx context.Context, repositoryRoot string) error {
	return validateGovernance(ctx, repositoryRoot, "", "")
}

// ValidateCandidateTree validates every retained review unit while binding any
// not-yet-registered candidate to an externally supplied exact Git commit. The
// caller must separately prove that its worktree is at candidateCommit; keeping
// that Git check outside this package avoids hidden process execution and a
// candidate-commit self-reference in repository content.
func ValidateCandidateTree(ctx context.Context, repositoryRoot, candidateCommit string) error {
	var initial problems
	validateCommit(candidateCommit, "/candidateCommit", &initial)
	if err := initial.err(); err != nil {
		return err
	}
	return validateGovernance(ctx, repositoryRoot, "", candidateCommit)
}

func validateGovernance(ctx context.Context, repositoryRoot, requiredPromotionCommit, unregisteredCandidateCommit string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := safeRoot(repositoryRoot)
	if err != nil {
		return err
	}
	policy, policyRaw, err := readStrictJSON[ReviewPolicy](ctx, filepath.Join(root, "pack-review-policy.json"))
	if err != nil {
		return err
	}
	if err := requireCanonicalJSONFile("pack-review-policy.json", policyRaw, policy); err != nil {
		return err
	}
	registry, registryRaw, err := readStrictJSON[Registry](ctx, filepath.Join(root, "review-registry.json"))
	if err != nil {
		return err
	}
	if err := requireCanonicalJSONFile("review-registry.json", registryRaw, registry); err != nil {
		return err
	}
	var validation problems
	validateReviewPolicy(policy, &validation)
	validateRegistry(registry, &validation)
	// The registry supplies identifiers and reviewed paths used below to derive
	// filesystem locations. Never continue into tree traversal or promoted-record
	// verification with semantically invalid governance data: validation errors
	// must be a precondition failure, not merely diagnostics recorded after an
	// attacker-controlled path has already been dereferenced.
	if err := validation.err(); err != nil {
		return err
	}
	policyHash := digestHex(policyRaw)
	foundCommit := false
	referencedReviewedPaths := map[string]struct{}{}
	verifiedVersion := map[string]struct{}{}
	for _, record := range registry.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if requiredPromotionCommit != "" && record.PromotionContentCommit == requiredPromotionCommit {
			foundCommit = true
		}
		if record.PromotionContentCommit == "" {
			continue
		}
		key := record.IncidentID + "\x00" + record.PackVersion
		if _, already := verifiedVersion[key]; already {
			continue
		}
		verifiedVersion[key] = struct{}{}
		referencedReviewedPaths[record.ReviewedPath] = struct{}{}
		verifyPromotedRecord(ctx, root, record, &validation)
	}
	if requiredPromotionCommit != "" && !foundCommit {
		validation.add("PROMOTION_COMMIT_ABSENT", "/promotionContentCommit", "registry has no promoted event for the supplied content commit")
	}
	if err := validateReviewedTree(ctx, root, referencedReviewedPaths); err != nil {
		return err
	}
	if err := validateCandidateReviewUnits(ctx, root, registry, unregisteredCandidateCommit, policyHash, &validation); err != nil {
		return err
	}
	return validation.err()
}

func validateCandidateReviewUnits(ctx context.Context, root string, registry Registry, unregisteredCandidateCommit, currentPolicyHash string, p *problems) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	latest := make(map[string]RegistryRecord)
	for _, record := range registry.Records {
		latest[record.IncidentID+"\x00"+record.PackVersion] = record
	}
	packetsRoot, exists, err := governanceDirectory(root, "review-packets")
	if err != nil {
		return err
	}
	if !exists {
		for _, key := range sortedRegistryKeys(latest) {
			record := latest[key]
			if record.CandidateCommit != "" {
				p.add("MISSING_REVIEW_PACKET", "/review-packets", "registry candidate %s has no retained review unit", strings.ReplaceAll(key, "\x00", "/"))
			}
		}
		return validateCandidateCopyTree(ctx, root, map[string]struct{}{})
	}
	if err := validateBoundedGovernanceTree(ctx, packetsRoot, governanceTreeLimits{
		entries: maxGovernanceTreeEntries,
		files:   maxGovernanceTreeFiles,
		depth:   maxGovernanceTreeDepth,
	}, allowEmptyReviewPacketDirectory); err != nil {
		return err
	}
	incidentEntries, err := os.ReadDir(packetsRoot)
	if err != nil {
		return err
	}
	if len(incidentEntries) == 0 || len(incidentEntries) > maxRegistryTreeIncidents {
		return &ValidationError{Problems: []Problem{{Code: "REVIEW_PACKET_COUNT", Path: packetsRoot, Message: "review-packets must contain 1-10000 incident directories"}}}
	}
	seen := make(map[string]struct{})
	for _, incidentEntry := range incidentEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !incidentEntry.IsDir() || incidentEntry.Type()&os.ModeSymlink != 0 || !stableIDRE.MatchString(incidentEntry.Name()) || !safeFilenameComponent(incidentEntry.Name()) {
			return &ValidationError{Problems: []Problem{{Code: "REVIEW_PACKET_PATH", Path: filepath.Join(packetsRoot, incidentEntry.Name()), Message: "review packet incident path must be a safe real directory"}}}
		}
		incidentRoot := filepath.Join(packetsRoot, incidentEntry.Name())
		versionEntries, err := os.ReadDir(incidentRoot)
		if err != nil {
			return err
		}
		if len(versionEntries) == 0 || len(versionEntries) > maxVersionsPerIncident {
			return &ValidationError{Problems: []Problem{{Code: "REVIEW_PACKET_VERSION_COUNT", Path: incidentRoot, Message: "review packet incident must contain 1-1000 version directories"}}}
		}
		for _, versionEntry := range versionEntries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(seen) >= maxCandidateCopies {
				return &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_COUNT", Path: packetsRoot, Message: "review unit count exceeds 10000"}}}
			}
			version := versionEntry.Name()
			unitRoot := filepath.Join(incidentRoot, version)
			if !versionEntry.IsDir() || versionEntry.Type()&os.ModeSymlink != 0 || !validSemVer(version) || !safeFilenameComponent(version) {
				return &ValidationError{Problems: []Problem{{Code: "REVIEW_PACKET_PATH", Path: unitRoot, Message: "review packet version path must be a canonical SemVer real directory"}}}
			}
			key := incidentEntry.Name() + "\x00" + version
			seen[key] = struct{}{}
			record, registered := latest[key]
			// A retained review unit with no registered candidate identity is an
			// unregistered candidate whose C may be supplied by candidate CI. Git
			// cannot retain its otherwise-empty approvals directory. A registered
			// candidate is likewise still pre-review; every later state requires
			// the approvals root even before deeper policy validation.
			preReviewCandidate := !registered || record.CandidateCommit == "" || record.Status == "candidate"
			if err := validateReviewUnitTreeShape(ctx, unitRoot, preReviewCandidate); err != nil {
				p.add("INVALID_CANDIDATE_REVIEW_UNIT", "/review-packets/"+incidentEntry.Name()+"/"+version, "candidate review unit has an invalid or incomplete closed tree layout")
				continue
			}
			candidateCommit := record.CandidateCommit
			if !registered || candidateCommit == "" {
				candidateCommit = unregisteredCandidateCommit
			}
			// An unregistered candidate cannot contain its own Git identity without
			// a hash cycle. Baseline governance therefore leaves it unasserted;
			// candidate CI supplies C from the exact checked-out Git worktree.
			if candidateCommit == "" {
				continue
			}
			unit, err := ValidateUnit(ctx, unitRoot, candidateCommit)
			if err != nil {
				p.add("INVALID_CANDIDATE_REVIEW_UNIT", "/review-packets/"+incidentEntry.Name()+"/"+version, "candidate review unit does not validate against its registry commit")
				continue
			}
			if registered && record.CandidateCommit != "" && record.ReviewPolicySHA256 != unit.Pack.ReviewPolicySHA256 {
				p.add("REGISTRY_CANDIDATE_POLICY_DRIFT", "/review-packets/"+incidentEntry.Name()+"/"+version, "registry review policy identity disagrees with the retained candidate policy")
			}
			activePrePromotion := !registered || record.CandidateCommit == "" || record.Status == "candidate" || record.Status == "review_in_progress"
			if activePrePromotion && unit.Pack.ReviewPolicySHA256 != currentPolicyHash {
				p.add("CANDIDATE_POLICY_STALE", "/review-packets/"+incidentEntry.Name()+"/"+version, "active unpromoted candidate must retain the exact current repository review policy")
			}
		}
	}
	if err := validateCandidateCopyTree(ctx, root, seen); err != nil {
		return err
	}
	for _, key := range sortedRegistryKeys(latest) {
		record := latest[key]
		if record.CandidateCommit == "" {
			continue
		}
		if _, retained := seen[key]; !retained {
			p.add("MISSING_REVIEW_PACKET", "/review-packets", "registry candidate %s has no retained review unit", strings.ReplaceAll(key, "\x00", "/"))
		}
	}
	return nil
}

func sortedRegistryKeys(records map[string]RegistryRecord) []string {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validateCandidateCopyTree(ctx context.Context, root string, expected map[string]struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	incidentsRoot, incidentsExist, err := governanceDirectory(root, "incidents")
	if err != nil {
		return err
	}
	candidatesRoot := filepath.Join(incidentsRoot, "candidates")
	if !incidentsExist {
		if len(expected) == 0 {
			return nil
		}
		return &ValidationError{Problems: []Problem{{Code: "MISSING_CANDIDATE_COPY", Path: candidatesRoot, Message: "review units require byte-identical incident candidate copies"}}}
	}
	candidatesRoot, candidatesExist, err := governanceDirectory(root, "incidents", "candidates")
	if err != nil {
		return err
	}
	if !candidatesExist {
		if len(expected) == 0 {
			return nil
		}
		return &ValidationError{Problems: []Problem{{Code: "MISSING_CANDIDATE_COPY", Path: candidatesRoot, Message: "review units require byte-identical incident candidate copies"}}}
	}
	if err := validateBoundedGovernanceTree(ctx, candidatesRoot, governanceTreeLimits{
		entries: maxCandidateCopies + maxRegistryTreeIncidents,
		files:   maxCandidateCopies,
		depth:   2,
	}, allowEmptyCandidateIncidentDirectory); err != nil {
		return err
	}
	incidentEntries, err := os.ReadDir(candidatesRoot)
	if err != nil {
		return err
	}
	if len(incidentEntries) == 0 || len(incidentEntries) > maxRegistryTreeIncidents {
		return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_COUNT", Path: candidatesRoot, Message: "candidate tree must contain 1-10000 incident directories"}}}
	}
	found := make(map[string]struct{}, len(expected))
	copyCount := 0
	for _, incidentEntry := range incidentEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		incidentID := incidentEntry.Name()
		incidentRoot := filepath.Join(candidatesRoot, incidentID)
		if !incidentEntry.IsDir() || incidentEntry.Type()&os.ModeSymlink != 0 || !stableIDRE.MatchString(incidentID) || !safeFilenameComponent(incidentID) {
			return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_PATH", Path: incidentRoot, Message: "candidate incident path must be a safe real directory"}}}
		}
		versions, err := os.ReadDir(incidentRoot)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			prefix := incidentID + "\x00"
			for _, key := range sortedSetKeys(expected) {
				if strings.HasPrefix(key, prefix) {
					return &ValidationError{Problems: []Problem{{Code: "MISSING_CANDIDATE_COPY", Path: incidentRoot, Message: "review unit has no matching incident candidate copy for " + strings.ReplaceAll(key, "\x00", "/")}}}
				}
			}
			return &ValidationError{Problems: []Problem{{Code: "GOVERNANCE_EMPTY_DIRECTORY", Path: incidentRoot, Message: "empty candidate incident directories are outside the closed tree layout"}}}
		}
		if len(versions) > maxVersionsPerIncident {
			return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_COUNT", Path: incidentRoot, Message: "candidate incident directory must contain 1-1000 version files"}}}
		}
		for _, entry := range versions {
			if err := ctx.Err(); err != nil {
				return err
			}
			copyCount++
			if err := validateCandidateCopyCount(copyCount, candidatesRoot); err != nil {
				return err
			}
			path := filepath.Join(incidentRoot, entry.Name())
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".yaml" {
				return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_PATH", Path: path, Message: "candidate copy must be a regular identifier-derived YAML file"}}}
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			version := strings.TrimSuffix(entry.Name(), ".yaml")
			if !info.Mode().IsRegular() || !validSemVer(version) || !safeFilenameComponent(entry.Name()) {
				return &ValidationError{Problems: []Problem{{Code: "CANDIDATE_COPY_PATH", Path: path, Message: "candidate copy must use a canonical SemVer filename and be a regular file"}}}
			}
			key := incidentID + "\x00" + version
			if _, ok := expected[key]; !ok {
				return &ValidationError{Problems: []Problem{{Code: "ORPHAN_CANDIDATE_COPY", Path: path, Message: "candidate copy has no matching retained review unit"}}}
			}
			found[key] = struct{}{}
		}
	}
	missing := make([]string, 0, len(expected))
	for key := range expected {
		if _, ok := found[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return &ValidationError{Problems: []Problem{{Code: "MISSING_CANDIDATE_COPY", Path: candidatesRoot, Message: "review unit has no matching incident candidate copy for " + strings.ReplaceAll(missing[0], "\x00", "/")}}}
	}
	return nil
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func verifyPromotedRecord(ctx context.Context, root string, record RegistryRecord, p *problems) {
	base := "/registry/" + record.RecordID
	unitRoot := reviewUnitPath(root, record.IncidentID, record.PackVersion)
	unit, err := ValidateUnit(ctx, unitRoot, record.CandidateCommit)
	if err != nil {
		p.add("REGISTRY_REVIEW_UNIT", base, "referenced review unit does not validate")
		return
	}
	promotion, raw, err := readStrictJSON[PromotionRecord](ctx, filepath.Join(unitRoot, "promotion-record.json"))
	if err != nil {
		p.add("REGISTRY_PROMOTION", base, "promotion record is missing or invalid")
		return
	}
	if err := requireCanonicalJSONFile("promotion-record.json", raw, promotion); err != nil {
		p.add("REGISTRY_PROMOTION", base, "promotion record is not canonical")
		return
	}
	validatePromotion(promotion, p)
	_, reviewManifestHash, err := verifyReviewManifest(ctx, unitRoot)
	if err != nil {
		p.add("REGISTRY_REVIEW_MANIFEST", base, "review-record manifest does not verify")
		return
	}
	if promotion.IncidentID != record.IncidentID || promotion.PackVersion != record.PackVersion ||
		promotion.CandidateCommit != record.CandidateCommit || promotion.CandidateManifestSHA256 != record.CandidateManifestSHA256 ||
		promotion.OriginalPackSHA256 != record.OriginalPackSHA256 || promotion.CanonicalPackSHA256 != record.CanonicalPackSHA256 ||
		promotion.ReviewedPath != record.ReviewedPath || promotion.ReviewPolicyProfile != record.ReviewPolicyProfile ||
		promotion.ReviewPolicySHA256 != record.ReviewPolicySHA256 || !equalStrings(promotion.ApprovalIDs, record.ApprovalIDs) {
		p.add("REGISTRY_PROMOTION_DRIFT", base, "registry identity disagrees with immutable promotion record")
	}
	platformPath := filepath.Join(unitRoot, "platform-approvals.json")
	policyResult, approvalErr := CheckApprovals(ctx, unitRoot, record.CandidateCommit, record.CandidateManifestSHA256, platformPath)
	if approvalErr != nil {
		p.add("REGISTRY_APPROVAL_REVALIDATION", base, "retained approval records and platform snapshot no longer satisfy policy")
	} else if !equalStrings(policyResult.QualifyingApprovalIDs, promotion.ApprovalIDs) {
		p.add("REGISTRY_APPROVAL_DRIFT", base, "revalidated qualifying approval IDs disagree with promotion")
	}
	platformRecord, platformBytes, platformErr := readStrictJSON[PlatformApprovalSnapshot](ctx, platformPath)
	if platformErr != nil || digestHex(platformBytes) != promotion.PlatformSnapshotSHA256 {
		p.add("REGISTRY_PLATFORM_SNAPSHOT", base, "retained platform snapshot hash disagrees with promotion")
	} else {
		validatePromotionSnapshotChronology(platformRecord.ObservedAt, promotion.PromotedAt, p)
	}
	if reviewManifestHash != record.ReviewRecordManifestSHA256 {
		p.add("REGISTRY_MANIFEST_HASH", base+"/reviewRecordManifestSha256", "does not match exact review-record manifest bytes")
	}
	if unit.CandidateManifestSHA256 != record.CandidateManifestSHA256 || unit.Pack.ReviewPolicySHA256 != record.ReviewPolicySHA256 {
		p.add("REGISTRY_CANDIDATE_DRIFT", base, "candidate content or retained policy changed after review")
	}
	reviewedBytes, err := readBoundedRegularContext(ctx, filepath.Join(root, filepath.FromSlash(record.ReviewedPath)), incident.MaxPackBytes)
	if err != nil {
		p.add("REGISTRY_REVIEWED_PACK", base+"/reviewedPath", "reviewed pack is missing or unreadable")
		return
	}
	candidateBytes, err := readBoundedRegularContext(ctx, filepath.Join(unit.CandidateContent, "pack.yaml"), incident.MaxPackBytes)
	if err != nil || !bytes.Equal(reviewedBytes, candidateBytes) {
		p.add("REGISTRY_REVIEWED_PACK_DRIFT", base+"/reviewedPath", "reviewed pack is not byte-identical to approved candidate")
	}
	validated, err := incident.ValidateForPolicy(ctx, reviewedBytes, unit.Pack.ValidatorVersion)
	if err != nil || validated.OriginalSHA256 != record.OriginalPackSHA256 || validated.CanonicalSHA256 != record.CanonicalPackSHA256 {
		p.add("REGISTRY_PACK_HASH", base+"/reviewedPath", "reviewed pack hashes do not match registry")
	}
}

func validateReviewedTree(ctx context.Context, root string, referenced map[string]struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	incidentsRoot, incidentsExist, err := governanceDirectory(root, "incidents")
	if err != nil {
		return err
	}
	reviewedRoot := filepath.Join(incidentsRoot, "reviewed")
	if !incidentsExist {
		if len(referenced) == 0 {
			return nil
		}
		return &ValidationError{Problems: []Problem{{Code: "MISSING_REVIEWED_PACK", Path: reviewedRoot, Message: "registry references reviewed packs but the reviewed tree is absent"}}}
	}
	reviewedRoot, reviewedExists, err := governanceDirectory(root, "incidents", "reviewed")
	if err != nil {
		return err
	}
	if !reviewedExists {
		if len(referenced) == 0 {
			return nil
		}
		return &ValidationError{Problems: []Problem{{Code: "MISSING_REVIEWED_PACK", Path: reviewedRoot, Message: "registry references reviewed packs but the reviewed tree is absent"}}}
	}
	if err := validateBoundedGovernanceTree(ctx, reviewedRoot, governanceTreeLimits{
		entries: maxReviewedPacks + maxRegistryTreeIncidents,
		files:   maxReviewedPacks,
		depth:   2,
	}, nil); err != nil {
		return err
	}
	incidentEntries, err := os.ReadDir(reviewedRoot)
	if err != nil {
		return err
	}
	if len(incidentEntries) == 0 || len(incidentEntries) > maxRegistryTreeIncidents {
		return &ValidationError{Problems: []Problem{{Code: "REVIEWED_TREE_COUNT", Path: reviewedRoot, Message: "reviewed tree must contain 1-10000 incident directories"}}}
	}
	seen := map[string]struct{}{}
	packCount := 0
	for _, incidentEntry := range incidentEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		incidentID := incidentEntry.Name()
		incidentRoot := filepath.Join(reviewedRoot, incidentID)
		if incidentEntry.Type()&os.ModeSymlink != 0 || !incidentEntry.IsDir() || !stableIDRE.MatchString(incidentID) || !safeFilenameComponent(incidentID) {
			return &ValidationError{Problems: []Problem{{Code: "REVIEWED_TREE_PATH", Path: incidentRoot, Message: "reviewed incident path must be a safe real directory"}}}
		}
		versions, err := os.ReadDir(incidentRoot)
		if err != nil {
			return err
		}
		if len(versions) == 0 || len(versions) > maxVersionsPerIncident {
			return &ValidationError{Problems: []Problem{{Code: "REVIEWED_TREE_COUNT", Path: incidentRoot, Message: "reviewed incident directory must contain 1-1000 version files"}}}
		}
		for _, entry := range versions {
			if err := ctx.Err(); err != nil {
				return err
			}
			packCount++
			if packCount > maxReviewedPacks {
				return &ValidationError{Problems: []Problem{{Code: "REVIEWED_TREE_COUNT", Path: reviewedRoot, Message: "reviewed pack count exceeds the global bound of 10000"}}}
			}
			path := filepath.Join(incidentRoot, entry.Name())
			info, err := entry.Info()
			if err != nil {
				return err
			}
			version := strings.TrimSuffix(entry.Name(), ".yaml")
			if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || filepath.Ext(entry.Name()) != ".yaml" || !validSemVer(version) || !safeFilenameComponent(entry.Name()) {
				return &ValidationError{Problems: []Problem{{Code: "REVIEWED_TREE_PATH", Path: path, Message: "reviewed pack must use a canonical SemVer filename and be a regular YAML file"}}}
			}
			name := filepath.ToSlash(filepath.Join("incidents", "reviewed", incidentID, entry.Name()))
			if _, ok := referenced[name]; !ok {
				return &ValidationError{Problems: []Problem{{Code: "UNREGISTERED_REVIEWED_PACK", Path: name, Message: "reviewed pack is absent from append-only registry history"}}}
			}
			seen[name] = struct{}{}
		}
	}
	missing := make([]string, 0, len(referenced))
	for name := range referenced {
		if _, ok := seen[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return &ValidationError{Problems: []Problem{{Code: "MISSING_REVIEWED_PACK", Path: missing[0], Message: "registry references a missing reviewed pack"}}}
	}
	return nil
}
