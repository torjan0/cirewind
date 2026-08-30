package packreview

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateUnitRejectsArchiveTraversalBeforeDereference(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	outOfTree := filepath.Join(filepath.Dir(repo.unit), "synthetic-out-of-tree-source.txt")
	mustWrite(t, outOfTree, []byte("synthetic marker outside candidate-content\n"))

	sources := repo.unitValue.Sources
	sources.Sources = append([]SourceRecord(nil), sources.Sources...)
	sources.Sources[0].ArchivePath = "fixtures/../../../synthetic-out-of-tree-source.txt"
	sourcesRaw := mustCanonical(t, sources)
	mustWrite(t, filepath.Join(repo.candidate, "sources.json"), sourcesRaw)

	packet := repo.unitValue.Pack
	packet.SourcesSHA256 = digestHex(sourcesRaw)
	mustWrite(t, filepath.Join(repo.candidate, "packet.json"), mustCanonical(t, packet))
	if _, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}

	_, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit)
	assertProblemCode(t, err, "SAFE_PATH")
	assertNoProblemCode(t, err, "SOURCE_ARCHIVE_LENGTH")
	assertNoProblemCode(t, err, "SOURCE_ARCHIVE_HASH")
	assertNoProblemCode(t, err, "SOURCE_ARCHIVE_MISSING")
}

func TestValidateUnitRejectsUnsafePacketIdentityBeforeCandidateCopyDereference(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	packet := repo.unitValue.Pack
	packet.IncidentID = "../synthetic-escaped-incident"
	mustWrite(t, filepath.Join(repo.candidate, "packet.json"), mustCanonical(t, packet))
	if _, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}

	escapedCopy := candidatePackPath(repo.root, packet.IncidentID, packet.PackVersion)
	mustMkdir(t, filepath.Dir(escapedCopy))
	if err := os.Link(filepath.Join(repo.candidate, "pack.yaml"), escapedCopy); err != nil {
		t.Fatal(err)
	}

	_, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit)
	assertProblemCode(t, err, "SAFE_ID")
	assertNoProblemCode(t, err, "CANDIDATE_COPY_HARDLINK")
}

func TestVerifyRegistryRejectsPathBearingFieldsBeforeDereference(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Registry)
		code   string
	}{
		{
			name: "reviewed path",
			mutate: func(registry *Registry) {
				registry.Records[len(registry.Records)-1].ReviewedPath = "../synthetic-out-of-tree-pack.yaml"
			},
			code: "REVIEWED_PATH",
		},
		{
			name: "incident identifier",
			mutate: func(registry *Registry) {
				for index := range registry.Records {
					registry.Records[index].IncidentID = "../synthetic-escaped-incident"
				}
				reviewed := &registry.Records[len(registry.Records)-1]
				reviewed.ReviewedPath = slashReviewedPackPath(reviewed.IncidentID, reviewed.PackVersion)
			},
			code: "SAFE_ID",
		},
		{
			name: "pack version",
			mutate: func(registry *Registry) {
				for index := range registry.Records {
					registry.Records[index].PackVersion = "../synthetic-escaped-version"
				}
				reviewed := &registry.Records[len(registry.Records)-1]
				reviewed.ReviewedPath = slashReviewedPackPath(reviewed.IncidentID, reviewed.PackVersion)
			},
			code: "PACK_VERSION",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			registry, promotionCommit := syntheticPromotedRegistry(t, &repo)
			test.mutate(&registry)
			mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, registry))

			err := VerifyRegistry(context.Background(), repo.root, promotionCommit)
			assertProblemCode(t, err, test.code)
			assertNoProblemCode(t, err, "REGISTRY_REVIEW_UNIT")
			assertNoProblemCode(t, err, "REGISTRY_REVIEWED_PACK")
		})
	}
}

func syntheticPromotedRegistry(t *testing.T, repo *syntheticReviewRepo) (Registry, string) {
	t.Helper()
	addSyntheticApprovals(t, repo, 1)
	promotionCommit := stringOf('e', 40)
	promotion, err := Promote(context.Background(), PromotionOptions{
		ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
		PromotedAt: "2026-08-21T00:05:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	reviewManifest, err := os.ReadFile(filepath.Join(repo.unit, ReviewManifestName))
	if err != nil {
		t.Fatal(err)
	}
	identity := RegistryRecord{
		IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion, CandidateCommit: syntheticCommit,
		OriginalPackSHA256: promotion.OriginalPackSHA256, CanonicalPackSHA256: promotion.CanonicalPackSHA256,
		CandidateManifestSHA256: promotion.CandidateManifestSHA256, ReviewPolicyProfile: promotion.ReviewPolicyProfile,
		ReviewPolicySHA256: promotion.ReviewPolicySHA256, ApprovalIDs: []string{},
	}
	research := RegistryRecord{
		RecordID: "synthetic-path-research", IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion,
		Status: "research", ApprovalIDs: []string{}, RecordedAt: "2026-08-19T00:00:00Z",
	}
	candidate := identity
	candidate.RecordID = "synthetic-path-candidate"
	candidate.PreviousRecordID = research.RecordID
	candidate.Status = "candidate"
	candidate.RecordedAt = "2026-08-20T00:00:00Z"
	inProgress := identity
	inProgress.RecordID = "synthetic-path-review"
	inProgress.PreviousRecordID = candidate.RecordID
	inProgress.Status = "review_in_progress"
	inProgress.RecordedAt = "2026-08-21T00:00:00Z"
	reviewed := identity
	reviewed.RecordID = "synthetic-path-reviewed"
	reviewed.PreviousRecordID = inProgress.RecordID
	reviewed.Status = "reviewed"
	reviewed.RecordedAt = "2026-08-22T00:00:00Z"
	reviewed.PromotionContentCommit = promotionCommit
	reviewed.ReviewedPath = promotion.ReviewedPath
	reviewed.ReviewRecordManifestSHA256 = digestHex(reviewManifest)
	reviewed.ApprovalIDs = promotion.ApprovalIDs
	return Registry{SchemaVersion: RegistrySchema, Records: []RegistryRecord{research, candidate, inProgress, reviewed}}, promotionCommit
}

func assertNoProblemCode(t *testing.T, err error, code string) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("got %v, want validation error without code %s", err, code)
	}
	for _, problem := range validation.Problems {
		if problem.Code == code {
			t.Fatalf("unexpected problem code %s in %+v", code, validation.Problems)
		}
	}
}
