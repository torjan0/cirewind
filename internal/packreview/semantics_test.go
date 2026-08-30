package packreview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/incident"
)

func TestRenderReviewIsDeterministicAndEscapesHostileMarkdown(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	reviews := addSyntheticApprovals(t, &repo, 1)
	review := reviews[0]
	review.Rationale = "Synthetic rationale.\n# forged heading [link](javascript:alert(1)) `code`"
	review.ConflictDisclosure = "| forged | table |"
	review.KnownLimitations = []string{"- forged list", "![image](javascript:alert(1))"}
	refreshReviewBodyBindingForParity(&review)
	first, err := RenderReview(review)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderReview(review)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Markdown rendering is nondeterministic")
	}
	text := string(first)
	for _, forbidden := range []string{"[link](javascript", "![image](javascript", "\n# forged", "\n| forged"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("rendered Markdown contains active form %q:\n%s", forbidden, text)
		}
	}
	if !strings.Contains(text, "does not certify itself") {
		t.Fatal("self-certification disclaimer is missing")
	}
}

func TestRenderReviewRejectsHTMLAngleBrackets(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	review := addSyntheticApprovals(t, &repo, 1)[0]
	for _, test := range []struct{ name, value string }{
		{name: "left angle", value: "<script"},
		{name: "right angle", value: "a > b"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := review
			changed.Rationale = test.value
			_, err := RenderReview(changed)
			assertProblemCode(t, err, "UNSAFE_TEXT")
		})
	}
}

func TestAllowedTransitionExhaustive(t *testing.T) {
	statuses := []string{"research", "candidate", "review_in_progress", "reviewed", "superseded", "withdrawn", "invalid"}
	want := map[string]bool{
		"research>candidate":           true,
		"candidate>review_in_progress": true,
		"candidate>withdrawn":          true,
		"review_in_progress>candidate": true,
		"review_in_progress>reviewed":  true,
		"reviewed>superseded":          true,
		"reviewed>withdrawn":           true,
		"superseded>withdrawn":         true,
	}
	for _, from := range statuses {
		for _, to := range statuses {
			if got := AllowedTransition(from, to); got != want[from+">"+to] {
				t.Errorf("AllowedTransition(%q,%q)=%t", from, to, got)
			}
		}
	}
}

func TestConflictDispositionRequiresExplicitResolutionOrOmission(t *testing.T) {
	t.Run("resolved selections required", func(t *testing.T) {
		var got problems
		validateConflicts(ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{{
			ConflictID: "conflict", ClaimIDs: []string{"claim"}, CompetingSourceIDs: []string{"source-a", "source-b"},
			Description: "Synthetic conflict.", Materiality: "identity", Disposition: "resolved", Rationale: "Synthetic resolution.",
		}}}, &got)
		assertProblemCode(t, got.err(), "RESOLUTION_SOURCES")
	})

	t.Run("other dispositions cannot select", func(t *testing.T) {
		var got problems
		validateConflicts(ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{{
			ConflictID: "conflict", ClaimIDs: []string{"claim"}, CompetingSourceIDs: []string{"source-a", "source-b"},
			Description: "Synthetic conflict.", Materiality: "identity", Disposition: "blocking", Rationale: "Synthetic block.",
			SelectedClaimID: "claim", SelectedSourceIDs: []string{"source-a"},
		}}}, &got)
		assertProblemCode(t, got.err(), "UNEXPECTED_RESOLUTION")
	})

	t.Run("resolved source must support selected claim", func(t *testing.T) {
		claim := Claim{ClaimID: "claim", SourceIDs: []string{"source-a"}, ConflictIDs: []string{"conflict"}, AuthorAssessment: AuthorAssessment{Decision: "inclusion"}}
		ledger := ClaimLedger{SchemaVersion: ClaimsSchema, Claims: []Claim{claim}}
		conflicts := ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{{
			ConflictID: "conflict", ClaimIDs: []string{"claim"}, CompetingSourceIDs: []string{"source-a", "source-b"},
			Disposition: "resolved", SelectedClaimID: "claim", SelectedSourceIDs: []string{"source-b"},
		}}}
		sources := map[string]SourceRecord{"source-a": {SourceID: "source-a"}, "source-b": {SourceID: "source-b"}}
		var got problems
		validateClaimConflictClosure(ledger, conflicts, map[string]Claim{"claim": claim}, map[string]int{"claim": 0}, map[string]struct{}{}, sources, &got)
		assertProblemCode(t, got.err(), "RESOLUTION_SOURCE_BINDING")
	})

	t.Run("excluded conflict requires omission", func(t *testing.T) {
		claim := Claim{ClaimID: "claim", SourceIDs: []string{"source-a"}, ConflictIDs: []string{"conflict"}, AuthorAssessment: AuthorAssessment{Decision: "inclusion"}}
		ledger := ClaimLedger{SchemaVersion: ClaimsSchema, Claims: []Claim{claim}}
		conflicts := ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{{
			ConflictID: "conflict", ClaimIDs: []string{"claim"}, CompetingSourceIDs: []string{"source-a", "source-b"}, Disposition: "excluded",
		}}}
		sources := map[string]SourceRecord{"source-a": {SourceID: "source-a"}, "source-b": {SourceID: "source-b"}}
		var got problems
		validateClaimConflictClosure(ledger, conflicts, map[string]Claim{"claim": claim}, map[string]int{"claim": 0}, map[string]struct{}{}, sources, &got)
		assertProblemCode(t, got.err(), "EXCLUDED_WITHOUT_OMISSION")
	})
}

func TestRFC6901ResolutionAndRejection(t *testing.T) {
	canonical := []byte(`{"a/b":{"~key":["zero","one"]}}`)
	value, err := resolvePointer(canonical, "/a~1b/~0key/1")
	if err != nil || value != "one" {
		t.Fatalf("resolvePointer=%v,%v", value, err)
	}
	for _, pointer := range []string{"", "/bad~2escape", "/a~1b/~0key/01", "/a~1b/~0key/-", "/missing"} {
		if err := validateRFC6901(pointer); err != nil {
			continue
		}
		if _, err := resolvePointer(canonical, pointer); err == nil {
			t.Errorf("accepted invalid/unresolvable pointer %q", pointer)
		}
	}
}

func TestClaimSourceClosureAndPointerBinding(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	if _, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	t.Run("orphan source", func(t *testing.T) {
		ledger := repo.unitValue.Sources
		ledger.Sources = append(ledger.Sources, SourceRecord{
			SourceID: "orphan", SourceClass: "synthetic-fixture", Publisher: "Synthetic", Title: "Orphan",
			Locator: "https://example.invalid/orphan", RetrievedAt: "2026-08-20T00:00:00Z", MediaType: "text/plain",
			ReviewedSHA256: stringOf('c', 64), NotRedistributedReason: "Synthetic omission.", RedistributionAssessment: "metadata-only", ConflictIDs: []string{},
		})
		var got problems
		validatedClaimsPack(t, repo, ledger, repo.unitValue.Claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "ORPHAN_SOURCE")
	})

	t.Run("pointer drift", func(t *testing.T) {
		claims := repo.unitValue.Claims
		claims.Claims = append([]Claim(nil), claims.Claims...)
		changed := claims.Claims[0]
		wrong := "wrong"
		changed.NormalizedValue = &wrong
		claims.Claims[0] = changed
		var got problems
		validatedClaimsPack(t, repo, repo.unitValue.Sources, claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "NORMALIZED_VALUE")
	})

	t.Run("unmapped material", func(t *testing.T) {
		claims := repo.unitValue.Claims
		claims.Claims = append([]Claim(nil), claims.Claims[1:]...)
		var got problems
		validatedClaimsPack(t, repo, repo.unitValue.Sources, claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "UNMAPPED_MATERIAL_FIELD")
	})

	t.Run("typed namespace loss", func(t *testing.T) {
		claims := repo.unitValue.Claims
		claims.Claims = append([]Claim(nil), claims.Claims...)
		changed := claims.Claims[len(claims.Claims)-1]
		changed.SemanticRole = "package-digest"
		claims.Claims[len(claims.Claims)-1] = changed
		var got problems
		validatedClaimsPack(t, repo, repo.unitValue.Sources, claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "ROLE_MISMATCH")
	})

	t.Run("fabricated temporal precision", func(t *testing.T) {
		claims := repo.unitValue.Claims
		claims.Claims = append([]Claim(nil), claims.Claims...)
		changed := claims.Claims[0]
		changed.SourcePrecision = "second"
		changed.Approximation = "exact"
		claims.Claims[0] = changed
		var got problems
		validatedClaimsPack(t, repo, repo.unitValue.Sources, claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "NON_TEMPORAL_PRECISION")
	})

	t.Run("secondary-only critical claim", func(t *testing.T) {
		sources := repo.unitValue.Sources
		sources.Sources = append([]SourceRecord(nil), sources.Sources...)
		sources.Sources[0].SourceClass = "secondary-lead"
		var got problems
		validatedClaimsPack(t, repo, sources, repo.unitValue.Claims, repo.unitValue.Conflicts, &got)
		assertProblemCode(t, got.err(), "SECONDARY_ONLY")
	})
}

func TestOmissionClaimsBindOnlyActuallyAbsentSlots(t *testing.T) {
	pack := incident.Pack{Metadata: incident.Metadata{ID: "CIR-SYNTHETIC-OMISSION"}, Spec: incident.Spec{
		Components: []incident.Component{{ID: "action", Subpaths: []string{}}},
		Windows:    []incident.Window{{ID: "open-window", Start: "", End: "2026-08-30T00:00:00Z", SourcePrecision: "minute", Approximation: "source-rounded"}},
		Indicators: []incident.Indicator{{ID: "exact", ComponentID: "action", Kind: "action-commit"}},
	}}
	sources := map[string]SourceRecord{"primary": {SourceID: "primary", StatedPrecision: "minute"}}
	base := Claim{CanonicalPointer: nil, SourceIDs: []string{"primary"}, NormalizedValue: nil, SemanticRole: "window",
		SemanticSelector: "window:open-window/field:start", OmittedSlot: "window-start", SourcePrecision: "minute", Approximation: "source-rounded",
		AuthorAssessment: AuthorAssessment{Decision: "omission"}}

	t.Run("valid absent endpoint", func(t *testing.T) {
		var got problems
		validateOmissionClaim(base, "/claims/0", omissionInventory(pack), sources, &got)
		if err := got.err(); err != nil {
			t.Fatalf("valid omission rejected: %v", err)
		}
	})
	t.Run("present endpoint", func(t *testing.T) {
		changed := base
		changed.SemanticSelector = "window:open-window/field:end"
		changed.OmittedSlot = "window-end"
		var got problems
		validateOmissionClaim(changed, "/claims/0", omissionInventory(pack), sources, &got)
		assertProblemCode(t, got.err(), "OMISSION_NOT_ABSENT")
	})
	t.Run("temporal precision cannot disappear", func(t *testing.T) {
		changed := base
		changed.SourcePrecision = ""
		changed.Approximation = ""
		var got problems
		validateOmissionClaim(changed, "/claims/0", omissionInventory(pack), sources, &got)
		assertProblemCode(t, got.err(), "OMISSION_TEMPORAL_PRECISION")
	})
}

func TestMaterialInventoryPreservesWindowAndIdentityNamespaces(t *testing.T) {
	validated, err := incident.Validate(context.Background(), mustReadSyntheticPack(t))
	if err != nil {
		t.Fatal(err)
	}
	items := materialInventory(validated.Pack)
	bySelector := make(map[string]materialItem, len(items))
	for _, item := range items {
		bySelector[item.Selector] = item
	}
	checks := map[string]struct {
		role, precision, approximation string
	}{
		"indicator:synthetic-compromised-commit/value:gitObject.value": {role: "compromised-sha"},
		"indicator:synthetic-action-package/value:digest":              {role: "package-digest"},
		"known-good:synthetic-known-good-commit/value:gitObject.value": {role: "known-good-sha"},
		"window:synthetic-exposure/field:start":                        {role: "window", precision: "second", approximation: "exact"},
		"window:synthetic-exposure/field:bounds":                       {role: "window"},
	}
	for selector, want := range checks {
		got, ok := bySelector[selector]
		if !ok {
			t.Errorf("material inventory omitted %s", selector)
			continue
		}
		if got.Role != want.role || got.SourcePrecision != want.precision || got.Approximation != want.approximation {
			t.Errorf("%s = role %q precision %q approximation %q, want %+v", selector, got.Role, got.SourcePrecision, got.Approximation, want)
		}
	}
}

func TestArchivedSourceBytesMustMatchLedger(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	sources := repo.unitValue.Sources
	sources.Sources = append([]SourceRecord(nil), sources.Sources...)
	sources.Sources[0].ReviewedSHA256 = stringOf('f', 64)
	var got problems
	validateArchivedSources(context.Background(), repo.candidate, sources, &got)
	assertProblemCode(t, got.err(), "SOURCE_ARCHIVE_HASH")

	sources.Sources[0].ArchivePath = "outside.txt"
	got = problems{}
	validateArchivedSources(context.Background(), repo.candidate, sources, &got)
	assertProblemCode(t, got.err(), "SOURCE_ARCHIVE_PATH")
}

func mustReadSyntheticPack(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func validatedClaimsPack(t *testing.T, repo syntheticReviewRepo, sources SourceLedger, claims ClaimLedger, conflicts ConflictLedger, got *problems) {
	t.Helper()
	validated, err := incidentValidateSynthetic()
	if err != nil {
		t.Fatal(err)
	}
	validateClaims(claims, validated, sources, conflicts, repo.unitValue.Pack, got)
}

func incidentValidateSynthetic() (*incident.ValidatedPack, error) {
	return incident.Validate(context.Background(), []byte(syntheticPack))
}
