package packreview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

const (
	syntheticCommit           = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	syntheticIncidentID       = "CIR-SYNTHETIC-REVIEW"
	syntheticPackVersion      = "0.2.0"
	syntheticSourceID         = "synthetic-source"
	syntheticCompleteScenario = "complete-boundary-matrix"
	syntheticDownloadScenario = "downloaded-only"
	syntheticPack             = `apiVersion: cirewind.dev/v1alpha1
kind: GitHubActionsIncident
metadata:
  id: CIR-SYNTHETIC-REVIEW
  packVersion: 0.2.0
  title: Synthetic review fixture
  publishedAt: "2026-08-20T00:00:00Z"
  updatedAt: "2026-08-20T00:00:00Z"
  sources:
    - id: synthetic-source
      type: synthetic-fixture
      title: Synthetic source object
      publisher: CIRewind test maintainers
      url: https://example.invalid/synthetic-source
      retrievedAt: "2026-08-20T00:00:00Z"
spec:
  description: Unmistakably synthetic incident review fixture.
  components:
    - id: synthetic-action
      type: github-action
      repository:
        owner: cirewind-fixtures
        name: harmless-action
  indicators:
    - id: synthetic-commit
      componentId: synthetic-action
      kind: action-commit
      value:
        gitObject:
          algorithm: sha1
          value: "1111111111111111111111111111111111111111"
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-source
`
)

var syntheticSourceBytes = []byte("synthetic reviewed source object\n")

type syntheticReviewRepo struct {
	root, unit, candidate, snapshot string
	unitValue                       *Unit
}

func newSyntheticReviewRepo(t *testing.T, profile string) syntheticReviewRepo {
	t.Helper()
	ctx := context.Background()
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packBytes := syntheticReviewPack(t, bundle, syntheticSourceBytes)
	root := t.TempDir()
	unit := filepath.Join(root, "review-packets", syntheticIncidentID, syntheticPackVersion)
	candidate := filepath.Join(unit, "candidate-content")
	mustMkdir(t, filepath.Join(candidate, "fixtures"))
	mustMkdir(t, filepath.Join(unit, "approvals"))
	mustMkdir(t, filepath.Join(root, "incidents", "candidates", syntheticIncidentID))

	policy := syntheticPolicy()
	policyRaw := mustCanonical(t, policy)
	mustWrite(t, filepath.Join(root, "pack-review-policy.json"), policyRaw)
	mustWrite(t, filepath.Join(root, "review-registry.json"), mustCanonical(t, Registry{SchemaVersion: RegistrySchema, Records: []RegistryRecord{}}))
	mustWrite(t, filepath.Join(candidate, "review-policy.json"), policyRaw)
	mustWrite(t, filepath.Join(candidate, "pack.yaml"), packBytes)
	mustWrite(t, filepath.Join(root, "incidents", "candidates", syntheticIncidentID, syntheticPackVersion+".yaml"), packBytes)
	mustWrite(t, filepath.Join(candidate, "fixtures", "source.txt"), syntheticSourceBytes)

	validated, err := incident.Validate(ctx, packBytes)
	if err != nil {
		t.Fatal(err)
	}
	downloadedOnly := syntheticSnapshotForRun(t, bundle.Snapshot, 1002)
	scenarios := []struct {
		id       string
		snapshot archive.Snapshot
	}{
		{syntheticCompleteScenario, bundle.Snapshot},
		{syntheticDownloadScenario, downloadedOnly},
	}
	fixtureIndex := FixtureIndex{SchemaVersion: FixtureIndexSchema, Scenarios: make([]FixtureScenario, 0, len(scenarios))}
	for _, scenario := range scenarios {
		scenarioDirectory := filepath.Join(candidate, "fixtures", "scenarios", scenario.id)
		mustMkdir(t, scenarioDirectory)
		mustWrite(t, filepath.Join(scenarioDirectory, "archive-snapshot.json"), mustCanonical(t, scenario.snapshot))
		fixtureIndex.Scenarios = append(fixtureIndex.Scenarios, FixtureScenario{
			ScenarioID: scenario.id, SnapshotPath: "scenarios/" + scenario.id + "/archive-snapshot.json",
			AnalysisTime: bundle.AnalysisTime.Format(time.RFC3339Nano),
		})
	}
	mustWrite(t, filepath.Join(candidate, "fixtures", "index.json"), mustCanonical(t, fixtureIndex))

	complete, err := analyze.Derive(bundle.Snapshot, validated, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	requireCompleteSyntheticMatrix(t, complete.Case.Findings)
	downloaded, err := analyze.Derive(downloadedOnly, validated, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	requireDownloadedOnlyScenario(t, downloaded.Case.Findings)

	sourceDigest := sha256.Sum256(syntheticSourceBytes)
	sources := SourceLedger{SchemaVersion: SourcesSchema, Sources: []SourceRecord{{
		SourceID: syntheticSourceID, SourceClass: "synthetic-fixture", Publisher: "CIRewind test maintainers",
		Title: "Synthetic source object", Locator: "https://example.invalid/synthetic-source", PublishedAt: "2026-08-20T00:00:00Z",
		StatedPrecision: "second", RetrievedAt: "2026-08-20T00:00:00Z", ImmutableRevision: "fixture-v2",
		MediaType: "text/plain", ReviewedByteLength: int64(len(syntheticSourceBytes)), ReviewedSHA256: hex.EncodeToString(sourceDigest[:]),
		ArchivePath: "fixtures/source.txt", RedistributionAssessment: "redistributable", ConflictIDs: []string{},
	}}}
	conflicts := ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{}}
	claims := syntheticClaims(t, validated, syntheticSourceID)
	sourcesRaw := mustCanonical(t, sources)
	claimsRaw := mustCanonical(t, claims)
	conflictsRaw := mustCanonical(t, conflicts)
	expectedRows := expectedRowsForScenario(syntheticCompleteScenario, complete.Case, bundle.Snapshot)
	expectedRows = append(expectedRows, expectedRowsForScenario(syntheticDownloadScenario, downloaded.Case, downloadedOnly)...)
	requireExactCoverageOracle(t, expectedRows)
	expected := NormalizeExpectedFindings(ExpectedFindings{SchemaVersion: ExpectedFindingsSchema,
		Findings: expectedRows,
		Forbidden: []ForbiddenExpectedFinding{{ScenarioID: syntheticDownloadScenario, State: model.ConfirmedExecuted,
			Rationale: "Preparation without a lifecycle start must never produce a confirmed-executed conclusion."}}})
	expectedRaw := mustCanonical(t, expected)
	mustWrite(t, filepath.Join(candidate, "sources.json"), sourcesRaw)
	mustWrite(t, filepath.Join(candidate, "claims.json"), claimsRaw)
	mustWrite(t, filepath.Join(candidate, "conflicts.json"), conflictsRaw)
	mustWrite(t, filepath.Join(candidate, "expected-findings.json"), expectedRaw)
	fixtureManifest, err := BuildFixtureManifest(ctx, filepath.Join(candidate, "fixtures"), filepath.Join(candidate, "fixtures", FixtureManifestName))
	if err != nil {
		t.Fatal(err)
	}

	fixtureManifestHash := digestHex(fixtureManifest)
	packet := Packet{
		SchemaVersion: PacketSchema, IncidentID: validated.Pack.Metadata.ID, PackVersion: validated.Pack.Metadata.PackVersion,
		ReviewUnitPackPath: "pack.yaml", OriginalPackSHA256: validated.OriginalSHA256, CanonicalPackSHA256: validated.CanonicalSHA256,
		PackSchemaVersion: incident.APIVersion, ValidatorVersion: incident.PolicyVersion, ValidatorPolicySHA256: incident.ValidatorPolicySHA256(),
		ClaimsSHA256: digestHex(claimsRaw), SourcesSHA256: digestHex(sourcesRaw), ConflictsSHA256: digestHex(conflictsRaw),
		ExpectedFindingsSHA256: digestHex(expectedRaw), FixtureManifestSHA256: fixtureManifestHash, ConflictIDs: []string{},
		ReviewPolicyProfile: profile, ReviewPolicySHA256: digestHex(policyRaw), Preparation: Preparation{
			Preparer:           HumanIdentity{Login: "synthetic-author", DatabaseID: 100},
			Authors:            []HumanIdentity{{Login: "synthetic-author", DatabaseID: 100}},
			SourceTranscribers: []HumanIdentity{{Login: "synthetic-transcriber", DatabaseID: 101}},
		},
	}
	packetRaw := mustCanonical(t, packet)
	mustWrite(t, filepath.Join(candidate, "packet.json"), packetRaw)
	validation := CandidateValidation{SchemaVersion: ValidationSchema, IncidentID: packet.IncidentID, PackVersion: packet.PackVersion,
		OriginalPackSHA256: packet.OriginalPackSHA256, CanonicalPackSHA256: packet.CanonicalPackSHA256,
		ValidatorVersion: packet.ValidatorVersion, ValidatorPolicySHA256: packet.ValidatorPolicySHA256,
		ExpectedFindingsSHA256: packet.ExpectedFindingsSHA256, FixtureManifestSHA256: packet.FixtureManifestSHA256, Result: "pass"}
	mustWrite(t, filepath.Join(candidate, "validation.json"), mustCanonical(t, validation))
	if _, err := BuildCandidateManifest(ctx, candidate, filepath.Join(candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}
	unitValue, err := ValidateUnit(ctx, unit, syntheticCommit)
	if err != nil {
		t.Fatalf("synthetic review unit must validate: %v", err)
	}
	return syntheticReviewRepo{root: root, unit: unit, candidate: candidate, unitValue: unitValue}
}

func syntheticReviewPack(t *testing.T, bundle demodata.DemoBundle, sourceBytes []byte) []byte {
	t.Helper()
	sourceDigest := sha256.Sum256(sourceBytes)
	pack := string(bundle.PackYAML)
	pack = replaceSyntheticPackText(t, pack, "id: CIR-SYNTHETIC-0001", "id: "+syntheticIncidentID)
	pack = replaceSyntheticPackText(t, pack, "packVersion: 2.0.0", "packVersion: "+syntheticPackVersion)
	pack = strings.ReplaceAll(pack, "synthetic-lab-protocol", syntheticSourceID)
	pack = replaceSyntheticPackText(t, pack, "title: Harmless controlled lab protocol", "title: Synthetic source object")
	pack = replaceSyntheticPackText(t, pack, "url: https://example.invalid/cirewind/synthetic-lab", "url: https://example.invalid/synthetic-source")
	pack = replaceSyntheticPackText(t, pack, strings.Repeat("a", 64), hex.EncodeToString(sourceDigest[:]))
	originalMutableIndicator := `    - id: synthetic-mutable-ref
      componentId: harmless-action
      kind: mutable-action-ref
      value:
        ref: v1
      windowRefs:
        - synthetic-exposure
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-source
`
	pack = replaceSyntheticPackText(t, pack, originalMutableIndicator, "")

	boundaryWindows := `    - id: synthetic-inclusive-start
      start: "2026-08-19T10:30:00Z"
      end: "2026-08-19T10:31:00Z"
      bounds: "[)"
      sourcePrecision: second
      approximation: exact
      sourceRefs:
        - synthetic-source
    - id: synthetic-exclusive-end
      start: "2026-08-19T10:29:00Z"
      end: "2026-08-19T10:30:00Z"
      bounds: "[)"
      sourcePrecision: second
      approximation: exact
      sourceRefs:
        - synthetic-source
`
	pack = replaceSyntheticPackText(t, pack, "  indicators:\n", boundaryWindows+"  indicators:\n")
	boundaryIndicators := `    - id: synthetic-boundary-inclusive-start
      componentId: harmless-action
      kind: mutable-action-ref
      value:
        ref: v1
      windowRefs:
        - synthetic-inclusive-start
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-source
    - id: synthetic-boundary-exclusive-end
      componentId: paired-rerun-action
      kind: mutable-action-ref
      value:
        ref: v1
      windowRefs:
        - synthetic-exclusive-end
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-source
`
	pack = replaceSyntheticPackText(t, pack, "  knownGood:\n", boundaryIndicators+"  knownGood:\n")
	return []byte(pack)
}

func replaceSyntheticPackText(t *testing.T, value, old, replacement string) string {
	t.Helper()
	if strings.Count(value, old) != 1 {
		t.Fatalf("synthetic pack replacement %q occurred %d times, want exactly one", old, strings.Count(value, old))
	}
	return strings.Replace(value, old, replacement, 1)
}

func syntheticSnapshotForRun(t *testing.T, source archive.Snapshot, runID model.WorkflowRunID) archive.Snapshot {
	t.Helper()
	filtered := source
	filtered.Facts = make([]archive.Fact, 0)
	for _, fact := range source.Facts {
		if fact.Kind == archive.FactRepository || fact.Subject.RunID != nil && *fact.Subject.RunID == runID {
			filtered.Facts = append(filtered.Facts, fact)
		}
	}
	normalized, err := archive.NormalizeSnapshot(filtered)
	if err != nil {
		t.Fatalf("normalize run %d synthetic snapshot: %v", runID, err)
	}
	return normalized
}

func requireCompleteSyntheticMatrix(t *testing.T, findings []report.Finding) {
	t.Helper()
	seen := make(map[model.FindingState]struct{}, len(findings))
	var observed []string
	boundaryStartMatches, boundaryEndMatches := 0, 0
	for _, finding := range findings {
		state := model.FindingState(finding.State)
		seen[state] = struct{}{}
		observed = append(observed, finding.IndicatorID+"="+finding.State)
		switch finding.IndicatorID {
		case "synthetic-boundary-inclusive-start":
			if state == model.RunInWindowMutableRef {
				boundaryStartMatches++
			}
		case "synthetic-boundary-exclusive-end":
			if state == model.RunInWindowMutableRef || state == model.PotentialTransitive {
				boundaryEndMatches++
			}
		}
	}
	for _, state := range model.FindingStates() {
		if _, ok := seen[state]; !ok {
			t.Fatalf("complete synthetic review packet does not exercise canonical state %s; observed %v", state, observed)
		}
	}
	if boundaryStartMatches == 0 {
		t.Fatal("inclusive-start boundary indicator did not match the event at the exact window start")
	}
	if boundaryEndMatches != 0 {
		t.Fatalf("exclusive-end boundary indicator produced %d temporal matches at the exact excluded window end", boundaryEndMatches)
	}
}

func requireDownloadedOnlyScenario(t *testing.T, findings []report.Finding) {
	t.Helper()
	downloaded := 0
	for _, finding := range findings {
		switch model.FindingState(finding.State) {
		case model.ConfirmedDownloaded:
			downloaded++
		case model.ConfirmedExecuted:
			t.Fatalf("downloaded-only scenario produced prohibited %s finding %s", finding.State, finding.FindingID)
		}
	}
	if downloaded == 0 {
		t.Fatal("downloaded-only scenario did not produce CONFIRMED_DOWNLOADED")
	}
}

func requireExactCoverageOracle(t *testing.T, rows []ExpectedFinding) {
	t.Helper()
	noMatch, gap := 0, 0
	for _, row := range rows {
		switch row.State {
		case model.NoMatchConfirmed:
			noMatch++
			if len(row.EvidenceIDs) == 0 || len(row.CoverageAssessmentIDs) == 0 || len(row.EvidenceGapCodes) != 0 {
				t.Fatalf("NO_MATCH_CONFIRMED row does not freeze exact evidence and closed coverage: %#v", row)
			}
		case model.UnknownEvidenceGap:
			gap++
			if len(row.CoverageAssessmentIDs) == 0 || len(row.EvidenceGapCodes) == 0 {
				t.Fatalf("UNKNOWN_EVIDENCE_GAP row does not freeze exact gap assessment and reason: %#v", row)
			}
		}
	}
	if noMatch == 0 || gap == 0 {
		t.Fatalf("complete synthetic oracle lacks closed no-match or gap rows: no-match=%d gap=%d", noMatch, gap)
	}
}

func syntheticPolicy() ReviewPolicy {
	return ReviewPolicy{SchemaVersion: ReviewPolicySchema, PolicyVersion: "synthetic-policy-v1", OfficialRepository: "example/cirewind",
		EligibleMaintainers: []HumanIdentity{{Login: "synthetic-maintainer-one", DatabaseID: 201}, {Login: "synthetic-maintainer-two", DatabaseID: 202}},
		Profiles: []ReviewPolicyProfile{
			{ProfileID: StandardPolicyProfile, MinimumMaintainers: 2, MinimumOutsideReviewers: 1, RequiredAnyApprovalScopes: []string{"hostile-input-privacy", "identity"}, RequiredOutsideScopes: []string{}},
			{ProfileID: TrivyPolicyProfile, MinimumMaintainers: 2, MinimumOutsideReviewers: 2, RequiredAnyApprovalScopes: []string{"hostile-input-privacy", "identity"}, RequiredOutsideScopes: []string{"component-namespace", "ioc-extraction", "time"}},
		}}
}

func syntheticClaims(t *testing.T, validated *incident.ValidatedPack, sourceID string) ClaimLedger {
	t.Helper()
	items := materialInventory(validated.Pack)
	claims := make([]Claim, 0, len(items))
	for i, item := range items {
		value, ok := normalizedScalar(item.Value)
		if !ok {
			reflected := reflect.ValueOf(item.Value)
			if reflected.IsValid() && reflected.Kind() == reflect.String {
				value, ok = reflected.String(), true
			}
		}
		if !ok {
			t.Fatalf("material item %s is not scalar", item.Pointer)
		}
		pointer, normalized := item.Pointer, value
		claim := Claim{ClaimID: fmt.Sprintf("synthetic-claim-%03d", i), CanonicalPointer: &pointer,
			SemanticSelector: item.Selector, SemanticRole: item.Role,
			SourceIDs: []string{sourceID}, SourceLocations: []SourceLocation{{SourceID: sourceID, Location: "synthetic line 1"}},
			Transformation: "verbatim", SourcePrecision: item.SourcePrecision, Approximation: item.Approximation,
			ConflictIDs: []string{}, AuthorAssessment: AuthorAssessment{Decision: "inclusion", Rationale: "Synthetic fixture mapping."}}
		if normalized == "" {
			canonical, err := evidence.CanonicalJSON(item.Value)
			if err != nil {
				t.Fatalf("canonicalize synthetic empty material value: %v", err)
			}
			claim.ValueSHA256 = digestHex(canonical)
		} else {
			claim.NormalizedValue = &normalized
		}
		claims = append(claims, claim)
	}
	return ClaimLedger{SchemaVersion: ClaimsSchema, Claims: claims}
}

func addSyntheticApprovals(t *testing.T, repo *syntheticReviewRepo, outside int) []Review {
	t.Helper()
	identities := []struct {
		id          int64
		login, role string
		scopes      []string
	}{
		{201, "synthetic-maintainer-one", "maintainer", []string{"identity"}},
		{202, "synthetic-maintainer-two", "maintainer", []string{"hostile-input-privacy"}},
		{301, "synthetic-outsider-one", "outside-technical", []string{"complete"}},
		{302, "synthetic-outsider-two", "outside-technical", []string{"component-namespace", "ioc-extraction", "time"}},
	}
	identities = identities[:2+outside]
	bindings := ReviewBindings{CandidateManifestSHA256: repo.unitValue.CandidateManifestSHA256,
		OriginalPackSHA256: repo.unitValue.Pack.OriginalPackSHA256, CanonicalPackSHA256: repo.unitValue.Pack.CanonicalPackSHA256,
		ClaimsSHA256: repo.unitValue.Pack.ClaimsSHA256, SourcesSHA256: repo.unitValue.Pack.SourcesSHA256,
		ConflictsSHA256: repo.unitValue.Pack.ConflictsSHA256, FixtureManifestSHA256: repo.unitValue.Pack.FixtureManifestSHA256,
		ValidatorPolicySHA256: repo.unitValue.Pack.ValidatorPolicySHA256, ReviewPolicySHA256: repo.unitValue.Pack.ReviewPolicySHA256}
	var reviews []Review
	var platform []PlatformApproval
	for index, identity := range identities {
		reviewID := fmt.Sprintf("synthetic-review-%d", index+1)
		databaseID := int64(1001 + index)
		reviewURL := fmt.Sprintf("https://github.com/example/cirewind/pull/7#pullrequestreview-%d", databaseID)
		review := Review{SchemaVersion: ReviewSchema, ReviewID: reviewID, Reviewer: HumanIdentity{Login: identity.login, DatabaseID: identity.id},
			DeclaredRole: identity.role, Independent: true, ConflictDisclosure: "Unmistakably synthetic test record; no real approval.",
			IncidentID: repo.unitValue.Pack.IncidentID, PackVersion: repo.unitValue.Pack.PackVersion, CandidateCommit: syntheticCommit,
			Bindings: bindings, PlatformReview: PlatformReviewReference{Repository: "example/cirewind", PullRequestNumber: 7, ReviewURL: reviewURL, ReviewDatabaseID: databaseID},
			Scopes: identity.scopes, Commands: []ReproductionCommand{}, SourceObjectsChecked: []CheckedSourceObject{}, Decision: "approve", ReviewedAt: "2026-08-21T00:00:00Z",
			Rationale: "Synthetic approval used only to test offline governance policy.", KnownLimitations: []string{"Not a real external review."}}
		if index == 0 || containsString(review.Scopes, "complete") {
			review.SourceObjectsChecked = []CheckedSourceObject{{SourceID: repo.unitValue.Sources.Sources[0].SourceID, SHA256: repo.unitValue.Sources.Sources[0].ReviewedSHA256}}
		}
		bodyBinding, err := ComputeReviewBodyBinding(review)
		if err != nil {
			t.Fatal(err)
		}
		review.PlatformReview.AssertionSHA256 = bodyBinding.AssertionSHA256
		review.PlatformReview.BodySHA256 = bodyBinding.BodySHA256
		directory := filepath.Join(repo.unit, "approvals", reviewID)
		mustMkdir(t, directory)
		mustWrite(t, filepath.Join(directory, "review.json"), mustCanonical(t, review))
		if err := RenderReviewFile(context.Background(), filepath.Join(directory, "review.json"), filepath.Join(directory, "REVIEW.md")); err != nil {
			t.Fatal(err)
		}
		reviews = append(reviews, review)
		platform = append(platform, PlatformApproval{ReviewDatabaseID: databaseID, ReviewURL: reviewURL,
			Reviewer: PlatformActor{Login: identity.login, DatabaseID: identity.id}, AccountType: "User", State: "APPROVED", CommitID: syntheticCommit,
			SubmittedAt: "2026-08-20T23:59:00Z", BodySHA256: bodyBinding.BodySHA256})
	}
	snapshot := PlatformApprovalSnapshot{SchemaVersion: PlatformSnapshotSchema, Repository: "example/cirewind", PullRequestNumber: 7,
		CandidateCommit: syntheticCommit, ObservedAt: "2026-08-21T00:01:00Z", ObservationSource: "github-rest-api",
		WorkflowSourceCommit: syntheticCommit, WorkflowRunURL: "https://github.com/example/cirewind/actions/runs/77", WorkflowRunID: 77, WorkflowRunAttempt: 1,
		ResponseSHA256: stringOf('b', 64), Approvals: platform}
	repo.snapshot = filepath.Join(repo.unit, "platform-approvals.json")
	mustWrite(t, repo.snapshot, mustCanonical(t, snapshot))
	return reviews
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	data, err := marshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func stringOf(value byte, count int) string {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return string(result)
}
func sortedReviews(values []Review) []Review {
	result := append([]Review(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].ReviewID < result[j].ReviewID })
	return result
}
