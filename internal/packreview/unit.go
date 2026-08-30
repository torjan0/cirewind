package packreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/torjan0/cirewind/internal/incident"
)

// ValidateUnit validates a complete immutable candidate-content review unit.
// candidateCommit is an expected external Git identity; it is deliberately not
// written into candidate content and therefore cannot participate in a hash
// cycle.
func ValidateUnit(ctx context.Context, reviewUnitRoot, candidateCommit string) (*Unit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var initial problems
	validateCommit(candidateCommit, "/candidateCommit", &initial)
	if err := initial.err(); err != nil {
		return nil, err
	}
	root, err := safeRoot(reviewUnitRoot)
	if err != nil {
		return nil, err
	}
	candidate := filepath.Join(root, "candidate-content")
	if _, err := safeRoot(candidate); err != nil {
		return nil, fmt.Errorf("candidate-content: %w", err)
	}
	if err := validateReviewUnitRootEntries(root); err != nil {
		return nil, err
	}
	repositoryRoot := filepath.Dir(filepath.Dir(filepath.Dir(root)))
	if filepath.Base(filepath.Dir(filepath.Dir(root))) != "review-packets" {
		return nil, &ValidationError{Problems: []Problem{{Code: "REVIEW_UNIT_PATH", Path: root, Message: "review unit must be below review-packets/INCIDENT_ID/PACK_VERSION"}}}
	}
	policy, policyRaw, err := readStrictJSON[ReviewPolicy](ctx, filepath.Join(candidate, "review-policy.json"))
	if err != nil {
		return nil, err
	}
	if err := requireCanonicalJSONFile("review-policy.json", policyRaw, policy); err != nil {
		return nil, err
	}

	manifestBytes, manifestHash, err := VerifyCandidateManifest(ctx, candidate)
	if err != nil {
		return nil, err
	}
	packBytes, err := readBoundedRegularContext(ctx, filepath.Join(candidate, "pack.yaml"), incident.MaxPackBytes)
	if err != nil {
		return nil, fmt.Errorf("read candidate pack: %w", err)
	}
	packet, packetRaw, err := readStrictJSON[Packet](ctx, filepath.Join(candidate, "packet.json"))
	if err != nil {
		return nil, err
	}
	if err := requireCanonicalJSONFile("packet.json", packetRaw, packet); err != nil {
		return nil, err
	}
	validatorPolicy, supported := incident.ResolveValidatorPolicy(packet.ValidatorVersion)
	if !supported {
		return nil, &ValidationError{Problems: []Problem{{
			Code: "UNSUPPORTED_INCIDENT_VALIDATOR_POLICY", Path: "/packet/validatorVersion",
			Message: "retained packet names an incident-validator policy this binary does not implement",
		}}}
	}
	validated, err := incident.ValidateForPolicy(ctx, packBytes, validatorPolicy.Version)
	if err != nil {
		return nil, fmt.Errorf("validate candidate pack: %w", err)
	}

	sources, sourcesRaw, err := readStrictJSON[SourceLedger](ctx, filepath.Join(candidate, "sources.json"))
	if err != nil {
		return nil, err
	}
	claims, claimsRaw, err := readStrictJSON[ClaimLedger](ctx, filepath.Join(candidate, "claims.json"))
	if err != nil {
		return nil, err
	}
	conflicts, conflictsRaw, err := readStrictJSON[ConflictLedger](ctx, filepath.Join(candidate, "conflicts.json"))
	if err != nil {
		return nil, err
	}
	validation, validationRaw, err := readStrictJSON[CandidateValidation](ctx, filepath.Join(candidate, "validation.json"))
	if err != nil {
		return nil, err
	}
	for _, file := range []struct {
		name  string
		raw   []byte
		value any
	}{
		{"sources.json", sourcesRaw, sources},
		{"claims.json", claimsRaw, claims},
		{"conflicts.json", conflictsRaw, conflicts},
		{"validation.json", validationRaw, validation},
	} {
		if err := requireCanonicalJSONFile(file.name, file.raw, file.value); err != nil {
			return nil, err
		}
	}
	// Packet and source-ledger validation is otherwise accumulated so reviewers
	// can receive more than one useful diagnostic. Path-bearing fields are a
	// harder boundary: reject them before they can influence any filesystem
	// lookup. Recording a later validation problem is not sufficient because an
	// invalid candidate must never cause an out-of-tree read on its way to being
	// rejected.
	if err := validateUnitFilesystemInputs(packet, sources); err != nil {
		return nil, err
	}

	expected, expectedBytes, err := readStrictJSON[ExpectedFindings](ctx, filepath.Join(candidate, "expected-findings.json"))
	if err != nil {
		return nil, fmt.Errorf("read expected findings: %w", err)
	}
	if err := requireCanonicalJSONFile("expected-findings.json", expectedBytes, expected); err != nil {
		return nil, err
	}
	fixtureManifestBytes, fixtureManifestHash, err := VerifyFixtureManifest(ctx, filepath.Join(candidate, "fixtures"))
	if err != nil {
		return nil, err
	}

	var semantic problems
	validatePacket(packet, &semantic)
	validateReviewPolicy(policy, &semantic)
	validateSources(sources, &semantic)
	validateConflicts(conflicts, &semantic)
	validateCandidateValidation(validation, &semantic)
	validateExpectedFindings(expected, &semantic)
	if err := validateFixtureResults(ctx, candidate, validated, expected, &semantic); err != nil {
		return nil, err
	}
	validateClaims(claims, validated, sources, conflicts, packet, &semantic)
	validateArchivedSources(ctx, candidate, sources, &semantic)
	validateUnitBindings(packet, validation, validated, validatorPolicy, packetRaw, sourcesRaw, claimsRaw, conflictsRaw, expectedBytes, fixtureManifestBytes, policyRaw, fixtureManifestHash, manifestHash, &semantic)
	if filepath.Base(root) != packet.PackVersion || filepath.Base(filepath.Dir(root)) != packet.IncidentID {
		semantic.add("REVIEW_UNIT_PATH", root, "review-unit path must end in incidentId/packVersion")
	}
	candidateCopyPath := candidatePackPath(repositoryRoot, packet.IncidentID, packet.PackVersion)
	candidateCopy, readCandidateErr := readBoundedRegularContext(ctx, candidateCopyPath, incident.MaxPackBytes)
	if readCandidateErr != nil {
		semantic.add("CANDIDATE_COPY", candidateCopyPath, "candidate pack copy is missing or unreadable")
	} else if !bytes.Equal(candidateCopy, packBytes) {
		semantic.add("CANDIDATE_COPY", candidateCopyPath, "candidate pack copy is not byte-identical to review-unit pack.yaml")
	} else {
		copyInfo, copyErr := os.Lstat(candidateCopyPath)
		packInfo, packErr := os.Lstat(filepath.Join(candidate, "pack.yaml"))
		if copyErr != nil || packErr != nil || os.SameFile(copyInfo, packInfo) {
			semantic.add("CANDIDATE_COPY_HARDLINK", candidateCopyPath, "candidate copy and review-unit pack.yaml must be distinct regular files")
		}
	}
	if err := semantic.err(); err != nil {
		return nil, err
	}

	return &Unit{
		Root:                     root,
		CandidateContent:         candidate,
		Pack:                     packet,
		Sources:                  sources,
		Claims:                   claims,
		Conflicts:                conflicts,
		Validation:               validation,
		ExpectedFindings:         expected,
		Policy:                   policy,
		OriginalPackSHA256:       validated.OriginalSHA256,
		CanonicalPackSHA256:      validated.CanonicalSHA256,
		CandidateManifestSHA256:  manifestHash,
		CandidateManifestContent: append([]byte(nil), manifestBytes...),
	}, nil
}

func validateArchivedSources(ctx context.Context, candidateRoot string, ledger SourceLedger, p *problems) {
	for index, source := range ledger.Sources {
		if source.ArchivePath == "" {
			continue
		}
		base := fmt.Sprintf("/sources/%d/archivePath", index)
		if !strings.HasPrefix(source.ArchivePath, "fixtures/") {
			p.add("SOURCE_ARCHIVE_PATH", base, "redistributed source objects must be below candidate-content/fixtures")
			continue
		}
		data, err := readBoundedRegularContext(ctx, filepath.Join(candidateRoot, filepath.FromSlash(source.ArchivePath)), maxReviewFileBytes)
		if err != nil {
			p.add("SOURCE_ARCHIVE_MISSING", base, "archived source object is missing, unsafe, or exceeds review limits")
			continue
		}
		if int64(len(data)) != source.ReviewedByteLength {
			p.add("SOURCE_ARCHIVE_LENGTH", base, "archived source byte length does not match sources.json")
		}
		if digestHex(data) != source.ReviewedSHA256 {
			p.add("SOURCE_ARCHIVE_HASH", base, "archived source SHA-256 does not match sources.json")
		}
	}
}

func validateUnitFilesystemInputs(packet Packet, ledger SourceLedger) error {
	var pathSafety problems
	validateID(packet.IncidentID, "/incidentId", &pathSafety)
	validateSemVer(packet.PackVersion, "/packVersion", &pathSafety)
	for index, source := range ledger.Sources {
		if source.ArchivePath == "" {
			continue
		}
		base := fmt.Sprintf("/sources/%d/archivePath", index)
		validateSafeRelativePath(source.ArchivePath, base, &pathSafety)
		if !strings.HasPrefix(source.ArchivePath, "fixtures/") {
			pathSafety.add("SOURCE_ARCHIVE_PATH", base, "redistributed source objects must be below candidate-content/fixtures")
		}
	}
	return pathSafety.err()
}

func validateCandidateValidation(validation CandidateValidation, p *problems) {
	if validation.SchemaVersion != ValidationSchema {
		p.add("SCHEMA_VERSION", "/validation/schemaVersion", "must equal %q", ValidationSchema)
	}
	validateID(validation.IncidentID, "/validation/incidentId", p)
	validateSemVer(validation.PackVersion, "/validation/packVersion", p)
	for _, field := range []struct{ pointer, value string }{
		{"/validation/originalPackSha256", validation.OriginalPackSHA256},
		{"/validation/canonicalPackSha256", validation.CanonicalPackSHA256},
		{"/validation/validatorPolicySha256", validation.ValidatorPolicySHA256},
		{"/validation/expectedFindingsSha256", validation.ExpectedFindingsSHA256},
		{"/validation/fixtureManifestSha256", validation.FixtureManifestSHA256},
	} {
		validateSHA256(field.value, field.pointer, p)
	}
	validateText(validation.ValidatorVersion, 1, 200, false, "/validation/validatorVersion", p)
	if validation.Result != "pass" {
		p.add("VALIDATION_RESULT", "/validation/result", "must equal pass")
	}
}

func validateUnitBindings(packet Packet, validation CandidateValidation, validated *incident.ValidatedPack, validatorPolicy incident.ValidatorPolicyIdentity, packetRaw, sourcesRaw, claimsRaw, conflictsRaw, expectedRaw, fixtureManifestRaw, policyRaw []byte, fixtureManifestHash, candidateManifestHash string, p *problems) {
	digests := map[string]string{
		"sources":          digestHex(sourcesRaw),
		"claims":           digestHex(claimsRaw),
		"conflicts":        digestHex(conflictsRaw),
		"expectedFindings": digestHex(expectedRaw),
		"fixtureManifest":  digestHex(fixtureManifestRaw),
		"reviewPolicy":     digestHex(policyRaw),
	}
	checks := []struct {
		path string
		got  string
		want string
	}{
		{"/packet/incidentId", packet.IncidentID, validated.Pack.Metadata.ID},
		{"/packet/packVersion", packet.PackVersion, validated.Pack.Metadata.PackVersion},
		{"/packet/originalPackSha256", packet.OriginalPackSHA256, validated.OriginalSHA256},
		{"/packet/canonicalPackSha256", packet.CanonicalPackSHA256, validated.CanonicalSHA256},
		{"/packet/validatorVersion", packet.ValidatorVersion, validated.ValidatorPolicy},
		{"/packet/validatorPolicySha256", packet.ValidatorPolicySHA256, validatorPolicy.SHA256},
		{"/packet/sourcesSha256", packet.SourcesSHA256, digests["sources"]},
		{"/packet/claimsSha256", packet.ClaimsSHA256, digests["claims"]},
		{"/packet/conflictsSha256", packet.ConflictsSHA256, digests["conflicts"]},
		{"/packet/expectedFindingsSha256", packet.ExpectedFindingsSHA256, digests["expectedFindings"]},
		{"/packet/fixtureManifestSha256", packet.FixtureManifestSHA256, digests["fixtureManifest"]},
		{"/packet/reviewPolicySha256", packet.ReviewPolicySHA256, digests["reviewPolicy"]},
		{"/validation/incidentId", validation.IncidentID, packet.IncidentID},
		{"/validation/packVersion", validation.PackVersion, packet.PackVersion},
		{"/validation/originalPackSha256", validation.OriginalPackSHA256, packet.OriginalPackSHA256},
		{"/validation/canonicalPackSha256", validation.CanonicalPackSHA256, packet.CanonicalPackSHA256},
		{"/validation/validatorVersion", validation.ValidatorVersion, packet.ValidatorVersion},
		{"/validation/validatorPolicySha256", validation.ValidatorPolicySHA256, packet.ValidatorPolicySHA256},
		{"/validation/expectedFindingsSha256", validation.ExpectedFindingsSHA256, packet.ExpectedFindingsSHA256},
		{"/validation/fixtureManifestSha256", validation.FixtureManifestSHA256, packet.FixtureManifestSHA256},
	}
	for _, check := range checks {
		if check.got != check.want {
			p.add("HASH_BINDING", check.path, "does not match the recomputed immutable review-unit value")
		}
	}
	if fixtureManifestHash != packet.FixtureManifestSHA256 {
		p.add("FIXTURE_MANIFEST_HASH", "/packet/fixtureManifestSha256", "does not match SHA-256 of exact fixture manifest bytes")
	}
	if candidateManifestHash == "" {
		p.add("CANDIDATE_MANIFEST_HASH", "/candidateManifest", "candidate manifest hash is unavailable")
	}
	_ = packetRaw // Strict decoding excludes all self-referential fields.
}

func validateReviewUnitRootEntries(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "candidate-content" || name == "approvals" || name == "promotion-record.json" || name == ReviewManifestName || name == "platform-approvals.json" {
			continue
		}
		return &ValidationError{Problems: []Problem{{Code: "UNEXPECTED_REVIEW_UNIT_ENTRY", Path: filepath.Join(root, name), Message: "entry is outside the closed review-unit layout"}}}
	}
	return nil
}

func requireCanonicalJSONFile(name string, raw []byte, value any) error {
	canonical, err := marshalCanonical(value)
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", name, err)
	}
	if !bytes.Equal(raw, canonical) {
		return &ValidationError{Problems: []Problem{{Code: "NON_CANONICAL_JSON", Path: name, Message: "JSON must use restricted RFC 8785 canonical bytes followed by one LF"}}}
	}
	return nil
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func reviewUnitPath(repositoryRoot, incidentID, packVersion string) string {
	return filepath.Join(repositoryRoot, "review-packets", incidentID, packVersion)
}

func candidatePackPath(repositoryRoot, incidentID, packVersion string) string {
	return filepath.Join(repositoryRoot, "incidents", "candidates", incidentID, packVersion+".yaml")
}

func reviewedPackPath(repositoryRoot, incidentID, packVersion string) string {
	return filepath.Join(repositoryRoot, "incidents", "reviewed", incidentID, packVersion+".yaml")
}

func slashReviewedPackPath(incidentID, packVersion string) string {
	return strings.Join([]string{"incidents", "reviewed", incidentID, packVersion + ".yaml"}, "/")
}
