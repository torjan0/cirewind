package packreview

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

// Candidate authoring. A preparer hand-writes pack.yaml, sources.json,
// claims.json, conflicts.json, and any archived source objects; this code
// derives everything else deterministically and never invents a fact: it
// canonicalizes the hand-written ledgers, writes the indexed fixture
// snapshots, replays them through the production derivation to produce the
// expected-finding oracle, and binds all of it in packet.json,
// validation.json, and the manifests. Running it twice yields identical
// bytes. It records no approval and no candidate commit.

// AuthoredScenario is one fixture snapshot supplied by a generator.
type AuthoredScenario struct {
	ScenarioID   string
	Snapshot     archive.Snapshot
	AnalysisTime time.Time
	Forbidden    []ForbiddenExpectedFinding
}

// AuthoringInput names the candidate content directory and the derived
// inputs that are not hand-written.
type AuthoringInput struct {
	CandidateContent    string
	RepositoryPolicy    string
	Scenarios           []AuthoredScenario
	ReviewPolicyProfile string
	Preparation         Preparation
}

// AssembleCandidate derives and writes the generated candidate-content files.
// It returns the packet it wrote. Callers validate the unit afterwards.
func AssembleCandidate(ctx context.Context, input AuthoringInput) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, err
	}
	candidate := input.CandidateContent
	info, err := os.Lstat(candidate)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Packet{}, errors.New("candidate content must be an existing real directory")
	}
	if len(input.Scenarios) == 0 {
		return Packet{}, errors.New("candidate authoring requires at least one fixture scenario")
	}
	if !safeFilenameComponent(input.ReviewPolicyProfile) {
		return Packet{}, errors.New("review policy profile is not a safe identifier")
	}

	packBytes, err := readBoundedRegularContext(ctx, filepath.Join(candidate, "pack.yaml"), maxReviewFileBytes)
	if err != nil {
		return Packet{}, err
	}
	validated, err := incident.Validate(ctx, packBytes)
	if err != nil {
		return Packet{}, fmt.Errorf("validate pack.yaml: %w", err)
	}

	policyRaw, err := readBoundedRegularContext(ctx, input.RepositoryPolicy, maxReviewFileBytes)
	if err != nil {
		return Packet{}, fmt.Errorf("read repository review policy: %w", err)
	}
	policy, _, err := readStrictJSON[ReviewPolicy](ctx, input.RepositoryPolicy)
	if err != nil {
		return Packet{}, err
	}
	if err := requireCanonicalJSONFile("pack-review-policy.json", policyRaw, policy); err != nil {
		return Packet{}, err
	}
	if err := writeGenerated(filepath.Join(candidate, "review-policy.json"), policyRaw); err != nil {
		return Packet{}, err
	}

	sources, sourcesRaw, err := canonicalizeLedger[SourceLedger](ctx, filepath.Join(candidate, "sources.json"))
	if err != nil {
		return Packet{}, err
	}
	_ = sources
	_, claimsRaw, err := canonicalizeLedger[ClaimLedger](ctx, filepath.Join(candidate, "claims.json"))
	if err != nil {
		return Packet{}, err
	}
	conflicts, conflictsRaw, err := canonicalizeLedger[ConflictLedger](ctx, filepath.Join(candidate, "conflicts.json"))
	if err != nil {
		return Packet{}, err
	}

	fixturesRoot := filepath.Join(candidate, "fixtures")
	if err := os.MkdirAll(filepath.Join(fixturesRoot, "scenarios"), 0o755); err != nil {
		return Packet{}, err
	}
	index := FixtureIndex{SchemaVersion: FixtureIndexSchema, Scenarios: make([]FixtureScenario, 0, len(input.Scenarios))}
	expected := ExpectedFindings{SchemaVersion: ExpectedFindingsSchema, Findings: []ExpectedFinding{}, Forbidden: []ForbiddenExpectedFinding{}}
	seen := make(map[string]struct{}, len(input.Scenarios))
	for _, scenario := range input.Scenarios {
		if err := ctx.Err(); err != nil {
			return Packet{}, err
		}
		if !stableIDRE.MatchString(scenario.ScenarioID) || !safeFilenameComponent(scenario.ScenarioID) {
			return Packet{}, fmt.Errorf("scenario ID %q is not a safe stable identifier", scenario.ScenarioID)
		}
		if _, duplicate := seen[scenario.ScenarioID]; duplicate {
			return Packet{}, fmt.Errorf("scenario ID %q is duplicated", scenario.ScenarioID)
		}
		seen[scenario.ScenarioID] = struct{}{}
		if scenario.AnalysisTime.IsZero() {
			return Packet{}, fmt.Errorf("scenario %s has no analysis time", scenario.ScenarioID)
		}
		snapshotRaw, err := marshalCanonical(scenario.Snapshot)
		if err != nil {
			return Packet{}, err
		}
		directory := filepath.Join(fixturesRoot, "scenarios", scenario.ScenarioID)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return Packet{}, err
		}
		if err := writeGenerated(filepath.Join(directory, "archive-snapshot.json"), snapshotRaw); err != nil {
			return Packet{}, err
		}
		index.Scenarios = append(index.Scenarios, FixtureScenario{
			ScenarioID: scenario.ScenarioID, SnapshotPath: "scenarios/" + scenario.ScenarioID + "/archive-snapshot.json",
			AnalysisTime: scenario.AnalysisTime.UTC().Format(time.RFC3339Nano),
		})
		result, err := analyze.Derive(scenario.Snapshot, validated, scenario.AnalysisTime, analyze.ModeReplay)
		if err != nil {
			return Packet{}, fmt.Errorf("derive scenario %s: %w", scenario.ScenarioID, err)
		}
		expected.Findings = append(expected.Findings, expectedRowsForScenario(scenario.ScenarioID, result.Case, scenario.Snapshot)...)
		for _, forbidden := range scenario.Forbidden {
			if !forbidden.State.Valid() {
				return Packet{}, fmt.Errorf("scenario %s forbids an unknown state %q", scenario.ScenarioID, forbidden.State)
			}
			for _, row := range expected.Findings {
				if row.ScenarioID == scenario.ScenarioID && row.State == forbidden.State {
					return Packet{}, fmt.Errorf("scenario %s derived forbidden state %s", scenario.ScenarioID, forbidden.State)
				}
			}
			expected.Forbidden = append(expected.Forbidden, ForbiddenExpectedFinding{ScenarioID: scenario.ScenarioID, State: forbidden.State, Rationale: forbidden.Rationale})
		}
	}
	indexRaw, err := marshalCanonical(index)
	if err != nil {
		return Packet{}, err
	}
	if err := writeGenerated(filepath.Join(fixturesRoot, "index.json"), indexRaw); err != nil {
		return Packet{}, err
	}
	expectedRaw, err := marshalCanonical(NormalizeExpectedFindings(expected))
	if err != nil {
		return Packet{}, err
	}
	if err := writeGenerated(filepath.Join(candidate, "expected-findings.json"), expectedRaw); err != nil {
		return Packet{}, err
	}
	fixtureManifest, err := BuildFixtureManifest(ctx, fixturesRoot, filepath.Join(fixturesRoot, FixtureManifestName))
	if err != nil {
		return Packet{}, err
	}

	packet := Packet{
		SchemaVersion: PacketSchema, IncidentID: validated.Pack.Metadata.ID, PackVersion: validated.Pack.Metadata.PackVersion,
		ReviewUnitPackPath: "pack.yaml", OriginalPackSHA256: validated.OriginalSHA256, CanonicalPackSHA256: validated.CanonicalSHA256,
		PackSchemaVersion: incident.APIVersion, ValidatorVersion: incident.PolicyVersion, ValidatorPolicySHA256: incident.ValidatorPolicySHA256(),
		ClaimsSHA256: digestHex(claimsRaw), SourcesSHA256: digestHex(sourcesRaw), ConflictsSHA256: digestHex(conflictsRaw),
		ExpectedFindingsSHA256: digestHex(expectedRaw), FixtureManifestSHA256: digestHex(fixtureManifest), ConflictIDs: conflictIDs(conflicts),
		ReviewPolicyProfile: input.ReviewPolicyProfile, ReviewPolicySHA256: digestHex(policyRaw), Preparation: input.Preparation,
	}
	packetRaw, err := marshalCanonical(packet)
	if err != nil {
		return Packet{}, err
	}
	if err := writeGenerated(filepath.Join(candidate, "packet.json"), packetRaw); err != nil {
		return Packet{}, err
	}
	validation := CandidateValidation{SchemaVersion: ValidationSchema, IncidentID: packet.IncidentID, PackVersion: packet.PackVersion,
		OriginalPackSHA256: packet.OriginalPackSHA256, CanonicalPackSHA256: packet.CanonicalPackSHA256,
		ValidatorVersion: packet.ValidatorVersion, ValidatorPolicySHA256: packet.ValidatorPolicySHA256,
		ExpectedFindingsSHA256: packet.ExpectedFindingsSHA256, FixtureManifestSHA256: packet.FixtureManifestSHA256, Result: "pass"}
	validationRaw, err := marshalCanonical(validation)
	if err != nil {
		return Packet{}, err
	}
	if err := writeGenerated(filepath.Join(candidate, "validation.json"), validationRaw); err != nil {
		return Packet{}, err
	}
	if _, err := BuildCandidateManifest(ctx, candidate, filepath.Join(candidate, CandidateManifestName)); err != nil {
		return Packet{}, err
	}
	return packet, nil
}

// canonicalizeLedger strictly decodes a hand-written ledger and rewrites it
// in canonical form so its bytes are the hash-bound review input.
func canonicalizeLedger[T any](ctx context.Context, path string) (T, []byte, error) {
	value, _, err := readStrictJSON[T](ctx, path)
	if err != nil {
		var zero T
		return zero, nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	canonical, err := marshalCanonical(value)
	if err != nil {
		var zero T
		return zero, nil, err
	}
	if err := writeGenerated(path, canonical); err != nil {
		var zero T
		return zero, nil, err
	}
	return value, canonical, nil
}

// writeGenerated replaces a generated regular file; it refuses links.
func writeGenerated(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular file %s", filepath.Base(path))
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// ForbiddenStateFor converts a model state into an oracle forbidden row.
func ForbiddenStateFor(scenarioID string, state model.FindingState, rationale string) ForbiddenExpectedFinding {
	return ForbiddenExpectedFinding{ScenarioID: scenarioID, State: state, Rationale: rationale}
}
