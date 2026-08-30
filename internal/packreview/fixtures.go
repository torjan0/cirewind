package packreview

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func validateFixtureResults(ctx context.Context, candidateRoot string, pack *incident.ValidatedPack, oracle ExpectedFindings, p *problems) error {
	fixturesRoot := filepath.Join(candidateRoot, "fixtures")
	index, raw, err := readStrictJSON[FixtureIndex](ctx, filepath.Join(fixturesRoot, "index.json"))
	if err != nil {
		return fmt.Errorf("read fixture index: %w", err)
	}
	if err := requireCanonicalJSONFile("fixtures/index.json", raw, index); err != nil {
		return err
	}
	validateFixtureIndex(index, oracle, p)
	if err := validateFixtureScenarioTree(ctx, fixturesRoot, index, p); err != nil {
		return err
	}
	for scenarioIndex, scenario := range index.Scenarios {
		if err := ctx.Err(); err != nil {
			return err
		}
		base := fmt.Sprintf("/fixtures/scenarios/%d", scenarioIndex)
		// Derive the only path we will read from an already-safe scenario ID.
		// Merely recording an invalid path as a later validation problem is not
		// sufficient: hostile candidate content must never cause an out-of-root
		// read, even when the candidate will ultimately be rejected.
		if !stableIDRE.MatchString(scenario.ScenarioID) || !safeFilenameComponent(scenario.ScenarioID) {
			continue
		}
		wantPath := "scenarios/" + scenario.ScenarioID + "/archive-snapshot.json"
		if scenario.SnapshotPath != wantPath {
			continue
		}
		snapshotPath := filepath.Join(fixturesRoot, filepath.FromSlash(wantPath))
		snapshotRaw, err := readBoundedRegularContext(ctx, snapshotPath, maxReviewFileBytes)
		if err != nil {
			p.add("FIXTURE_SNAPSHOT_READ", base+"/snapshotPath", "snapshot is missing, unsafe, or exceeds review limits")
			continue
		}
		if err := rejectDuplicateJSONKeys(snapshotRaw); err != nil {
			p.add("FIXTURE_SNAPSHOT_JSON", base+"/snapshotPath", "snapshot contains duplicate keys or invalid JSON")
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		snapshot, err := archive.DecodeSnapshot(bytes.NewReader(snapshotRaw))
		if err != nil {
			p.add("FIXTURE_SNAPSHOT", base+"/snapshotPath", "%s", boundedError(err))
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		canonical, err := marshalCanonical(snapshot)
		if err != nil || !bytes.Equal(snapshotRaw, canonical) {
			p.add("FIXTURE_SNAPSHOT_CANONICAL", base+"/snapshotPath", "snapshot must use normalized canonical JSON followed by one LF")
			continue
		}
		analysisTime, err := time.Parse(time.RFC3339Nano, scenario.AnalysisTime)
		if err != nil {
			continue // validateFixtureIndex already records the bounded diagnostic.
		}
		result, err := analyze.Derive(snapshot, pack, analysisTime, analyze.ModeReplay)
		if err != nil {
			p.add("FIXTURE_ANALYSIS", base, "%s", boundedError(err))
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		actual := expectedRowsForScenario(scenario.ScenarioID, result.Case, snapshot)
		want := expectedRowsForID(oracle.Findings, scenario.ScenarioID)
		if !reflect.DeepEqual(actual, want) {
			p.add("FIXTURE_ORACLE_MISMATCH", base, "derived finding identities, states, provenance, evidence, or gap codes do not match the frozen oracle")
		}
		for _, forbidden := range oracle.Forbidden {
			if forbidden.ScenarioID != scenario.ScenarioID {
				continue
			}
			for _, finding := range actual {
				if finding.State == forbidden.State {
					p.add("FORBIDDEN_FIXTURE_STATE", base, "derived state %s is explicitly forbidden by the synthetic oracle", forbidden.State)
				}
			}
		}
	}
	return nil
}

func validateFixtureScenarioTree(ctx context.Context, fixturesRoot string, index FixtureIndex, p *problems) error {
	scenariosRoot := filepath.Join(fixturesRoot, "scenarios")
	entries, err := scanTree(ctx, scenariosRoot, func(string) bool { return false }, validateScenarioDirectory, validateScenarioFile)
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, len(index.Scenarios))
	for _, scenario := range index.Scenarios {
		if !stableIDRE.MatchString(scenario.ScenarioID) || !safeFilenameComponent(scenario.ScenarioID) {
			continue
		}
		expected := scenario.ScenarioID + "/archive-snapshot.json"
		if scenario.SnapshotPath == "scenarios/"+expected {
			want[expected] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		seen[entry.Path] = struct{}{}
		if _, ok := want[entry.Path]; !ok {
			p.add("UNINDEXED_FIXTURE_SNAPSHOT", "/fixtures/scenarios", "scenario tree contains unindexed snapshot %s", entry.Path)
		}
	}
	for expected := range want {
		if _, ok := seen[expected]; !ok {
			p.add("MISSING_FIXTURE_SNAPSHOT", "/fixtures/scenarios", "fixture index references missing snapshot %s", expected)
		}
	}
	return nil
}

func validateScenarioDirectory(name string) error {
	if !strings.Contains(name, "/") && stableIDRE.MatchString(name) && safeFilenameComponent(name) {
		return nil
	}
	return &ValidationError{Problems: []Problem{{Code: "FIXTURE_SCENARIO_DIRECTORY", Path: name, Message: "scenario tree permits one safe scenario-ID directory level"}}}
}

func validateScenarioFile(name string, data []byte) error {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || !stableIDRE.MatchString(parts[0]) || !safeFilenameComponent(parts[0]) || parts[1] != "archive-snapshot.json" {
		return &ValidationError{Problems: []Problem{{Code: "FIXTURE_SCENARIO_FILE", Path: name, Message: "scenario directory permits only archive-snapshot.json"}}}
	}
	return rejectActiveOrSensitiveFixture(name, data)
}

func validateFixtureIndex(index FixtureIndex, oracle ExpectedFindings, p *problems) {
	if index.SchemaVersion != FixtureIndexSchema {
		p.add("SCHEMA_VERSION", "/fixtures/schemaVersion", "must equal %q", FixtureIndexSchema)
	}
	if len(index.Scenarios) == 0 || len(index.Scenarios) > 2000 {
		p.add("FIXTURE_SCENARIO_COUNT", "/fixtures/scenarios", "must contain 1-2000 scenarios")
	}
	known := make(map[string]struct{}, len(index.Scenarios))
	for position, scenario := range index.Scenarios {
		base := fmt.Sprintf("/fixtures/scenarios/%d", position)
		validateID(scenario.ScenarioID, base+"/scenarioId", p)
		if position > 0 && index.Scenarios[position-1].ScenarioID >= scenario.ScenarioID {
			p.add("FIXTURE_SCENARIO_ORDER", "/fixtures/scenarios", "scenarios must be strictly sorted by scenarioId")
		}
		known[scenario.ScenarioID] = struct{}{}
		wantPath := "scenarios/" + scenario.ScenarioID + "/archive-snapshot.json"
		if scenario.SnapshotPath != wantPath {
			p.add("FIXTURE_SNAPSHOT_PATH", base+"/snapshotPath", "must equal the scenario-ID-derived archive snapshot path")
		}
		validateSafeRelativePath(scenario.SnapshotPath, base+"/snapshotPath", p)
		validateTime(scenario.AnalysisTime, base+"/analysisTime", p)
	}
	rows := make(map[string]int, len(oracle.Findings)+len(oracle.Forbidden))
	for _, finding := range oracle.Findings {
		rows[finding.ScenarioID]++
		if _, ok := known[finding.ScenarioID]; !ok {
			p.add("UNKNOWN_FIXTURE_SCENARIO", "/expectedFindings/findings", "oracle references unknown scenario %s", finding.ScenarioID)
		}
	}
	for _, forbidden := range oracle.Forbidden {
		rows[forbidden.ScenarioID]++
		if _, ok := known[forbidden.ScenarioID]; !ok {
			p.add("UNKNOWN_FIXTURE_SCENARIO", "/expectedFindings/forbidden", "oracle references unknown scenario %s", forbidden.ScenarioID)
		}
	}
	for scenarioID := range known {
		if rows[scenarioID] == 0 {
			p.add("UNMAPPED_FIXTURE_SCENARIO", "/fixtures/scenarios", "scenario %s has no expected or forbidden oracle row", scenarioID)
		}
	}
}

func expectedRowsForScenario(scenarioID string, caseValue report.Case, snapshot archive.Snapshot) []ExpectedFinding {
	gapCodes := coverageGapCodes(snapshot)
	rows := make([]ExpectedFinding, 0, len(caseValue.Findings))
	for _, finding := range caseValue.Findings {
		evidenceIDs := make([]model.EvidenceID, len(finding.EvidenceIDs))
		for index, evidenceID := range finding.EvidenceIDs {
			evidenceIDs[index] = model.EvidenceID(evidenceID)
		}
		gaps := make([]string, 0)
		for _, coverageID := range finding.CollectionCoverage {
			if code := gapCodes[coverageID]; code != "" {
				gaps = append(gaps, code)
			}
		}
		sort.Strings(gaps)
		gaps = deduplicateStrings(gaps)
		rows = append(rows, ExpectedFinding{
			ScenarioID: scenarioID, IndicatorID: finding.IndicatorID, Repository: finding.Repository,
			Workflow: finding.Workflow, RunID: finding.RunID, RunAttempt: int64(finding.RunAttempt), JobID: finding.JobID,
			StepIdentity: finding.StepIdentity, State: model.FindingState(finding.State), Provenance: model.ProvenanceLevel(finding.Provenance),
			EvidenceIDs: evidenceIDs, CoverageAssessmentIDs: coverageAssessmentIDs(finding.CollectionCoverage), EvidenceGapCodes: gaps,
		})
	}
	normalized := NormalizeExpectedFindings(ExpectedFindings{Findings: rows})
	return normalized.Findings
}

func coverageAssessmentIDs(values []string) []model.CoverageAssessmentID {
	result := make([]model.CoverageAssessmentID, len(values))
	for index, value := range values {
		result[index] = model.CoverageAssessmentID(value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func expectedRowsForID(rows []ExpectedFinding, scenarioID string) []ExpectedFinding {
	result := make([]ExpectedFinding, 0)
	for _, row := range rows {
		if row.ScenarioID == scenarioID {
			result = append(result, row)
		}
	}
	normalized := NormalizeExpectedFindings(ExpectedFindings{Findings: result})
	return normalized.Findings
}

func coverageGapCodes(snapshot archive.Snapshot) map[string]string {
	result := make(map[string]string)
	for _, fact := range snapshot.Facts {
		if fact.CoverageGap == nil || fact.CoverageGap.Assessment.Gap == nil {
			continue
		}
		result[string(fact.CoverageGap.Assessment.ID)] = string(fact.CoverageGap.Assessment.Gap.Reason)
	}
	return result
}

func deduplicateStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
