package packreview

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
)

func validateExpectedFindings(oracle ExpectedFindings, p *problems) {
	if oracle.SchemaVersion != ExpectedFindingsSchema {
		p.add("SCHEMA_VERSION", "/expectedFindings/schemaVersion", "must equal %q", ExpectedFindingsSchema)
	}
	if len(oracle.Findings) == 0 || len(oracle.Findings) > 20_000 {
		p.add("EXPECTED_FINDING_COUNT", "/expectedFindings/findings", "must contain 1-20000 rows")
	}
	if len(oracle.Forbidden) == 0 || len(oracle.Forbidden) > 20_000 {
		p.add("FORBIDDEN_FINDING_COUNT", "/expectedFindings/forbidden", "must contain 1-20000 rows")
	}

	expectedStates := make(map[string]struct{}, len(oracle.Findings))
	previous := ""
	for index, finding := range oracle.Findings {
		base := fmt.Sprintf("/expectedFindings/findings/%d", index)
		if finding.EvidenceIDs == nil || finding.CoverageAssessmentIDs == nil || finding.EvidenceGapCodes == nil {
			p.add("EXPLICIT_ARRAY", base, "evidenceIds, coverageAssessmentIds, and evidenceGapCodes must be arrays, not null")
		}
		validateID(finding.ScenarioID, base+"/scenarioId", p)
		validateID(finding.IndicatorID, base+"/indicatorId", p)
		validateRepository(finding.Repository, base+"/repository", p)
		if finding.Workflow != "" {
			validateWorkflowPath(finding.Workflow, base+"/workflow", p)
		}
		for _, field := range []struct {
			name  string
			value int64
		}{{"runId", finding.RunID}, {"runAttempt", finding.RunAttempt}, {"jobId", finding.JobID}} {
			if field.value < 0 || field.value > 1<<53-1 {
				p.add("EXPECTED_EXECUTION_ID", base+"/"+field.name, "execution ID must be absent or a positive JSON-safe integer")
			}
		}
		if finding.RunAttempt != 0 && finding.RunID == 0 || finding.JobID != 0 && (finding.RunID == 0 || finding.RunAttempt == 0) || finding.StepIdentity != "" && (finding.RunID == 0 || finding.RunAttempt == 0 || finding.JobID == 0) {
			p.add("EXPECTED_EXECUTION_HIERARCHY", base, "attempt requires run, job requires attempt, and step requires job identity")
		}
		if finding.RunID == 0 && (finding.RunAttempt != 0 || finding.JobID != 0 || finding.StepIdentity != "") {
			p.add("EXPECTED_EXECUTION_HIERARCHY", base, "repository-scoped finding must omit all child execution identity")
		}
		if finding.RunID != 0 && finding.RunID <= 0 || finding.RunAttempt != 0 && finding.RunAttempt <= 0 || finding.JobID != 0 && finding.JobID <= 0 {
			p.add("EXPECTED_EXECUTION_ID", base, "present execution IDs must be positive")
		}
		if finding.StepIdentity != "" {
			validateText(finding.StepIdentity, 1, 4096, false, base+"/stepIdentity", p)
		}
		if !finding.State.Valid() {
			p.add("FINDING_STATE", base+"/state", "must use a canonical finding state")
		}
		if !finding.Provenance.Valid() {
			p.add("PROVENANCE_LEVEL", base+"/provenance", "must use a canonical provenance level")
		}
		validateExpectedEvidenceIDs(finding.EvidenceIDs, base+"/evidenceIds", p)
		validateExpectedCoverageIDs(finding.CoverageAssessmentIDs, base+"/coverageAssessmentIds", p)
		validateSortedUniqueIDs(finding.EvidenceGapCodes, base+"/evidenceGapCodes", p)
		if len(finding.EvidenceIDs) == 0 && len(finding.EvidenceGapCodes) == 0 {
			p.add("EXPECTED_FINDING_SUPPORT", base, "finding requires evidence IDs or an explicit evidence-gap code")
		}
		if finding.State == model.UnknownEvidenceGap && len(finding.EvidenceGapCodes) == 0 {
			p.add("EXPECTED_UNKNOWN_GAP", base+"/evidenceGapCodes", "UNKNOWN_EVIDENCE_GAP requires an explicit gap code")
		}
		if finding.State == model.NoMatchConfirmed && (len(finding.EvidenceIDs) == 0 || len(finding.CoverageAssessmentIDs) == 0 || len(finding.EvidenceGapCodes) != 0) {
			p.add("EXPECTED_NO_MATCH_COVERAGE", base, "NO_MATCH_CONFIRMED requires evidence, closed coverage, and no gap codes")
		}

		key := expectedFindingKey(finding)
		if previous >= key {
			p.add("EXPECTED_FINDING_ORDER", base, "finding rows must be strictly sorted by execution identity and state")
		}
		previous = key
		expectedStates[finding.ScenarioID+"\x00"+string(finding.State)] = struct{}{}
	}

	previous = ""
	for index, forbidden := range oracle.Forbidden {
		base := fmt.Sprintf("/expectedFindings/forbidden/%d", index)
		validateID(forbidden.ScenarioID, base+"/scenarioId", p)
		if !forbidden.State.Valid() {
			p.add("FINDING_STATE", base+"/state", "must use a canonical finding state")
		}
		validateText(forbidden.Rationale, 1, 4096, true, base+"/rationale", p)
		key := forbidden.ScenarioID + "\x00" + string(forbidden.State)
		if previous >= key {
			p.add("FORBIDDEN_FINDING_ORDER", base, "forbidden rows must be strictly sorted by scenario and state")
		}
		previous = key
		if _, contradictory := expectedStates[key]; contradictory {
			p.add("CONTRADICTORY_ORACLE", base, "the same scenario and state are both expected and forbidden")
		}
	}
}

func validateExpectedEvidenceIDs(ids []model.EvidenceID, pointer string, p *problems) {
	if len(ids) > 2000 {
		p.add("EVIDENCE_ID_COUNT", pointer, "must contain at most 2000 evidence IDs")
	}
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			p.add("EVIDENCE_ID", fmt.Sprintf("%s/%d", pointer, index), "must be a canonical evidence ID")
		}
		if index > 0 && ids[index-1] >= id {
			p.add("CANONICAL_ORDER", pointer, "must be strictly sorted and unique")
			break
		}
	}
}

func validateExpectedCoverageIDs(ids []model.CoverageAssessmentID, pointer string, p *problems) {
	if len(ids) > 2000 {
		p.add("COVERAGE_ID_COUNT", pointer, "must contain at most 2000 coverage assessment IDs")
	}
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			p.add("COVERAGE_ASSESSMENT_ID", fmt.Sprintf("%s/%d", pointer, index), "must be a canonical coverage assessment ID")
		}
		if index > 0 && ids[index-1] >= id {
			p.add("CANONICAL_ORDER", pointer, "must be strictly sorted and unique")
			break
		}
	}
}

func validateWorkflowPath(value, pointer string, p *problems) {
	workflow, err := model.NewWorkflowPath(value)
	text := string(workflow)
	extension := path.Ext(text)
	relative := strings.TrimPrefix(text, ".github/workflows/")
	if err != nil || !reviewWorkflowRE.MatchString(text) || !strings.HasPrefix(text, ".github/workflows/") || extension != ".yml" && extension != ".yaml" || strings.TrimSuffix(relative, extension) == "" {
		p.add("WORKFLOW_PATH", pointer, "must be a canonical .github/workflows/*.yml or *.yaml path")
	}
}

func expectedFindingKey(finding ExpectedFinding) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%020d\x00%020d\x00%020d\x00%s\x00%s",
		finding.ScenarioID, finding.IndicatorID, finding.Repository, finding.Workflow,
		finding.RunID, finding.RunAttempt, finding.JobID, finding.StepIdentity, finding.State)
}

// NormalizeExpectedFindings returns a canonical ordering for packet builders.
// It does not create expected conclusions or execute fixtures.
func NormalizeExpectedFindings(oracle ExpectedFindings) ExpectedFindings {
	result := oracle
	result.Findings = append([]ExpectedFinding(nil), oracle.Findings...)
	for index := range result.Findings {
		result.Findings[index].EvidenceIDs = cloneEvidenceIDs(result.Findings[index].EvidenceIDs)
		result.Findings[index].CoverageAssessmentIDs = cloneCoverageIDs(result.Findings[index].CoverageAssessmentIDs)
		result.Findings[index].EvidenceGapCodes = cloneStrings(result.Findings[index].EvidenceGapCodes)
		sort.Strings(result.Findings[index].EvidenceGapCodes)
		sort.Slice(result.Findings[index].EvidenceIDs, func(left, right int) bool {
			return result.Findings[index].EvidenceIDs[left] < result.Findings[index].EvidenceIDs[right]
		})
		sort.Slice(result.Findings[index].CoverageAssessmentIDs, func(left, right int) bool {
			return result.Findings[index].CoverageAssessmentIDs[left] < result.Findings[index].CoverageAssessmentIDs[right]
		})
	}
	sort.Slice(result.Findings, func(left, right int) bool {
		return expectedFindingKey(result.Findings[left]) < expectedFindingKey(result.Findings[right])
	})
	result.Forbidden = append([]ForbiddenExpectedFinding(nil), oracle.Forbidden...)
	sort.Slice(result.Forbidden, func(left, right int) bool {
		leftKey := result.Forbidden[left].ScenarioID + "\x00" + string(result.Forbidden[left].State)
		rightKey := result.Forbidden[right].ScenarioID + "\x00" + string(result.Forbidden[right].State)
		return leftKey < rightKey
	})
	return result
}

func cloneEvidenceIDs(values []model.EvidenceID) []model.EvidenceID {
	result := make([]model.EvidenceID, len(values))
	copy(result, values)
	return result
}

func cloneCoverageIDs(values []model.CoverageAssessmentID) []model.CoverageAssessmentID {
	result := make([]model.CoverageAssessmentID, len(values))
	copy(result, values)
	return result
}

func cloneStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}
