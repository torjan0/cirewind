package demodata

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

// ExposureMetric names the six bounded contextual relationships asserted by
// the synthetic demo. These are counts, not severity scores.
type ExposureMetric string

const (
	ExposureWriteTokenJob       ExposureMetric = "WRITE_CAPABLE_GITHUB_TOKEN_JOB"
	ExposureNamedSecretFlow     ExposureMetric = "NAMED_SECRET_FLOW"
	ExposureOIDCMintingJob      ExposureMetric = "OIDC_MINTING_CAPABILITY_JOB"
	ExposureSelfHostedRunnerJob ExposureMetric = "SELF_HOSTED_RUNNER_JOB"
	ExposureDeploymentAfter     ExposureMetric = "DEPLOYMENT_OBSERVED_AFTER"
	ExposureEnvironmentPending  ExposureMetric = "ENVIRONMENT_GATE_NOT_CROSSED"
)

// ExpectedFinding is an exact per-indicator subject conclusion in the v2
// synthetic fixture. It deliberately preserves attempt and job identity.
type ExpectedFinding struct {
	IndicatorID  string
	Workflow     string
	RunID        int64
	RunAttempt   int
	JobID        int64
	StepIdentity string
	State        model.FindingState
	Provenance   model.ProvenanceLevel
	EvidenceIDs  []string
	CoverageIDs  []string
}

// ExpectedExposure is one exact, versioned presentation relationship in the
// synthetic case. The oracle compares the complete record rather than scanning
// conclusion prose for a few forbidden phrases: a changed conclusion, basis,
// subject, or evidence chain is a demo NO-GO even when the aggregate count is
// unchanged.
type ExpectedExposure struct {
	Metric       ExposureMetric
	Category     string
	IndicatorID  string
	RunID        int64
	RunAttempt   int
	JobID        int64
	StepIdentity string
	Kind         string
	Name         string
	Capability   string
	Basis        string
	Conclusion   string
	EvidenceIDs  []string
}

// ExpectedEnvironment is the exact non-executed environment context retained
// by the fixture. It is deliberately separate from finding exposure arrays:
// a pending, unstarted job has no environment-secret eligibility.
type ExpectedEnvironment struct {
	Execution       model.JobExecutionIdentity
	EnvironmentName string
	GateState       string
	JobStarted      bool
	EvidenceIDs     []string
}

// Oracle is the versioned result contract for the embedded demonstration.
type Oracle struct {
	ID                  string
	PackOriginalSHA256  string
	PackCanonicalSHA256 string
	FindingCounts       map[model.FindingState]int
	ExposureCounts      map[ExposureMetric]int
	Findings            []ExpectedFinding
	Exposures           []ExpectedExposure
	Environment         ExpectedEnvironment
	FinalFiles          []string
	OIDCRuleID          string
}

func newOracle() Oracle {
	findings := []ExpectedFinding{
		{IndicatorID: "synthetic-paired-rerun-compromised-commit", RunID: 1001, RunAttempt: 1, JobID: 2001, StepIdentity: "101/1001/1/2001/step:2/MAIN/1", State: model.ConfirmedExecuted, Provenance: model.L4Certain},
		{
			IndicatorID: "synthetic-paired-rerun-compromised-commit", RunID: 1001, RunAttempt: 2, JobID: 2101,
			StepIdentity: "101/1001/2/2101/step:2/MAIN/1", State: model.NoMatchConfirmed, Provenance: model.L4Certain,
			EvidenceIDs: []string{"ev1:9963e4351aa7b4a3cc1aba93e372a596230672a04a59ac18295f43a1e91e5bc2"},
			CoverageIDs: []string{
				"cova1:a7aab9549e45a8e78c934514f5a8512bf70883d77708d87c9350183a997bdad2",
				"cova1:b59477a5fe0c24a954a2e7c448e04aacd454239f2aeee447093cb95c50e09987",
			},
		},
		{IndicatorID: "synthetic-compromised-commit", RunID: 1002, RunAttempt: 1, JobID: 2002, State: model.ConfirmedDownloaded, Provenance: model.L4Certain},
		{IndicatorID: "synthetic-called-workflow", RunID: 1003, RunAttempt: 2, State: model.ConfirmedCalledWorkflow, Provenance: model.L4Certain},
		{IndicatorID: "synthetic-compromised-commit", RunID: 1004, RunAttempt: 1, JobID: 2004, State: model.PotentialTransitive, Provenance: model.L1Possible},
		{IndicatorID: "synthetic-mutable-ref", RunID: 1004, RunAttempt: 1, JobID: 2004, State: model.PotentialTransitive, Provenance: model.L1Possible},
		{IndicatorID: "synthetic-mutable-ref", RunID: 1005, RunAttempt: 1, JobID: 2005, State: model.RunInWindowMutableRef, Provenance: model.L2Probable},
		{IndicatorID: "synthetic-compromised-commit", Workflow: ".github/workflows/current.yml", State: model.CurrentReferenceOnly, Provenance: model.L1Possible},
		{IndicatorID: "synthetic-action-package", RunID: 1007, RunAttempt: 1, JobID: 2007, State: model.UnknownEvidenceGap, Provenance: model.L0Unknown},
		{IndicatorID: "synthetic-compromised-commit", RunID: 1008, RunAttempt: 1, JobID: 2008, StepIdentity: "101/1008/1/2008/step:2/MAIN/1", State: model.ContradictoryEvidence, Provenance: model.L4Certain},
		{IndicatorID: "synthetic-compromised-commit", RunID: 1010, RunAttempt: 1, JobID: 2010, State: model.DeclaredAtRunSHA, Provenance: model.L3Strong},
	}
	exposureEvidence := []string{"ev1:71e0c8ba4c43bec297a1451db3fe36fab876da7659f73be77b8cdb1405739dfc"}
	exposureSubject := ExpectedFinding{
		IndicatorID: "synthetic-paired-rerun-compromised-commit",
		RunID:       1001, RunAttempt: 1, JobID: 2001,
		StepIdentity: "101/1001/1/2001/step:2/MAIN/1",
	}
	exposure := func(metric ExposureMetric, category, kind, name, capability, basis, conclusion string) ExpectedExposure {
		return ExpectedExposure{
			Metric: metric, Category: category,
			IndicatorID: exposureSubject.IndicatorID, RunID: exposureSubject.RunID,
			RunAttempt: exposureSubject.RunAttempt, JobID: exposureSubject.JobID,
			StepIdentity: exposureSubject.StepIdentity,
			Kind:         kind, Name: name, Capability: capability, Basis: basis,
			Conclusion: conclusion, EvidenceIDs: append([]string(nil), exposureEvidence...),
		}
	}
	return Oracle{
		ID:                  BundleID,
		PackOriginalSHA256:  "a86eb0a3d19ecdf73a19017ea47362e5e52e12cd641e2aafab34ab6bed86caa9",
		PackCanonicalSHA256: "0b91d20cc3c4f9f080bd09a420f54386a2b7808cb9846dba2b1c749341cac418",
		FindingCounts: map[model.FindingState]int{
			model.ConfirmedExecuted:       1,
			model.ConfirmedDownloaded:     1,
			model.ConfirmedCalledWorkflow: 1,
			model.DeclaredAtRunSHA:        1,
			model.RunInWindowMutableRef:   1,
			model.PotentialTransitive:     2,
			model.CurrentReferenceOnly:    1,
			model.NoMatchConfirmed:        1,
			model.UnknownEvidenceGap:      1,
			model.ContradictoryEvidence:   1,
		},
		ExposureCounts: map[ExposureMetric]int{
			ExposureWriteTokenJob:       1,
			ExposureNamedSecretFlow:     1,
			ExposureOIDCMintingJob:      1,
			ExposureSelfHostedRunnerJob: 1,
			ExposureDeploymentAfter:     1,
			ExposureEnvironmentPending:  1,
		},
		Findings: findings,
		Exposures: []ExpectedExposure{
			exposure(
				ExposureWriteTokenJob, "credential", string(model.ExposureGitHubTokenPermission), "", "contents:write",
				string(model.ExposureBasisRuntimeObserved),
				"The affected lifecycle could use the runtime-observed contents: write permission; no repository write was proven.",
			),
			exposure(
				"", "credential", string(model.ExposureGitHubTokenPermission), "", "id-token:write",
				string(model.ExposureBasisRuntimeObserved),
				"The affected lifecycle had the runtime-observed id-token: write permission; this typed permission supports only the bounded OIDC capability inference.",
			),
			exposure(
				ExposureOIDCMintingJob, "credential", string(model.ExposureOIDCMintingCapability), "", "id-token:write",
				string(model.ExposureBasisRuntimeObserved),
				"Runtime-observed id-token: write supports only OIDC minting capability under oidc-minting-capability/v1; no token request, cloud trust, exchange, cloud identity, or role assumption was proven.",
			),
			exposure(
				ExposureNamedSecretFlow, "credential", string(model.ExposureSecretPassedToStep), "FAKE_DEPLOY_KEY", "",
				string(model.ExposureBasisHistoricalDefinitionFlow),
				"The historical definition passed the fake named secret to the affected step; no value, read, or exfiltration was proven.",
			),
			exposure(
				ExposureDeploymentAfter, "resource", string(model.ResourceDeployment), "synthetic-deployment", "",
				string(model.CorrelationObservedAfter),
				"A synthetic deployment was observed after the affected step; causation was not proven.",
			),
			exposure(
				ExposureSelfHostedRunnerJob, "resource", "SELF_HOSTED_RUNNER", "synthetic-runner", "", "observed",
				"Affected job runner classification was observed; persistence is not inferred.",
			),
		},
		Environment: ExpectedEnvironment{
			Execution:       model.JobExecutionIdentity{RepositoryID: 101, RunID: 1005, RunAttempt: 1, JobID: 2005},
			EnvironmentName: "production-fixture", GateState: "pending", JobStarted: false,
			EvidenceIDs: []string{"ev1:4c434e7380c9b3687b437152754b9326a842ca55bd6c657412333306f11e89bf"},
		},
		FinalFiles: []string{
			"affected-runs.csv",
			"case.db",
			"collection-metadata.json",
			"evidence.jsonl",
			"findings.json",
			"graph.json",
			"graph.svg",
			"report.html",
			"summary.md",
			"manifest.sha256",
		},
		OIDCRuleID: OIDCCapabilityRuleID,
	}
}

// Validate checks both cross-fact fixture invariants and the full per-indicator
// derived result set. Any mismatch is a demo NO-GO; it is never coerced into a
// safer or more severe state.
func (o Oracle) Validate(snapshot archive.Snapshot, caseValue report.Case) error {
	if o.ID != BundleID || o.OIDCRuleID != OIDCCapabilityRuleID {
		return errors.New("synthetic oracle identity or OIDC rule drifted")
	}
	if caseValue.Metadata.IncidentPackVersion != FixtureVersion ||
		caseValue.Metadata.SourcePackSHA256 != o.PackOriginalSHA256 ||
		caseValue.Metadata.CanonicalPackSHA256 != o.PackCanonicalSHA256 {
		return fmt.Errorf(
			"synthetic pack provenance drifted: version=%q source=%q canonical=%q",
			caseValue.Metadata.IncidentPackVersion,
			caseValue.Metadata.SourcePackSHA256,
			caseValue.Metadata.CanonicalPackSHA256,
		)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	actualCounts := make(map[model.FindingState]int, len(model.FindingStates()))
	expected := make(map[string]ExpectedFinding, len(o.Findings))
	for _, item := range o.Findings {
		key := expectedFindingKey(item.IndicatorID, item.RunID, item.RunAttempt, item.JobID, item.StepIdentity)
		if _, duplicate := expected[key]; duplicate {
			return fmt.Errorf("oracle has duplicate expected finding %s", key)
		}
		expected[key] = item
	}
	for _, finding := range caseValue.Findings {
		state := model.FindingState(finding.State)
		if !state.Valid() {
			return fmt.Errorf("derived non-canonical state %q", finding.State)
		}
		actualCounts[state]++
		key := expectedFindingKey(finding.IndicatorID, finding.RunID, finding.RunAttempt, finding.JobID, finding.StepIdentity)
		want, ok := expected[key]
		if !ok {
			return fmt.Errorf("unexpected derived finding %s state=%s", key, finding.State)
		}
		if state != want.State || model.ProvenanceLevel(finding.Provenance) != want.Provenance {
			return fmt.Errorf("finding %s got %s/%s, want %s/%s", key, finding.State, finding.Provenance, want.State, want.Provenance)
		}
		if want.Workflow != "" && finding.Workflow != want.Workflow {
			return fmt.Errorf("finding %s workflow=%q, want %q", key, finding.Workflow, want.Workflow)
		}
		if state == model.CurrentReferenceOnly && finding.EventTime != "unknown" {
			return fmt.Errorf("present-day-only finding %s event time=%q, want explicitly unknown", key, finding.EventTime)
		}
		if state == model.CurrentReferenceOnly && len(finding.CollectionCoverage) != 0 {
			return fmt.Errorf("present-day-only finding %s acquired historical run/job coverage %v", key, finding.CollectionCoverage)
		}
		if state == model.NoMatchConfirmed {
			if !equalStrings(finding.EvidenceIDs, want.EvidenceIDs) || !equalStrings(finding.CollectionCoverage, want.CoverageIDs) || len(finding.EvidenceGaps) != 0 {
				return fmt.Errorf("restored-A finding %s does not cite the exact known-good evidence and closed coverage", key)
			}
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return fmt.Errorf("missing expected findings: %s", strings.Join(keys, ", "))
	}
	if len(caseValue.Findings) != len(o.Findings) {
		return fmt.Errorf("derived %d findings, want %d", len(caseValue.Findings), len(o.Findings))
	}
	for _, state := range model.FindingStates() {
		if actualCounts[state] != o.FindingCounts[state] {
			return fmt.Errorf("state %s count=%d, want %d", state, actualCounts[state], o.FindingCounts[state])
		}
	}
	actualExposures, err := o.validateExposures(caseValue, snapshot)
	if err != nil {
		return err
	}
	for _, metric := range []ExposureMetric{
		ExposureWriteTokenJob,
		ExposureNamedSecretFlow,
		ExposureOIDCMintingJob,
		ExposureSelfHostedRunnerJob,
		ExposureDeploymentAfter,
		ExposureEnvironmentPending,
	} {
		want := o.ExposureCounts[metric]
		if actualExposures[metric] != want {
			return fmt.Errorf("exposure %s count=%d, want %d", metric, actualExposures[metric], want)
		}
	}
	return nil
}

func expectedFindingKey(indicator string, runID int64, attempt int, jobID int64, stepIdentity string) string {
	return fmt.Sprintf("%s/run:%d/attempt:%d/job:%d/step:%s", indicator, runID, attempt, jobID, stepIdentity)
}

func (o Oracle) validateExposures(caseValue report.Case, snapshot archive.Snapshot) (map[ExposureMetric]int, error) {
	counts := make(map[ExposureMetric]int)
	expected := make(map[string]ExpectedExposure, len(o.Exposures))
	for _, exposure := range o.Exposures {
		key := expectedExposureKey(exposure.Category, exposure.IndicatorID, exposure.RunID, exposure.RunAttempt, exposure.JobID, exposure.StepIdentity, exposure.Kind, exposure.Name, exposure.Capability)
		if exposure.Category != "credential" && exposure.Category != "resource" {
			return nil, fmt.Errorf("oracle exposure %s has invalid category %q", key, exposure.Category)
		}
		if _, duplicate := expected[key]; duplicate {
			return nil, fmt.Errorf("oracle has duplicate expected exposure %s", key)
		}
		expected[key] = exposure
	}
	for _, finding := range caseValue.Findings {
		for _, exposure := range finding.CredentialExposure {
			metric, err := consumeExpectedExposure(expected, "credential", finding, exposure)
			if err != nil {
				return nil, err
			}
			if metric != "" {
				counts[metric]++
			}
		}
		for _, exposure := range finding.ResourceExposure {
			metric, err := consumeExpectedExposure(expected, "resource", finding, exposure)
			if err != nil {
				return nil, err
			}
			if metric != "" {
				counts[metric]++
			}
		}
	}
	if len(expected) != 0 {
		keys := make([]string, 0, len(expected))
		for key := range expected {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("missing exact synthetic exposures: %s", strings.Join(keys, ", "))
	}

	environmentCount := 0
	for _, fact := range snapshot.Facts {
		if fact.Kind == archive.FactExposure && fact.Exposure != nil && fact.Exposure.Environment != nil {
			environment := fact.Exposure.Environment
			if fact.Exposure.Execution != o.Environment.Execution || !subjectMatchesExecution(fact.Subject, o.Environment.Execution) ||
				environment.EnvironmentName != o.Environment.EnvironmentName || environment.GateState != o.Environment.GateState ||
				environment.JobStarted != o.Environment.JobStarted || len(environment.SecretNames) != 0 ||
				!equalStrings(idsToStrings(fact.EvidenceIDs), o.Environment.EvidenceIDs) {
				return nil, fmt.Errorf("synthetic environment context disagrees with the exact oracle: execution=%s environment=%q", fact.Exposure.Execution, environment.EnvironmentName)
			}
			environmentCount++
		}
	}
	if environmentCount != 1 {
		return nil, fmt.Errorf("synthetic environment context count=%d, want 1", environmentCount)
	}
	counts[ExposureEnvironmentPending] = 1
	return counts, nil
}

func subjectMatchesExecution(subject archive.FactSubject, execution model.JobExecutionIdentity) bool {
	return subject.RepositoryID == execution.RepositoryID && subject.RunID != nil && *subject.RunID == execution.RunID &&
		subject.RunAttempt != nil && *subject.RunAttempt == execution.RunAttempt && subject.JobID != nil && *subject.JobID == execution.JobID &&
		subject.StepKey == ""
}

func consumeExpectedExposure(expected map[string]ExpectedExposure, category string, finding report.Finding, actual report.Exposure) (ExposureMetric, error) {
	key := expectedExposureKey(category, finding.IndicatorID, finding.RunID, finding.RunAttempt, finding.JobID, finding.StepIdentity, actual.Kind, actual.Name, actual.Capability)
	want, ok := expected[key]
	if !ok {
		return "", fmt.Errorf("unexpected synthetic exposure %s", key)
	}
	if actual.Basis != want.Basis || actual.Conclusion != want.Conclusion || !equalStrings(actual.EvidenceIDs, want.EvidenceIDs) {
		return "", fmt.Errorf("synthetic exposure %s disagrees with exact versioned oracle", key)
	}
	delete(expected, key)
	return want.Metric, nil
}

func expectedExposureKey(category, indicator string, runID int64, attempt int, jobID int64, stepIdentity, kind, name, capability string) string {
	return strings.Join([]string{
		category,
		expectedFindingKey(indicator, runID, attempt, jobID, stepIdentity),
		kind,
		name,
		capability,
	}, "/")
}

func idsToStrings(ids []model.EvidenceID) []string {
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = string(id)
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
