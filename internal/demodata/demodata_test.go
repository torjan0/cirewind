package demodata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

func TestBundleDerivesExactV2Oracle(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Oracle.Validate(bundle.Snapshot, result.Case); err != nil {
		t.Fatalf("%s NO-GO: %v", bundle.Oracle.ID, err)
	}
}

func TestOracleRejectsPackProvenanceAndStepIdentityDrift(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*report.Case)
		want   string
	}{
		{name: "pack version", mutate: func(value *report.Case) { value.Metadata.IncidentPackVersion = "2.0.1" }, want: "pack provenance"},
		{name: "source hash", mutate: func(value *report.Case) { value.Metadata.SourcePackSHA256 = strings.Repeat("0", 64) }, want: "pack provenance"},
		{name: "canonical hash", mutate: func(value *report.Case) { value.Metadata.CanonicalPackSHA256 = strings.Repeat("0", 64) }, want: "pack provenance"},
		{name: "step identity", mutate: func(value *report.Case) {
			for index := range value.Findings {
				if value.Findings[index].State == string(model.ConfirmedExecuted) {
					value.Findings[index].StepIdentity = "101/1001/1/2001/step:999/MAIN/1"
					return
				}
			}
		}, want: "unexpected derived finding"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := result.Case
			changed.Findings = append([]report.Finding(nil), result.Case.Findings...)
			test.mutate(&changed)
			if err := bundle.Oracle.Validate(bundle.Snapshot, changed); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("oracle drift error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestOracleRejectsExposureOverclaimsAndEvidenceDrift(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*report.Case)
	}{
		{
			name: "runner persistence claim",
			mutate: func(value *report.Case) {
				exposure := findReportExposure(t, value, false, "SELF_HOSTED_RUNNER")
				exposure.Conclusion = "The self-hosted runner was persistent."
			},
		},
		{
			name: "cloud role assumption claim",
			mutate: func(value *report.Case) {
				exposure := findReportExposure(t, value, true, string(model.ExposureOIDCMintingCapability))
				exposure.Conclusion += " An AWS role was assumed."
			},
		},
		{
			name: "secret read and leak claim",
			mutate: func(value *report.Case) {
				exposure := findReportExposure(t, value, true, string(model.ExposureSecretPassedToStep))
				exposure.Conclusion = "The secret was accessed and leaked."
			},
		},
		{
			name: "causal deployment claim",
			mutate: func(value *report.Case) {
				exposure := findReportExposure(t, value, false, string(model.ResourceDeployment))
				exposure.Conclusion = "The attacker caused the deployment."
			},
		},
		{
			name: "exposure evidence substitution",
			mutate: func(value *report.Case) {
				exposure := findReportExposure(t, value, true, string(model.ExposureGitHubTokenPermission))
				exposure.EvidenceIDs = []string{value.Findings[0].EvidenceIDs[0]}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCasePresentation(result.Case)
			test.mutate(&changed)
			if err := bundle.Oracle.Validate(bundle.Snapshot, changed); err == nil || !strings.Contains(err.Error(), "exact versioned oracle") {
				t.Fatalf("overclaim mutation error=%v, want exact oracle rejection", err)
			}
		})
	}
}

func TestOracleBindsNoMatchToExactKnownGoodEvidenceAndCoverage(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	var unrelatedEvidence, gapCoverage string
	for _, finding := range result.Case.Findings {
		if finding.State == string(model.ConfirmedExecuted) {
			unrelatedEvidence = finding.EvidenceIDs[0]
		}
		if finding.State == string(model.UnknownEvidenceGap) {
			gapCoverage = finding.CollectionCoverage[0]
		}
	}
	if unrelatedEvidence == "" || gapCoverage == "" {
		t.Fatal("fixture lacks unrelated evidence or gap coverage for mutation tests")
	}
	tests := []struct {
		name   string
		mutate func(*report.Finding)
	}{
		{name: "unrelated evidence", mutate: func(finding *report.Finding) { finding.EvidenceIDs = []string{unrelatedEvidence} }},
		{name: "gap coverage", mutate: func(finding *report.Finding) { finding.CollectionCoverage = []string{gapCoverage} }},
		{name: "missing parser closure", mutate: func(finding *report.Finding) { finding.CollectionCoverage = finding.CollectionCoverage[:1] }},
		{name: "extra closure ID", mutate: func(finding *report.Finding) {
			finding.CollectionCoverage = append(finding.CollectionCoverage, gapCoverage)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneCasePresentation(result.Case)
			finding := findReportFinding(t, &changed, model.NoMatchConfirmed)
			test.mutate(finding)
			if err := bundle.Oracle.Validate(bundle.Snapshot, changed); err == nil || !strings.Contains(err.Error(), "exact known-good evidence and closed coverage") {
				t.Fatalf("NO_MATCH mutation error=%v, want exact support rejection", err)
			}
		})
	}
}

func TestOracleRejectsDownloadedOnlyFixtureUpgradedToExecution(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	mutated := false
	for index := range bundle.Snapshot.Facts {
		fact := &bundle.Snapshot.Facts[index]
		if fact.ActionOccurrence == nil || fact.ActionOccurrence.Observation.Execution.RunID != 1002 {
			continue
		}
		stepNumber := model.APIStepNumber(2)
		fact.ActionOccurrence.Observation.Kind = model.ObservationLifecycleStarted
		fact.ActionOccurrence.Observation.Step = &model.StepIdentity{
			Job: fact.ActionOccurrence.Observation.Execution, APIStepNumber: &stepNumber,
			LifecyclePhase: model.LifecycleMain, Occurrence: 1,
		}
		fact.ActionOccurrence.Observation.ID, err = evidence.NewRuntimeObservationID(fact.ActionOccurrence.Observation)
		if err != nil {
			t.Fatal(err)
		}
		fact.ID = ""
		mutated = true
		break
	}
	if !mutated {
		t.Fatal("downloaded-only fixture observation not found")
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Oracle.Validate(bundle.Snapshot, result.Case); err == nil || !strings.Contains(err.Error(), "unexpected derived finding") || !strings.Contains(err.Error(), string(model.ConfirmedExecuted)) {
		t.Fatalf("downloaded-only execution mutation error=%v, want exact executed-state rejection", err)
	}
}

func TestBundlePackMatchesPublicPackAndHashes(t *testing.T) {
	bundle, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile("../../incidents/synthetic/mutable-tag.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.PackYAML, public) {
		t.Fatal("embedded and public synthetic pack bytes differ")
	}
	embedded, err := incident.Validate(context.Background(), bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	publicPack, err := incident.Validate(context.Background(), public)
	if err != nil {
		t.Fatal(err)
	}
	if embedded.Pack.Metadata.PackVersion != FixtureVersion || embedded.Pack.Metadata.Sources[0].SourceRevision != "fixture-v2" {
		t.Fatalf("fixture version drifted: pack=%q source=%q", embedded.Pack.Metadata.PackVersion, embedded.Pack.Metadata.Sources[0].SourceRevision)
	}
	if embedded.OriginalSHA256 != publicPack.OriginalSHA256 || embedded.CanonicalSHA256 != publicPack.CanonicalSHA256 {
		t.Fatal("embedded and public pack hashes differ")
	}
	if embedded.OriginalSHA256 != bundle.Oracle.PackOriginalSHA256 || embedded.CanonicalSHA256 != bundle.Oracle.PackCanonicalSHA256 {
		t.Fatalf("pack hash oracle drifted: original=%s canonical=%s", embedded.OriginalSHA256, embedded.CanonicalSHA256)
	}
}

func TestBundleConstructionsDoNotShareMutableState(t *testing.T) {
	first, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.PackYAML[0] = 'X'
	first.Oracle.FindingCounts[model.ConfirmedExecuted] = 99
	first.Oracle.ExposureCounts[ExposureWriteTokenJob] = 99
	first.Oracle.FinalFiles[0] = "changed"
	first.Oracle.Findings[0].IndicatorID = "changed"
	first.Oracle.Exposures[0].Conclusion = "changed"
	first.Oracle.Exposures[0].EvidenceIDs[0] = "changed"
	first.Oracle.Environment.EvidenceIDs[0] = "changed"
	first.Snapshot.Facts[0].ID = "changed"
	if second.PackYAML[0] != 'a' || second.Oracle.FindingCounts[model.ConfirmedExecuted] != 1 || second.Oracle.ExposureCounts[ExposureWriteTokenJob] != 1 || second.Oracle.FinalFiles[0] != "affected-runs.csv" || second.Oracle.Findings[0].IndicatorID == "changed" || second.Oracle.Exposures[0].Conclusion == "changed" || second.Oracle.Exposures[0].EvidenceIDs[0] == "changed" || second.Oracle.Environment.EvidenceIDs[0] == "changed" || second.Snapshot.Facts[0].ID == "changed" {
		t.Fatal("bundle construction shared mutable state")
	}
}

func cloneCasePresentation(value report.Case) report.Case {
	result := value
	result.Findings = append([]report.Finding(nil), value.Findings...)
	for index := range result.Findings {
		finding := &result.Findings[index]
		finding.EvidenceIDs = append([]string(nil), finding.EvidenceIDs...)
		finding.CollectionCoverage = append([]string(nil), finding.CollectionCoverage...)
		finding.CredentialExposure = append([]report.Exposure(nil), finding.CredentialExposure...)
		finding.ResourceExposure = append([]report.Exposure(nil), finding.ResourceExposure...)
		for exposureIndex := range finding.CredentialExposure {
			finding.CredentialExposure[exposureIndex].EvidenceIDs = append([]string(nil), finding.CredentialExposure[exposureIndex].EvidenceIDs...)
		}
		for exposureIndex := range finding.ResourceExposure {
			finding.ResourceExposure[exposureIndex].EvidenceIDs = append([]string(nil), finding.ResourceExposure[exposureIndex].EvidenceIDs...)
		}
	}
	return result
}

func findReportFinding(t *testing.T, value *report.Case, state model.FindingState) *report.Finding {
	t.Helper()
	for index := range value.Findings {
		if value.Findings[index].State == string(state) {
			return &value.Findings[index]
		}
	}
	t.Fatalf("report finding %s not found", state)
	return nil
}

func findReportExposure(t *testing.T, value *report.Case, credential bool, kind string) *report.Exposure {
	t.Helper()
	for findingIndex := range value.Findings {
		finding := &value.Findings[findingIndex]
		exposures := &finding.ResourceExposure
		if credential {
			exposures = &finding.CredentialExposure
		}
		for exposureIndex := range *exposures {
			if (*exposures)[exposureIndex].Kind == kind {
				return &(*exposures)[exposureIndex]
			}
		}
	}
	t.Fatalf("report exposure %s not found", kind)
	return nil
}

func TestBundleHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Bundle(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Bundle cancellation error=%v, want context.Canceled", err)
	}
	if _, err := Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Snapshot cancellation error=%v, want context.Canceled", err)
	}
}

func TestSnapshotRejectsCrossFactContradictions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *archive.Snapshot)
		want   string
	}{
		{
			name: "unstarted job has completed status",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findJobFact(t, snapshot, waitingIdentity)
				fact.Job.Status = "completed"
				fact.ID = ""
			},
			want: "JobStarted:false",
		},
		{
			name: "unstarted job has Action lifecycle",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				appendLifecycleFact(t, snapshot, waitingIdentity)
			},
			want: "Action lifecycle",
		},
		{
			name: "pending run terminal success",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findRunFact(t, snapshot, 1005)
				fact.Run.Status = "completed"
				fact.Run.Conclusion = "success"
				fact.ID = ""
			},
			want: "nonempty run",
		},
		{
			name: "pending statuses disagree",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findAttemptFact(t, snapshot, waitingIdentity)
				fact.Attempt.Status = "queued"
				fact.ID = ""
			},
			want: "statuses disagree",
		},
		{
			name: "pending gate has secret eligibility relationship",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				appendEnvironmentEligibilityFact(t, snapshot)
			},
			want: "environment-secret eligibility",
		},
		{
			name: "credential basis empty",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findCredentialFact(t, snapshot, model.ExposureGitHubTokenPermission)
				fact.Exposure.Credential.Basis = ""
				fact.ID = ""
			},
			want: "invalid credential-exposure basis",
		},
		{
			name: "credential basis unknown",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findCredentialFact(t, snapshot, model.ExposureGitHubTokenPermission)
				fact.Exposure.Credential.Basis = model.CredentialExposureBasis("unknown-basis")
				fact.ID = ""
			},
			want: "invalid credential-exposure basis",
		},
		{
			name: "secret basis misclassified",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findCredentialFact(t, snapshot, model.ExposureSecretPassedToStep)
				fact.Exposure.Credential.Basis = model.ExposureBasisRuntimeObserved
				fact.ID = ""
			},
			want: "historical-definition flow",
		},
		{
			name: "typed OIDC permission missing",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findTokenPermissionFact(t, snapshot, "id-token")
				fact.Exposure.Credential.Permission = "actions"
				fact.ID = ""
			},
			want: "not a supported runtime-observed",
		},
		{
			name: "called workflow downgraded to historical YAML",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findCalledWorkflowFact(t, snapshot)
				caller := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("2", 40)})
				job := execution(1003, 2, 2003)
				fact.Dependency.Basis = archive.DefinitionHistoricalAtRun
				fact.Dependency.CallerWorkflowObjectID = &caller
				fact.Dependency.AttemptExecution = nil
				fact.Dependency.Execution = &job
				fact.ID = ""
			},
			want: "not exact GitHub run-attempt metadata",
		},
		{
			name: "contradiction points to arbitrary fact",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findContradictionDefinition(t, snapshot)
				fact.Dependency.ContradictsFactIDs = []string{"fact1:" + strings.Repeat("f", 64)}
				fact.ID = ""
			},
			want: "contradicts fact absent from snapshot",
		},
		{
			name: "contradiction static identity equals runtime",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				fact := findContradictionDefinition(t, snapshot)
				affected := mustActionOID(strings.Repeat("1", 40))
				fact.Dependency.TargetActionObjectID = &affected
				fact.ID = ""
			},
			want: "historical A versus linked exact runtime B",
		},
		{
			name: "required parser coverage absent",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				for index, fact := range snapshot.Facts {
					if fact.Coverage != nil && fact.Coverage.Unit.Kind == model.CoverageParserGrammar {
						snapshot.Facts = append(snapshot.Facts[:index], snapshot.Facts[index+1:]...)
						return
					}
				}
				t.Fatal("parser coverage fact not found")
			},
			want: "want one job-log and one parser-grammar",
		},
		{
			name: "duplicate conflicting run",
			mutate: func(t *testing.T, snapshot *archive.Snapshot) {
				original := *findRunFact(t, snapshot, 1001)
				copyRun := *original.Run
				copyRun.Status = "queued"
				original.ID = ""
				original.Run = &copyRun
				snapshot.Facts = append(snapshot.Facts, original)
			},
			want: "duplicate run metadata",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := Bundle(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, &bundle.Snapshot)
			err = ValidateSnapshot(bundle.Snapshot)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateSnapshot error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func findJobFact(t *testing.T, snapshot *archive.Snapshot, identity model.JobExecutionIdentity) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Job != nil && fact.Job.Execution == identity {
			return fact
		}
	}
	t.Fatalf("job fact %s not found", identity)
	return nil
}

func findTokenPermissionFact(t *testing.T, snapshot *archive.Snapshot, permission string) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Exposure != nil && fact.Exposure.Credential != nil && fact.Exposure.Credential.Kind == model.ExposureGitHubTokenPermission && fact.Exposure.Credential.Permission == permission {
			return fact
		}
	}
	t.Fatalf("token permission fact %s not found", permission)
	return nil
}

func findCalledWorkflowFact(t *testing.T, snapshot *archive.Snapshot) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Dependency != nil && fact.Dependency.TargetKind == archive.DependencyTargetReusableWorkflow {
			return fact
		}
	}
	t.Fatal("called-workflow fact not found")
	return nil
}

func findContradictionDefinition(t *testing.T, snapshot *archive.Snapshot) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Dependency != nil && fact.Dependency.CallerPath == ".github/workflows/contradiction.yml" {
			return fact
		}
	}
	t.Fatal("contradiction definition fact not found")
	return nil
}

func findRunFact(t *testing.T, snapshot *archive.Snapshot, runID model.WorkflowRunID) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Run != nil && fact.Run.RunID == runID {
			return fact
		}
	}
	t.Fatalf("run fact %d not found", runID)
	return nil
}

func findAttemptFact(t *testing.T, snapshot *archive.Snapshot, identity model.JobExecutionIdentity) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Attempt != nil && fact.Attempt.RunID == identity.RunID && fact.Attempt.RunAttempt == identity.RunAttempt {
			return fact
		}
	}
	t.Fatalf("attempt fact %s not found", identity)
	return nil
}

func findCredentialFact(t *testing.T, snapshot *archive.Snapshot, kind model.CredentialExposureKind) *archive.Fact {
	t.Helper()
	for index := range snapshot.Facts {
		fact := &snapshot.Facts[index]
		if fact.Exposure != nil && fact.Exposure.Credential != nil && fact.Exposure.Credential.Kind == kind {
			return fact
		}
	}
	t.Fatalf("credential fact %s not found", kind)
	return nil
}

func appendLifecycleFact(t *testing.T, snapshot *archive.Snapshot, identity model.JobExecutionIdentity) {
	t.Helper()
	var source archive.Fact
	for _, fact := range snapshot.Facts {
		if fact.ActionOccurrence != nil && fact.ActionOccurrence.Observation.Execution == executedIdentity {
			source = fact
			break
		}
	}
	if source.ActionOccurrence == nil {
		t.Fatal("source lifecycle fact not found")
	}
	observation := source.ActionOccurrence.Observation
	observation.Execution = identity
	if observation.Step == nil {
		t.Fatal("source lifecycle step identity not found")
	}
	step := *observation.Step
	step.Job = identity
	observation.Step = &step
	observation.ID = ""
	var err error
	observation.ID, err = evidence.NewRuntimeObservationID(observation)
	if err != nil {
		t.Fatal(err)
	}
	source.ID = ""
	source.Subject = archive.FactSubject{}
	source.ActionOccurrence = &archive.ActionOccurrenceFact{Observation: observation}
	snapshot.Facts = append(snapshot.Facts, source)
}

func appendEnvironmentEligibilityFact(t *testing.T, snapshot *archive.Snapshot) {
	t.Helper()
	var supporting model.EvidenceID
	for _, fact := range snapshot.Facts {
		if fact.Exposure != nil && fact.Exposure.Environment != nil {
			supporting = fact.EvidenceIDs[0]
			break
		}
	}
	if supporting == "" {
		t.Fatal("pending environment evidence not found")
	}
	name, err := model.NewSecretName("FAKE_ENVIRONMENT_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	exposure := archive.ExposureFact{
		Execution: waitingIdentity,
		Credential: &model.CredentialExposure{
			Kind: model.ExposureEnvironmentSecretEligible, Basis: model.ExposureBasisHistoricalDefinitionFlow,
			SecretName: &name, Conclusion: "Synthetic relationship that must be rejected while the gate is pending.", EvidenceIDs: []model.EvidenceID{supporting},
		},
		EventTime: instantEvent(model.MustInstant(demoTime)),
	}
	snapshot.Facts = append(snapshot.Facts, archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{supporting}, Exposure: &exposure})
}
