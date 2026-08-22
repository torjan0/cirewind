package livecollect

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

func TestHistoricalProjectionUsesStaticOIDCFallbackAndRuntimePermissionPrecedence(t *testing.T) {
	parsed := parseExposureWorkflow(t, `
name: controlled J
on: workflow_dispatch
permissions:
  contents: read
  id-token: write
jobs:
  oidc-capability:
    runs-on: ubuntu-24.04
    steps:
      - name: Invoke affected marker
        uses: acme/affected@v1
        env:
          DIRECT_INPUT: ${{ secrets.CIREWIND_LAB_DIRECT }}
`)
	started := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
	input, execution := exposureInput(t, parsed, []githubapi.WorkflowJob{{
		ID: 20, Name: "oidc-capability", Status: "completed", Conclusion: "success", StartedAt: &started,
		Steps: []githubapi.JobStep{{Number: 2, Name: "Invoke affected marker", Status: "completed", Conclusion: "success", StartedAt: &started}},
	}})
	step := model.StepIdentity{Job: execution, APIStepNumber: ptrExposure(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	action, err := model.NewRepositorySlug("acme/affected")
	if err != nil {
		t.Fatal(err)
	}
	input.sourceFacts = append(input.sourceFacts,
		archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: []model.EvidenceID{exposureEvidence('c')}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
			Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: action, DeclaredRef: "v1", EventTime: jobEventTime(input.jobs[0]),
		}}},
		archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{exposureEvidence('d')}, Exposure: &archive.ExposureFact{Execution: execution, Credential: &model.CredentialExposure{
			Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "contents", Access: "read",
			Conclusion: "runtime fixture", EvidenceIDs: []model.EvidenceID{exposureEvidence('d')},
		}, EventTime: jobEventTime(input.jobs[0])}},
	)

	output, err := buildHistoricalExposureProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.issues) != 0 {
		t.Fatalf("unexpected projection gaps: %#v", output.issues)
	}
	if output.staticPermissionFacts != 1 || output.secretFlowFacts != 1 {
		t.Fatalf("fact counters: static=%d secret=%d", output.staticPermissionFacts, output.secretFlowFacts)
	}
	credentials := projectedCredentials(output.facts)
	assertCredential(t, credentials, model.ExposureOIDCMintingCapability, "", "", "", model.ExposureBasisStaticInferred)
	assertCredential(t, credentials, model.ExposureSecretPassedToStep, "CIREWIND_LAB_DIRECT", "", "", model.ExposureBasisHistoricalDefinitionFlow)
	for _, credential := range credentials {
		if credential.Kind == model.ExposureGitHubTokenPermission && credential.Permission == "id-token" {
			t.Fatal("id-token syntax was mislabeled as a GITHUB_TOKEN repository permission")
		}
		if credential.Kind == model.ExposureGitHubTokenPermission && credential.Permission == "contents" {
			t.Fatal("static contents permission duplicated runtime-observed permission")
		}
		if credential.Kind == model.ExposureOIDCMintingCapability && !strings.Contains(credential.Conclusion, "No token request") {
			t.Fatalf("OIDC conclusion overclaims: %q", credential.Conclusion)
		}
	}
}

func TestRuntimeIDTokenIsOnlyOIDCCapability(t *testing.T) {
	evidenceID := exposureEvidence('a')
	scope := logparse.ExecutionScope{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	result := repositoryResult{}
	err := convertSetupObservations([]setupObservation{
		{observation: logparse.Observation{Kind: logparse.ObservationTokenPermission, Scope: scope, Permission: "contents", Access: "read"}, evidenceIDs: []model.EvidenceID{evidenceID}},
		{observation: logparse.Observation{Kind: logparse.ObservationTokenPermission, Scope: scope, Permission: "id-token", Access: "write"}, evidenceIDs: []model.EvidenceID{evidenceID}},
	}, githubapi.WorkflowJob{ID: 20, Name: "build"}, &result)
	if err != nil {
		t.Fatal(err)
	}
	credentials := projectedCredentials(result.facts)
	assertCredential(t, credentials, model.ExposureGitHubTokenPermission, "", "contents", "read", model.ExposureBasisRuntimeObserved)
	assertCredential(t, credentials, model.ExposureOIDCMintingCapability, "", "", "", model.ExposureBasisRuntimeObserved)
	for _, credential := range credentials {
		if credential.Kind == model.ExposureGitHubTokenPermission && credential.Permission == "id-token" {
			t.Fatal("runtime id-token observation was mislabeled as a GITHUB_TOKEN repository permission")
		}
	}
}

func TestHistoricalProjectionSkippedStepNeverBecomesSecretFlow(t *testing.T) {
	parsed := parseExposureWorkflow(t, `
name: skipped
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: Skipped affected marker
        if: ${{ false }}
        uses: acme/affected@v1
        env:
          DIRECT_INPUT: ${{ secrets.CIREWIND_LAB_DIRECT }}
`)
	started := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
	input, _ := exposureInput(t, parsed, []githubapi.WorkflowJob{{
		ID: 20, Name: "build", Status: "completed", Conclusion: "success", StartedAt: &started,
		Steps: []githubapi.JobStep{{Number: 2, Name: "Skipped affected marker", Status: "completed", Conclusion: "skipped"}},
	}})
	output, err := buildHistoricalExposureProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.facts) != 0 || len(output.issues) != 0 {
		t.Fatalf("skipped step projected exposure or gap: facts=%#v issues=%#v", output.facts, output.issues)
	}
}

func TestHistoricalProjectionReusableMappingAndInheritanceRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		name        string
		callerYAML  string
		wantMapped  bool
		wantPassed  bool
		wantInherit bool
	}{
		{
			name: "explicit one-hop map",
			callerYAML: `
name: caller
on: workflow_dispatch
jobs:
  mapping:
    uses: acme/workflows/.github/workflows/called.yml@v1
    secrets:
      TARGET: ${{ secrets.CIREWIND_LAB_DIRECT }}
`,
			wantMapped: true, wantPassed: true,
		},
		{
			name: "inherit preserves unnamed relationship",
			callerYAML: `
name: caller
on: workflow_dispatch
jobs:
  mapping:
    uses: acme/workflows/.github/workflows/called.yml@v1
    secrets: inherit
`,
			wantInherit: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := parseExposureWorkflow(t, test.callerYAML)
			called := parseExposureWorkflow(t, `
name: called
on: workflow_call
jobs:
  nested:
    runs-on: ubuntu-24.04
    steps:
      - name: Invoke nested marker
        uses: acme/affected@v1
        env:
          MAPPED_INPUT: ${{ secrets.TARGET }}
`)
			started := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
			apiJob := githubapi.WorkflowJob{ID: 21, Name: "mapping / nested", Status: "completed", Conclusion: "success", StartedAt: &started, Steps: []githubapi.JobStep{{Number: 2, Name: "Invoke nested marker", Status: "completed", Conclusion: "success", StartedAt: &started}}}
			input, execution := exposureInput(t, caller, []githubapi.WorkflowJob{apiJob})
			calledEvidence := exposureEvidence('e')
			input.documents = append(input.documents, historicalExposureDocument{
				root: historicalWorkflowRoot{scope: "called_workflow_definition", resolved: resolve.ResolvedWorkflow{Definition: resolve.DefinitionKey{
					Repository: resolve.Repository{ID: 2, Owner: "acme", Name: "workflows"}, Path: ".github/workflows/called.yml", Commit: resolve.GitObject{Algorithm: "sha1", Value: strings.Repeat("b", 40)},
				}}}, workflow: called, evidenceID: calledEvidence,
			})
			step := model.StepIdentity{Job: execution, APIStepNumber: ptrExposure(model.APIStepNumber(2)), LifecyclePhase: model.LifecycleMain, Occurrence: 1}
			action, err := model.NewRepositorySlug("acme/affected")
			if err != nil {
				t.Fatal(err)
			}
			input.sourceFacts = append(input.sourceFacts, archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: []model.EvidenceID{exposureEvidence('f')}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: model.RuntimeActionObservation{
				Kind: model.ObservationLifecycleStarted, Execution: execution, Step: &step, ActionRepository: action, DeclaredRef: "v1", EventTime: jobEventTime(apiJob),
			}}})

			output, err := buildHistoricalExposureProjection(input)
			if err != nil {
				t.Fatal(err)
			}
			if len(output.issues) != 0 {
				t.Fatalf("unexpected issues: %#v", output.issues)
			}
			credentials := projectedCredentials(output.facts)
			mapped, passed, inherited := false, false, false
			for _, credential := range credentials {
				switch credential.Kind {
				case model.ExposureReusableSecretMapped:
					mapped = credential.SecretName != nil && *credential.SecretName == "CIREWIND_LAB_DIRECT"
				case model.ExposureSecretPassedToStep:
					passed = credential.SecretName != nil && *credential.SecretName == "CIREWIND_LAB_DIRECT"
				case model.ExposureReusableSecretInherited:
					inherited = credential.SecretName == nil
				}
			}
			if mapped != test.wantMapped || passed != test.wantPassed || inherited != test.wantInherit {
				t.Fatalf("relationships mapped=%v passed=%v inherited=%v; credentials=%#v", mapped, passed, inherited, credentials)
			}
		})
	}
}

func TestHistoricalProjectionEnvironmentTargetDistinguishesPendingFromCrossed(t *testing.T) {
	parsed := parseExposureWorkflow(t, `
name: environment
on: workflow_dispatch
jobs:
  gated:
    environment: production
    runs-on: ubuntu-24.04
    steps:
      - run: echo harmless
`)
	started := time.Date(2026, 8, 22, 2, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		job       githubapi.WorkflowJob
		wantGate  string
		wantStart bool
	}{
		{name: "pending gate", job: githubapi.WorkflowJob{ID: 20, Name: "gated", Status: "waiting"}, wantGate: "pending"},
		{name: "job start proves only crossing", job: githubapi.WorkflowJob{ID: 20, Name: "gated", Status: "completed", Conclusion: "success", StartedAt: &started}, wantGate: "crossed", wantStart: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, _ := exposureInput(t, parsed, []githubapi.WorkflowJob{test.job})
			output, err := buildHistoricalExposureProjection(input)
			if err != nil {
				t.Fatal(err)
			}
			if len(output.issues) != 0 || len(output.facts) != 1 || output.facts[0].Exposure == nil || output.facts[0].Exposure.Environment == nil {
				t.Fatalf("environment projection = facts %#v issues %#v", output.facts, output.issues)
			}
			environment := output.facts[0].Exposure.Environment
			if environment.GateState != test.wantGate || environment.JobStarted != test.wantStart || len(environment.SecretNames) != 0 {
				t.Fatalf("environment = %#v", environment)
			}
		})
	}
}

func TestHistoricalProjectionNilStartUsesValidUnknownEvent(t *testing.T) {
	caller := parseExposureWorkflow(t, `
name: caller
on: workflow_dispatch
jobs:
  mapping:
    uses: acme/workflows/.github/workflows/called.yml@v1
    secrets: inherit
`)
	called := parseExposureWorkflow(t, `
name: called
on: workflow_call
jobs:
  nested:
    runs-on: ubuntu-24.04
    steps:
      - run: echo harmless
`)
	apiJob := githubapi.WorkflowJob{ID: 21, Name: "mapping / nested", Status: "queued"}
	input, _ := exposureInput(t, caller, []githubapi.WorkflowJob{apiJob})
	input.documents = append(input.documents, historicalExposureDocument{
		root: historicalWorkflowRoot{scope: "called_workflow_definition", resolved: resolve.ResolvedWorkflow{Definition: resolve.DefinitionKey{
			Repository: resolve.Repository{ID: 2, Owner: "acme", Name: "workflows"}, Path: ".github/workflows/called.yml", Commit: resolve.GitObject{Algorithm: "sha1", Value: strings.Repeat("b", 40)},
		}}}, workflow: called, evidenceID: exposureEvidence('e'),
	})
	output, err := buildHistoricalExposureProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.issues) != 0 || len(output.facts) != 1 {
		t.Fatalf("nil-start projection: facts=%#v issues=%#v", output.facts, output.issues)
	}
	if err := output.facts[0].EventTime.Validate(); err != nil {
		t.Fatalf("nil-start fact retained invalid event interval: %v", err)
	}
	if output.facts[0].EventTime.Precision != model.PrecisionUnknown {
		t.Fatalf("nil-start event precision = %q", output.facts[0].EventTime.Precision)
	}
}

func TestHistoricalProjectionAmbiguousDynamicJobIsMaterialGapNotExposure(t *testing.T) {
	parsed := parseExposureWorkflow(t, `
name: dynamic
on: workflow_dispatch
jobs:
  build:
    name: ${{ matrix.label }}
    runs-on: ubuntu-24.04
    steps:
      - uses: acme/affected@v1
        env:
          DIRECT_INPUT: ${{ secrets.CIREWIND_LAB_DIRECT }}
`)
	input, _ := exposureInput(t, parsed, []githubapi.WorkflowJob{{ID: 20, Name: "linux"}})
	output, err := buildHistoricalExposureProjection(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.facts) != 0 || len(output.issues) != 1 || output.issues[0].scope != exposureJoinScope {
		t.Fatalf("ambiguous join = facts %#v issues %#v", output.facts, output.issues)
	}
}

func exposureInput(t *testing.T, parsed *workflow.Workflow, jobs []githubapi.WorkflowJob) (historicalExposureInput, model.JobExecutionIdentity) {
	t.Helper()
	definitionEvidence := exposureEvidence('a')
	definition := resolve.DefinitionKey{Repository: resolve.Repository{ID: 1, Owner: "acme", Name: "consumer"}, Path: ".github/workflows/ci.yml", Commit: resolve.GitObject{Algorithm: "sha1", Value: strings.Repeat("a", 40)}}
	input := historicalExposureInput{
		repositoryID: 1, runID: 10, attempt: 1, jobs: jobs,
		documents: []historicalExposureDocument{{root: historicalWorkflowRoot{scope: "historical_workflow", resolved: resolve.ResolvedWorkflow{Definition: definition}}, workflow: parsed, evidenceID: definitionEvidence}},
	}
	if len(jobs) == 0 {
		return input, model.JobExecutionIdentity{}
	}
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: model.JobID(jobs[0].ID)}
	input.sourceFacts = []archive.Fact{{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{exposureEvidence('b')}, Job: &archive.JobFact{Execution: execution, DisplayName: jobs[0].Name, Status: jobs[0].Status, Conclusion: jobs[0].Conclusion, EventTime: jobEventTime(jobs[0])}}}
	return input, execution
}

func parseExposureWorkflow(t *testing.T, source string) *workflow.Workflow {
	t.Helper()
	parsed, diagnostics, err := workflow.ParseWorkflow([]byte(source), workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("workflow diagnostics: %#v", diagnostics)
	}
	return parsed
}

func projectedCredentials(facts []archive.Fact) []model.CredentialExposure {
	result := make([]model.CredentialExposure, 0)
	for _, fact := range facts {
		if fact.Exposure != nil && fact.Exposure.Credential != nil {
			result = append(result, *fact.Exposure.Credential)
		}
	}
	return result
}

func assertCredential(t *testing.T, values []model.CredentialExposure, kind model.CredentialExposureKind, name, permission, access string, basis model.CredentialExposureBasis) {
	t.Helper()
	for _, value := range values {
		actualName := ""
		if value.SecretName != nil {
			actualName = string(*value.SecretName)
		}
		if value.Kind == kind && actualName == name && value.Permission == permission && value.Access == access && value.Basis == basis {
			return
		}
	}
	t.Fatalf("missing credential kind=%s name=%q permission=%q access=%q basis=%q in %#v", kind, name, permission, access, basis, values)
}

func exposureEvidence(char byte) model.EvidenceID {
	return model.EvidenceID("ev1:" + strings.Repeat(string(char), 64))
}

func ptrExposure[T any](value T) *T { return &value }
