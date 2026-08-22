package workflow

import (
	"strings"
	"testing"
)

func TestParseWorkflowActionsReusableAndSecrets(t *testing.T) {
	t.Parallel()
	data := []byte(`name: fixture
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  direct:
    environment: protected
    steps:
      - id: affected
        uses: Owner/Action/path@v1
        env:
          DIRECT: ${{ secrets.DIRECT_SECRET }}
  called:
    uses: owner/workflows/.github/workflows/reusable.yml@main
    secrets:
      TARGET: ${{ secrets.SOURCE }}
`)
	parsed, diagnostics, err := ParseWorkflow(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	if len(parsed.Jobs) != 2 || parsed.Jobs[0].Uses == nil || parsed.Jobs[0].Uses.Kind != ReferenceReusableWorkflow {
		t.Fatalf("bad jobs: %+v", parsed.Jobs)
	}
	if len(parsed.Jobs[0].SecretMappings) != 1 || parsed.Jobs[0].SecretMappings[0].SourceName != "SOURCE" || len(parsed.Jobs[0].SecretRefs) != 0 {
		t.Fatalf("reusable secret mapping was not kept distinct: %+v", parsed.Jobs[0])
	}
	if parsed.Jobs[1].Steps[0].Uses.Kind != ReferenceRepository || parsed.Jobs[1].Steps[0].Uses.Subpath != "path" {
		t.Fatalf("bad Action ref: %+v", parsed.Jobs[1].Steps[0].Uses)
	}
	if len(parsed.Jobs[1].Steps[0].SecretRefs) != 1 || parsed.Jobs[1].Steps[0].SecretRefs[0].Name != "DIRECT_SECRET" {
		t.Fatalf("bad secret refs: %+v", parsed.Jobs[1].Steps[0].SecretRefs)
	}
	if parsed.Jobs[1].Steps[0].SecretRefs[0].Scope != SecretReferenceStepEnvironment {
		t.Fatalf("direct secret scope = %q", parsed.Jobs[1].Steps[0].SecretRefs[0].Scope)
	}
	if len(parsed.Jobs[1].SecretRefs) != 0 {
		t.Fatalf("step secret was aggregated into job refs: %+v", parsed.Jobs[1].SecretRefs)
	}
}

func TestSecretReferencesRemainLexicallyScoped(t *testing.T) {
	t.Parallel()
	data := []byte(`name: ${{ secrets.WORKFLOW_LABEL }}
env:
  GLOBAL_TOKEN: ${{ secrets.WORKFLOW_ENV }}
jobs:
  build:
    name: ${{ secrets.JOB_LABEL }}
    env:
      JOB_TOKEN: ${{ secrets.JOB_ENV }}
      ${{ secrets.KEY_ONLY }}: ordinary
    steps:
      - id: affected
        uses: owner/affected@v1
      - id: sibling
        name: ${{ secrets.SIBLING_LABEL }}
        uses: owner/sibling@v1
        with:
          token: ${{ secrets.SIBLING_INPUT }}
        env:
          TOKEN: ${{ secrets.SIBLING_ENV }}
      - id: shell
        run: echo "${{ secrets.SIBLING_COMMAND }}"
      - id: literal
        run: echo "secrets.NOT_AN_EXPRESSION"
`)
	parsed, diagnostics, err := ParseWorkflow(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	assertSecretScopes(t, parsed.SecretRefs, map[string]SecretReferenceScope{
		"WORKFLOW_ENV":   SecretReferenceWorkflowEnvironment,
		"WORKFLOW_LABEL": SecretReferenceWorkflowField,
	})
	job := parsed.Jobs[0]
	assertSecretScopes(t, job.SecretRefs, map[string]SecretReferenceScope{
		"JOB_ENV":   SecretReferenceJobEnvironment,
		"JOB_LABEL": SecretReferenceJobField,
	})
	if len(job.Steps[0].SecretRefs) != 0 {
		t.Fatalf("affected step inherited sibling refs: %+v", job.Steps[0].SecretRefs)
	}
	assertSecretScopes(t, job.Steps[1].SecretRefs, map[string]SecretReferenceScope{
		"SIBLING_ENV":   SecretReferenceStepEnvironment,
		"SIBLING_INPUT": SecretReferenceStepInput,
		"SIBLING_LABEL": SecretReferenceStepField,
	})
	assertSecretScopes(t, job.Steps[2].SecretRefs, map[string]SecretReferenceScope{
		"SIBLING_COMMAND": SecretReferenceStepCommand,
	})
	if len(job.Steps[3].SecretRefs) != 0 {
		t.Fatalf("plain text was treated as a secret expression: %+v", job.Steps[3].SecretRefs)
	}
	for _, refs := range [][]SecretReference{parsed.SecretRefs, job.SecretRefs, job.Steps[0].SecretRefs, job.Steps[1].SecretRefs, job.Steps[2].SecretRefs, job.Steps[3].SecretRefs} {
		for _, ref := range refs {
			if ref.Name == "KEY_ONLY" {
				t.Fatal("mapping key was treated as an evaluated secret expression")
			}
		}
	}
}

func assertSecretScopes(t *testing.T, refs []SecretReference, want map[string]SecretReferenceScope) {
	t.Helper()
	if len(refs) != len(want) {
		t.Fatalf("secret refs = %+v, want %v", refs, want)
	}
	for _, ref := range refs {
		if got, ok := want[ref.Name]; !ok || got != ref.Scope {
			t.Fatalf("secret ref %+v has unexpected scope; want %v", ref, want)
		}
	}
}

func TestOnIsNotBoolean(t *testing.T) {
	t.Parallel()
	parsed, _, err := ParseWorkflow([]byte("on: [push, schedule]\njobs:\n  a:\n    steps:\n      - run: true\n"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(parsed.Triggers, ",") != "push,schedule" {
		t.Fatalf("triggers = %v", parsed.Triggers)
	}
}

func TestReusableSecretInheritanceIsNotAReference(t *testing.T) {
	t.Parallel()
	parsed, diagnostics, err := ParseWorkflow([]byte(`jobs:
  call:
    uses: owner/workflows/.github/workflows/reusable.yml@v1
    secrets: inherit
`), DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	job := parsed.Jobs[0]
	if !job.SecretsInherit || len(job.SecretMappings) != 0 || len(job.SecretRefs) != 0 {
		t.Fatalf("secrets: inherit was conflated with named references: %+v", job)
	}
}

func TestParseActionCompositeWithoutExecuting(t *testing.T) {
	t.Parallel()
	data := []byte("name: wrapper\nruns:\n  using: composite\n  steps:\n    - uses: owner/child@" + strings.Repeat("1", 40) + "\n")
	parsed, diagnostics, err := ParseAction(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseAction() error = %v diagnostics=%+v", err, diagnostics)
	}
	if parsed.IsLeaf || len(parsed.Steps) != 1 {
		t.Fatalf("bad composite: %+v", parsed)
	}
}

func TestDuplicateAndAliasCycleFailClosed(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		"jobs:\n  a: {}\n  a: {}\n",
		"jobs: &jobs\n  a:\n    steps: *jobs\n",
	} {
		if _, diagnostics, err := ParseWorkflow([]byte(data), DefaultLimits()); err == nil || len(diagnostics) == 0 {
			t.Fatalf("unsafe YAML accepted: %q diagnostics=%+v", data, diagnostics)
		}
	}
}

func TestWorkflowAliasesPreserveDependenciesAndSecretBoundaries(t *testing.T) {
	t.Parallel()
	data := []byte(`jobs:
  direct:
    steps: &shared_steps
      - uses: &action_ref owner/direct-action@v1
      - uses: *action_ref
      - &shared_step
        id: shared
        uses: owner/whole-step-action@v2
        with:
          token: &secret_expr ${{ secrets.STEP_SECRET }}
      - *shared_step
  duplicated_steps:
    steps: *shared_steps
  reusable:
    uses: &workflow_ref owner/workflows/.github/workflows/call.yml@v3
    secrets: &secret_map
      TARGET: *secret_expr
  reusable_alias:
    uses: *workflow_ref
    secrets: *secret_map
  inherited:
    uses: owner/workflows/.github/workflows/inherit.yml@v4
    secrets: &inherit_value inherit
  inherited_alias:
    uses: owner/workflows/.github/workflows/inherit.yml@v4
    secrets: *inherit_value
`)
	parsed, diagnostics, err := ParseWorkflow(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("ParseWorkflow() diagnostics = %+v", diagnostics)
	}
	jobs := make(map[string]Job, len(parsed.Jobs))
	for _, job := range parsed.Jobs {
		jobs[job.ID] = job
	}
	for _, jobID := range []string{"direct", "duplicated_steps"} {
		job := jobs[jobID]
		if len(job.Steps) != 4 {
			t.Fatalf("job %q steps = %+v", jobID, job.Steps)
		}
		want := []string{"owner/direct-action@v1", "owner/direct-action@v1", "owner/whole-step-action@v2", "owner/whole-step-action@v2"}
		for i, raw := range want {
			if job.Steps[i].Uses == nil || job.Steps[i].Uses.Raw != raw || job.Steps[i].Uses.Kind != ReferenceRepository {
				t.Fatalf("job %q step %d dependency = %+v, want %q", jobID, i, job.Steps[i].Uses, raw)
			}
		}
		for _, index := range []int{2, 3} {
			assertSecretScopes(t, job.Steps[index].SecretRefs, map[string]SecretReferenceScope{"STEP_SECRET": SecretReferenceStepInput})
		}
	}
	for _, jobID := range []string{"reusable", "reusable_alias"} {
		job := jobs[jobID]
		if job.Uses == nil || job.Uses.Kind != ReferenceReusableWorkflow || job.Uses.Raw != "owner/workflows/.github/workflows/call.yml@v3" {
			t.Fatalf("job %q reusable dependency = %+v", jobID, job.Uses)
		}
		if len(job.SecretMappings) != 1 || job.SecretMappings[0].TargetName != "TARGET" || job.SecretMappings[0].SourceName != "STEP_SECRET" || job.SecretMappings[0].Dynamic {
			t.Fatalf("job %q secret mappings = %+v", jobID, job.SecretMappings)
		}
	}
	for _, jobID := range []string{"inherited", "inherited_alias"} {
		job := jobs[jobID]
		if job.Uses == nil || !job.SecretsInherit || len(job.SecretMappings) != 0 {
			t.Fatalf("job %q inherited-secret boundary = %+v", jobID, job)
		}
	}
}

func TestEntireAliasedJobMappingPreservesActionDependency(t *testing.T) {
	t.Parallel()
	parsed, diagnostics, err := ParseWorkflow([]byte(`jobs:
  original: &action_job
    steps:
      - uses: owner/from-job-alias@v1
  duplicate: *action_job
`), DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	if len(parsed.Jobs) != 2 {
		t.Fatalf("jobs = %+v", parsed.Jobs)
	}
	for _, job := range parsed.Jobs {
		if len(job.Steps) != 1 || job.Steps[0].Uses == nil || job.Steps[0].Uses.Raw != "owner/from-job-alias@v1" {
			t.Fatalf("aliased job %q omitted dependency: %+v", job.ID, job)
		}
	}
}

func TestActionAliasesPreserveCompositeDependencies(t *testing.T) {
	t.Parallel()
	data := []byte(`name: wrapper
runs:
  using: composite
  steps:
    - uses: &child_ref owner/scalar-child@v1
    - uses: *child_ref
    - &whole_step
      uses: owner/whole-step-child@v2
    - *whole_step
`)
	parsed, diagnostics, err := ParseAction(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseAction() error = %v diagnostics=%+v", err, diagnostics)
	}
	want := []string{"owner/scalar-child@v1", "owner/scalar-child@v1", "owner/whole-step-child@v2", "owner/whole-step-child@v2"}
	if len(parsed.Steps) != len(want) {
		t.Fatalf("steps = %+v", parsed.Steps)
	}
	for i, raw := range want {
		if parsed.Steps[i].Uses == nil || parsed.Steps[i].Uses.Raw != raw || parsed.Steps[i].Uses.Kind != ReferenceRepository {
			t.Fatalf("step %d dependency = %+v, want %q", i, parsed.Steps[i].Uses, raw)
		}
	}
}

func TestAliasLimitsFailClosedWithTypedDiagnostics(t *testing.T) {
	t.Parallel()
	data := []byte(`jobs:
  aliases:
    steps:
      - uses: &action_ref owner/action@v1
      - uses: *action_ref
      - uses: *action_ref
`)
	tests := []struct {
		name string
		code string
		set  func(*Limits)
	}{
		{name: "count", code: "YAML_ALIAS_LIMIT", set: func(limits *Limits) { limits.MaxAliases = 1 }},
		{name: "expanded bytes", code: "YAML_ALIAS_EXPANSION_LIMIT", set: func(limits *Limits) { limits.MaxAliasBytes = 8 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			limits := DefaultLimits()
			test.set(&limits)
			if _, diagnostics, err := ParseWorkflow(data, limits); err == nil || !hasDiagnostic(diagnostics, test.code) {
				t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v, want %s", err, diagnostics, test.code)
			}
		})
	}
}

func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, item := range diagnostics {
		if item.Code == code {
			return true
		}
	}
	return false
}

func TestDynamicAndLocalReferencesStayDistinct(t *testing.T) {
	t.Parallel()
	data := []byte(`jobs:
  refs:
    steps:
      - uses: ./.github/actions/local
      - uses: $/actions/self
      - uses: owner/${{ matrix.action }}@v1
`)
	parsed, diagnostics, err := ParseWorkflow(data, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseWorkflow() error = %v diagnostics=%+v", err, diagnostics)
	}
	kinds := []ReferenceKind{ReferenceLocalWorkspace, ReferenceSelfRepository, ReferenceDynamic}
	for i, want := range kinds {
		if got := parsed.Jobs[0].Steps[i].Uses.Kind; got != want {
			t.Fatalf("step %d kind=%s want=%s", i, got, want)
		}
	}
}

func FuzzParseWorkflow(f *testing.F) {
	f.Add([]byte("on: push\njobs:\n  a:\n    steps:\n      - uses: owner/action@v1\n"))
	f.Fuzz(func(t *testing.T, input []byte) { _, _, _ = ParseWorkflow(input, DefaultLimits()) })
}

func FuzzParseActionMetadata(f *testing.F) {
	f.Add([]byte("name: synthetic\nruns:\n  using: composite\n  steps:\n    - uses: owner/action@v1\n"))
	f.Add([]byte("name: leaf\nruns:\n  using: node20\n  main: dist/index.js\n"))
	f.Fuzz(func(t *testing.T, input []byte) { _, _, _ = ParseAction(input, DefaultLimits()) })
}
