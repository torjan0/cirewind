package acceptance_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/exposure"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

type fixtureContentSource map[string]resolve.Content

func (s fixtureContentSource) Fetch(ctx context.Context, key resolve.DefinitionKey) (resolve.Content, error) {
	if err := ctx.Err(); err != nil {
		return resolve.Content{}, err
	}
	content, ok := s[key.String()]
	if !ok {
		return resolve.Content{}, resolve.ErrContentNotFound
	}
	return content, nil
}

func TestCompositeAndReusableFixturesRunThroughHistoricalResolver(t *testing.T) {
	inventory, _ := loadInventory(t)
	consumer := resolve.Repository{ID: inventory.Repository.ID, Owner: "cirewind-fixtures", Name: "consumer"}
	wrapper := resolve.Repository{ID: 900002, Owner: "cirewind-fixtures", Name: "wrapper"}
	harmless := resolve.Repository{ID: 900003, Owner: "cirewind-fixtures", Name: "harmless"}
	workflows := resolve.Repository{ID: 900004, Owner: "cirewind-fixtures", Name: "workflows"}
	historical := resolve.GitObject{Algorithm: "sha1", Value: inventory.Identifiers.HistoricalWorkflowSHA}
	wrapperObject := resolve.GitObject{Algorithm: "sha1", Value: inventory.Identifiers.WrapperActionSHA}
	affectedObject := resolve.GitObject{Algorithm: "sha1", Value: inventory.Identifiers.AffectedActionSHA}
	calledObject := resolve.GitObject{Algorithm: "sha1", Value: inventory.Identifiers.CalledWorkflowSHA}

	t.Run("B composite runtime binding", func(t *testing.T) {
		metadataBytes := readRepositoryFile(t, "testdata/workflows/composite/action.yml")
		rootDefinition := definitionKey(wrapper, "action.yml", wrapperObject)
		parsed, diagnostics, err := workflow.ParseAction(metadataBytes, workflow.DefaultLimits())
		if err != nil || len(diagnostics) != 0 {
			t.Fatalf("parse wrapper: err=%v diagnostics=%+v", err, diagnostics)
		}
		childOccurrence := resolve.OccurrenceKey(rootDefinition, parsed.Steps[0].Uses.Span)
		source := fixtureContentSource{rootDefinition.String(): {Bytes: metadataBytes, EvidenceID: "ev-wrapper-definition"}}
		result, err := (resolve.Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveAction(context.Background(), resolve.ResolvedAction{
			Repository: wrapper, Commit: wrapperObject, EvidenceIDs: []string{"ev-wrapper-runtime"},
		}, resolve.ResolutionInputs{Actions: map[string]resolve.ResolvedAction{
			childOccurrence: {Repository: harmless, Commit: affectedObject, EvidenceIDs: []string{"ev-affected-runtime"}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		edge := requireResolverEdge(t, result, resolve.EdgeActionContainsAction, "cirewind-fixtures/harmless")
		if !edge.Exact || !edge.RuntimeBound || edge.GapCode != "HISTORICAL_CONTENT_MISSING" {
			t.Fatalf("composite child binding was over- or under-stated: %+v", edge)
		}
	})

	t.Run("C reusable to composite to affected", func(t *testing.T) {
		callerBytes := readRepositoryFile(t, "testdata/workflows/reusable-caller.yml")
		calledBytes := readRepositoryFile(t, "testdata/workflows/reusable-called.yml")
		wrapperBytes := readRepositoryFile(t, "testdata/workflows/composite/action.yml")
		callerDefinition := definitionKey(consumer, ".github/workflows/reusable-caller.yml", historical)
		calledDefinition := definitionKey(workflows, ".github/workflows/reusable.yml", calledObject)
		callerParsed, _, err := workflow.ParseWorkflow(callerBytes, workflow.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		calledParsed, _, err := workflow.ParseWorkflow(calledBytes, workflow.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		calledOccurrence := resolve.OccurrenceKey(callerDefinition, callerParsed.Jobs[0].Uses.Span)
		var wrapperSpan workflow.SourceSpan
		for _, step := range calledParsed.Jobs[0].Steps {
			if step.Uses != nil && step.Uses.Kind == workflow.ReferenceRepository {
				wrapperSpan = step.Uses.Span
				break
			}
		}
		wrapperOccurrence := resolve.OccurrenceKey(calledDefinition, wrapperSpan)
		wrapperDefinition := definitionKey(wrapper, "action.yml", wrapperObject)
		wrapperParsed, _, err := workflow.ParseAction(wrapperBytes, workflow.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		harmlessOccurrence := resolve.OccurrenceKey(wrapperDefinition, wrapperParsed.Steps[0].Uses.Span)
		source := fixtureContentSource{
			calledDefinition.String():  {Bytes: calledBytes, EvidenceID: "ev-called-definition"},
			wrapperDefinition.String(): {Bytes: wrapperBytes, EvidenceID: "ev-wrapper-definition"},
		}
		result, err := (resolve.Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveWorkflow(context.Background(), callerDefinition, resolve.Content{Bytes: callerBytes, EvidenceID: "ev-caller-definition"}, resolve.ResolutionInputs{
			CalledWorkflows: map[string]resolve.ResolvedWorkflow{calledOccurrence: {Definition: calledDefinition, EvidenceIDs: []string{"ev-called-api"}}},
			Actions: map[string]resolve.ResolvedAction{
				wrapperOccurrence:  {Repository: wrapper, Commit: wrapperObject, EvidenceIDs: []string{"ev-wrapper-runtime"}},
				harmlessOccurrence: {Repository: harmless, Commit: affectedObject, EvidenceIDs: []string{"ev-affected-runtime"}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		calledEdge := requireResolverEdge(t, result, resolve.EdgeWorkflowCalledWorkflow, "cirewind-fixtures/workflows")
		if !calledEdge.Exact || !calledEdge.RuntimeBound || calledEdge.To == "" {
			t.Fatalf("called-workflow identity was not retained: %+v", calledEdge)
		}
		affectedEdge := requireResolverEdge(t, result, resolve.EdgeActionContainsAction, "cirewind-fixtures/harmless")
		if !affectedEdge.Exact || !affectedEdge.RuntimeBound {
			t.Fatalf("nested affected Action was not runtime-bound: %+v", affectedEdge)
		}
	})

	t.Run("local workspace remains uncertain", func(t *testing.T) {
		callerBytes := readRepositoryFile(t, "testdata/workflows/local-caller.yml")
		localBytes := readRepositoryFile(t, "testdata/workflows/local/action.yml")
		callerDefinition := definitionKey(consumer, ".github/workflows/local-caller.yml", historical)
		localDefinition := definitionKey(consumer, ".github/actions/local/action.yml", historical)
		localParsed, _, err := workflow.ParseAction(localBytes, workflow.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		childOccurrence := resolve.OccurrenceKey(localDefinition, localParsed.Steps[0].Uses.Span)
		source := fixtureContentSource{localDefinition.String(): {Bytes: localBytes, EvidenceID: "ev-local-definition"}}
		result, err := (resolve.Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveWorkflow(context.Background(), callerDefinition, resolve.Content{Bytes: callerBytes, EvidenceID: "ev-local-caller"}, resolve.ResolutionInputs{Actions: map[string]resolve.ResolvedAction{
			childOccurrence: {Repository: harmless, Commit: affectedObject, EvidenceIDs: []string{"ev-affected-runtime"}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		localEdge := requireResolverEdge(t, result, resolve.EdgeWorkflowDeclaredAction, "./.github/actions/local")
		if localEdge.Exact || !localEdge.WorkspaceUncertain || localEdge.GapCode != "LOCAL_WORKSPACE_BYTES_UNPROVEN" {
			t.Fatalf("local workspace bytes were overclaimed: %+v", localEdge)
		}
		affectedEdge := requireResolverEdge(t, result, resolve.EdgeActionContainsAction, "cirewind-fixtures/harmless")
		if !affectedEdge.Exact || !affectedEdge.RuntimeBound {
			t.Fatalf("runtime-observed nested local dependency was lost: %+v", affectedEdge)
		}
	})
}

func TestHistoricalAndEventSemanticsUseActualWorkflowFixtures(t *testing.T) {
	inventory, metadata := loadInventory(t)
	byID := make(map[string]scenario)
	for _, item := range inventory.Scenarios {
		byID[item.ID] = item
	}

	historical := parseWorkflowFixture(t, byID["O"].Workflow)
	current := parseWorkflowFixture(t, byID["O"].CurrentWorkflow)
	if got := firstActionRef(t, historical).Ref; got != "v1" {
		t.Fatalf("historical Action ref = %q, want v1", got)
	}
	if got := firstActionRef(t, current).Ref; got != inventory.Identifiers.SafeActionSHA {
		t.Fatalf("current definition ref = %q, want safe exact SHA", got)
	}
	if byID["O"].WorkflowDefinitionCommit == byID["O"].CurrentDefaultCommit {
		t.Fatal("historical and present-day workflow identities were merged")
	}

	contradiction := parseWorkflowFixture(t, byID["P"].Workflow)
	if got := firstActionRef(t, contradiction).Ref; got != byID["P"].DeclaredSHA || got == byID["P"].RuntimeSHA {
		t.Fatalf("contradiction fixture failed to preserve declaration/runtime distinction: declared=%s runtime=%s", got, byID["P"].RuntimeSHA)
	}

	pullRequestTarget := parseWorkflowFixture(t, byID["L"].Workflow)
	if strings.Join(pullRequestTarget.Triggers, ",") != "pull_request_target" || byID["L"].UntrustedCheckoutPresent == nil || *byID["L"].UntrustedCheckoutPresent {
		t.Fatalf("pull_request_target fixture semantics drifted: triggers=%v checkout=%v", pullRequestTarget.Triggers, byID["L"].UntrustedCheckoutPresent)
	}

	jobs := make(map[int64]bool)
	for _, matrix := range metadata.MatrixJobs {
		if matrix.Scenario == "M" {
			jobs[matrix.JobID] = true
		}
	}
	if len(jobs) != 2 || !jobs[920013] || !jobs[920014] {
		t.Fatalf("matrix API job identities were merged: %v", jobs)
	}
}

func TestCredentialRunnerAndConcurrencyFixturesRunThroughExposureEngine(t *testing.T) {
	inventory, metadata := loadInventory(t)
	byID := make(map[string]scenario)
	for _, item := range append(append([]scenario(nil), inventory.Scenarios...), inventory.Supplemental...) {
		byID[item.ID] = item
	}

	t.Run("G direct named secret", func(t *testing.T) {
		parsed := parseWorkflowFixture(t, byID["G"].Workflow)
		step := parsed.Jobs[0].Steps[0]
		if len(step.SecretRefs) != 1 {
			t.Fatalf("direct step secret refs = %+v", step.SecretRefs)
		}
		result := exposure.Analyze(exposure.Input{
			AffectedStepKey: step.ID, AffectedLifecycleStarted: true, JobStarted: true,
			SecretFlows: []exposure.SecretFlow{{Name: step.SecretRefs[0].Name, Kind: exposure.SecretPassedToStep, DestinationStep: step.ID, EvidenceIDs: []string{"ev-workflow"}}},
		})
		requireExposureFact(t, result.Credentials, string(exposure.SecretPassedToStep), "CIREWIND_LAB_DIRECT")
	})

	t.Run("H one-hop inherit", func(t *testing.T) {
		caller := parseWorkflowFixture(t, byID["H"].Workflow)
		callee := parseWorkflowFixture(t, byID["H"].ReusableWorkflow)
		if !caller.Jobs[0].SecretsInherit || len(callee.Jobs[0].Steps[0].SecretRefs) != 1 {
			t.Fatalf("inherit fixture did not parse: caller=%+v callee=%+v", caller.Jobs[0], callee.Jobs[0])
		}
		name := callee.Jobs[0].Steps[0].SecretRefs[0].Name
		result := exposure.Analyze(exposure.Input{AffectedLifecycleStarted: true, JobStarted: true, SecretFlows: []exposure.SecretFlow{{
			Name: name, Kind: exposure.ReusableSecretInherited, CallHop: 1, EvidenceIDs: []string{"ev-caller", "ev-callee"},
		}}})
		requireExposureFact(t, result.Credentials, string(exposure.ReusableSecretInherited), "CIREWIND_LAB_INHERITED")
	})

	t.Run("I gate not crossed", func(t *testing.T) {
		parsed := parseWorkflowFixture(t, byID["I"].Workflow)
		job := parsed.Jobs[0]
		if job.Environment == "" || len(job.Steps[0].SecretRefs) != 1 {
			t.Fatalf("environment fixture did not parse: %+v", job)
		}
		result := exposure.Analyze(exposure.Input{
			AffectedStepKey: "gated", AffectedLifecycleStarted: false, JobStarted: false,
			Environment: exposure.EnvironmentGate{Name: job.Environment, Targeted: true, Crossed: false, JobStarted: false, EvidenceIDs: []string{"ev-environment"}},
			SecretFlows: []exposure.SecretFlow{{Name: job.Steps[0].SecretRefs[0].Name, Kind: exposure.EnvironmentSecretEligible, DestinationStep: "gated", EvidenceIDs: []string{"ev-workflow"}}},
		})
		if len(result.Credentials) != 0 {
			t.Fatalf("non-started gated job received credential eligibility: %+v", result.Credentials)
		}
	})

	t.Run("J OIDC is capability only", func(t *testing.T) {
		permissions := permissionsFromLog(t, inventory, "testdata/github-logs/scenario-j/setup.txt")
		result := exposure.Analyze(exposure.Input{AffectedLifecycleStarted: true, JobStarted: true, Permissions: permissions})
		requireExposureFact(t, result.Credentials, "OIDC_MINTING_CAPABILITY", "")
		for _, fact := range result.Credentials {
			if fact.Kind == "CLOUD_IDENTITY_REACHABLE" || strings.Contains(strings.ToLower(fact.Conclusion), "role assumed") {
				t.Fatalf("OIDC capability was promoted to cloud reachability: %+v", fact)
			}
		}
	})

	t.Run("K self-hosted classification", func(t *testing.T) {
		var runner runnerMetadata
		for _, candidate := range metadata.Runners {
			if candidate.Scenario == "K" {
				runner = candidate
			}
		}
		result := exposure.Analyze(exposure.Input{AffectedLifecycleStarted: true, JobStarted: true, Runner: exposure.Runner{
			Classification: strings.ToLower(strings.ReplaceAll(runner.Classification, "_", "-")), ID: valueOrZero(runner.RunnerID),
			Name: runner.RunnerName, Group: runner.RunnerGroup, Labels: runner.Labels, EvidenceIDs: []string{"ev-runner"},
		}})
		requireExposureFact(t, result.Resources, "SELF_HOSTED_RUNNER", runner.RunnerName)
	})

	t.Run("secret existence alone", func(t *testing.T) {
		var unused secretMetadata
		for _, candidate := range metadata.SecretMetadata {
			if candidate.Name == "CIREWIND_LAB_UNUSED" {
				unused = candidate
			}
		}
		result := exposure.Analyze(exposure.Input{AffectedLifecycleStarted: true, JobStarted: true, SecretFlows: []exposure.SecretFlow{{
			Name: unused.Name, Kind: exposure.SecretExistsMetadata, EvidenceIDs: []string{"ev-secret-metadata"},
		}}})
		if len(result.Credentials) != 0 {
			t.Fatalf("secret existence was called exposure: %+v", result.Credentials)
		}
	})

	t.Run("mapped reusable secret is one hop", func(t *testing.T) {
		caller := parseWorkflowFixture(t, byID["REUSABLE_SECRET_MAPPED"].Workflow)
		mapping := caller.Jobs[0].SecretMappings[0]
		result := exposure.Analyze(exposure.Input{AffectedLifecycleStarted: true, JobStarted: true, SecretFlows: []exposure.SecretFlow{{
			Name: mapping.SourceName, Kind: exposure.ReusableSecretMapped, CallHop: 1, EvidenceIDs: []string{"ev-secret-map"},
		}}})
		requireExposureFact(t, result.Credentials, string(exposure.ReusableSecretMapped), "CIREWIND_LAB_DIRECT")
	})

	t.Run("Q overlapping jobs have no causal order", func(t *testing.T) {
		affected := logInterval(t, "testdata/github-logs/scenario-q/affected-step.txt")
		independent := logInterval(t, "testdata/github-logs/scenario-q/independent-step.txt")
		intervals := map[string]exposure.Interval{"affected": affected, "independent": independent}
		if exposure.HappensBefore("affected", "independent", intervals, nil) || exposure.HappensBefore("independent", "affected", intervals, nil) {
			t.Fatalf("overlapping fixture intervals were causally ordered: %+v", intervals)
		}
		result := exposure.Analyze(exposure.Input{AffectedStepKey: "affected", AffectedLifecycleStarted: true, JobStarted: true, AffectedInterval: affected, StepIntervals: intervals})
		if len(result.Resources) != 0 {
			t.Fatalf("overlap without resource/synchronization evidence produced a resource conclusion: %+v", result.Resources)
		}
	})
}

func definitionKey(repository resolve.Repository, path string, object resolve.GitObject) resolve.DefinitionKey {
	return resolve.DefinitionKey{Repository: repository, Path: path, Commit: object}
}

func requireResolverEdge(t testing.TB, result resolve.Result, kind resolve.EdgeKind, rawContains string) resolve.Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Kind == kind && strings.Contains(edge.Declaration.Raw, rawContains) {
			return edge
		}
	}
	t.Fatalf("resolver edge %s containing %q absent: edges=%+v diagnostics=%+v", kind, rawContains, result.Edges, result.Diagnostics)
	return resolve.Edge{}
}

func parseWorkflowFixture(t testing.TB, path string) *workflow.Workflow {
	t.Helper()
	parsed, diagnostics, err := workflow.ParseWorkflow(readRepositoryFile(t, path), workflow.DefaultLimits())
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("parse workflow %s: err=%v diagnostics=%+v", path, err, diagnostics)
	}
	return parsed
}

func firstActionRef(t testing.TB, parsed *workflow.Workflow) workflow.Reference {
	t.Helper()
	for _, job := range parsed.Jobs {
		for _, step := range job.Steps {
			if step.Uses != nil && step.Uses.Kind == workflow.ReferenceRepository {
				return *step.Uses
			}
		}
	}
	t.Fatal("workflow has no repository Action reference")
	return workflow.Reference{}
}

func permissionsFromLog(t testing.TB, inventory fixtureInventory, path string) []exposure.Permission {
	t.Helper()
	for _, parsed := range parseInventoryLogs(t, inventory) {
		if parsed.Entry.Path != path {
			continue
		}
		var permissions []exposure.Permission
		for _, observation := range parsed.Result.Observations {
			if observation.Kind == logparse.ObservationTokenPermission {
				permissions = append(permissions, exposure.Permission{Name: observation.Permission, Access: observation.Access, Basis: exposure.BasisRuntimeObserved, EvidenceIDs: []string{"ev-token-permissions"}})
			}
		}
		return permissions
	}
	t.Fatalf("log fixture %s not found", path)
	return nil
}

func requireExposureFact(t testing.TB, facts []exposure.Fact, kind, name string) exposure.Fact {
	t.Helper()
	for _, fact := range facts {
		if fact.Kind == kind && (name == "" || fact.Name == name) {
			return fact
		}
	}
	t.Fatalf("exposure fact kind=%s name=%s absent from %+v", kind, name, facts)
	return exposure.Fact{}
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func logInterval(t testing.TB, path string) exposure.Interval {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(readRepositoryFile(t, path)))
	var values []time.Time
	for scanner.Scan() {
		line := scanner.Text()
		space := strings.IndexByte(line, ' ')
		if space <= 0 {
			continue
		}
		value, err := time.Parse(time.RFC3339Nano, line[:space])
		if err == nil {
			values = append(values, value)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(values) < 2 {
		t.Fatalf("fixture %s lacks a bounded interval", path)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Before(values[j]) })
	return exposure.Interval{Start: values[0], End: values[len(values)-1]}
}

func TestResolverFixturePathsAreSyntheticAndBounded(t *testing.T) {
	inventory, _ := loadInventory(t)
	for _, item := range append(append([]scenario(nil), inventory.Scenarios...), inventory.Supplemental...) {
		for _, path := range append(append([]string{item.Workflow, item.CurrentWorkflow, item.ReusableWorkflow}, item.ActionDefinitions...), "") {
			if path == "" {
				continue
			}
			if !strings.HasPrefix(path, "testdata/") || strings.Contains(path, "..") {
				t.Errorf("fixture path escaped testdata: scenario=%s path=%q", item.ID, path)
			}
		}
	}
	if !inventory.SyntheticOnly {
		t.Fatal(fmt.Errorf("fixture inventory must remain synthetic"))
	}
}
