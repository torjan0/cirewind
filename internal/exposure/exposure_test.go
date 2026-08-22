package exposure

import (
	"strings"
	"testing"
	"time"
)

func TestSecretExistenceIsNotExposure(t *testing.T) {
	t.Parallel()
	result := Analyze(Input{AffectedStepKey: "s", AffectedLifecycleStarted: true, JobStarted: true, SecretFlows: []SecretFlow{{Name: "DEPLOY_KEY", Kind: SecretExistsMetadata, EvidenceIDs: []string{"ev-exists"}}, {Name: "DIRECT", Kind: SecretPassedToStep, DestinationStep: "other", EvidenceIDs: []string{"ev-other"}}}})
	if len(result.Credentials) != 0 {
		t.Fatalf("unreachable secret called exposed: %+v", result)
	}
}

func TestSiblingStepSecretDoesNotReachAffectedStep(t *testing.T) {
	t.Parallel()
	result := Analyze(Input{
		AffectedStepKey:          "affected",
		AffectedLifecycleStarted: true,
		JobStarted:               true,
		SecretFlows: []SecretFlow{
			{Name: "SIBLING_ONLY", Kind: SecretPassedToStep, DestinationStep: "sibling", EvidenceIDs: []string{"ev-sibling"}},
			{Name: "JOB_REFERENCE", Kind: SecretReferencedByJob, EvidenceIDs: []string{"ev-job-reference"}},
			{Name: "JOB_ENV", Kind: SecretPassedToStep, DestinationStep: "affected", EvidenceIDs: []string{"ev-job-env"}},
			// A job-reference proposition with a step destination is malformed and
			// must fail closed instead of becoming job-wide reachability.
			{Name: "MISSCOPED", Kind: SecretReferencedByJob, DestinationStep: "sibling", EvidenceIDs: []string{"ev-misscoped"}},
		},
	})
	if len(result.Credentials) != 2 {
		t.Fatalf("sibling or misscoped secret leaked into affected-step result: %+v", result.Credentials)
	}
	byName := make(map[string]Fact, len(result.Credentials))
	for _, fact := range result.Credentials {
		byName[fact.Name] = fact
	}
	if _, ok := byName["SIBLING_ONLY"]; ok {
		t.Fatal("sibling-step secret was attributed to the affected step")
	}
	if _, ok := byName["MISSCOPED"]; ok {
		t.Fatal("step-scoped reference was accepted as job-scoped")
	}
	jobRef, ok := byName["JOB_REFERENCE"]
	if !ok || jobRef.Kind != string(SecretReferencedByJob) || !strings.Contains(jobRef.Conclusion, "does not establish") || strings.Contains(jobRef.Conclusion, "potentially reachable") {
		t.Fatalf("job-only reference language overclaims reachability: %+v", jobRef)
	}
	jobEnv, ok := byName["JOB_ENV"]
	if !ok || jobEnv.Kind != string(SecretPassedToStep) || !strings.Contains(jobEnv.Conclusion, "passed") || !strings.Contains(jobEnv.Conclusion, "does not establish") {
		t.Fatalf("job environment flow was not kept distinct: %+v", jobEnv)
	}
}

func TestDirectSecretEnvironmentAndInheritanceRemainDistinct(t *testing.T) {
	t.Parallel()
	result := Analyze(Input{AffectedStepKey: "affected", AffectedLifecycleStarted: true, JobStarted: true, Environment: EnvironmentGate{Name: "prod", Targeted: true, Crossed: false, JobStarted: false, EvidenceIDs: []string{"ev-gate"}}, SecretFlows: []SecretFlow{{Name: "DIRECT", Kind: SecretPassedToStep, DestinationStep: "affected", EvidenceIDs: []string{"ev-direct"}}, {Name: "INHERITED", Kind: ReusableSecretInherited, CallHop: 1, EvidenceIDs: []string{"ev-inherit"}}, {Name: "ENV", Kind: EnvironmentSecretEligible, DestinationStep: "affected", EvidenceIDs: []string{"ev-env"}}}})
	if len(result.Credentials) != 2 {
		t.Fatalf("blocked environment secret became eligible or flows lost: %+v", result)
	}
	for _, fact := range result.Credentials {
		if fact.Name == "ENV" {
			t.Fatal("blocked environment secret emitted")
		}
	}
}

func TestOIDCMeansMintingOnly(t *testing.T) {
	t.Parallel()
	result := Analyze(Input{AffectedLifecycleStarted: true, Permissions: []Permission{{Name: "id-token", Access: "write", Basis: BasisRuntimeObserved, EvidenceIDs: []string{"ev-perm"}}}})
	joined := ""
	for _, fact := range result.Credentials {
		joined += fact.Kind + " " + fact.Conclusion
	}
	if !strings.Contains(joined, "OIDC_MINTING_CAPABILITY") || strings.Contains(strings.ToLower(joined), "role was assumed") {
		t.Fatalf("OIDC overclaim: %s", joined)
	}
}

func TestRuntimePermissionsOutrankStatic(t *testing.T) {
	t.Parallel()
	result := Analyze(Input{AffectedLifecycleStarted: true, Permissions: []Permission{{Name: "contents", Access: "write", Basis: BasisStaticInferred, EvidenceIDs: []string{"ev-static"}}, {Name: "contents", Access: "read", Basis: BasisRuntimeObserved, EvidenceIDs: []string{"ev-runtime"}}}})
	if len(result.Credentials) != 1 || result.Credentials[0].Capability != "read" {
		t.Fatalf("static permission overrode runtime: %+v", result)
	}
}

func TestEnvironmentRequiresGateAndJobStart(t *testing.T) {
	t.Parallel()
	base := Input{AffectedStepKey: "s", AffectedLifecycleStarted: true, JobStarted: true, SecretFlows: []SecretFlow{{Name: "ENV", Kind: EnvironmentSecretEligible, DestinationStep: "s", EvidenceIDs: []string{"ev-flow"}}}}
	for _, gate := range []EnvironmentGate{{Targeted: true, Crossed: false, JobStarted: false}, {Targeted: true, Crossed: true, JobStarted: false}} {
		base.Environment = gate
		if result := Analyze(base); len(result.Credentials) != 0 {
			t.Fatalf("ungated environment eligible: %+v", result)
		}
	}
	base.Environment = EnvironmentGate{Targeted: true, Crossed: true, JobStarted: true, EvidenceIDs: []string{"ev-gate"}}
	if result := Analyze(base); len(result.Credentials) != 1 {
		t.Fatalf("crossed gate missing eligibility: %+v", result)
	}
}

func TestConcurrentStepsAreUnorderedWithoutWait(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	intervals := map[string]Interval{"a": {Start: start, End: start.Add(10 * time.Second)}, "b": {Start: start.Add(time.Second), End: start.Add(2 * time.Second)}}
	if HappensBefore("a", "b", intervals, nil) {
		t.Fatal("overlap treated as happens-before")
	}
	if !HappensBefore("a", "b", intervals, []SynchronizationEdge{{FromStep: "a", ToStep: "b", EvidenceIDs: []string{"ev-wait"}}}) {
		t.Fatal("explicit wait not honored")
	}
}

func TestDeploymentUsesObservedAfterNotCausation(t *testing.T) {
	t.Parallel()
	end := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	result := Analyze(Input{AffectedLifecycleStarted: true, AffectedInterval: Interval{Start: end.Add(-time.Second), End: end}, Resources: []Resource{{Kind: "deployment", Name: "prod", EventTime: end.Add(time.Second), EvidenceIDs: []string{"ev-deploy"}}}})
	if len(result.Resources) != 1 || result.Resources[0].Basis != "temporal-correlation" || strings.Contains(strings.ToLower(result.Resources[0].Conclusion), "caused") {
		t.Fatalf("deployment causation overclaimed: %+v", result)
	}
}
