package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
)

func TestEnvironmentGateContextRequiresConfirmedExactJobExecution(t *testing.T) {
	runID, attempt, jobID := model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt, JobID: jobID}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	fact, err := archive.NormalizeFact(archive.Fact{
		Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID},
		Exposure: &archive.ExposureFact{
			Execution: execution,
			Environment: &archive.EnvironmentEligibilityFact{
				EnvironmentName: "production", GateState: "crossed", JobStarted: true, SecretNames: []model.SecretName{},
			},
			EventTime: unknownTime(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	subject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	idx := index{exposures: []archive.Fact{fact}}

	credentials, resources := exposuresFor(idx, subject, model.ConfirmedExecuted)
	if len(credentials) != 0 || len(resources) != 1 {
		t.Fatalf("confirmed environment context: credentials=%#v resources=%#v", credentials, resources)
	}
	context := resources[0]
	if context.Kind != "ENVIRONMENT_GATE_CONTEXT" || context.Name != "production" || context.Capability != "crossed" || !strings.Contains(context.Conclusion, "No environment secret names were retained") {
		t.Fatalf("environment report context = %#v", context)
	}
	if credentials, resources = exposuresFor(idx, subject, model.ConfirmedDownloaded); len(credentials) != 0 || len(resources) != 0 {
		t.Fatalf("downloaded-only finding received environment reachability: credentials=%#v resources=%#v", credentials, resources)
	}
}

func TestEnvironmentEligibilityStatesStayAlignedBetweenReportAndV2Graph(t *testing.T) {
	secretName, err := model.NewSecretName("DEPLOY_KEY")
	if err != nil {
		t.Fatal(err)
	}
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
	runID, attempt, jobID := execution.RunID, execution.RunAttempt, execution.JobID
	subject := archive.FactSubject{RepositoryID: 1, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	focus := "frev1:" + strings.Repeat("b", 64)

	for _, test := range []struct {
		state         string
		started       bool
		eligible      bool
		gateSatisfied bool
		gateRule      string
	}{
		{state: "approved", started: true, eligible: true, gateSatisfied: true, gateRule: graph.EnvironmentGateSatisfiedApprovedRule},
		{state: "bypassed", started: true, eligible: true, gateSatisfied: true, gateRule: graph.EnvironmentGateSatisfiedBypassedRule},
		{state: "crossed", started: true, eligible: true, gateSatisfied: true, gateRule: graph.EnvironmentGateSatisfiedCrossedRule},
		{state: "not-required", started: true, eligible: true, gateSatisfied: true, gateRule: graph.EnvironmentGateSatisfiedNotRequiredRule},
		{state: "pending", started: false},
		{state: "rejected", started: false},
		{state: "unknown", started: true},
	} {
		t.Run(test.state, func(t *testing.T) {
			event := unknownTime()
			if test.state == "not-required" {
				event = instantEventAt(time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC))
			}
			environment := archive.EnvironmentEligibilityFact{
				EnvironmentName: "production", GateState: test.state, JobStarted: test.started, SecretNames: []model.SecretName{},
			}
			if test.eligible {
				environment.SecretNames = []model.SecretName{secretName}
			}
			fact, err := archive.NormalizeFact(archive.Fact{
				Kind: archive.FactExposure, Subject: subject, EvidenceIDs: []model.EvidenceID{evidenceID},
				Exposure: &archive.ExposureFact{Execution: execution, Environment: &environment, EventTime: event},
			})
			if err != nil {
				t.Fatal(err)
			}
			credentials, resources := exposuresFor(index{exposures: []archive.Fact{fact}}, subject, model.ConfirmedExecuted)
			if len(resources) != 1 || resources[0].Capability != test.state {
				t.Fatalf("report environment context=%#v", resources)
			}
			for _, prohibited := range []string{"secret was read", "secret was used", "secret was accessed"} {
				if strings.Contains(strings.ToLower(resources[0].Conclusion), prohibited) {
					t.Fatalf("environment context overclaims %q: %s", prohibited, resources[0].Conclusion)
				}
			}
			if test.eligible {
				wantPhrase := map[string]string{
					"approved":     "records approval",
					"bypassed":     "records a gate bypass",
					"crossed":      "records the gate as crossed",
					"not-required": "records that no gate was required",
				}[test.state]
				if !strings.Contains(resources[0].Conclusion, wantPhrase) {
					t.Fatalf("gate state %s lost conservative distinction: %s", test.state, resources[0].Conclusion)
				}
			}
			if got := len(credentials); got != map[bool]int{false: 0, true: 1}[test.eligible] {
				t.Fatalf("eligible credential count=%d, want eligible=%t: %#v", got, test.eligible, credentials)
			}
			if test.eligible {
				credential := credentials[0]
				if credential.Kind != string(model.ExposureEnvironmentSecretEligible) || credential.Name != string(secretName) ||
					credential.Basis != string(model.ExposureBasisHistoricalDefinitionFlow) || !strings.Contains(credential.Conclusion, "not demonstrated") {
					t.Fatalf("environment credential conclusion=%#v", credential)
				}
			}

			builder := newV2ScopedExposureBuilder()
			if err := builder.projectEnvironment(execution, environment, []string{string(evidenceID)}, event, focus); err != nil {
				t.Fatal(err)
			}
			var targetEdges, crossedEdges, eligibleEdges int
			var gateRule string
			for _, edge := range builder.edges {
				switch edge.Type {
				case graph.EdgeTargetedEnvironment:
					targetEdges++
				case graph.EdgeEnvironmentGateSatisfied:
					crossedEdges++
					gateRule = edge.DerivationRule
				case graph.EdgeEnvironmentSecretEligible:
					eligibleEdges++
				}
			}
			if targetEdges != 1 || (crossedEdges == 1) != test.gateSatisfied || (eligibleEdges == 1) != test.eligible {
				t.Fatalf("v2 environment edges target=%d crossed=%d eligible=%d", targetEdges, crossedEdges, eligibleEdges)
			}
			if gateRule != test.gateRule {
				t.Fatalf("v2 environment gate rule=%q, want %q", gateRule, test.gateRule)
			}
		})
	}

	t.Run("not-required unknown time does not establish eligibility", func(t *testing.T) {
		environment := archive.EnvironmentEligibilityFact{
			EnvironmentName: "production", GateState: "not-required", JobStarted: true, SecretNames: []model.SecretName{},
		}
		fact, err := archive.NormalizeFact(archive.Fact{
			Kind: archive.FactExposure, Subject: subject, EvidenceIDs: []model.EvidenceID{evidenceID},
			Exposure: &archive.ExposureFact{Execution: execution, Environment: &environment, EventTime: unknownTime()},
		})
		if err != nil {
			t.Fatal(err)
		}
		credentials, resources := exposuresFor(index{exposures: []archive.Fact{fact}}, subject, model.ConfirmedExecuted)
		if len(credentials) != 0 || len(resources) != 1 || strings.Contains(resources[0].Conclusion, "establishes environment-secret eligibility") {
			t.Fatalf("unknown-time not-required state established eligibility: credentials=%#v resources=%#v", credentials, resources)
		}
		builder := newV2ScopedExposureBuilder()
		if err := builder.projectEnvironment(execution, environment, []string{string(evidenceID)}, unknownTime(), focus); err != nil {
			t.Fatal(err)
		}
		for _, edge := range builder.edges {
			if edge.Type == graph.EdgeEnvironmentGateSatisfied || edge.Type == graph.EdgeEnvironmentSecretEligible {
				t.Fatalf("unknown-time not-required state emitted %s", edge.Type)
			}
		}
	})
}
