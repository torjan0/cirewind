package analyze

import (
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/archive"
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
	if context.Kind != "ENVIRONMENT_GATE_CONTEXT" || context.Name != "production" || context.Capability != "crossed" || !strings.Contains(context.Conclusion, "environment secret names or values") {
		t.Fatalf("environment report context = %#v", context)
	}
	if credentials, resources = exposuresFor(idx, subject, model.ConfirmedDownloaded); len(credentials) != 0 || len(resources) != 0 {
		t.Fatalf("downloaded-only finding received environment reachability: credentials=%#v resources=%#v", credentials, resources)
	}
}
