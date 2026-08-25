package demodata

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/model"
)

var (
	executedIdentity      = execution(1001, 1, 2001)
	restoredIdentity      = execution(1001, 2, 2101)
	waitingIdentity       = execution(1005, 1, 2005)
	contradictionIdentity = execution(1008, 1, 2008)
)

// ValidateSnapshot enforces relationships that are individually valid archive
// facts but would form an incoherent or overclaiming synthetic narrative when
// combined. It is intentionally stricter than general archive validation.
func ValidateSnapshot(snapshot archive.Snapshot) error {
	normalized, err := archive.NormalizeSnapshot(snapshot)
	if err != nil {
		return fmt.Errorf("normalize: %w", err)
	}
	runs := make(map[string]archive.RunFact)
	attempts := make(map[string]archive.AttemptFact)
	jobs := make(map[string]archive.JobFact)
	jobsByAttempt := make(map[string][]archive.JobFact)
	var actionFacts, dependencyFacts, exposureFacts, coverageFacts []archive.Fact
	for _, fact := range normalized.Facts {
		switch fact.Kind {
		case archive.FactRun:
			if fact.Run == nil {
				return errors.New("run fact has no run payload")
			}
			key := runKey(fact.Run.RepositoryID, fact.Run.RunID)
			if _, duplicate := runs[key]; duplicate {
				return fmt.Errorf("duplicate run metadata for %s", key)
			}
			runs[key] = *fact.Run
		case archive.FactAttempt:
			if fact.Attempt == nil {
				return errors.New("attempt fact has no attempt payload")
			}
			key := attemptKey(fact.Attempt.RepositoryID, fact.Attempt.RunID, fact.Attempt.RunAttempt)
			if _, duplicate := attempts[key]; duplicate {
				return fmt.Errorf("duplicate attempt metadata for %s", key)
			}
			attempts[key] = *fact.Attempt
		case archive.FactJob:
			if fact.Job == nil {
				return errors.New("job fact has no job payload")
			}
			key := fact.Job.Execution.String()
			if _, duplicate := jobs[key]; duplicate {
				return fmt.Errorf("duplicate job metadata for %s", key)
			}
			jobs[key] = *fact.Job
			attempt := fact.Job.Execution
			jobsByAttempt[attemptKey(attempt.RepositoryID, attempt.RunID, attempt.RunAttempt)] = append(jobsByAttempt[attemptKey(attempt.RepositoryID, attempt.RunID, attempt.RunAttempt)], *fact.Job)
		case archive.FactActionOccurrence:
			actionFacts = append(actionFacts, fact)
		case archive.FactDependency:
			dependencyFacts = append(dependencyFacts, fact)
		case archive.FactExposure:
			exposureFacts = append(exposureFacts, fact)
		case archive.FactCoverage:
			coverageFacts = append(coverageFacts, fact)
		}
	}
	if err := validateExecutionParents(runs, attempts, jobs); err != nil {
		return err
	}
	if err := validateExposures(runs, attempts, jobs, jobsByAttempt, actionFacts, exposureFacts); err != nil {
		return err
	}
	if err := validatePairedRerun(actionFacts, coverageFacts); err != nil {
		return err
	}
	if err := validateExactCalledWorkflow(dependencyFacts); err != nil {
		return err
	}
	if err := validateRuntimeDefinitionContradiction(actionFacts, dependencyFacts); err != nil {
		return err
	}
	return nil
}

func validateExecutionParents(runs map[string]archive.RunFact, attempts map[string]archive.AttemptFact, jobs map[string]archive.JobFact) error {
	if len(runs) != 11 {
		return fmt.Errorf("run count=%d, want 11 coherent run facts", len(runs))
	}
	jobKeys := make([]string, 0, len(jobs))
	for key := range jobs {
		jobKeys = append(jobKeys, key)
	}
	sort.Strings(jobKeys)
	for _, key := range jobKeys {
		job := jobs[key]
		execution := job.Execution
		if _, ok := runs[runKey(execution.RepositoryID, execution.RunID)]; !ok {
			return fmt.Errorf("job %s has no run fact", execution)
		}
		if _, ok := attempts[attemptKey(execution.RepositoryID, execution.RunID, execution.RunAttempt)]; !ok {
			return fmt.Errorf("job %s has no attempt fact", execution)
		}
	}
	if _, ok := jobs[executedIdentity.String()]; !ok {
		return errors.New("affected B execution job is absent")
	}
	if _, ok := jobs[restoredIdentity.String()]; !ok {
		return errors.New("restored A rerun job is absent")
	}
	return nil
}

func validatePairedRerun(actions, coverage []archive.Fact) error {
	affectedValue := strings.Repeat("1", 40)
	knownGoodValue := strings.Repeat("0", 40)
	affectedCount, knownGoodCount := 0, 0
	for _, fact := range actions {
		if fact.ActionOccurrence == nil {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.ActionRepository != mustRepository(affectedAction) || observation.ActionSubpath != "paired-rerun" || observation.SourceObjectID == nil {
			continue
		}
		value := model.GitObjectID(*observation.SourceObjectID).Value
		switch {
		case observation.Execution == executedIdentity && value == affectedValue && observation.Kind.SupportsExecuted():
			affectedCount++
		case observation.Execution == restoredIdentity && value == knownGoodValue && observation.Kind.SupportsExecuted():
			knownGoodCount++
		default:
			return fmt.Errorf("unexpected paired-rerun runtime observation for %s identity=%s lifecycle=%s", observation.Execution, value, observation.Kind)
		}
	}
	if affectedCount != 1 || knownGoodCount != 1 {
		return fmt.Errorf("paired rerun observations affected-B=%d restored-A=%d, want 1/1", affectedCount, knownGoodCount)
	}
	closed := make(map[model.CoverageKind]int)
	for _, fact := range coverage {
		if fact.Coverage == nil || fact.Subject.RepositoryID != restoredIdentity.RepositoryID || fact.Subject.RunID == nil || fact.Subject.RunAttempt == nil || fact.Subject.JobID == nil {
			continue
		}
		if *fact.Subject.RunID == restoredIdentity.RunID && *fact.Subject.RunAttempt == restoredIdentity.RunAttempt && *fact.Subject.JobID == restoredIdentity.JobID &&
			fact.Coverage.Unit.RequiredForNegative && fact.Coverage.Assessment.Status == model.CoverageCollected && fact.Coverage.Assessment.ExpectedCount != nil &&
			*fact.Coverage.Assessment.ExpectedCount == 1 && fact.Coverage.Assessment.ObservedCount == 1 {
			closed[fact.Coverage.Unit.Kind]++
		}
	}
	if closed[model.CoverageJobLog] != 1 || closed[model.CoverageParserGrammar] != 1 || len(closed) != 2 {
		return fmt.Errorf("restored-A required closure=%v, want one job-log and one parser-grammar assessment", closed)
	}
	return nil
}

func validateExactCalledWorkflow(dependencies []archive.Fact) error {
	count := 0
	for _, fact := range dependencies {
		dep := fact.Dependency
		if dep == nil || dep.TargetRepository != mustRepository(affectedWorkflow) {
			continue
		}
		if dep.Basis != archive.DefinitionRuntimeAttemptMetadata || dep.AttemptExecution == nil || dep.Execution != nil || dep.TargetCalledWorkflowObjectID == nil {
			return errors.New("called-workflow fixture is not exact GitHub run-attempt metadata")
		}
		if *dep.AttemptExecution != (model.RunAttemptIdentity{RepositoryID: consumerRepositoryID, RunID: 1003, RunAttempt: 2}) {
			return errors.New("called-workflow metadata has the wrong run-attempt identity")
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("exact called-workflow metadata count=%d, want 1", count)
	}
	return nil
}

func validateRuntimeDefinitionContradiction(actions, dependencies []archive.Fact) error {
	var runtime *archive.Fact
	for index := range actions {
		fact := &actions[index]
		if fact.ActionOccurrence != nil && fact.ActionOccurrence.Observation.Execution == contradictionIdentity && fact.ActionOccurrence.Observation.Kind.SupportsExecuted() {
			runtime = fact
		}
	}
	if runtime == nil || runtime.ActionOccurrence.Observation.SourceObjectID == nil || runtime.Subject.StepKey == "" {
		return errors.New("contradiction fixture lacks exact runtime B at a step")
	}
	count := 0
	for _, fact := range dependencies {
		dep := fact.Dependency
		if dep == nil || dep.Execution == nil || *dep.Execution != contradictionIdentity || dep.CallerPath != ".github/workflows/contradiction.yml" {
			continue
		}
		if dep.Basis != archive.DefinitionHistoricalAtRun || dep.TargetActionObjectID == nil || model.GitObjectID(*dep.TargetActionObjectID).Value != strings.Repeat("0", 40) ||
			dep.StepKey != runtime.Subject.StepKey || len(dep.ContradictsFactIDs) != 1 || dep.ContradictsFactIDs[0] != runtime.ID {
			return errors.New("contradiction fixture is not historical A versus linked exact runtime B at one occurrence")
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("runtime-definition contradiction count=%d, want 1", count)
	}
	return nil
}

func validateExposures(runs map[string]archive.RunFact, attempts map[string]archive.AttemptFact, jobs map[string]archive.JobFact, jobsByAttempt map[string][]archive.JobFact, actions, exposures []archive.Fact) error {
	credentialCounts := make(map[model.CredentialExposureKind]int)
	tokenPermissions := make(map[string]int)
	runnerCount, deploymentCount, pendingCount := 0, 0, 0
	for _, fact := range exposures {
		if fact.Exposure == nil {
			continue
		}
		exposure := fact.Exposure
		if exposure.Credential != nil {
			credential := exposure.Credential
			if credential.Basis == "" || !credential.Basis.Valid() {
				return fmt.Errorf("credential %s has empty or unknown basis", credential.Kind)
			}
			credentialCounts[credential.Kind]++
			switch credential.Kind {
			case model.ExposureGitHubTokenPermission:
				if exposure.Execution != executedIdentity || credential.Access != "write" || credential.Basis != model.ExposureBasisRuntimeObserved ||
					(credential.Permission != "contents" && credential.Permission != "id-token") {
					return errors.New("token fact is not a supported runtime-observed write capability on affected B")
				}
				tokenPermissions[credential.Permission+":"+credential.Access]++
			case model.ExposureSecretPassedToStep:
				if exposure.Execution != executedIdentity || credential.Basis != model.ExposureBasisHistoricalDefinitionFlow {
					return errors.New("secret flow is not a historical-definition flow to affected B")
				}
			case model.ExposureOIDCMintingCapability:
				return errors.New("OIDC capability must be derived from typed id-token:write permission, not archived as a conclusion")
			case model.ExposureEnvironmentSecretEligible:
				return errors.New("pending demo environment cannot carry environment-secret eligibility")
			default:
				return fmt.Errorf("unexpected demo credential relationship %s", credential.Kind)
			}
		}
		if exposure.Runner != nil {
			if exposure.Execution != executedIdentity || exposure.Runner.Classification != "self-hosted" {
				return errors.New("self-hosted runner context is not scoped to affected B")
			}
			runnerCount++
		}
		if exposure.Resource != nil {
			if exposure.Execution != executedIdentity || exposure.Resource.Kind != model.ResourceDeployment || exposure.Resource.Correlation != model.CorrelationObservedAfter {
				return errors.New("deployment context is not a temporal observed-after relationship on affected B")
			}
			deploymentCount++
		}
		if exposure.Environment != nil {
			pendingCount++
			if err := validatePendingEnvironment(*exposure, runs, attempts, jobs, jobsByAttempt, actions); err != nil {
				return err
			}
		}
	}
	for _, expected := range []struct {
		kind model.CredentialExposureKind
		want int
	}{
		{model.ExposureGitHubTokenPermission, 2},
		{model.ExposureSecretPassedToStep, 1},
		{model.ExposureOIDCMintingCapability, 0},
	} {
		if credentialCounts[expected.kind] != expected.want {
			return fmt.Errorf("credential relationship %s count=%d, want %d", expected.kind, credentialCounts[expected.kind], expected.want)
		}
	}
	if runnerCount != 1 || deploymentCount != 1 || pendingCount != 1 {
		return fmt.Errorf("runner/deployment/pending-environment counts=%d/%d/%d, want 1/1/1", runnerCount, deploymentCount, pendingCount)
	}
	if tokenPermissions["contents:write"] != 1 || tokenPermissions["id-token:write"] != 1 || len(tokenPermissions) != 2 {
		return fmt.Errorf("typed token permissions=%v, want contents:write and id-token:write", tokenPermissions)
	}
	return nil
}

func validatePendingEnvironment(exposure archive.ExposureFact, runs map[string]archive.RunFact, attempts map[string]archive.AttemptFact, jobs map[string]archive.JobFact, jobsByAttempt map[string][]archive.JobFact, actions []archive.Fact) error {
	environment := exposure.Environment
	if environment == nil {
		return errors.New("pending environment payload is absent")
	}
	if exposure.Execution != waitingIdentity || environment.EnvironmentName != "production-fixture" || environment.GateState != "pending" || environment.JobStarted || len(environment.SecretNames) != 0 {
		return errors.New("pending environment is not the unstarted run 1005 fixture without eligible secrets")
	}
	job, ok := jobs[exposure.Execution.String()]
	if !ok {
		return errors.New("pending environment job metadata is absent")
	}
	if statusIndicatesStarted(job.Status) || job.Conclusion != "" {
		return fmt.Errorf("JobStarted:false conflicts with job status/conclusion %q/%q", job.Status, job.Conclusion)
	}
	for _, fact := range actions {
		if fact.ActionOccurrence != nil && fact.ActionOccurrence.Observation.Execution == exposure.Execution && fact.ActionOccurrence.Observation.Kind.SupportsExecuted() {
			return errors.New("JobStarted:false conflicts with an Action lifecycle start or completion")
		}
	}
	attemptKeyValue := attemptKey(exposure.Execution.RepositoryID, exposure.Execution.RunID, exposure.Execution.RunAttempt)
	children := jobsByAttempt[attemptKeyValue]
	if len(children) != 1 {
		return fmt.Errorf("pending environment attempt has %d jobs, want exactly one for fixture coherence", len(children))
	}
	run, runOK := runs[runKey(exposure.Execution.RepositoryID, exposure.Execution.RunID)]
	attempt, attemptOK := attempts[attemptKeyValue]
	if !runOK || !attemptOK {
		return errors.New("pending environment lacks parent run or attempt")
	}
	if run.Conclusion != "" || attempt.Conclusion != "" || job.Conclusion != "" {
		return errors.New("pending environment has a nonempty run, attempt, or job conclusion")
	}
	if run.Status != "waiting" || attempt.Status != "waiting" || job.Status != "waiting" || run.Status != attempt.Status || attempt.Status != job.Status {
		return fmt.Errorf("pending environment parent/child statuses disagree: run=%q attempt=%q job=%q", run.Status, attempt.Status, job.Status)
	}
	return nil
}

func statusIndicatesStarted(status string) bool {
	switch status {
	case "in_progress", "completed":
		return true
	default:
		return false
	}
}

func runKey(repository model.RepositoryID, run model.WorkflowRunID) string {
	return fmt.Sprintf("%d/%d", repository, run)
}

func attemptKey(repository model.RepositoryID, run model.WorkflowRunID, attempt model.RunAttempt) string {
	return fmt.Sprintf("%d/%d/%d", repository, run, attempt)
}
