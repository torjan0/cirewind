package archive

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

const maxDependencyDepth = 32

// NormalizeFact validates a compact source fact, derives its material subject,
// and assigns its content-addressed identifier. Supporting evidence is not part
// of the identity, so a later collection can attach an additional observation
// without rewriting the archived fact.
func NormalizeFact(input Fact) (Fact, error) {
	return normalizeFact(input, false)
}

// NormalizeRetainedV1Fact preserves the exact canonical identity of a retained
// v1alpha1 exposure whose credential basis is empty or no longer part of the
// current closed vocabulary. All other fact validation remains identical to
// NormalizeFact. It must never be used for newly collected facts.
func NormalizeRetainedV1Fact(input Fact) (Fact, error) {
	return normalizeFact(input, true)
}

func normalizeFact(input Fact, allowRetainedLegacyBasis bool) (Fact, error) {
	fact := input
	normalizeFactSlices(&fact)
	fact.EvidenceIDs = sortEvidenceIDs(fact.EvidenceIDs)

	var (
		subject FactSubject
		event   model.EventInterval
		nested  []model.EvidenceID
	)
	payloadCount := 0
	if fact.Repository != nil {
		payloadCount++
		if fact.Kind != FactRepository {
			return Fact{}, errors.New("repository payload has a different fact kind")
		}
		if err := fact.Repository.Repository.Validate(); err != nil {
			return Fact{}, fmt.Errorf("repository fact: %w", err)
		}
		if fact.Repository.Visibility != "" && fact.Repository.Visibility != "public" && fact.Repository.Visibility != "private" && fact.Repository.Visibility != "internal" {
			return Fact{}, errors.New("repository visibility is invalid")
		}
		if err := safeText(fact.Repository.DefaultBranch, 1024, true); err != nil {
			return Fact{}, fmt.Errorf("repository default branch: %w", err)
		}
		subject = FactSubject{RepositoryID: fact.Repository.Repository.ID}
		event = unknownEventTime()
	}
	if fact.Run != nil {
		payloadCount++
		if fact.Kind != FactRun {
			return Fact{}, errors.New("run payload has a different fact kind")
		}
		if err := validateRunFact(*fact.Run); err != nil {
			return Fact{}, err
		}
		runID := fact.Run.RunID
		subject = FactSubject{RepositoryID: fact.Run.RepositoryID, RunID: &runID}
		event = fact.Run.EventTime
	}
	if fact.Attempt != nil {
		payloadCount++
		if fact.Kind != FactAttempt {
			return Fact{}, errors.New("attempt payload has a different fact kind")
		}
		if err := validateAttemptFact(*fact.Attempt); err != nil {
			return Fact{}, err
		}
		runID, attempt := fact.Attempt.RunID, fact.Attempt.RunAttempt
		subject = FactSubject{RepositoryID: fact.Attempt.RepositoryID, RunID: &runID, RunAttempt: &attempt}
		event = fact.Attempt.EventTime
	}
	if fact.Job != nil {
		payloadCount++
		if fact.Kind != FactJob {
			return Fact{}, errors.New("job payload has a different fact kind")
		}
		if err := validateJobFact(*fact.Job); err != nil {
			return Fact{}, err
		}
		subject = executionSubject(fact.Job.Execution, "")
		event = fact.Job.EventTime
	}
	if fact.ActionOccurrence != nil {
		payloadCount++
		if fact.Kind != FactActionOccurrence {
			return Fact{}, errors.New("Action occurrence payload has a different fact kind")
		}
		observation := fact.ActionOccurrence.Observation
		if err := evidence.ValidateRuntimeObservationIdentity(observation); err != nil {
			return Fact{}, fmt.Errorf("Action occurrence fact: %w", err)
		}
		stepKey := ""
		if observation.Step != nil {
			stepKey = observation.Step.Key()
		}
		subject = executionSubject(observation.Execution, stepKey)
		event = observation.EventTime
		nested = append(nested, observation.SourceEvidenceIDs...)
	}
	if fact.Dependency != nil && fact.Dependency.ContradictsFactIDs != nil {
		payloadCount++
		if fact.Kind != FactDependency {
			return Fact{}, errors.New("dependency payload has a different fact kind")
		}
		if err := validateDependencyFact(*fact.Dependency); err != nil {
			return Fact{}, err
		}
		if fact.Dependency.Execution != nil {
			subject = executionSubject(*fact.Dependency.Execution, fact.Dependency.StepKey)
		} else if fact.Dependency.AttemptExecution != nil {
			attempt := fact.Dependency.AttemptExecution
			runID, runAttempt := attempt.RunID, attempt.RunAttempt
			subject = FactSubject{RepositoryID: attempt.RepositoryID, RunID: &runID, RunAttempt: &runAttempt}
		} else {
			subject = FactSubject{RepositoryID: fact.Dependency.CallerRepositoryID}
		}
		event = fact.Dependency.EventTime
	}
	if fact.Coverage != nil {
		payloadCount++
		if fact.Kind != FactCoverage {
			return Fact{}, errors.New("coverage payload has a different fact kind")
		}
		coverage := fact.Coverage
		if err := evidence.ValidateCoverageUnitIdentity(coverage.Unit); err != nil {
			return Fact{}, fmt.Errorf("coverage unit: %w", err)
		}
		if err := evidence.ValidateCoverageAssessmentIdentity(coverage.Assessment); err != nil {
			return Fact{}, fmt.Errorf("coverage assessment: %w", err)
		}
		if coverage.Assessment.UnitID != coverage.Unit.ID ||
			(coverage.Assessment.Status != model.CoverageCollected && coverage.Assessment.Status != model.CoverageNotApplicable) {
			return Fact{}, errors.New("coverage fact requires a matching terminal non-gap assessment")
		}
		if coverage.Unit.Scope.RepositoryID == nil {
			return Fact{}, errors.New("archived coverage requires repository scope")
		}
		subject = subjectFromCoverageScope(coverage.Unit.Scope)
		event = unknownEventTime()
		nested = append(nested, coverage.Assessment.EvidenceIDs...)
	}
	if fact.CoverageGap != nil {
		payloadCount++
		if fact.Kind != FactCoverageGap {
			return Fact{}, errors.New("coverage-gap payload has a different fact kind")
		}
		gap := fact.CoverageGap
		if err := evidence.ValidateCoverageUnitIdentity(gap.Unit); err != nil {
			return Fact{}, fmt.Errorf("coverage-gap unit: %w", err)
		}
		if err := evidence.ValidateCoverageAssessmentIdentity(gap.Assessment); err != nil {
			return Fact{}, fmt.Errorf("coverage-gap assessment: %w", err)
		}
		if gap.Assessment.UnitID != gap.Unit.ID || gap.Assessment.Status != model.CoverageGap {
			return Fact{}, errors.New("coverage-gap fact requires a matching gap assessment")
		}
		if gap.Unit.Scope.RepositoryID == nil && gap.Unit.Kind != model.CoverageRepositoryVisibility {
			return Fact{}, errors.New("archived coverage gap requires repository scope")
		}
		subject = subjectFromCoverageScope(gap.Unit.Scope)
		event = unknownEventTime()
		nested = append(nested, gap.Assessment.EvidenceIDs...)
	}
	if fact.Exposure != nil {
		payloadCount++
		if fact.Kind != FactExposure {
			return Fact{}, errors.New("exposure payload has a different fact kind")
		}
		var err error
		nested, err = validateExposureFact(*fact.Exposure, allowRetainedLegacyBasis)
		if err != nil {
			return Fact{}, err
		}
		subject = executionSubject(fact.Exposure.Execution, fact.Exposure.StepKey)
		event = fact.Exposure.EventTime
	}
	if payloadCount != 1 || !fact.Kind.Valid() {
		return Fact{}, errors.New("fact must have exactly one payload matching a valid kind")
	}

	fact.Subject = subject
	fact.EventTime = event
	fact.EvidenceIDs = sortEvidenceIDs(append(fact.EvidenceIDs, nested...))
	if err := fact.Subject.Validate(); err != nil {
		return Fact{}, fmt.Errorf("fact subject: %w", err)
	}
	if err := fact.EventTime.Validate(); err != nil {
		return Fact{}, fmt.Errorf("fact event time: %w", err)
	}
	if fact.Kind != FactCoverageGap && len(fact.EvidenceIDs) == 0 {
		return Fact{}, errors.New("archived material fact requires supporting evidence")
	}
	for _, id := range fact.EvidenceIDs {
		if err := id.Validate(); err != nil {
			return Fact{}, fmt.Errorf("fact evidence: %w", err)
		}
	}

	preimage := fact
	preimage.ID = ""
	preimage.EvidenceIDs = []model.EvidenceID{}
	hash, err := evidence.CanonicalSHA256(struct {
		Version string `json:"version"`
		Fact    Fact   `json:"fact"`
	}{Version: "archive-fact/v1", Fact: preimage})
	if err != nil {
		return Fact{}, fmt.Errorf("derive archive fact ID: %w", err)
	}
	expected := "fact1:" + hash
	if fact.ID != "" && fact.ID != expected {
		return Fact{}, errors.New("archive fact ID does not match canonical content")
	}
	fact.ID = expected
	return fact, nil
}

func validateRunFact(fact RunFact) error {
	if err := fact.RepositoryID.Validate(); err != nil {
		return err
	}
	if err := fact.RunID.Validate(); err != nil {
		return err
	}
	if fact.WorkflowPath != nil {
		if err := fact.WorkflowPath.Validate(); err != nil {
			return err
		}
	}
	if err := safeMachineName(fact.EventType, 128); err != nil {
		return fmt.Errorf("run event type: %w", err)
	}
	for label, value := range map[string]string{"status": fact.Status, "conclusion": fact.Conclusion, "trigger ref": fact.TriggerRef} {
		if err := safeText(value, 1024, true); err != nil {
			return fmt.Errorf("run %s: %w", label, err)
		}
	}
	if fact.TriggerObject != nil {
		if err := fact.TriggerObject.Validate(); err != nil {
			return err
		}
	}
	if err := fact.Actor.Validate(); err != nil {
		return err
	}
	return fact.EventTime.Validate()
}

func validateAttemptFact(fact AttemptFact) error {
	if err := fact.RepositoryID.Validate(); err != nil {
		return err
	}
	if err := fact.RunID.Validate(); err != nil {
		return err
	}
	if err := fact.RunAttempt.Validate(); err != nil {
		return err
	}
	for label, value := range map[string]string{"status": fact.Status, "conclusion": fact.Conclusion} {
		if err := safeText(value, 128, true); err != nil {
			return fmt.Errorf("attempt %s: %w", label, err)
		}
	}
	if err := fact.Actor.Validate(); err != nil {
		return err
	}
	if err := fact.TriggeringActor.Validate(); err != nil {
		return err
	}
	return fact.EventTime.Validate()
}

func validateJobFact(fact JobFact) error {
	if err := fact.Execution.Validate(); err != nil {
		return err
	}
	if err := safeText(fact.DisplayName, 4096, false); err != nil {
		return fmt.Errorf("job display name: %w", err)
	}
	for label, value := range map[string]string{"status": fact.Status, "conclusion": fact.Conclusion} {
		if err := safeText(value, 128, true); err != nil {
			return fmt.Errorf("job %s: %w", label, err)
		}
	}
	return fact.EventTime.Validate()
}

func validateDependencyFact(fact DependencyFact) error {
	if !fact.Relation.Valid() || !fact.TargetKind.Valid() || !fact.Basis.Valid() {
		return errors.New("dependency relation, target kind, or definition basis is invalid")
	}
	if err := fact.CallerRepositoryID.Validate(); err != nil {
		return err
	}
	if err := fact.CallerRepository.Validate(); err != nil {
		return err
	}
	if !safeRepositoryPath(fact.CallerPath) {
		return errors.New("dependency caller path is unsafe")
	}
	if err := fact.TargetRepository.Validate(); err != nil {
		return err
	}
	if fact.TargetPath != "" && !safeRepositoryPath(fact.TargetPath) {
		return errors.New("dependency target path is unsafe")
	}
	if err := safeText(fact.DeclaredRef, 1024, true); err != nil {
		return fmt.Errorf("dependency declared ref: %w", err)
	}
	callerIDs := 0
	if fact.CallerWorkflowObjectID != nil {
		callerIDs++
		if err := fact.CallerWorkflowObjectID.Validate(); err != nil {
			return err
		}
	}
	if fact.CallerActionObjectID != nil {
		callerIDs++
		if err := fact.CallerActionObjectID.Validate(); err != nil {
			return err
		}
	}
	if callerIDs != 1 && fact.Basis == DefinitionHistoricalAtRun {
		return errors.New("historical dependency requires exactly one typed caller object ID")
	}
	if fact.Basis == DefinitionRuntimeAttemptMetadata && callerIDs != 0 {
		return errors.New("runtime attempt metadata must not invent a caller object ID")
	}
	if callerIDs > 1 {
		return errors.New("dependency cannot have workflow and Action caller object IDs")
	}
	targetIDs := 0
	if fact.TargetActionObjectID != nil {
		targetIDs++
		if err := fact.TargetActionObjectID.Validate(); err != nil {
			return err
		}
		if fact.TargetKind == DependencyTargetReusableWorkflow {
			return errors.New("reusable-workflow dependency cannot carry an Action object ID")
		}
	}
	if fact.TargetCalledWorkflowObjectID != nil {
		targetIDs++
		if err := fact.TargetCalledWorkflowObjectID.Validate(); err != nil {
			return err
		}
		if fact.TargetKind != DependencyTargetReusableWorkflow {
			return errors.New("called-workflow object ID requires reusable-workflow target")
		}
	}
	if fact.PackageDigest != nil {
		targetIDs++
		if err := fact.PackageDigest.Validate(); err != nil {
			return err
		}
		if fact.TargetKind == DependencyTargetReusableWorkflow {
			return errors.New("reusable workflow cannot carry an Action package digest")
		}
	}
	if targetIDs > 1 {
		return errors.New("dependency has competing exact target identities")
	}
	if fact.Relation == DependencyRefResolvedTo && targetIDs != 1 {
		return errors.New("REF_RESOLVED_TO requires exactly one exact target identity")
	}
	if fact.Basis == DefinitionRuntimeAttemptMetadata {
		if fact.Relation != DependencyWorkflowCalledWorkflow || fact.TargetKind != DependencyTargetReusableWorkflow {
			return errors.New("runtime attempt metadata only supports GitHub-recorded reusable-workflow calls")
		}
		if fact.TargetCalledWorkflowObjectID == nil || targetIDs != 1 {
			return errors.New("runtime attempt metadata requires one exact called-workflow object ID")
		}
		if fact.AttemptExecution == nil || fact.Execution != nil {
			return errors.New("runtime attempt metadata requires an attempt identity without invented job attribution")
		}
		if fact.StepKey != "" {
			return errors.New("attempt-level reusable-workflow metadata cannot carry a step identity")
		}
	}
	if fact.Basis == DefinitionCurrentSnapshot {
		if fact.Execution != nil || fact.AttemptExecution != nil || fact.StepKey != "" {
			return errors.New("current snapshot cannot carry historical run-attempt, job, or step identity")
		}
		if fact.EventTime.Start != nil || fact.EventTime.End != nil || fact.EventTime.Bounds != nil ||
			fact.EventTime.Precision != model.PrecisionUnknown || fact.EventTime.Approximation != model.ApproximationUnknown || fact.EventTime.Basis != model.TimeBasisUnknown {
			return errors.New("current snapshot cannot carry a historical event time")
		}
	}
	if fact.TargetKind == DependencyTargetReusableWorkflow && fact.TargetPath == "" {
		return errors.New("reusable-workflow target requires a path")
	}
	if fact.TargetKind == DependencyTargetLocalAction && fact.TargetRepository != fact.CallerRepository {
		return errors.New("local Action target must remain in the caller repository")
	}
	if fact.TransitiveDepth > maxDependencyDepth {
		return fmt.Errorf("dependency depth exceeds %d", maxDependencyDepth)
	}
	if fact.AttemptExecution != nil {
		if err := fact.AttemptExecution.Validate(); err != nil {
			return err
		}
		if fact.AttemptExecution.RepositoryID != fact.CallerRepositoryID {
			return errors.New("dependency attempt belongs to a different caller repository")
		}
	}
	if fact.Execution != nil {
		if err := fact.Execution.Validate(); err != nil {
			return err
		}
		if fact.Execution.RepositoryID != fact.CallerRepositoryID {
			return errors.New("dependency execution belongs to a different caller repository")
		}
	} else if fact.StepKey != "" {
		return errors.New("dependency step key requires execution identity")
	}
	if fact.AttemptExecution != nil && fact.Execution != nil {
		return errors.New("dependency cannot carry both attempt and job execution identities")
	}
	if err := safeText(fact.StepKey, 1024, true); err != nil {
		return err
	}
	if fact.ContradictsFactIDs == nil {
		return errors.New("dependency contradiction IDs must be an explicit array")
	}
	for index, id := range fact.ContradictsFactIDs {
		if !validPrefixedHash(id, "fact1:") {
			return errors.New("dependency contradiction fact ID is invalid")
		}
		if index > 0 && fact.ContradictsFactIDs[index-1] >= id {
			return errors.New("dependency contradiction fact IDs must be sorted and unique")
		}
	}
	return fact.EventTime.Validate()
}

func validateExposureFact(fact ExposureFact, allowRetainedLegacyBasis bool) ([]model.EvidenceID, error) {
	if err := fact.Execution.Validate(); err != nil {
		return nil, err
	}
	if err := safeText(fact.StepKey, 1024, true); err != nil {
		return nil, err
	}
	if err := fact.EventTime.Validate(); err != nil {
		return nil, err
	}
	kinds := 0
	var evidenceIDs []model.EvidenceID
	if fact.Credential != nil {
		kinds++
		if err := validateCredentialExposure(*fact.Credential, allowRetainedLegacyBasis); err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, fact.Credential.EvidenceIDs...)
	}
	if fact.Resource != nil {
		kinds++
		if err := fact.Resource.Validate(); err != nil {
			return nil, err
		}
		evidenceIDs = append(evidenceIDs, fact.Resource.EvidenceIDs...)
	}
	if fact.Runner != nil {
		kinds++
		if err := validateRunner(*fact.Runner); err != nil {
			return nil, err
		}
	}
	if fact.Environment != nil {
		kinds++
		if err := validateEnvironment(*fact.Environment, fact.EventTime); err != nil {
			return nil, err
		}
	}
	if kinds != 1 {
		return nil, errors.New("exposure fact requires exactly one credential, resource, runner, or environment assertion")
	}
	return evidenceIDs, nil
}

func validateCredentialExposure(credential model.CredentialExposure, allowRetainedLegacyBasis bool) error {
	if credential.Basis.Valid() {
		return credential.Validate()
	}
	if !allowRetainedLegacyBasis {
		return credential.Validate()
	}
	// Empty was legal in the retained v1 model. A nonempty value can represent
	// a basis removed from the current closed vocabulary, but it remains hostile
	// input and must be a small machine name before being preserved verbatim.
	if credential.Basis != "" {
		if err := safeMachineName(string(credential.Basis), 128); err != nil {
			return fmt.Errorf("retained credential-exposure basis: %w", err)
		}
	}
	preserved := credential.Basis
	credential.Basis = model.ExposureBasisStaticInferred
	if err := credential.Validate(); err != nil {
		return err
	}
	credential.Basis = preserved
	return nil
}

func validateRunner(runner RunnerContextFact) error {
	switch runner.Classification {
	case "github-hosted", "self-hosted", "unknown":
	default:
		return errors.New("runner classification is invalid")
	}
	if runner.RunnerID != nil && *runner.RunnerID <= 0 {
		return errors.New("runner ID must be positive")
	}
	if runner.RunnerGroupID != nil && *runner.RunnerGroupID < 0 {
		return errors.New("runner group ID must be nonnegative")
	}
	for _, value := range []string{runner.RunnerName, runner.RunnerGroup} {
		if err := safeText(value, 1024, true); err != nil {
			return err
		}
	}
	if runner.Labels == nil || len(runner.Labels) > 256 {
		return errors.New("runner labels must be an explicit bounded array")
	}
	for index, label := range runner.Labels {
		if err := safeText(label, 256, false); err != nil {
			return err
		}
		if index > 0 && runner.Labels[index-1] >= label {
			return errors.New("runner labels must be sorted and unique")
		}
	}
	return nil
}

func validateEnvironment(environment EnvironmentEligibilityFact, event model.EventInterval) error {
	if err := safeText(environment.EnvironmentName, 1024, false); err != nil {
		return err
	}
	switch environment.GateState {
	case "approved", "bypassed", "crossed", "pending", "rejected", "not-required", "unknown":
	default:
		return errors.New("environment gate state is invalid")
	}
	if environment.JobStarted && (environment.GateState == "pending" || environment.GateState == "rejected") {
		return errors.New("a pending or rejected environment job cannot be recorded as started")
	}
	if environment.SecretNames == nil || len(environment.SecretNames) > 10_000 {
		return errors.New("environment secret names must be an explicit bounded array")
	}
	for index, name := range environment.SecretNames {
		if err := name.Validate(); err != nil {
			return err
		}
		if index > 0 && environment.SecretNames[index-1] >= name {
			return errors.New("environment secret names must be sorted and unique")
		}
	}
	if len(environment.SecretNames) > 0 && !environment.GateRequirementSatisfiedAt(event) {
		return errors.New("environment secrets cannot be eligible before the job starts and the retained gate requirement is satisfied, bypassed, or not required")
	}
	return nil
}

func executionSubject(execution model.JobExecutionIdentity, stepKey string) FactSubject {
	runID, attempt, jobID := execution.RunID, execution.RunAttempt, execution.JobID
	return FactSubject{RepositoryID: execution.RepositoryID, RunID: &runID, RunAttempt: &attempt, JobID: &jobID, StepKey: stepKey}
}

func subjectFromCoverageScope(scope model.CoverageScope) FactSubject {
	subject := FactSubject{
		RunID:      scope.RunID,
		RunAttempt: scope.RunAttempt,
		JobID:      scope.JobID,
		StepKey:    scope.StepKey,
	}
	if scope.RepositoryID != nil {
		subject.RepositoryID = *scope.RepositoryID
	}
	return subject
}

func unknownEventTime() model.EventInterval {
	return model.EventInterval{
		Precision:     model.PrecisionUnknown,
		Approximation: model.ApproximationUnknown,
		Basis:         model.TimeBasisUnknown,
	}
}

func safeRepositoryPath(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.Contains(value, `\`) && !strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && !strings.HasPrefix(value, "../")
}

func normalizeFactSlices(fact *Fact) {
	if fact.Dependency != nil {
		fact.Dependency.ContradictsFactIDs = append(make([]string, 0, len(fact.Dependency.ContradictsFactIDs)), fact.Dependency.ContradictsFactIDs...)
		sort.Strings(fact.Dependency.ContradictsFactIDs)
	}
	if fact.Exposure != nil && fact.Exposure.Runner != nil && fact.Exposure.Runner.Labels != nil {
		fact.Exposure.Runner.Labels = append(make([]string, 0, len(fact.Exposure.Runner.Labels)), fact.Exposure.Runner.Labels...)
		sort.Strings(fact.Exposure.Runner.Labels)
	}
	if fact.Exposure != nil && fact.Exposure.Environment != nil && fact.Exposure.Environment.SecretNames != nil {
		fact.Exposure.Environment.SecretNames = append(make([]model.SecretName, 0, len(fact.Exposure.Environment.SecretNames)), fact.Exposure.Environment.SecretNames...)
		sort.Slice(fact.Exposure.Environment.SecretNames, func(i, j int) bool {
			return fact.Exposure.Environment.SecretNames[i] < fact.Exposure.Environment.SecretNames[j]
		})
	}
}
