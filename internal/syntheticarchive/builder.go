// Package syntheticarchive builds deterministic compact archive snapshots from
// declarative synthetic scenarios. The embedded demo and review-packet
// fixtures share it so that fixture evidence never diverges from the
// production normalization path. Nothing here reads a network, executes
// content, or consults the current state of any real repository; every
// identity is supplied by the caller and every timestamp is explicit.
package syntheticarchive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

// Options fix the consumer repository, collection session, and fixture
// versioning of one snapshot. Defaults reproduce the embedded demo contract.
type Options struct {
	RepositoryID     model.RepositoryID
	Repository       string
	SessionID        model.CollectionSessionID
	When             time.Time
	ExtractorVersion string
	RedactionPolicy  string
	WatchHorizonDays uint64
}

// Builder accumulates evidence envelopes and normalized facts in insertion
// order. Facts with an already-present identity are ignored, matching the
// demo's idempotent composition.
type Builder struct {
	repositoryID     model.RepositoryID
	repository       model.RepositorySlug
	session          archive.CollectionSession
	evidence         []evidence.Envelope
	facts            []archive.Fact
	nextReq          int
	when             model.Instant
	createdAt        model.Instant
	extractorVersion string
	redactionPolicy  string
}

// New validates the options and starts an empty snapshot.
func New(options Options) (*Builder, error) {
	if options.RepositoryID <= 0 {
		return nil, errors.New("synthetic archive requires a positive repository ID")
	}
	repository, err := model.NewRepositorySlug(options.Repository)
	if err != nil {
		return nil, fmt.Errorf("synthetic archive repository: %w", err)
	}
	if options.SessionID == "" {
		return nil, errors.New("synthetic archive requires a collection session ID")
	}
	if options.When.IsZero() {
		return nil, errors.New("synthetic archive requires an explicit instant")
	}
	extractorVersion := options.ExtractorVersion
	if extractorVersion == "" {
		extractorVersion = "v2"
	}
	redactionPolicy := options.RedactionPolicy
	if redactionPolicy == "" {
		redactionPolicy = "synthetic-v2"
	}
	horizon := options.WatchHorizonDays
	if horizon == 0 {
		horizon = 65
	}
	when := model.MustInstant(options.When.UTC())
	return &Builder{
		repositoryID: options.RepositoryID,
		repository:   repository,
		session: archive.CollectionSession{
			ID: options.SessionID, Mode: "fixture", AuthKind: "none", StartedAt: when, EndedAt: when,
			Scope:  archive.CollectionScope{Repositories: []model.RepositoryID{options.RepositoryID}},
			Limits: map[string]uint64{"raw_log_bytes": 0, "watch_horizon_days": horizon},
		},
		when:             when,
		createdAt:        when,
		extractorVersion: extractorVersion,
		redactionPolicy:  redactionPolicy,
	}, nil
}

// SetWhen changes the instant stamped on subsequently added evidence and
// facts, which lets a scenario place runs before, inside, and after a window.
func (b *Builder) SetWhen(when time.Time) error {
	if when.IsZero() {
		return errors.New("synthetic archive instant must not be zero")
	}
	b.when = model.MustInstant(when.UTC())
	return nil
}

// When is the instant stamped on the next added evidence and facts.
func (b *Builder) When() model.Instant { return b.when }

// RepositoryID is the consumer repository identity.
func (b *Builder) RepositoryID() model.RepositoryID { return b.repositoryID }

// Repository is the consumer repository slug.
func (b *Builder) Repository() model.RepositorySlug { return b.repository }

// Execution names one job execution in the consumer repository.
func (b *Builder) Execution(run int64, attempt uint32, job int64) model.JobExecutionIdentity {
	return model.JobExecutionIdentity{RepositoryID: b.repositoryID, RunID: model.WorkflowRunID(run), RunAttempt: model.RunAttempt(attempt), JobID: model.JobID(job)}
}

// AddRepository records the consumer repository fact.
func (b *Builder) AddRepository(ctx context.Context, visibility, defaultBranch string) error {
	evidenceID, err := b.source(ctx, "repository", model.CoverageScope{RepositoryID: ptr(b.repositoryID)}, fmt.Sprintf(`{"repository":%q}`, string(b.repository)))
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{evidenceID}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: b.repositoryID, Name: b.repository}, Visibility: visibility, DefaultBranch: defaultBranch}})
}

// AddExecution records a run, its attempt, and one job with one shared
// evidence envelope.
func (b *Builder) AddExecution(ctx context.Context, run int64, attempt uint32, job int64, eventType, workflow, name, status, conclusion string) error {
	runID, attemptID, jobID := model.WorkflowRunID(run), model.RunAttempt(attempt), model.JobID(job)
	workflowPath, err := model.NewWorkflowPath(workflow)
	if err != nil {
		return err
	}
	scope := model.CoverageScope{RepositoryID: ptr(b.repositoryID), RunID: &runID, RunAttempt: &attemptID, JobID: &jobID}
	evidenceID, err := b.source(ctx, fmt.Sprintf("run-%d-attempt-%d-job-%d", run, attempt, job), scope, fmt.Sprintf(`{"run":%d,"attempt":%d,"job":%d}`, run, attempt, job))
	if err != nil {
		return err
	}
	event := InstantEvent(b.when)
	for _, fact := range []archive.Fact{
		{Kind: archive.FactRun, EvidenceIDs: []model.EvidenceID{evidenceID}, Run: &archive.RunFact{RepositoryID: b.repositoryID, RunID: runID, WorkflowPath: &workflowPath, EventType: eventType, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{evidenceID}, Attempt: &archive.AttemptFact{RepositoryID: b.repositoryID, RunID: runID, RunAttempt: attemptID, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{evidenceID}, Job: &archive.JobFact{Execution: model.JobExecutionIdentity{RepositoryID: b.repositoryID, RunID: runID, RunAttempt: attemptID, JobID: jobID}, DisplayName: name, Status: status, Conclusion: conclusion, EventTime: event}},
	} {
		if err := b.add(fact); err != nil {
			return err
		}
	}
	return nil
}

// AddAttemptJob records an additional attempt and job of an existing run
// without emitting another run fact.
func (b *Builder) AddAttemptJob(ctx context.Context, run int64, attempt uint32, job int64, name, status, conclusion string) error {
	runID, attemptID, jobID := model.WorkflowRunID(run), model.RunAttempt(attempt), model.JobID(job)
	scope := model.CoverageScope{RepositoryID: ptr(b.repositoryID), RunID: &runID, RunAttempt: &attemptID, JobID: &jobID}
	evidenceID, err := b.source(ctx, fmt.Sprintf("run-%d-attempt-%d-job-%d", run, attempt, job), scope, fmt.Sprintf(`{"run":%d,"attempt":%d,"job":%d}`, run, attempt, job))
	if err != nil {
		return err
	}
	event := InstantEvent(b.when)
	for _, fact := range []archive.Fact{
		{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{evidenceID}, Attempt: &archive.AttemptFact{RepositoryID: b.repositoryID, RunID: runID, RunAttempt: attemptID, Status: status, Conclusion: conclusion, EventTime: event}},
		{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{evidenceID}, Job: &archive.JobFact{Execution: model.JobExecutionIdentity{RepositoryID: b.repositoryID, RunID: runID, RunAttempt: attemptID, JobID: jobID}, DisplayName: name, Status: status, Conclusion: conclusion, EventTime: event}},
	} {
		if err := b.add(fact); err != nil {
			return err
		}
	}
	return nil
}

// AddRuntime records a runner-log observation of an Action for one job: a
// completed preparation (download) or a lifecycle start on a step.
func (b *Builder) AddRuntime(ctx context.Context, execution model.JobExecutionIdentity, stepNumber int32, kind model.RuntimeObservationKind, actionRepository model.RepositorySlug, oid model.ActionSourceObjectID, declaredRef, subpath string) error {
	return b.AddRuntimeWithDigest(ctx, execution, stepNumber, kind, actionRepository, oid, declaredRef, subpath, nil)
}

// AddRuntimeWithDigest records a runtime observation that also carries the
// package digest the runner reported for the resolved action, so fixtures can
// prove that a digest matches only inside its own namespace.
func (b *Builder) AddRuntimeWithDigest(ctx context.Context, execution model.JobExecutionIdentity, stepNumber int32, kind model.RuntimeObservationKind, actionRepository model.RepositorySlug, oid model.ActionSourceObjectID, declaredRef, subpath string, digest *model.PackageDigest) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "runtime-"+execution.String()+"-"+string(kind), scope, `{"synthetic":"runner-control"}`)
	if err != nil {
		return err
	}
	observation := model.RuntimeActionObservation{Kind: kind, Execution: execution, ActionRepository: actionRepository, ActionSubpath: subpath, DeclaredRef: declaredRef, SourceObjectID: &oid, PackageDigest: digest, EventTime: InstantEvent(b.when), SourceEvidenceIDs: []model.EvidenceID{evidenceID}, SourceSpan: model.SourceSpan{ByteStart: 0, ByteEnd: 32, LineStart: 1, LineEnd: 1}, ExtractorName: "synthetic-runner-log", ExtractorVersion: logparse.GrammarVersion, RulesetSHA256: strings.Repeat("e", 64)}
	if stepNumber > 0 {
		number := model.APIStepNumber(stepNumber)
		observation.Step = &model.StepIdentity{Job: execution, APIStepNumber: &number, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	}
	observation.ID, err = evidence.NewRuntimeObservationID(observation)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: observation}})
}

// RuntimeFactID returns the identity of the most recent runtime fact for a
// job step, for contradiction links.
func (b *Builder) RuntimeFactID(execution model.JobExecutionIdentity, stepNumber model.APIStepNumber) (string, error) {
	for index := len(b.facts) - 1; index >= 0; index-- {
		fact := b.facts[index]
		if fact.ActionOccurrence == nil || fact.ActionOccurrence.Observation.Execution != execution || fact.ActionOccurrence.Observation.Step == nil {
			continue
		}
		step := fact.ActionOccurrence.Observation.Step
		if step.APIStepNumber != nil && *step.APIStepNumber == stepNumber {
			return fact.ID, nil
		}
	}
	return "", fmt.Errorf("runtime fact for %s step %d is absent", execution, stepNumber)
}

// AddDependency records a historical, current, or runtime dependency edge.
func (b *Builder) AddDependency(ctx context.Context, dependency archive.DependencyFact) error {
	scope := model.CoverageScope{RepositoryID: ptr(dependency.CallerRepositoryID)}
	if dependency.Execution != nil {
		scope.RunID, scope.RunAttempt, scope.JobID = ptr(dependency.Execution.RunID), ptr(dependency.Execution.RunAttempt), ptr(dependency.Execution.JobID)
	}
	evidenceID, err := b.source(ctx, "dependency-"+dependency.CallerPath+"-"+dependency.DeclaredRef+fmt.Sprint(b.nextReq), scope, `{"synthetic":"historical-definition"}`)
	if err != nil {
		return err
	}
	fact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{evidenceID}, Dependency: &dependency})
	if err != nil {
		return err
	}
	b.facts = append(b.facts, fact)
	return nil
}

// AddMissingLog records a material retention gap for one job's log.
func (b *Builder) AddMissingLog(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "missing-log-"+execution.String(), scope, `{"status":404,"classification":"retention_or_deletion"}`)
	if err != nil {
		return err
	}
	unit := model.CoverageUnit{Kind: model.CoverageJobLog, Scope: scope, LogicalKey: "job-log:" + execution.String(), RequiredForNegative: true}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{UnitID: unit.ID, Status: model.CoverageGap, ExpectedCount: &one, Gap: &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: true, SanitizedMessage: "synthetic retained log is unavailable"}, EvidenceIDs: []model.EvidenceID{evidenceID}}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactCoverageGap, EvidenceIDs: []model.EvidenceID{evidenceID}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}})
}

// AddClosedCoverage records complete job-log and parser-grammar coverage for
// one job, the basis a negative conclusion requires.
func (b *Builder) AddClosedCoverage(ctx context.Context, execution model.JobExecutionIdentity) error {
	for _, kind := range []model.CoverageKind{model.CoverageJobLog, model.CoverageParserGrammar} {
		if err := b.addClosedCoverageKind(ctx, execution, kind); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) addClosedCoverageKind(ctx context.Context, execution model.JobExecutionIdentity, kind model.CoverageKind) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "closed-"+strings.ToLower(string(kind))+"-"+execution.String(), scope, `{"status":200,"complete":true,"synthetic":true}`)
	if err != nil {
		return err
	}
	unit := model.CoverageUnit{Kind: kind, Scope: scope, LogicalKey: strings.ToLower(string(kind)) + ":" + execution.String(), RequiredForNegative: true}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{UnitID: unit.ID, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1, EvidenceIDs: []model.EvidenceID{evidenceID}}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	return b.add(archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: []model.EvidenceID{evidenceID}, Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}})
}

// AddExposures records the fixed synthetic credential, runner, and resource
// context for one job: a write-capable token permission, an OIDC permission,
// a named fake secret passed to step 2, a self-hosted runner, and a
// deployment observed afterwards without causation.
func (b *Builder) AddExposures(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "exposure-"+execution.String(), scope, `{"synthetic":"credential-and-runner-context"}`)
	if err != nil {
		return err
	}
	secret, _ := model.NewSecretName("FAKE_DEPLOY_KEY")
	stepNumber := model.APIStepNumber(2)
	affectedStep := model.StepIdentity{Job: execution, APIStepNumber: &stepNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}.Key()
	exposures := []archive.ExposureFact{
		{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "contents", Access: "write", Conclusion: "The affected lifecycle could use the runtime-observed contents: write permission; no repository write was proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: InstantEvent(b.when)},
		{Execution: execution, Credential: &model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: "id-token", Access: "write", Conclusion: "The affected lifecycle had the runtime-observed id-token: write permission; this typed permission supports only the bounded OIDC capability inference.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: InstantEvent(b.when)},
		{Execution: execution, StepKey: affectedStep, Credential: &model.CredentialExposure{Kind: model.ExposureSecretPassedToStep, Basis: model.ExposureBasisHistoricalDefinitionFlow, SecretName: &secret, Conclusion: "The historical definition passed the fake named secret to the affected step; no value, read, or exfiltration was proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: InstantEvent(b.when)},
		{Execution: execution, Runner: &archive.RunnerContextFact{Classification: "self-hosted", RunnerName: "synthetic-runner", RunnerGroup: "fixture", Labels: []string{"linux", "self-hosted"}}, EventTime: InstantEvent(b.when)},
		{Execution: execution, Resource: &model.ResourceExposure{Kind: model.ResourceDeployment, ResourceID: "synthetic-deployment", Correlation: model.CorrelationObservedAfter, Conclusion: "A synthetic deployment was observed after the affected step; causation was not proven.", EvidenceIDs: []model.EvidenceID{evidenceID}}, EventTime: InstantEvent(b.when)},
	}
	for _, exposureFact := range exposures {
		if err := b.add(archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID}, Exposure: &exposureFact}); err != nil {
			return err
		}
	}
	return nil
}

// AddPendingEnvironment records an environment gate that was never crossed.
func (b *Builder) AddPendingEnvironment(ctx context.Context, execution model.JobExecutionIdentity) error {
	scope := model.CoverageScope{RepositoryID: ptr(execution.RepositoryID), RunID: ptr(execution.RunID), RunAttempt: ptr(execution.RunAttempt), JobID: ptr(execution.JobID)}
	evidenceID, err := b.source(ctx, "environment-"+execution.String(), scope, `{"synthetic":"pending-environment-gate"}`)
	if err != nil {
		return err
	}
	exposure := archive.ExposureFact{
		Execution: execution,
		Environment: &archive.EnvironmentEligibilityFact{
			EnvironmentName: "production-fixture",
			GateState:       "pending",
			JobStarted:      false,
			SecretNames:     []model.SecretName{},
		},
		EventTime: InstantEvent(b.when),
	}
	return b.add(archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID}, Exposure: &exposure})
}

// DefaultCapabilities is the structured-only capability set of synthetic
// snapshots: definitions and logs are retained as structured facts, raw log
// bytes are discarded.
func DefaultCapabilities() []archive.Capability {
	return []archive.Capability{
		{Name: "action_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "synthetic-v2", Details: map[string]string{}},
		{Name: "attempt_logs", Status: archive.CapabilityStructuredOnly, ExtractorVersion: logparse.GrammarVersion, Details: map[string]string{"raw": "discarded"}},
		{Name: "workflow_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "synthetic-v2", Details: map[string]string{}},
	}
}

// Snapshot assembles and normalizes the accumulated evidence and facts.
func (b *Builder) Snapshot(archiveID string, capabilities []archive.Capability) (archive.Snapshot, error) {
	metadata := archive.SnapshotMetadata{SchemaVersion: archive.SnapshotSchemaVersion, StoreSchemaVersion: store.SchemaVersion, ArchiveID: archiveID, CreatedAt: b.createdAt}
	snapshot := archive.Snapshot{Metadata: metadata, Collections: []archive.CollectionSession{b.session}, Payloads: []archive.Payload{}, Evidence: append([]evidence.Envelope(nil), b.evidence...), Facts: append([]archive.Fact(nil), b.facts...), Capabilities: capabilities, Checkpoints: []archive.Checkpoint{}}
	return archive.NormalizeSnapshot(snapshot)
}

func (b *Builder) source(ctx context.Context, name string, scope model.CoverageScope, content string) (model.EvidenceID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.nextReq++
	envelope, err := evidence.NewEnvelope(evidence.EnvelopeInput{
		Kind: evidence.SourceOtherBounded, CanonicalSourceID: "synthetic/" + name, Provider: evidence.ProviderCIRewind,
		RequestParameters: evidence.RequestParameters{}, Scope: scope, EventTime: InstantEvent(b.when), MediaType: "application/json",
		SourceBytes: []byte(content), Complete: true,
		Extractor:         evidence.ExtractorDescriptor{Name: "synthetic-fixture", Version: b.extractorVersion, RulesetSHA256: strings.Repeat("e", 64)},
		Redaction:         evidence.RedactionDescriptor{Status: evidence.RedactionStructuredAllowlist, PolicyVersion: b.redactionPolicy},
		CollectionSession: b.session.ID, RequestID: model.RequestID(fmt.Sprintf("request:synthetic:%04d", b.nextReq)),
		CollectionTime: model.CollectionWindow{StartedAt: b.when, EndedAt: b.when},
	})
	if err != nil {
		return "", err
	}
	b.evidence = append(b.evidence, envelope)
	return envelope.Evidence.ID, nil
}

func (b *Builder) add(fact archive.Fact) error {
	normalized, err := archive.NormalizeFact(fact)
	if err != nil {
		return err
	}
	for _, existing := range b.facts {
		if existing.ID == normalized.ID {
			return nil
		}
	}
	b.facts = append(b.facts, normalized)
	return nil
}

// InstantEvent is an exact second-precision log-timestamp interval.
func InstantEvent(instant model.Instant) model.EventInterval {
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
}

// UnknownEvent is an interval with no known time, used for current-state
// snapshots that carry no historical instant.
func UnknownEvent() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}

// MustRepository parses an owner/name slug or panics; fixtures are constants.
func MustRepository(value string) model.RepositorySlug {
	result, err := model.NewRepositorySlug(value)
	if err != nil {
		panic(err)
	}
	return result
}

// MustWorkflowPath parses a workflow path or panics.
func MustWorkflowPath(value string) model.WorkflowPath {
	result, err := model.NewWorkflowPath(value)
	if err != nil {
		panic(err)
	}
	return result
}

// MustActionOID builds an Action source object identity from a full SHA-1.
func MustActionOID(value string) model.ActionSourceObjectID {
	git, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		panic(err)
	}
	result, err := model.NewActionSourceObjectID(git)
	if err != nil {
		panic(err)
	}
	return result
}

// MustCallerOID builds a caller workflow object identity from a full SHA-1.
func MustCallerOID(value string) model.CallerWorkflowObjectID {
	git, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		panic(err)
	}
	result, err := model.NewCallerWorkflowObjectID(git)
	if err != nil {
		panic(err)
	}
	return result
}

// MustCalledOID builds a called workflow object identity from a full SHA-1.
func MustCalledOID(value string) model.CalledWorkflowObjectID {
	git, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		panic(err)
	}
	result, err := model.NewCalledWorkflowObjectID(git)
	if err != nil {
		panic(err)
	}
	return result
}

func ptr[T any](value T) *T { return &value }
