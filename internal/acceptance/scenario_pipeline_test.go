package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/store"
	"github.com/torjan0/cirewind/internal/workflow"
)

var acceptanceTime = time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)

type fixtureExecution struct {
	RunID      int64
	RunAttempt int
	JobID      int64
}

func (e fixtureExecution) key() string { return executionKey(e.RunID, e.RunAttempt, e.JobID) }

func (e fixtureExecution) model(repositoryID int64) model.JobExecutionIdentity {
	return model.JobExecutionIdentity{
		RepositoryID: model.RepositoryID(repositoryID), RunID: model.WorkflowRunID(e.RunID),
		RunAttempt: model.RunAttempt(e.RunAttempt), JobID: model.JobID(e.JobID),
	}
}

type scenarioPipelineResult struct {
	Case                analyze.Result
	RuntimeObservations []model.RuntimeActionObservation
}

type snapshotBuilder struct {
	t              testing.TB
	inventory      fixtureInventory
	item           scenario
	metadata       normalizedMetadata
	session        archive.CollectionSession
	when           model.Instant
	evidence       []evidence.Envelope
	facts          []archive.Fact
	factIndex      map[string]int
	requestCounter int
	logEvidence    map[string]model.EvidenceID
	parsed         []parsedLog
}

func TestScenariosRunThroughEvidenceAnalyzer(t *testing.T) {
	inventory, metadata := loadInventory(t)
	pack := acceptanceIncidentPack(t, inventory)
	parsed := parseInventoryLogs(t, inventory)

	items := append(append([]scenario(nil), inventory.Scenarios...), inventory.Supplemental...)
	seenPrimary := make(map[string]bool)
	for _, item := range items {
		item := item
		t.Run(item.ID, func(t *testing.T) {
			result := runScenarioPipeline(t, inventory, metadata, parsed, pack, item)
			assertScenarioFindings(t, item, result)
			if len(item.ExpectedFindings) > 0 {
				seenPrimary[item.ID] = true
			}
		})
	}
	for _, item := range inventory.Scenarios {
		if len(item.ExpectedFindings) > 0 && !seenPrimary[item.ID] {
			t.Errorf("primary scenario %s did not execute an analyzer oracle", item.ID)
		}
	}
}

func runScenarioPipeline(t testing.TB, inventory fixtureInventory, metadata normalizedMetadata, allLogs []parsedLog, pack *incident.ValidatedPack, item scenario) scenarioPipelineResult {
	t.Helper()
	now := model.MustInstant(acceptanceTime)
	builder := &snapshotBuilder{
		t: t, inventory: inventory, item: item, metadata: metadata, when: now,
		session: archive.CollectionSession{
			ID: model.CollectionSessionID("collection:fixture-acceptance:" + strings.ToLower(item.ID)), Mode: "fixture", AuthKind: "none",
			StartedAt: now, EndedAt: now,
			Scope:  archive.CollectionScope{Repositories: []model.RepositoryID{model.RepositoryID(inventory.Repository.ID)}},
			Limits: map[string]uint64{"raw_log_bytes": 0},
		},
		factIndex:   make(map[string]int),
		logEvidence: make(map[string]model.EvidenceID),
	}
	executions := parseExecutionKeys(t, item.ExecutionKeys)
	keys := make(map[string]bool, len(executions))
	for _, execution := range executions {
		keys[execution.key()] = true
	}
	for _, value := range allLogs {
		if keys[executionKey(value.Entry.Scope.RunID, value.Entry.Scope.RunAttempt, value.Entry.Scope.JobID)] {
			builder.parsed = append(builder.parsed, value)
		}
	}
	builder.addLogEvidence()
	builder.addExecutionFacts(executions)
	builder.addRuntimeFacts(executions)
	builder.addReferencedWorkflowFacts()
	if item.ContradictionPreservesBoth && item.DeclaredSHA != "" && item.RuntimeSHA != "" {
		builder.addContradictionFacts(executions)
	}
	builder.addCoverageFacts(executions)

	archiveHash := sha256.Sum256([]byte("fixture-archive:" + item.ID))
	snapshot, err := archive.NormalizeSnapshot(archive.Snapshot{
		Metadata: archive.SnapshotMetadata{
			SchemaVersion: archive.SnapshotSchemaVersion, StoreSchemaVersion: store.SchemaVersion,
			ArchiveID: "arc1:" + hex.EncodeToString(archiveHash[:]), CreatedAt: now,
		},
		Collections: []archive.CollectionSession{builder.session}, Payloads: []archive.Payload{},
		Evidence: builder.evidence, Facts: builder.facts,
		Capabilities: []archive.Capability{
			{Name: "action_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "fixture-v1", Details: map[string]string{}},
			{Name: "attempt_logs", Status: archive.CapabilityStructuredOnly, ExtractorVersion: logparse.GrammarVersion, Details: map[string]string{"raw": "discarded"}},
			{Name: "job_logs", Status: archive.CapabilityStructuredOnly, ExtractorVersion: logparse.GrammarVersion, Details: map[string]string{"raw": "discarded"}},
			{Name: "repository_visibility", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "fixture-v1", Details: map[string]string{}},
			{Name: "workflow_definitions", Status: archive.CapabilityStructuredOnly, ExtractorVersion: "fixture-v1", Details: map[string]string{}},
		},
		Checkpoints: []archive.Checkpoint{},
	})
	if err != nil {
		t.Fatalf("normalize scenario %s snapshot: %v", item.ID, err)
	}
	result, err := analyze.Derive(snapshot, pack, acceptanceTime.Add(time.Hour), analyze.ModeReplay)
	if err != nil {
		t.Fatalf("analyze scenario %s: %v", item.ID, err)
	}
	runtimeObservations := make([]model.RuntimeActionObservation, 0)
	for _, fact := range snapshot.Facts {
		if fact.ActionOccurrence != nil {
			runtimeObservations = append(runtimeObservations, fact.ActionOccurrence.Observation)
		}
	}
	return scenarioPipelineResult{Case: result, RuntimeObservations: runtimeObservations}
}

func (b *snapshotBuilder) addLogEvidence() {
	for _, value := range b.parsed {
		scope := scopeFor(value.Entry.Scope, b.inventory.Repository.ID)
		event := unknownEvent()
		for _, observation := range value.Result.Observations {
			if observation.EventTime != nil {
				event = instantEvent(*observation.EventTime, model.TimeBasisLogTimestamp)
				break
			}
		}
		kind := evidence.SourceJobLog
		b.logEvidence[value.Entry.Path] = b.addEnvelope("log/"+value.Entry.Path, kind, scope, event, value.Bytes)
	}
}

func (b *snapshotBuilder) addExecutionFacts(executions []fixtureExecution) {
	repository, err := model.NewRepositorySlug(b.inventory.Repository.NameWithOwner)
	if err != nil {
		b.t.Fatal(err)
	}
	repositoryEvidence := b.addEnvelope("repository/"+b.item.ID, evidence.SourceAPIJSON,
		model.CoverageScope{RepositoryID: ptrModel(model.RepositoryID(b.inventory.Repository.ID))}, unknownEvent(),
		[]byte(fmt.Sprintf(`{"repositoryId":%d,"nameWithOwner":%q}`, b.inventory.Repository.ID, b.inventory.Repository.NameWithOwner)))
	b.addFact(archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{repositoryEvidence}, Repository: &archive.RepositoryFact{
		Repository: model.RepositorySubject{ID: model.RepositoryID(b.inventory.Repository.ID), Name: repository}, Visibility: "public", DefaultBranch: "main",
	}})

	for _, execution := range executions {
		identity := execution.model(b.inventory.Repository.ID)
		scope := scopeFor(logScope{RunID: execution.RunID, RunAttempt: execution.RunAttempt, JobID: execution.JobID}, b.inventory.Repository.ID)
		metadataBytes, _ := json.Marshal(struct {
			Scenario     string `json:"scenario"`
			ExecutionKey string `json:"executionKey"`
		}{b.item.ID, execution.key()})
		support := b.addEnvelope("execution/"+b.item.ID+"/"+execution.key(), evidence.SourceAPIJSON, scope, unknownEvent(), metadataBytes)
		event := b.executionEvent(execution)
		var workflowPath *model.WorkflowPath
		if b.item.Workflow != "" {
			value, pathErr := model.NewWorkflowPath(".github/workflows/" + filepathBase(b.item.Workflow))
			if pathErr != nil {
				b.t.Fatal(pathErr)
			}
			workflowPath = &value
		}
		eventType := b.item.Event
		if eventType == "" {
			eventType = "workflow_dispatch"
		}
		jobStatus, jobConclusion := "completed", "success"
		if value, ok := b.item.JobConclusionByAttempt[strconv.Itoa(execution.RunAttempt)]; ok {
			jobConclusion = value
		}
		for _, missing := range b.metadata.JobsWithoutLogs {
			if missing.Scenario == b.item.ID && missing.RunID == execution.RunID && missing.RunAttempt == execution.RunAttempt && missing.JobID == execution.JobID {
				jobStatus = missing.Status
				if missing.Conclusion == nil {
					jobConclusion = ""
				} else {
					jobConclusion = *missing.Conclusion
				}
			}
		}
		b.addFact(archive.Fact{Kind: archive.FactRun, EvidenceIDs: []model.EvidenceID{support}, Run: &archive.RunFact{
			RepositoryID: identity.RepositoryID, RunID: identity.RunID, WorkflowPath: workflowPath, EventType: eventType,
			Status: "completed", Conclusion: "success", EventTime: event,
		}})
		b.addFact(archive.Fact{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{support}, Attempt: &archive.AttemptFact{
			RepositoryID: identity.RepositoryID, RunID: identity.RunID, RunAttempt: identity.RunAttempt,
			Status: "completed", Conclusion: jobConclusion, EventTime: event,
		}})
		b.addFact(archive.Fact{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{support}, Job: &archive.JobFact{
			Execution: identity, DisplayName: "fixture-" + strings.ToLower(b.item.ID) + "-" + strconv.FormatInt(execution.JobID, 10),
			Status: jobStatus, Conclusion: jobConclusion, EventTime: event,
		}})
	}
}

type runtimeBinding struct {
	Action      logparse.Action
	Setup       parsedLog
	Preparation *logparse.Observation
	Lifecycle   *logparse.Observation
	StepLog     *parsedLog
}

func (b *snapshotBuilder) addRuntimeFacts(executions []fixtureExecution) {
	for _, execution := range executions {
		bindings := make(map[string][]runtimeBinding)
		var stepLogs []parsedLog
		for _, value := range b.parsed {
			if executionKey(value.Entry.Scope.RunID, value.Entry.Scope.RunAttempt, value.Entry.Scope.JobID) != execution.key() {
				continue
			}
			if value.Entry.Role == string(logparse.RoleActionStep) {
				stepLogs = append(stepLogs, value)
			}
			for index := range value.Result.Observations {
				observation := &value.Result.Observations[index]
				if observation.Kind != logparse.ObservationResolution || observation.Action == nil {
					continue
				}
				binding := runtimeBinding{Action: *observation.Action, Setup: value}
				for prepIndex := range value.Result.Observations {
					candidate := &value.Result.Observations[prepIndex]
					if candidate.Kind == logparse.ObservationPreparationComplete && candidate.Action != nil && actionKey(*candidate.Action) == actionKey(binding.Action) {
						binding.Preparation = candidate
					}
				}
				bindings[actionKey(binding.Action)] = append(bindings[actionKey(binding.Action)], binding)
			}
		}
		for key, values := range bindings {
			binding, ok := uniqueRuntimeBinding(values)
			if !ok {
				continue
			}
			for stepIndex := range stepLogs {
				stepLog := &stepLogs[stepIndex]
				for observationIndex := range stepLog.Result.Observations {
					observation := &stepLog.Result.Observations[observationIndex]
					if observation.Kind == logparse.ObservationLifecycleStarted && observation.Action != nil && actionKey(*observation.Action) == key {
						binding.Lifecycle, binding.StepLog = observation, stepLog
					}
				}
			}
			if binding.Lifecycle == nil && binding.Preparation == nil {
				continue
			}
			observation := b.runtimeObservation(execution, binding)
			b.addFact(archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: observation.SourceEvidenceIDs, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: observation}})
		}
	}
}

func uniqueRuntimeBinding(values []runtimeBinding) (runtimeBinding, bool) {
	if len(values) == 0 {
		return runtimeBinding{}, false
	}
	identities := make(map[string]runtimeBinding)
	for _, value := range values {
		identity := value.Action.Source.Algorithm + ":" + value.Action.Source.Value + ":" + value.Action.Digest.Algorithm + ":" + value.Action.Digest.Value
		identities[identity] = value
	}
	if len(identities) != 1 {
		return runtimeBinding{}, false
	}
	for _, value := range identities {
		return value, true
	}
	return runtimeBinding{}, false
}

func (b *snapshotBuilder) runtimeObservation(execution fixtureExecution, binding runtimeBinding) model.RuntimeActionObservation {
	repository, err := model.NewRepositorySlug(strings.ToLower(binding.Action.Owner + "/" + binding.Action.Repository))
	if err != nil {
		b.t.Fatal(err)
	}
	kind := model.ObservationPreparationComplete
	var eventTime *time.Time
	lineStart, lineEnd := 0, 0
	if binding.Preparation != nil {
		eventTime = binding.Preparation.EventTime
		lineStart, lineEnd = binding.Preparation.LineStart, binding.Preparation.LineEnd
	}
	evidenceIDs := []model.EvidenceID{b.logEvidence[binding.Setup.Entry.Path]}
	var step *model.StepIdentity
	if binding.Lifecycle != nil && binding.StepLog != nil {
		kind = model.ObservationLifecycleStarted
		eventTime = binding.Lifecycle.EventTime
		lineStart, lineEnd = binding.Lifecycle.LineStart, binding.Lifecycle.LineEnd
		evidenceIDs = append(evidenceIDs, b.logEvidence[binding.StepLog.Entry.Path])
		hash := sha256.Sum256([]byte(binding.StepLog.Entry.Scope.StepKey))
		identity := execution.model(b.inventory.Repository.ID)
		step = &model.StepIdentity{Job: identity, TimelineRecordID: "fixture-" + hex.EncodeToString(hash[:8]), LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	}
	if eventTime == nil {
		fallback := acceptanceTime
		eventTime = &fallback
	}
	result := model.RuntimeActionObservation{
		Kind: kind, Execution: execution.model(b.inventory.Repository.ID), Step: step,
		ActionRepository: repository, ActionSubpath: binding.Action.Subpath, DeclaredRef: binding.Action.Ref,
		EventTime: instantEvent(*eventTime, model.TimeBasisLogTimestamp), SourceEvidenceIDs: model.SortEvidenceIDs(evidenceIDs),
		SourceSpan:    model.SourceSpan{ByteStart: 0, ByteEnd: uint64(len(binding.Setup.Bytes)), LineStart: uint64(lineStart), LineEnd: uint64(lineEnd)},
		ExtractorName: "fixture-log-parser", ExtractorVersion: logparse.GrammarVersion,
	}
	if binding.Action.Source.Value != "" {
		object, objectErr := model.NewGitObjectID(model.HashAlgorithm(binding.Action.Source.Algorithm), binding.Action.Source.Value)
		if objectErr != nil {
			b.t.Fatal(objectErr)
		}
		typed, typedErr := model.NewActionSourceObjectID(object)
		if typedErr != nil {
			b.t.Fatal(typedErr)
		}
		result.SourceObjectID = &typed
	}
	if binding.Action.Digest.Value != "" {
		digest, digestErr := model.NewPackageDigest(model.DigestSubject(binding.Action.Digest.Subject), model.HashAlgorithm(binding.Action.Digest.Algorithm), binding.Action.Digest.Value)
		if digestErr != nil {
			b.t.Fatal(digestErr)
		}
		result.PackageDigest = &digest
		result.ImmutableVersion = binding.Action.Version
	}
	rules := sha256.Sum256([]byte(logparse.GrammarVersion))
	result.RulesetSHA256 = hex.EncodeToString(rules[:])
	result.ID, err = evidence.NewRuntimeObservationID(result)
	if err != nil {
		b.t.Fatalf("derive runtime observation for %s: %v", execution.key(), err)
	}
	return result
}

func (b *snapshotBuilder) addReferencedWorkflowFacts() {
	callerRepository, _ := model.NewRepositorySlug(b.inventory.Repository.NameWithOwner)
	for _, reference := range b.metadata.ReferencedWorkflows {
		if reference.Scenario != b.item.ID {
			continue
		}
		calledRepository, err := model.NewRepositorySlug(reference.CalledRepository)
		if err != nil {
			b.t.Fatal(err)
		}
		object, err := model.NewGitObjectID(model.HashSHA1, reference.CalledWorkflowSHA)
		if err != nil {
			b.t.Fatal(err)
		}
		called, err := model.NewCalledWorkflowObjectID(object)
		if err != nil {
			b.t.Fatal(err)
		}
		encoded, _ := json.Marshal(reference)
		runID, attempt := model.WorkflowRunID(reference.RunID), model.RunAttempt(reference.RunAttempt)
		scope := model.CoverageScope{RepositoryID: ptrModel(model.RepositoryID(b.inventory.Repository.ID)), RunID: &runID, RunAttempt: &attempt}
		support := b.addEnvelope("called-workflow/"+b.item.ID+"/"+strconv.Itoa(reference.RunAttempt), evidence.SourceAPIJSON, scope, unknownEvent(), encoded)
		callerPath := ".github/workflows/caller.yml"
		if b.item.Workflow != "" {
			callerPath = ".github/workflows/" + filepathBase(b.item.Workflow)
		}
		b.addFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{support}, Dependency: &archive.DependencyFact{
			Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow,
			Basis: archive.DefinitionRuntimeAttemptMetadata, CallerRepositoryID: model.RepositoryID(b.inventory.Repository.ID),
			CallerRepository: callerRepository, CallerPath: callerPath, TargetRepository: calledRepository,
			TargetPath: reference.CalledPath, TargetCalledWorkflowObjectID: &called,
			AttemptExecution:   &model.RunAttemptIdentity{RepositoryID: model.RepositoryID(b.inventory.Repository.ID), RunID: runID, RunAttempt: attempt},
			ContradictsFactIDs: []string{}, EventTime: b.eventForRun(reference.RunID, reference.RunAttempt),
		}})
	}
}

func (b *snapshotBuilder) addContradictionFacts(executions []fixtureExecution) {
	if len(executions) != 1 || b.item.Workflow == "" {
		b.t.Fatal("contradiction fixture requires one execution and a workflow")
	}
	execution := executions[0]
	workflowBytes := readRepositoryFile(b.t, b.item.Workflow)
	parsed, diagnostics, err := workflow.ParseWorkflow(workflowBytes, workflow.DefaultLimits())
	if err != nil || len(diagnostics) != 0 || len(parsed.Jobs) != 1 || len(parsed.Jobs[0].Steps) != 1 || parsed.Jobs[0].Steps[0].Uses == nil {
		b.t.Fatalf("parse contradiction workflow: err=%v diagnostics=%+v workflow=%+v", err, diagnostics, parsed)
	}
	declaration := parsed.Jobs[0].Steps[0].Uses
	callerRepository, _ := model.NewRepositorySlug(b.inventory.Repository.NameWithOwner)
	targetRepository, _ := model.NewRepositorySlug(declaration.Owner + "/" + declaration.Repository)
	callerObject := mustCallerObject(b.t, b.inventory.Identifiers.HistoricalWorkflowSHA)
	safeObject := mustActionObject(b.t, b.item.DeclaredSHA)
	affectedObject := mustActionObject(b.t, b.item.RuntimeSHA)
	runtime := b.exactRuntimeFact(execution, targetRepository, affectedObject)
	scope := scopeFor(logScope{RunID: execution.RunID, RunAttempt: execution.RunAttempt, JobID: execution.JobID}, b.inventory.Repository.ID)
	workflowEvidence := b.addEnvelope("workflow/"+b.item.ID, evidence.SourceRepositoryContent, scope, b.executionEvent(execution), workflowBytes)
	b.addFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{workflowEvidence}, Dependency: &archive.DependencyFact{
		Relation: archive.DependencyWorkflowDeclaredAction, TargetKind: archive.DependencyTargetAction,
		Basis: archive.DefinitionHistoricalAtRun, CallerRepositoryID: model.RepositoryID(b.inventory.Repository.ID),
		CallerRepository: callerRepository, CallerPath: ".github/workflows/" + filepathBase(b.item.Workflow),
		CallerWorkflowObjectID: &callerObject, TargetRepository: targetRepository, DeclaredRef: declaration.Ref,
		TargetActionObjectID: &safeObject, Execution: ptrModel(execution.model(b.inventory.Repository.ID)),
		StepKey: runtime.Subject.StepKey, ContradictsFactIDs: []string{runtime.ID}, EventTime: b.executionEvent(execution),
	}})
}

func (b *snapshotBuilder) exactRuntimeFact(execution fixtureExecution, repository model.RepositorySlug, object model.ActionSourceObjectID) archive.Fact {
	var matches []archive.Fact
	for _, fact := range b.facts {
		if fact.ActionOccurrence == nil || fact.Subject.StepKey == "" {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.Execution.String() != execution.model(b.inventory.Repository.ID).String() ||
			observation.ActionRepository != repository || observation.SourceObjectID == nil || *observation.SourceObjectID != object {
			continue
		}
		matches = append(matches, fact)
	}
	if len(matches) != 1 {
		b.t.Fatalf("contradiction fixture requires one exact runtime occurrence, got %d", len(matches))
	}
	return matches[0]
}

func (b *snapshotBuilder) addCoverageFacts(executions []fixtureExecution) {
	for _, execution := range executions {
		identity := execution.model(b.inventory.Repository.ID)
		scope := model.CoverageScope{RepositoryID: &identity.RepositoryID, RunID: &identity.RunID, RunAttempt: &identity.RunAttempt, JobID: &identity.JobID}
		evidenceIDs := make([]model.EvidenceID, 0)
		for _, value := range b.parsed {
			if executionKey(value.Entry.Scope.RunID, value.Entry.Scope.RunAttempt, value.Entry.Scope.JobID) == execution.key() {
				evidenceIDs = append(evidenceIDs, b.logEvidence[value.Entry.Path])
			}
		}
		if len(evidenceIDs) == 0 {
			encoded, _ := json.Marshal(struct {
				Scenario        string `json:"scenario"`
				ExecutionKey    string `json:"executionKey"`
				LogAvailability string `json:"logAvailability"`
			}{b.item.ID, execution.key(), b.logAvailability(execution)})
			evidenceIDs = append(evidenceIDs, b.addEnvelope("coverage/"+b.item.ID+"/"+execution.key(), evidence.SourceAPIJSON, scope, unknownEvent(), encoded))
		}
		evidenceIDs = model.SortEvidenceIDs(evidenceIDs)
		availability := b.logAvailability(execution)
		notApplicable := availability == "NOT_GENERATED" && !b.jobStarted(execution)
		parserGap := b.hasIncompleteParsedLog(execution)
		retentionGap := availability == "EXPIRED"
		parserGapReason := model.GapUnsupportedGrammar
		parserGapMessage := "synthetic log did not satisfy the pinned parser grammar"
		if retentionGap {
			parserGapReason = model.GapRetentionOrDeletion
			parserGapMessage = "synthetic retained logs are unavailable to the pinned parser grammar"
		}
		b.addCoverageFact(identity, scope, model.CoverageJobLog, "job-log:", evidenceIDs, notApplicable, retentionGap, model.GapRetentionOrDeletion, "synthetic retained logs are unavailable")
		b.addCoverageFact(identity, scope, model.CoverageParserGrammar, "parser-grammar:", evidenceIDs, notApplicable, retentionGap || parserGap, parserGapReason, parserGapMessage)
	}
}

func (b *snapshotBuilder) addCoverageFact(identity model.JobExecutionIdentity, scope model.CoverageScope, kind model.CoverageKind, logicalPrefix string, evidenceIDs []model.EvidenceID, notApplicable, gap bool, gapReason model.GapReason, gapMessage string) {
	unit := model.CoverageUnit{Kind: kind, Scope: scope, LogicalKey: logicalPrefix + identity.String(), RequiredForNegative: !notApplicable}
	var err error
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		b.t.Fatal(err)
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{UnitID: unit.ID, ExpectedCount: &one, EvidenceIDs: evidenceIDs}
	switch {
	case notApplicable:
		assessment.Status = model.CoverageNotApplicable
	case gap:
		assessment.Status = model.CoverageGap
		assessment.Gap = &model.CoverageGapDetail{Reason: gapReason, Material: true, SanitizedMessage: gapMessage}
	default:
		assessment.Status = model.CoverageCollected
		assessment.ObservedCount = 1
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		b.t.Fatal(err)
	}
	if gap {
		b.addFact(archive.Fact{Kind: archive.FactCoverageGap, EvidenceIDs: evidenceIDs, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}})
		return
	}
	b.addFact(archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: evidenceIDs, Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}})
}

func (b *snapshotBuilder) addEnvelope(label string, kind evidence.SourceKind, scope model.CoverageScope, event model.EventInterval, source []byte) model.EvidenceID {
	b.requestCounter++
	envelope, err := evidence.NewEnvelope(evidence.EnvelopeInput{
		Kind: kind, CanonicalSourceID: "synthetic-acceptance/" + label, Provider: evidence.ProviderCIRewind,
		RequestParameters: evidence.RequestParameters{}, Scope: scope, EventTime: event, MediaType: "application/octet-stream",
		SourceBytes: source, Complete: true,
		Extractor:         evidence.ExtractorDescriptor{Name: "fixture-acceptance", Version: "v1", RulesetSHA256: strings.Repeat("f", 64)},
		Redaction:         evidence.RedactionDescriptor{Status: evidence.RedactionStructuredAllowlist, PolicyVersion: "fixture-v1"},
		CollectionSession: b.session.ID, RequestID: model.RequestID(fmt.Sprintf("request:fixture:%s:%04d", strings.ToLower(b.item.ID), b.requestCounter)),
		CollectionTime: model.CollectionWindow{StartedAt: b.when, EndedAt: b.when},
	})
	if err != nil {
		b.t.Fatalf("construct evidence %s: %v", label, err)
	}
	b.evidence = append(b.evidence, envelope)
	return envelope.Evidence.ID
}

func (b *snapshotBuilder) addFact(input archive.Fact) archive.Fact {
	normalized, err := archive.NormalizeFact(input)
	if err != nil {
		b.t.Fatalf("normalize %s fact: %v", input.Kind, err)
	}
	if index, ok := b.factIndex[normalized.ID]; ok {
		existing := b.facts[index]
		existing.EvidenceIDs = model.SortEvidenceIDs(append(existing.EvidenceIDs, normalized.EvidenceIDs...))
		b.facts[index] = existing
		return existing
	}
	b.factIndex[normalized.ID] = len(b.facts)
	b.facts = append(b.facts, normalized)
	return normalized
}

func (b *snapshotBuilder) executionEvent(execution fixtureExecution) model.EventInterval {
	for _, value := range b.parsed {
		if executionKey(value.Entry.Scope.RunID, value.Entry.Scope.RunAttempt, value.Entry.Scope.JobID) != execution.key() {
			continue
		}
		for _, observation := range value.Result.Observations {
			if observation.EventTime != nil {
				return instantEvent(*observation.EventTime, model.TimeBasisLogTimestamp)
			}
		}
	}
	return instantEvent(acceptanceTime.Add(time.Duration(execution.RunID%3600)*time.Second), model.TimeBasisAPIField)
}

func (b *snapshotBuilder) eventForRun(runID int64, attempt int) model.EventInterval {
	for _, key := range b.item.ExecutionKeys {
		execution, err := parseExecutionKey(key)
		if err == nil && execution.RunID == runID && execution.RunAttempt == attempt {
			return b.executionEvent(execution)
		}
	}
	return unknownEvent()
}

func (b *snapshotBuilder) logAvailability(execution fixtureExecution) string {
	for _, item := range b.metadata.JobsWithoutLogs {
		if item.Scenario == b.item.ID && item.RunID == execution.RunID && item.RunAttempt == execution.RunAttempt && item.JobID == execution.JobID {
			return item.LogAvailability
		}
	}
	return "UNKNOWN"
}

func (b *snapshotBuilder) jobStarted(execution fixtureExecution) bool {
	for _, item := range b.metadata.JobsWithoutLogs {
		if item.Scenario == b.item.ID && item.RunID == execution.RunID && item.RunAttempt == execution.RunAttempt && item.JobID == execution.JobID {
			return item.JobStarted
		}
	}
	return len(b.parsed) != 0
}

func (b *snapshotBuilder) hasIncompleteParsedLog(execution fixtureExecution) bool {
	for _, value := range b.parsed {
		if executionKey(value.Entry.Scope.RunID, value.Entry.Scope.RunAttempt, value.Entry.Scope.JobID) == execution.key() && !value.Result.Complete {
			return true
		}
	}
	return false
}

func assertScenarioFindings(t testing.TB, item scenario, result scenarioPipelineResult) {
	t.Helper()
	findings := result.Case.Case.Findings
	if item.ID == "I" && len(findings) != 0 {
		t.Fatalf("non-started environment-gated job produced findings: %+v", findings)
	}
	for _, expected := range item.ExpectedFindings {
		if !model.FindingState(expected.State).Valid() || !model.ProvenanceLevel(expected.Provenance).Valid() {
			t.Fatalf("fixture expectation uses a non-canonical state or provenance: %+v", expected)
		}
		matched := false
		for _, finding := range findings {
			if finding.State != expected.State || finding.Provenance != expected.Provenance {
				continue
			}
			if expected.Attempt != 0 && finding.RunAttempt != expected.Attempt {
				continue
			}
			if expected.JobID != 0 && finding.JobID != expected.JobID {
				continue
			}
			if strings.Contains(expected.Component, "/.github/workflows/") && !strings.HasPrefix(finding.IndicatorID, "called-") {
				continue
			}
			if expected.Digest != "" && finding.IndicatorID != "affected-digest" {
				continue
			}
			if !strings.Contains(expected.Component, "/.github/workflows/") && expected.Digest == "" && finding.IndicatorID != "affected-commit" {
				continue
			}
			matched = true
			break
		}
		if !matched {
			t.Errorf("missing expected finding %+v; actual=%+v", expected, findings)
		}
		if expected.SourceSHA != "" && !hasRuntimeSource(result.RuntimeObservations, expected, expected.SourceSHA) {
			t.Errorf("expected source SHA %s was not preserved in a matching runtime observation", expected.SourceSHA)
		}
		if expected.Digest != "" && !hasRuntimeDigest(result.RuntimeObservations, expected, expected.Digest) {
			t.Errorf("expected digest %s was not preserved in a matching runtime observation", expected.Digest)
		}
	}
	for _, forbidden := range item.ForbiddenStates {
		if !model.FindingState(forbidden).Valid() {
			t.Fatalf("fixture forbidden state is non-canonical: %q", forbidden)
		}
		for _, finding := range findings {
			if finding.State == forbidden {
				t.Errorf("forbidden state %s was emitted: %+v", forbidden, finding)
			}
		}
	}
	if item.AttemptsMustRemainSeparate {
		for _, expected := range item.ExpectedFindings {
			if expected.Attempt == 0 {
				continue
			}
			found := false
			for _, finding := range findings {
				if finding.RunAttempt == expected.Attempt && finding.State == expected.State {
					found = true
				}
			}
			if !found {
				t.Errorf("attempt %d was merged or omitted for state %s", expected.Attempt, expected.State)
			}
		}
	}
	if item.MatrixJobsMustRemainSeparate {
		jobs := make(map[int64]bool)
		for _, finding := range findings {
			if finding.State == string(model.ConfirmedExecuted) {
				jobs[finding.JobID] = true
			}
		}
		if len(jobs) != 2 || !jobs[920013] || !jobs[920014] {
			t.Errorf("matrix jobs were not retained separately: %v", jobs)
		}
	}
	if item.ExpectedRuntimeObservationCount != nil && len(result.RuntimeObservations) != *item.ExpectedRuntimeObservationCount {
		t.Errorf("runtime observation count = %d, want %d", len(result.RuntimeObservations), *item.ExpectedRuntimeObservationCount)
	}
	assertTightenedScenarioSemantics(t, item, findings)
}

func assertTightenedScenarioSemantics(t testing.TB, item scenario, findings []report.Finding) {
	t.Helper()
	switch item.ID {
	case "E", "F":
		for _, finding := range findings {
			if finding.IndicatorID != "affected-commit" || finding.State != string(model.NoMatchConfirmed) || finding.RunAttempt != 2 {
				continue
			}
			if len(finding.CollectionCoverage) != 2 || finding.CollectionCoverage[0] == finding.CollectionCoverage[1] {
				t.Fatalf("scenario %s exact-runtime negative lacks distinct job-log and parser-grammar closure: %+v", item.ID, finding.CollectionCoverage)
			}
			return
		}
		t.Fatalf("scenario %s lacks its attempt-2 exact-runtime negative", item.ID)
	case "P":
		if len(findings) != 1 {
			t.Fatalf("contradiction scenario findings = %d, want exactly one: %+v", len(findings), findings)
		}
		finding := findings[0]
		if finding.State != string(model.ContradictoryEvidence) || finding.RunAttempt != 1 || finding.JobID != 920017 || finding.StepIdentity == "" {
			t.Fatalf("contradiction was not bound to the exact runtime step: %+v", finding)
		}
		if len(finding.ContradictoryEvidence) != 1 {
			t.Fatalf("contradiction lacks one explicit historical-definition fact link: %+v", finding.ContradictoryEvidence)
		}
		if len(finding.EvidenceIDs) < 3 {
			t.Fatalf("contradiction evidence chain omits historical or runtime support: %+v", finding.EvidenceIDs)
		}
	}
}

func hasRuntimeSource(observations []model.RuntimeActionObservation, expected expectedFinding, source string) bool {
	for _, observation := range observations {
		if expected.Attempt != 0 && int(observation.Execution.RunAttempt) != expected.Attempt {
			continue
		}
		if expected.JobID != 0 && int64(observation.Execution.JobID) != expected.JobID {
			continue
		}
		if observation.SourceObjectID != nil && model.GitObjectID(*observation.SourceObjectID).Value == source {
			return true
		}
	}
	return false
}

func hasRuntimeDigest(observations []model.RuntimeActionObservation, expected expectedFinding, digest string) bool {
	for _, observation := range observations {
		if expected.Attempt != 0 && int(observation.Execution.RunAttempt) != expected.Attempt {
			continue
		}
		if expected.JobID != 0 && int64(observation.Execution.JobID) != expected.JobID {
			continue
		}
		if observation.PackageDigest != nil && string(observation.PackageDigest.Algorithm)+":"+observation.PackageDigest.Value == digest {
			return true
		}
	}
	return false
}

func acceptanceIncidentPack(t testing.TB, inventory fixtureInventory) *incident.ValidatedPack {
	t.Helper()
	digest := strings.TrimPrefix(inventory.Identifiers.ImmutableDigest, "sha256:")
	packYAML := fmt.Sprintf(`apiVersion: cirewind.dev/v1alpha1
kind: GitHubActionsIncident
metadata:
  id: CIR-ACCEPTANCE-001
  packVersion: 1.0.0
  title: Synthetic fixture acceptance incident
  publishedAt: "2026-08-20T00:00:00Z"
  updatedAt: "2026-08-20T00:00:00Z"
  sources:
    - id: fixture
      type: synthetic-fixture
      title: Offline acceptance fixture
      publisher: CIRewind test maintainers
      url: https://example.invalid/cirewind/acceptance
      retrievedAt: "2026-08-20T00:00:00Z"
spec:
  description: Harmless synthetic fixture data only.
  components:
    - id: action
      type: github-action
      repository:
        owner: cirewind-fixtures
        name: harmless
    - id: workflows
      type: reusable-workflow
      repository:
        owner: cirewind-fixtures
        name: workflows
      workflowPaths:
        - .github/workflows/reusable-failing.yml
        - .github/workflows/reusable.yml
  indicators:
    - id: affected-commit
      componentId: action
      kind: action-commit
      value:
        gitObject:
          algorithm: sha1
          value: %q
      confidence: L4_CERTAIN
      sourceRefs: [fixture]
    - id: affected-digest
      componentId: action
      kind: digest
      value:
        subject: github-action-package
        algorithm: sha256
        digest: %q
      confidence: L4_CERTAIN
      sourceRefs: [fixture]
    - id: called-reusable
      componentId: workflows
      kind: reusable-workflow-commit
      value:
        gitObject:
          algorithm: sha1
          value: %q
        path: .github/workflows/reusable.yml
      confidence: L4_CERTAIN
      sourceRefs: [fixture]
    - id: called-reusable-failing
      componentId: workflows
      kind: reusable-workflow-commit
      value:
        gitObject:
          algorithm: sha1
          value: %q
        path: .github/workflows/reusable-failing.yml
      confidence: L4_CERTAIN
      sourceRefs: [fixture]
  knownGood:
    - id: known-good-action
      componentId: action
      kind: action-commit
      value:
        gitObject:
          algorithm: sha1
          value: %q
      confidence: L4_CERTAIN
      sourceRefs: [fixture]
`, inventory.Identifiers.AffectedActionSHA, digest, inventory.Identifiers.CalledWorkflowSHA, inventory.Identifiers.CalledWorkflowSHA, inventory.Identifiers.SafeActionSHA)
	pack, err := incident.Validate(context.Background(), []byte(packYAML))
	if err != nil {
		t.Fatalf("validate acceptance incident pack: %v", err)
	}
	return pack
}

func parseExecutionKeys(t testing.TB, values []string) []fixtureExecution {
	t.Helper()
	result := make([]fixtureExecution, 0, len(values))
	for _, value := range values {
		execution, err := parseExecutionKey(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, execution)
	}
	return result
}

func parseExecutionKey(value string) (fixtureExecution, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return fixtureExecution{}, fmt.Errorf("invalid fixture execution key %q", value)
	}
	runID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || runID <= 0 {
		return fixtureExecution{}, fmt.Errorf("invalid fixture run ID in %q", value)
	}
	attempt, err := strconv.Atoi(parts[1])
	if err != nil || attempt <= 0 {
		return fixtureExecution{}, fmt.Errorf("invalid fixture attempt in %q", value)
	}
	jobID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || jobID <= 0 {
		return fixtureExecution{}, fmt.Errorf("invalid fixture job ID in %q", value)
	}
	return fixtureExecution{RunID: runID, RunAttempt: attempt, JobID: jobID}, nil
}

func scopeFor(scope logScope, repositoryID int64) model.CoverageScope {
	repository := model.RepositoryID(repositoryID)
	runID, attempt, jobID := model.WorkflowRunID(scope.RunID), model.RunAttempt(scope.RunAttempt), model.JobID(scope.JobID)
	return model.CoverageScope{RepositoryID: &repository, RunID: &runID, RunAttempt: &attempt, JobID: &jobID, StepKey: scope.StepKey}
}

func actionKey(action logparse.Action) string {
	value := strings.ToLower(action.Owner + "/" + action.Repository)
	if action.Subpath != "" {
		value += "/" + action.Subpath
	}
	return value + "@" + action.Ref
}

func instantEvent(value time.Time, basis model.EventTimeBasis) model.EventInterval {
	instant := model.MustInstant(value)
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: basis}
}

func unknownEvent() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}

func filepathBase(value string) string {
	parts := strings.Split(filepathCleanSlash(value), "/")
	return parts[len(parts)-1]
}

func filepathCleanSlash(value string) string {
	for strings.Contains(value, "//") {
		value = strings.ReplaceAll(value, "//", "/")
	}
	return strings.Trim(value, "/")
}

func mustActionObject(t testing.TB, value string) model.ActionSourceObjectID {
	t.Helper()
	object, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := model.NewActionSourceObjectID(object)
	if err != nil {
		t.Fatal(err)
	}
	return typed
}

func mustCallerObject(t testing.TB, value string) model.CallerWorkflowObjectID {
	t.Helper()
	object, err := model.NewGitObjectID(model.HashSHA1, value)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := model.NewCallerWorkflowObjectID(object)
	if err != nil {
		t.Fatal(err)
	}
	return typed
}

func ptrModel[T any](value T) *T { return &value }
