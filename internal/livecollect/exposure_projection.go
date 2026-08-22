package livecollect

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

const (
	exposureJoinScope       = "historical_exposure_join"
	secretFlowScope         = "historical_secret_flow"
	staticPermissionScope   = "historical_permissions"
	environmentContextScope = "environment_job_context"
)

// historicalExposureDocument retains a bounded parse of exact historical
// bytes. The evidence ID identifies those bytes; a trigger SHA, current branch
// definition, or mutable declaration is never substituted here.
type historicalExposureDocument struct {
	root       historicalWorkflowRoot
	workflow   *workflow.Workflow
	evidenceID model.EvidenceID
}

type historicalExposureInput struct {
	repositoryID model.RepositoryID
	runID        model.WorkflowRunID
	attempt      model.RunAttempt
	documents    []historicalExposureDocument
	jobs         []githubapi.WorkflowJob
	sourceFacts  []archive.Fact
}

type historicalExposureIssue struct {
	reason     collect.GapReason
	scope      string
	jobID      int64
	diagnostic string
}

type historicalExposureOutput struct {
	facts                 []archive.Fact
	issues                []historicalExposureIssue
	secretFlowFacts       uint64
	staticPermissionFacts uint64
	environmentFacts      uint64
	seenFactIDs           map[string]struct{}
}

type exactJobBinding struct {
	definition resolve.DefinitionKey
	workflow   *workflow.Workflow
	job        workflow.Job
	apiJob     githubapi.WorkflowJob
	execution  model.JobExecutionIdentity
	evidence   []model.EvidenceID
}

func (h *historicalAttempt) projectHistoricalExposures(documents []historicalExposureDocument) error {
	projected, err := buildHistoricalExposureProjection(historicalExposureInput{
		repositoryID: model.RepositoryID(h.target.repository.ID),
		runID:        model.WorkflowRunID(h.runID),
		attempt:      model.RunAttempt(h.bundle.Attempt),
		documents:    documents,
		jobs:         h.bundle.Jobs,
		sourceFacts:  h.result.facts,
	})
	if err != nil {
		return err
	}
	h.result.facts = append(h.result.facts, projected.facts...)
	h.result.secretFlowFacts += projected.secretFlowFacts
	h.result.staticPermissionFacts += projected.staticPermissionFacts
	h.result.environmentFacts += projected.environmentFacts
	for _, issue := range projected.issues {
		if err := appendGap(h.result, collect.Gap{
			Reason: issue.reason, Scope: issue.scope, RepositoryID: h.target.repository.ID,
			RunID: h.runID, Attempt: h.bundle.Attempt, JobID: issue.jobID,
			Material: true, Diagnostic: issue.diagnostic,
		}); err != nil {
			return err
		}
	}
	return nil
}

func buildHistoricalExposureProjection(input historicalExposureInput) (historicalExposureOutput, error) {
	output := historicalExposureOutput{seenFactIDs: make(map[string]struct{})}
	if err := input.repositoryID.Validate(); err != nil {
		return output, err
	}
	if err := input.runID.Validate(); err != nil {
		return output, err
	}
	if err := input.attempt.Validate(); err != nil {
		return output, err
	}

	callers := make([]historicalExposureDocument, 0, 1)
	for _, document := range input.documents {
		if document.root.scope == "historical_workflow" {
			callers = append(callers, document)
		}
	}
	if len(callers) == 0 {
		// Caller reconstruction already persisted the material reason. Do not
		// invent exposure from a called definition with no exact caller.
		return output, nil
	}
	if len(callers) != 1 {
		output.issue(exposureJoinScope, 0, "more than one exact caller workflow parse was available; no credential or environment join was selected")
		return output, nil
	}
	caller := callers[0]
	if caller.workflow == nil {
		return output, errors.New("historical exposure caller parse is nil")
	}
	if len(caller.workflow.SecretRefs) > 0 {
		output.issue(secretFlowScope, 0, "workflow-scoped secret references were retained but not relabeled as job or affected-step exposure")
	}

	for _, job := range caller.workflow.Jobs {
		if job.Uses == nil {
			if err := projectDirectWorkflowJob(input, caller, job, &output); err != nil {
				return output, err
			}
			continue
		}
		if err := projectReusableWorkflowJob(input, caller, job, &output); err != nil {
			return output, err
		}
	}
	return output, nil
}

func projectDirectWorkflowJob(input historicalExposureInput, document historicalExposureDocument, job workflow.Job, output *historicalExposureOutput) error {
	if !jobHasExposureMaterial(document.workflow, job) {
		return nil
	}
	apiJob, ok := exactDirectJob(document.workflow, job, input.jobs)
	if !ok {
		output.issue(exposureJoinScope, 0, "an exposure-relevant historical job did not identify exactly one API job by its complete literal display label")
		return nil
	}
	evidenceIDs, ok := jobDefinitionEvidence(input.sourceFacts, executionFor(input, apiJob.ID), document.evidenceID)
	if !ok {
		output.issue(exposureJoinScope, apiJob.ID, "the exact historical job join lacked its API job evidence object")
		return nil
	}
	binding := exactJobBinding{definition: document.root.resolved.Definition, workflow: document.workflow, job: job, apiJob: apiJob, execution: executionFor(input, apiJob.ID), evidence: evidenceIDs}
	if err := projectEnvironmentContext(binding, output); err != nil {
		return err
	}
	if apiJob.StartedAt == nil || apiJob.StartedAt.IsZero() {
		// An unstarted or gated job did not receive token/step reachability.
		return nil
	}
	if err := projectStaticPermissions(input, binding, output); err != nil {
		return err
	}
	if err := projectJobSecretReferences(binding, nil, output); err != nil {
		return err
	}
	return projectStepSecretFlows(input, binding, nil, output)
}

func projectReusableWorkflowJob(input historicalExposureInput, caller historicalExposureDocument, call workflow.Job, output *historicalExposureOutput) error {
	if !reusableCallHasExposureMaterial(call) {
		return nil
	}
	callerLabel, ok := literalJobLabel(call)
	if !ok || workflowLabelCount(caller.workflow.Jobs, callerLabel) != 1 {
		output.issue(exposureJoinScope, 0, "an exposure-relevant reusable-workflow call had a dynamic or ambiguous caller job label")
		return nil
	}
	called, ok := exactCalledDocument(caller.root.resolved.Definition, *call.Uses, input.documents)
	if !ok || called.workflow == nil {
		output.issue(exposureJoinScope, 0, "an exposure-relevant reusable-workflow call did not bind to one exact GitHub-recorded called definition")
		return nil
	}
	mapping := make(map[string]string)
	for _, item := range call.SecretMappings {
		if item.Dynamic || item.SourceName == "" {
			output.issue(secretFlowScope, 0, "a reusable-workflow secret mapping was dynamic or did not contain one literal source secret name")
			continue
		}
		source, sourceErr := model.NewSecretName(item.SourceName)
		target, targetErr := model.NewSecretName(item.TargetName)
		if sourceErr != nil || targetErr != nil {
			output.issue(secretFlowScope, 0, "a reusable-workflow secret mapping contained an invalid source or target name")
			continue
		}
		mapping[string(target)] = string(source)
	}

	joined := 0
	for _, calledJob := range called.workflow.Jobs {
		calleeLabel, labelOK := literalJobLabel(calledJob)
		if !labelOK || workflowLabelCount(called.workflow.Jobs, calleeLabel) != 1 {
			if calledJobHasExposureMaterial(called.workflow, calledJob, call) {
				output.issue(exposureJoinScope, 0, "a called-workflow exposure-relevant job had a dynamic or ambiguous literal label")
			}
			continue
		}
		apiJob, jobOK := exactAPIJob(input.jobs, callerLabel+" / "+calleeLabel)
		if !jobOK {
			if calledJobHasExposureMaterial(called.workflow, calledJob, call) {
				output.issue(exposureJoinScope, 0, "a called-workflow exposure-relevant job did not identify exactly one API job by the complete one-hop label path")
			}
			continue
		}
		joined++
		execution := executionFor(input, apiJob.ID)
		evidenceIDs, evidenceOK := jobDefinitionEvidence(input.sourceFacts, execution, caller.evidenceID, called.evidenceID)
		if !evidenceOK {
			output.issue(exposureJoinScope, apiJob.ID, "the exact called-workflow job join lacked its API job evidence object")
			continue
		}
		binding := exactJobBinding{definition: called.root.resolved.Definition, workflow: called.workflow, job: calledJob, apiJob: apiJob, execution: execution, evidence: evidenceIDs}
		if err := projectEnvironmentContext(binding, output); err != nil {
			return err
		}
		for _, source := range sortedMappingSources(mapping) {
			if err := output.addCredential(execution, "", model.ExposureReusableSecretMapped, model.ExposureBasisReusableWorkflowCall, source,
				"The exact caller definition explicitly mapped this named source secret to the directly called workflow. A non-empty value, affected-step access, read, use, and exfiltration were not established.",
				evidenceIDs, jobEventTime(apiJob)); err != nil {
				return err
			}
		}
		if call.SecretsInherit {
			if err := output.addCredential(execution, "", model.ExposureReusableSecretInherited, model.ExposureBasisReusableWorkflowCall, "",
				"The exact caller definition declared secrets: inherit for this direct call. No secret names, values, or affected-step access were inferred.",
				evidenceIDs, jobEventTime(apiJob)); err != nil {
				return err
			}
		}
		if calledJob.Uses != nil {
			if calledJobHasExposureMaterial(called.workflow, calledJob, call) {
				output.issue(secretFlowScope, apiJob.ID, "secret propagation beyond one reusable-workflow call hop was not derived")
			}
			continue
		}
		if apiJob.StartedAt == nil || apiJob.StartedAt.IsZero() {
			continue
		}
		if len(mapping) > 0 {
			if err := projectJobSecretReferences(binding, mapping, output); err != nil {
				return err
			}
			if err := projectStepSecretFlows(input, binding, mapping, output); err != nil {
				return err
			}
		}
	}
	if joined == 0 && (len(call.SecretMappings) > 0 || call.SecretsInherit) {
		// The individual job diagnostics above explain why. This summary keeps
		// an empty/malformed called workflow from silently dropping the call.
		output.issue(exposureJoinScope, 0, "no exact called-workflow API job was available for the reusable secret relationship")
	}
	return nil
}

func projectStaticPermissions(input historicalExposureInput, binding exactJobBinding, output *historicalExposureOutput) error {
	permissions := binding.workflow.Permissions
	if binding.job.Permissions != nil {
		permissions = binding.job.Permissions
	}
	names := make([]string, 0, len(permissions))
	for name := range permissions {
		names = append(names, name)
	}
	sort.Strings(names)
	execution := executionFor(input, binding.apiJob.ID)
	for _, name := range names {
		access := strings.ToLower(permissions[name])
		if name == "*" || (access != "read" && access != "write" && access != "none") {
			output.issue(staticPermissionScope, binding.apiJob.ID, "an exact historical permissions declaration used a shorthand or unsupported access value and was not expanded")
			continue
		}
		if name == "id-token" {
			// id-token is workflow permission syntax for the separate OIDC
			// minting service. It is not a GITHUB_TOKEN repository permission.
			if access == "write" && !hasOIDCCapability(input.sourceFacts, output.facts, execution) {
				if err := output.addToken(execution, model.ExposureOIDCMintingCapability, "", "",
					"The exact historical definition granted id-token: write to this started job, establishing only inferred OIDC minting capability. No token request, compatible trust policy, exchange, cloud identity, or role assumption was established.",
					binding.evidence, jobEventTime(binding.apiJob)); err != nil {
					return err
				}
			}
			continue
		}
		if hasObservedPermission(input.sourceFacts, output.facts, execution, name) {
			continue
		}
		conclusion := fmt.Sprintf("The exact historical definition explicitly granted %s: %s to this started job. This is a static inference; retained evidence does not prove the permission was exercised.", name, access)
		if err := output.addToken(execution, model.ExposureGitHubTokenPermission, name, access, conclusion, binding.evidence, jobEventTime(binding.apiJob)); err != nil {
			return err
		}
	}
	return nil
}

func projectJobSecretReferences(binding exactJobBinding, mappedNames map[string]string, output *historicalExposureOutput) error {
	if binding.apiJob.StartedAt == nil || binding.apiJob.StartedAt.IsZero() {
		return nil
	}
	names := make(map[string]struct{})
	for _, reference := range binding.job.SecretRefs {
		name := strings.ToUpper(reference.Name)
		if mappedNames != nil {
			mapped, ok := mappedNames[name]
			if !ok {
				continue
			}
			name = mapped
		}
		names[name] = struct{}{}
	}
	for _, name := range sortedSet(names) {
		if err := output.addCredential(binding.execution, "", model.ExposureSecretReferencedByJob, model.ExposureBasisHistoricalDefinitionReference, name,
			"The exact historical definition contained a job-scoped reference to this secret name in the started job. A non-empty value, affected-step access, read, use, and exfiltration were not established.",
			binding.evidence, jobEventTime(binding.apiJob)); err != nil {
			return err
		}
	}
	return nil
}

// projectionExecution is set by projectStepSecretFlows before helpers that
// accept the compact exactJobBinding. Keeping it out of workflow AST types
// prevents a parsed definition from masquerading as a runtime identity.
func projectStepSecretFlows(input historicalExposureInput, binding exactJobBinding, mappedNames map[string]string, output *historicalExposureOutput) error {
	execution := executionFor(input, binding.apiJob.ID)
	for _, step := range binding.job.Steps {
		refs := directStepSecretReferences(step.SecretRefs, mappedNames)
		if len(refs) == 0 {
			continue
		}
		observation, factEvidence, event, state := bindLifecycleStep(input.sourceFacts, binding, step, execution)
		switch state {
		case stepJoinSkipped:
			continue
		case stepJoinMissing:
			output.issue(secretFlowScope, binding.apiJob.ID, "a direct step env/with secret reference could not be joined to one lifecycle-started API Action step")
			continue
		}
		evidenceIDs := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), binding.evidence...), factEvidence...))
		for _, name := range refs {
			if err := output.addCredential(execution, observation.Step.Key(), model.ExposureSecretPassedToStep, model.ExposureBasisHistoricalDefinitionFlow, name,
				"The exact historical step env/with field referenced this named secret and the same Action step demonstrably began. This supports potential passage to that step; a non-empty value, read, use, and exfiltration were not established.",
				evidenceIDs, event); err != nil {
				return err
			}
		}
	}
	return nil
}

func projectEnvironmentContext(binding exactJobBinding, output *historicalExposureOutput) error {
	name := binding.job.Environment
	if name == "" {
		return nil
	}
	if !literalLabel(name) || len(name) > 1024 {
		output.issue(environmentContextScope, binding.apiJob.ID, "a historical environment target was dynamic or unsafe and was not joined to a job")
		return nil
	}
	gate := "unknown"
	started := binding.apiJob.StartedAt != nil && !binding.apiJob.StartedAt.IsZero()
	if started {
		// GitHub does not start an environment job before its applicable
		// protection rules complete. "crossed" deliberately does not claim a
		// human approval, bypass, or absence of protection rules.
		gate = "crossed"
	} else if strings.EqualFold(binding.apiJob.Status, "waiting") {
		gate = "pending"
	}
	fact, err := archive.NormalizeFact(archive.Fact{
		Kind: archive.FactExposure, EvidenceIDs: binding.evidence,
		Exposure: &archive.ExposureFact{
			Execution: binding.execution,
			Environment: &archive.EnvironmentEligibilityFact{
				EnvironmentName: name, GateState: gate, JobStarted: started, SecretNames: []model.SecretName{},
			},
			EventTime: jobEventTime(binding.apiJob),
		},
	})
	if err != nil {
		return fmt.Errorf("normalize historical environment context: %w", err)
	}
	if output.addFact(fact) {
		output.environmentFacts++
	}
	return nil
}

type stepJoinState uint8

const (
	stepJoinMissing stepJoinState = iota
	stepJoinStarted
	stepJoinSkipped
)

func bindLifecycleStep(sourceFacts []archive.Fact, binding exactJobBinding, step workflow.Step, execution model.JobExecutionIdentity) (model.RuntimeActionObservation, []model.EvidenceID, model.EventInterval, stepJoinState) {
	if step.Uses == nil {
		return model.RuntimeActionObservation{}, nil, model.EventInterval{}, stepJoinMissing
	}
	var matches []archive.Fact
	for _, fact := range sourceFacts {
		if fact.Kind != archive.FactActionOccurrence || fact.ActionOccurrence == nil {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.Kind != model.ObservationLifecycleStarted || observation.Execution != execution || observation.Step == nil {
			continue
		}
		if observation.Step.APIStepNumber == nil {
			continue
		}
		if !actionReferenceMatches(binding.definition, *step.Uses, observation) {
			continue
		}
		apiStep, ok := exactAPIStep(binding.apiJob, int(*observation.Step.APIStepNumber))
		if !ok || apiStep.StartedAt == nil || apiStep.StartedAt.IsZero() {
			continue
		}
		if step.Name != "" && (!literalLabel(step.Name) || apiStep.Name != step.Name) {
			continue
		}
		matches = append(matches, fact)
	}
	if len(matches) == 1 && (step.Name != "" || actionReferenceCount(binding.job.Steps, *step.Uses) == 1) {
		return matches[0].ActionOccurrence.Observation, matches[0].EvidenceIDs, matches[0].ActionOccurrence.Observation.EventTime, stepJoinStarted
	}
	if step.Name != "" && literalLabel(step.Name) {
		matched, count := githubapi.JobStep{}, 0
		for _, apiStep := range binding.apiJob.Steps {
			if apiStep.Name == step.Name {
				matched, count = apiStep, count+1
			}
		}
		if count == 1 && strings.EqualFold(matched.Conclusion, "skipped") {
			return model.RuntimeActionObservation{}, nil, jobEventTime(binding.apiJob), stepJoinSkipped
		}
	}
	return model.RuntimeActionObservation{}, nil, model.EventInterval{}, stepJoinMissing
}

func actionReferenceMatches(definition resolve.DefinitionKey, reference workflow.Reference, observation model.RuntimeActionObservation) bool {
	var owner, repository string
	switch reference.Kind {
	case workflow.ReferenceRepository:
		owner, repository = reference.Owner, reference.Repository
	case workflow.ReferenceSelfRepository:
		owner, repository = definition.Repository.Owner, definition.Repository.Name
	default:
		return false
	}
	slug, err := model.NewRepositorySlug(strings.ToLower(owner) + "/" + strings.ToLower(repository))
	if err != nil || observation.ActionRepository != slug || observation.DeclaredRef != reference.Ref {
		return false
	}
	subpath, err := workflow.NormalizeRepositoryPath(reference.Subpath)
	return err == nil && observation.ActionSubpath == subpath
}

func actionReferenceCount(steps []workflow.Step, reference workflow.Reference) int {
	count := 0
	for _, step := range steps {
		if step.Uses != nil && sameReference(*step.Uses, reference) {
			count++
		}
	}
	return count
}

func sameReference(left, right workflow.Reference) bool {
	return left.Kind == right.Kind && left.Owner == right.Owner && left.Repository == right.Repository && left.Subpath == right.Subpath && left.Ref == right.Ref
}

func exactDirectJob(parsed *workflow.Workflow, wanted workflow.Job, jobs []githubapi.WorkflowJob) (githubapi.WorkflowJob, bool) {
	label, ok := literalJobLabel(wanted)
	if !ok || workflowLabelCount(parsed.Jobs, label) != 1 {
		return githubapi.WorkflowJob{}, false
	}
	return exactAPIJob(jobs, label)
}

func exactAPIJob(jobs []githubapi.WorkflowJob, label string) (githubapi.WorkflowJob, bool) {
	var selected githubapi.WorkflowJob
	count := 0
	for _, job := range jobs {
		if job.Name == label {
			selected, count = job, count+1
		}
	}
	return selected, count == 1
}

func literalJobLabel(job workflow.Job) (string, bool) {
	label := job.Name
	if label == "" {
		label = job.ID
	}
	return label, literalLabel(label) && !strings.Contains(label, " / ")
}

func literalLabel(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || strings.Contains(value, "${{") {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func workflowLabelCount(jobs []workflow.Job, label string) int {
	count := 0
	for _, job := range jobs {
		if candidate, ok := literalJobLabel(job); ok && candidate == label {
			count++
		}
	}
	return count
}

func exactCalledDocument(parent resolve.DefinitionKey, reference workflow.Reference, documents []historicalExposureDocument) (historicalExposureDocument, bool) {
	owner, repository := reference.Owner, reference.Repository
	if reference.Kind == workflow.ReferenceLocalWorkspace || reference.Kind == workflow.ReferenceSelfRepository {
		owner, repository = parent.Repository.Owner, parent.Repository.Name
	}
	pathValue, err := workflow.NormalizeRepositoryPath(reference.Subpath)
	if err != nil || pathValue == "" {
		return historicalExposureDocument{}, false
	}
	var selected historicalExposureDocument
	count := 0
	for _, document := range documents {
		if document.root.scope == "historical_workflow" {
			continue
		}
		definition := document.root.resolved.Definition
		if strings.EqualFold(definition.Repository.Owner, owner) && strings.EqualFold(definition.Repository.Name, repository) && definition.Path == pathValue {
			selected, count = document, count+1
		}
	}
	return selected, count == 1
}

func jobHasExposureMaterial(parsed *workflow.Workflow, job workflow.Job) bool {
	if job.Environment != "" || len(job.SecretRefs) > 0 || len(job.SecretMappings) > 0 || job.SecretsInherit {
		return true
	}
	permissions := parsed.Permissions
	if job.Permissions != nil {
		permissions = job.Permissions
	}
	if len(permissions) > 0 {
		return true
	}
	for _, step := range job.Steps {
		if len(directStepSecretReferences(step.SecretRefs, nil)) > 0 {
			return true
		}
	}
	return false
}

func reusableCallHasExposureMaterial(job workflow.Job) bool {
	return len(job.SecretMappings) > 0 || job.SecretsInherit
}

func calledJobHasExposureMaterial(parsed *workflow.Workflow, job workflow.Job, call workflow.Job) bool {
	if job.Environment != "" || len(job.SecretRefs) > 0 || len(call.SecretMappings) > 0 || call.SecretsInherit {
		return true
	}
	for _, step := range job.Steps {
		if len(directStepSecretReferences(step.SecretRefs, nil)) > 0 {
			return true
		}
	}
	return len(parsed.SecretRefs) > 0
}

func directStepSecretReferences(references []workflow.SecretReference, mappedNames map[string]string) []string {
	names := make(map[string]struct{})
	for _, reference := range references {
		if reference.Scope != workflow.SecretReferenceStepEnvironment && reference.Scope != workflow.SecretReferenceStepInput {
			continue
		}
		name := strings.ToUpper(reference.Name)
		if mappedNames != nil {
			mapped, ok := mappedNames[name]
			if !ok {
				continue
			}
			name = mapped
		}
		names[name] = struct{}{}
	}
	return sortedSet(names)
}

func sortedMappingSources(values map[string]string) []string {
	set := make(map[string]struct{})
	for _, value := range values {
		set[value] = struct{}{}
	}
	return sortedSet(set)
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func jobDefinitionEvidence(sourceFacts []archive.Fact, execution model.JobExecutionIdentity, definitions ...model.EvidenceID) ([]model.EvidenceID, bool) {
	result := append([]model.EvidenceID(nil), definitions...)
	found := false
	for _, fact := range sourceFacts {
		if fact.Kind == archive.FactJob && fact.Job != nil && fact.Job.Execution == execution {
			result = append(result, fact.EvidenceIDs...)
			found = true
		}
	}
	return model.SortEvidenceIDs(result), found
}

func executionFor(input historicalExposureInput, jobID int64) model.JobExecutionIdentity {
	return model.JobExecutionIdentity{RepositoryID: input.repositoryID, RunID: input.runID, RunAttempt: input.attempt, JobID: model.JobID(jobID)}
}

func hasObservedPermission(source, projected []archive.Fact, execution model.JobExecutionIdentity, permission string) bool {
	for _, fact := range append(append([]archive.Fact(nil), source...), projected...) {
		if fact.Kind != archive.FactExposure || fact.Exposure == nil || fact.Exposure.Execution != execution || fact.Exposure.Credential == nil {
			continue
		}
		credential := fact.Exposure.Credential
		if credential.Kind == model.ExposureGitHubTokenPermission && credential.Permission == permission && credential.Basis != model.ExposureBasisStaticInferred {
			return true
		}
	}
	return false
}

func hasOIDCCapability(source, projected []archive.Fact, execution model.JobExecutionIdentity) bool {
	for _, fact := range append(append([]archive.Fact(nil), source...), projected...) {
		if fact.Kind == archive.FactExposure && fact.Exposure != nil && fact.Exposure.Execution == execution && fact.Exposure.Credential != nil && fact.Exposure.Credential.Kind == model.ExposureOIDCMintingCapability {
			return true
		}
	}
	return false
}

func (o *historicalExposureOutput) addToken(execution model.JobExecutionIdentity, kind model.CredentialExposureKind, permission, access, conclusion string, evidenceIDs []model.EvidenceID, event model.EventInterval) error {
	credential := model.CredentialExposure{
		Kind: kind, Basis: model.ExposureBasisStaticInferred, Permission: permission, Access: access,
		Conclusion: conclusion, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs),
	}
	return o.addCredentialFact(execution, "", credential, event, true)
}

func (o *historicalExposureOutput) addCredential(execution model.JobExecutionIdentity, stepKey string, kind model.CredentialExposureKind, basis model.CredentialExposureBasis, secretName, conclusion string, evidenceIDs []model.EvidenceID, event model.EventInterval) error {
	credential := model.CredentialExposure{Kind: kind, Basis: basis, Conclusion: conclusion, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs)}
	if secretName != "" {
		name, err := model.NewSecretName(secretName)
		if err != nil {
			return err
		}
		credential.SecretName = &name
	}
	return o.addCredentialFact(execution, stepKey, credential, event, false)
}

func (o *historicalExposureOutput) addCredentialFact(execution model.JobExecutionIdentity, stepKey string, credential model.CredentialExposure, event model.EventInterval, staticPermission bool) error {
	if err := event.Validate(); err != nil {
		// Some retained lifecycle source facts have not yet passed through batch
		// normalization. Missing event precision must become an explicit unknown
		// interval, never an invalid zero-value interval or invented timestamp.
		event = unknownTime()
	}
	fact, err := archive.NormalizeFact(archive.Fact{
		Kind: archive.FactExposure, EvidenceIDs: credential.EvidenceIDs,
		Exposure: &archive.ExposureFact{Execution: execution, StepKey: stepKey, Credential: &credential, EventTime: event},
	})
	if err != nil {
		return fmt.Errorf("normalize historical credential exposure: %w", err)
	}
	if !o.addFact(fact) {
		return nil
	}
	if staticPermission {
		o.staticPermissionFacts++
	} else {
		o.secretFlowFacts++
	}
	return nil
}

func (o *historicalExposureOutput) addFact(fact archive.Fact) bool {
	if _, exists := o.seenFactIDs[fact.ID]; exists {
		return false
	}
	o.seenFactIDs[fact.ID] = struct{}{}
	o.facts = append(o.facts, fact)
	return true
}

func (o *historicalExposureOutput) issue(scope string, jobID int64, diagnostic string) {
	o.issues = append(o.issues, historicalExposureIssue{
		reason: collect.GapAmbiguousCorrelation, scope: scope, jobID: jobID,
		diagnostic: safeField(diagnostic, 2048),
	})
}
