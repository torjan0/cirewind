package analyze

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/match"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const (
	graphFindingRule       = match.RuleVersion
	graphCorrelationRule   = "resource-correlation/v1"
	graphContradictionRule = "archived-contradiction/v1"
)

type graphBuilder struct {
	nodes map[string]graph.Node
	edges map[string]graph.Edge
}

func buildGraph(idx index, findings []report.Finding) graph.Graph {
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	for _, finding := range findings {
		builder.projectFinding(idx, finding)
	}
	result := graph.Graph{SchemaVersion: graph.SchemaVersion}
	for _, node := range builder.nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, edge := range builder.edges {
		result.Edges = append(result.Edges, edge)
	}
	return result
}

func (b *graphBuilder) projectFinding(idx index, finding report.Finding) {
	focus := finding.FindingRevisionID
	findingNode := b.addNode(
		graph.NodeFinding,
		finding.State+" / "+finding.Provenance,
		[]string{"finding", finding.FindingRevisionID},
		finding.EvidenceIDs,
		focus,
	)

	for _, evidenceID := range finding.EvidenceIDs {
		evidenceNode := b.addNode(graph.NodeEvidenceObject, evidenceID, []string{"evidence", evidenceID}, []string{evidenceID}, focus)
		b.addEdge(graph.EdgeSupportedByEvidence, findingNode, evidenceNode, []string{evidenceID}, finding.EventTime, false, "", focus)
	}

	repositoryID, found := repositoryIDForGraph(idx, finding.Repository)
	if !found {
		return
	}
	repositoryEvidence := evidenceStrings(idx.repositoryFacts[repositoryID])
	repositoryNode := b.addNode(graph.NodeRepository, finding.Repository, []string{"repository", strconv.FormatInt(int64(repositoryID), 10)}, repositoryEvidence, focus)
	subjectNode := repositoryNode

	if finding.RunID > 0 {
		runID := model.WorkflowRunID(finding.RunID)
		runKeyValue := runKey(repositoryID, runID)
		runLabel := fmt.Sprintf("run %d", runID)
		if run, ok := idx.runs[runKeyValue]; ok && run.WorkflowPath != nil {
			runLabel += " / " + string(*run.WorkflowPath)
		}
		runFact := idx.runFacts[runKeyValue]
		runNode := b.addNode(graph.NodeWorkflowRun, runLabel, []string{"run", strconv.FormatInt(int64(repositoryID), 10), strconv.FormatInt(int64(runID), 10)}, evidenceStrings(runFact), focus)
		b.addFactEdge(graph.EdgeRunInRepository, repositoryNode, runNode, runFact, focus, false, "")
		subjectNode = runNode

		if finding.RunAttempt > 0 {
			attempt := model.RunAttempt(finding.RunAttempt)
			attemptKeyValue := attemptKey(repositoryID, runID, attempt)
			attemptFact := idx.attemptFacts[attemptKeyValue]
			attemptNode := b.addNode(graph.NodeRunAttempt, fmt.Sprintf("run %d / attempt %d", runID, attempt), []string{"attempt", strconv.FormatInt(int64(repositoryID), 10), strconv.FormatInt(int64(runID), 10), strconv.FormatUint(uint64(attempt), 10)}, evidenceStrings(attemptFact), focus)
			b.addFactEdge(graph.EdgeAttemptOfRun, attemptNode, runNode, attemptFact, focus, false, "")
			subjectNode = attemptNode

			if finding.JobID > 0 {
				execution := model.JobExecutionIdentity{RepositoryID: repositoryID, RunID: runID, RunAttempt: attempt, JobID: model.JobID(finding.JobID)}
				jobFact := idx.jobFacts[execution.String()]
				jobLabel := fmt.Sprintf("job %d", execution.JobID)
				if job, ok := idx.jobs[execution.String()]; ok && job.DisplayName != "" {
					jobLabel += " / " + job.DisplayName
				}
				jobNode := b.addNode(graph.NodeJob, jobLabel, []string{"job", execution.String()}, evidenceStrings(jobFact), focus)
				b.addFactEdge(graph.EdgeJobExecutedInAttempt, attemptNode, jobNode, jobFact, focus, false, "")
				subjectNode = jobNode

				if finding.StepIdentity != "" {
					stepNode := b.addNode(graph.NodeStep, finding.StepIdentity, []string{"step", finding.StepIdentity}, nil, focus)
					// The finding evidence proves the exact finding subject. It does
					// not turn a step into an execution observation; the Action edge
					// below retains that separate lifecycle evidence.
					b.addEdge(graph.EdgeStepInJob, jobNode, stepNode, finding.EvidenceIDs, finding.EventTime, true, graphFindingRule, focus)
					subjectNode = stepNode
				}
			}
		}
	}

	if len(finding.EvidenceIDs) > 0 {
		b.addEdge(graph.EdgeFindingAbout, findingNode, subjectNode, finding.EvidenceIDs, finding.EventTime, true, graphFindingRule, focus)
	}

	matchedFacts := b.projectFindingFacts(idx, finding, repositoryID)
	for _, target := range matchedFacts {
		if len(finding.EvidenceIDs) > 0 && target != "" && target != subjectNode {
			b.addEdge(graph.EdgeFindingAbout, findingNode, target, finding.EvidenceIDs, finding.EventTime, true, graphFindingRule, focus)
		}
	}

	if finding.State == string(model.ConfirmedExecuted) && finding.RunID > 0 && finding.RunAttempt > 0 && finding.JobID > 0 {
		b.projectExposures(idx, finding, repositoryID)
	}
}

func (b *graphBuilder) projectFindingFacts(idx index, finding report.Finding, repositoryID model.RepositoryID) []string {
	focus := finding.FindingRevisionID
	wantedEvidence := stringSet(finding.EvidenceIDs)
	var targets []string
	for _, fact := range idx.actions {
		if !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wantedEvidence) {
			continue
		}
		if target := b.projectRuntimeAction(fact, focus); target != "" {
			targets = append(targets, target)
		}
	}
	for _, fact := range idx.dependencies {
		if !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wantedEvidence) {
			continue
		}
		if target := b.projectDependency(idx, fact, focus, true); target != "" {
			targets = append(targets, target)
		}
	}
	return uniqueStrings(targets)
}

func (b *graphBuilder) projectRuntimeAction(fact archive.Fact, focus string) string {
	if fact.ActionOccurrence == nil {
		return ""
	}
	observation := fact.ActionOccurrence.Observation
	evidenceIDs := idsToStrings(fact.EvidenceIDs)
	actionRepository := b.addNode(graph.NodeActionRepository, string(observation.ActionRepository), []string{"action-repository", string(observation.ActionRepository)}, evidenceIDs, focus)
	exactTargets := b.runtimeExactTargets(observation, evidenceIDs, focus)
	primaryTarget := actionRepository
	if len(exactTargets) > 0 {
		primaryTarget = exactTargets[0]
	}

	if observation.DeclaredRef != "" {
		refLabel := actionReferenceLabel(observation.ActionRepository, observation.ActionSubpath, observation.DeclaredRef)
		refNode := b.addNode(graph.NodeActionRef, refLabel, []string{"action-ref", string(observation.ActionRepository), observation.ActionSubpath, observation.DeclaredRef}, evidenceIDs, focus)
		for _, exactTarget := range exactTargets {
			b.addEdge(graph.EdgeRefResolvedTo, refNode, exactTarget, evidenceIDs, eventText(observation.EventTime), false, "", focus)
		}
	}

	jobNode := b.jobNode(observation.Execution, evidenceIDs, focus)
	if observation.Step == nil {
		if observation.Kind.SupportsDownloaded() {
			b.addEdge(graph.EdgeJobPreparedAction, jobNode, primaryTarget, evidenceIDs, eventText(observation.EventTime), false, "", focus)
		}
		return primaryTarget
	}
	stepNode := b.stepNode(*observation.Step, evidenceIDs, focus)
	b.addEdge(graph.EdgeStepInJob, jobNode, stepNode, evidenceIDs, eventText(observation.EventTime), false, "", focus)
	if observation.Kind.SupportsDownloaded() {
		b.addEdge(graph.EdgeStepDownloadedAction, stepNode, primaryTarget, evidenceIDs, eventText(observation.EventTime), false, "", focus)
	}
	if observation.Kind.SupportsExecuted() {
		b.addEdge(graph.EdgeStepExecutedAction, stepNode, primaryTarget, evidenceIDs, eventText(observation.EventTime), false, "", focus)
	}
	return primaryTarget
}

func (b *graphBuilder) runtimeExactTargets(observation model.RuntimeActionObservation, evidenceIDs []string, focus string) []string {
	var targets []string
	var commitNode string
	if observation.SourceObjectID != nil {
		object := model.GitObjectID(*observation.SourceObjectID)
		commitNode = b.addNode(
			graph.NodeActionCommit,
			actionIdentityLabel(observation.ActionRepository, observation.ActionSubpath, object),
			[]string{"action-commit", string(observation.ActionRepository), observation.ActionSubpath, string(object.Algorithm), object.Value},
			evidenceIDs,
			focus,
		)
		targets = append(targets, commitNode)
	}
	if observation.PackageDigest != nil {
		digest := *observation.PackageDigest
		packageNode := b.addNode(
			graph.NodeImmutableActionPackage,
			fmt.Sprintf("%s %s:%s", observation.ActionRepository, digest.Subject, digest.Value),
			[]string{"immutable-action-package", string(observation.ActionRepository), observation.ActionSubpath, string(digest.Subject), string(digest.Algorithm), digest.Value},
			evidenceIDs,
			focus,
		)
		targets = append(targets, packageNode)
		if commitNode != "" {
			b.addEdge(graph.EdgePackageSourceCommit, packageNode, commitNode, evidenceIDs, eventText(observation.EventTime), false, "", focus)
		}
	}
	return targets
}

func (b *graphBuilder) projectDependency(idx index, fact archive.Fact, focus string, includeContradictions bool) string {
	if fact.Dependency == nil {
		return ""
	}
	dependency := *fact.Dependency
	evidenceIDs := idsToStrings(fact.EvidenceIDs)
	source := b.dependencySource(dependency, evidenceIDs, focus)
	if source == "" {
		return ""
	}
	target, exactTarget, refTarget := b.dependencyTarget(dependency, evidenceIDs, focus)
	if target == "" {
		return ""
	}

	relation := dependencyEdgeType(dependency.Relation)
	// REF_RESOLVED_TO is a relation from the declared Action ref to the
	// exact object, not from the containing workflow to the ref. The caller
	// fields retain provenance for the resolution fact, but are not an edge
	// endpoint for this relation.
	if relation != "" && dependency.Relation != archive.DependencyRefResolvedTo {
		b.addEdge(relation, source, target, evidenceIDs, eventText(dependency.EventTime), false, "", focus)
	}
	if refTarget != "" && exactTarget != "" {
		b.addEdge(graph.EdgeRefResolvedTo, refTarget, exactTarget, evidenceIDs, eventText(dependency.EventTime), false, "", focus)
	}
	if dependency.Basis == archive.DefinitionHistoricalAtRun && dependency.CallerWorkflowObjectID != nil && dependency.Execution != nil {
		runNode := b.runNode(dependency.Execution.RepositoryID, dependency.Execution.RunID, evidenceIDs, focus)
		b.addEdge(graph.EdgeRunInstantiatedWorkflow, runNode, source, evidenceIDs, eventText(dependency.EventTime), false, "", focus)
	}
	if includeContradictions && exactTarget != "" {
		for _, contradictedID := range dependency.ContradictsFactIDs {
			other, ok := idx.factsByID[contradictedID]
			if !ok || other.Dependency == nil {
				continue
			}
			otherTarget := b.projectDependency(idx, other, focus, false)
			if otherTarget == "" || otherTarget == exactTarget {
				continue
			}
			combined := append(idsToStrings(fact.EvidenceIDs), idsToStrings(other.EvidenceIDs)...)
			b.addEdge(graph.EdgeContradicts, exactTarget, otherTarget, combined, eventText(dependency.EventTime), false, graphContradictionRule, focus)
		}
	}
	if exactTarget != "" {
		return exactTarget
	}
	return target
}

func (b *graphBuilder) dependencySource(dependency archive.DependencyFact, evidenceIDs []string, focus string) string {
	if dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && dependency.AttemptExecution != nil {
		return b.attemptNode(*dependency.AttemptExecution, evidenceIDs, focus)
	}
	if dependency.CallerWorkflowObjectID != nil {
		object := model.GitObjectID(*dependency.CallerWorkflowObjectID)
		return b.addNode(
			graph.NodeWorkflowDefinition,
			fmt.Sprintf("%s/%s @ %s:%s", dependency.CallerRepository, dependency.CallerPath, object.Algorithm, object.Value),
			[]string{"workflow-definition", string(dependency.CallerRepository), dependency.CallerPath, string(object.Algorithm), object.Value},
			evidenceIDs,
			focus,
		)
	}
	if dependency.CallerActionObjectID != nil {
		object := model.GitObjectID(*dependency.CallerActionObjectID)
		return b.addNode(
			graph.NodeActionDefinition,
			fmt.Sprintf("%s/%s @ %s:%s", dependency.CallerRepository, dependency.CallerPath, object.Algorithm, object.Value),
			[]string{"action-definition", string(dependency.CallerRepository), dependency.CallerPath, string(object.Algorithm), object.Value},
			evidenceIDs,
			focus,
		)
	}
	// Current snapshots are deliberately distinct from historical definitions.
	// The basis is part of the identity and visible in the label.
	if dependency.CallerPath != "" {
		return b.addNode(
			graph.NodeWorkflowDefinition,
			fmt.Sprintf("%s/%s [%s]", dependency.CallerRepository, dependency.CallerPath, dependency.Basis),
			[]string{"workflow-definition-unbound", string(dependency.CallerRepository), dependency.CallerPath, string(dependency.Basis)},
			evidenceIDs,
			focus,
		)
	}
	return ""
}

// dependencyTarget returns the declaration target, exact target, and ref node.
// When a declaration has a ref and an exact identity, the caller points at the
// ref and a separate REF_RESOLVED_TO edge preserves the exact resolution.
func (b *graphBuilder) dependencyTarget(dependency archive.DependencyFact, evidenceIDs []string, focus string) (string, string, string) {
	var exact string
	switch {
	case dependency.TargetCalledWorkflowObjectID != nil:
		object := model.GitObjectID(*dependency.TargetCalledWorkflowObjectID)
		exact = b.addNode(
			graph.NodeReusableWorkflowDefinition,
			fmt.Sprintf("%s/%s @ %s:%s", dependency.TargetRepository, dependency.TargetPath, object.Algorithm, object.Value),
			[]string{"reusable-workflow-definition", string(dependency.TargetRepository), dependency.TargetPath, string(object.Algorithm), object.Value},
			evidenceIDs,
			focus,
		)
	case dependency.TargetActionObjectID != nil:
		object := model.GitObjectID(*dependency.TargetActionObjectID)
		nodeType := graph.NodeActionCommit
		identityKind := "action-commit"
		if dependency.TargetKind == archive.DependencyTargetLocalAction {
			nodeType = graph.NodeActionDefinition
			identityKind = "action-definition"
		}
		exact = b.addNode(
			nodeType,
			actionIdentityLabel(dependency.TargetRepository, dependency.TargetPath, object),
			[]string{identityKind, string(dependency.TargetRepository), dependency.TargetPath, string(object.Algorithm), object.Value},
			evidenceIDs,
			focus,
		)
	case dependency.PackageDigest != nil:
		digest := *dependency.PackageDigest
		exact = b.addNode(
			graph.NodeImmutableActionPackage,
			fmt.Sprintf("%s %s:%s", dependency.TargetRepository, digest.Subject, digest.Value),
			[]string{"immutable-action-package", string(dependency.TargetRepository), dependency.TargetPath, string(digest.Subject), string(digest.Algorithm), digest.Value},
			evidenceIDs,
			focus,
		)
	}
	if dependency.Basis == archive.DefinitionRuntimeAttemptMetadata && exact != "" {
		return exact, exact, ""
	}
	if dependency.DeclaredRef != "" {
		ref := b.addNode(
			graph.NodeActionRef,
			actionReferenceLabel(dependency.TargetRepository, dependency.TargetPath, dependency.DeclaredRef),
			[]string{"dependency-ref", string(dependency.TargetKind), string(dependency.TargetRepository), dependency.TargetPath, dependency.DeclaredRef},
			evidenceIDs,
			focus,
		)
		return ref, exact, ref
	}
	if exact != "" {
		return exact, exact, ""
	}
	repository := b.addNode(graph.NodeActionRepository, string(dependency.TargetRepository), []string{"action-repository", string(dependency.TargetRepository)}, evidenceIDs, focus)
	return repository, "", ""
}

func (b *graphBuilder) projectExposures(idx index, finding report.Finding, repositoryID model.RepositoryID) {
	execution := model.JobExecutionIdentity{
		RepositoryID: repositoryID,
		RunID:        model.WorkflowRunID(finding.RunID),
		RunAttempt:   model.RunAttempt(finding.RunAttempt),
		JobID:        model.JobID(finding.JobID),
	}
	focus := finding.FindingRevisionID
	for _, fact := range idx.exposures {
		if fact.Exposure == nil || fact.Exposure.Execution != execution {
			continue
		}
		exposure := fact.Exposure
		if exposure.StepKey != "" && finding.StepIdentity != "" && exposure.StepKey != finding.StepIdentity {
			continue
		}
		evidenceIDs := idsToStrings(fact.EvidenceIDs)
		jobNode := b.jobNode(execution, evidenceIDs, focus)
		sourceNode := jobNode
		if exposure.StepKey != "" {
			sourceNode = b.addNode(graph.NodeStep, exposure.StepKey, []string{"step", exposure.StepKey}, evidenceIDs, focus)
			b.addEdge(graph.EdgeStepInJob, jobNode, sourceNode, evidenceIDs, eventText(exposure.EventTime), false, "", focus)
		}
		switch {
		case exposure.Credential != nil:
			b.projectCredential(*exposure.Credential, sourceNode, jobNode, exposure.StepKey != "", exposure.EventTime, focus)
		case exposure.Resource != nil:
			b.projectResource(*exposure.Resource, sourceNode, exposure.EventTime, focus)
		case exposure.Runner != nil:
			b.projectRunner(*exposure.Runner, jobNode, evidenceIDs, exposure.EventTime, focus)
		case exposure.Environment != nil:
			b.projectEnvironment(*exposure.Environment, jobNode, evidenceIDs, exposure.EventTime, focus)
		}
	}
}

func (b *graphBuilder) projectCredential(credential model.CredentialExposure, sourceNode, jobNode string, hasStep bool, event model.EventInterval, focus string) {
	evidenceIDs := idsToStrings(credential.EvidenceIDs)
	switch credential.Kind {
	case model.ExposureGitHubTokenPermission:
		label := "GITHUB_TOKEN " + credential.Permission + ":" + credential.Access
		token := b.addNode(graph.NodeTokenCapability, label, []string{"token-capability", credential.Permission, credential.Access}, evidenceIDs, focus)
		b.addEdge(graph.EdgeHadTokenPermission, jobNode, token, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureOIDCMintingCapability:
		provider := b.addNode(graph.NodeOIDCProvider, "GitHub Actions OIDC token service", []string{"oidc-provider", "github-actions"}, evidenceIDs, focus)
		b.addEdge(graph.EdgeCouldMintOIDC, jobNode, provider, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureSecretReferencedByJob:
		secret := b.secretNode(credential.SecretName, "named secret reference", evidenceIDs, focus)
		b.addEdge(graph.EdgeReferencedSecret, jobNode, secret, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureSecretPassedToStep:
		if !hasStep {
			return
		}
		secret := b.secretNode(credential.SecretName, "named secret reference", evidenceIDs, focus)
		b.addEdge(graph.EdgePassedSecretTo, secret, sourceNode, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureReusableSecretMapped:
		secret := b.secretNode(credential.SecretName, "mapped secret reference", evidenceIDs, focus)
		b.addEdge(graph.EdgePassedSecretTo, secret, sourceNode, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureReusableSecretInherited:
		secret := b.secretNode(credential.SecretName, "inherited secret set (names not retained)", evidenceIDs, focus)
		b.addEdge(graph.EdgeInheritedSecret, sourceNode, secret, evidenceIDs, eventText(event), false, "", focus)
	case model.ExposureEnvironmentSecretEligible:
		// Eligibility needs the environment context to name and gate the source.
		// An isolated credential row cannot safely invent that context.
		return
	}
}

func (b *graphBuilder) projectRunner(runner archive.RunnerContextFact, jobNode string, evidenceIDs []string, event model.EventInterval, focus string) {
	identity := runner.Classification + ":" + runner.RunnerName
	if runner.RunnerID != nil {
		identity += ":" + strconv.FormatInt(*runner.RunnerID, 10)
	}
	label := runner.Classification
	if runner.RunnerName != "" {
		label += " / " + runner.RunnerName
	}
	runnerNode := b.addNode(graph.NodeRunner, label, []string{"runner", identity}, evidenceIDs, focus)
	b.addEdge(graph.EdgeExecutedOnRunner, jobNode, runnerNode, evidenceIDs, eventText(event), false, "", focus)
	if runner.RunnerGroup != "" {
		groupNode := b.addNode(graph.NodeRunnerGroup, runner.RunnerGroup, []string{"runner-group", runner.RunnerGroup}, evidenceIDs, focus)
		b.addEdge(graph.EdgeRunnerInGroup, runnerNode, groupNode, evidenceIDs, eventText(event), false, "", focus)
	}
}

func (b *graphBuilder) projectEnvironment(environment archive.EnvironmentEligibilityFact, jobNode string, evidenceIDs []string, event model.EventInterval, focus string) {
	environmentNode := b.addNode(graph.NodeEnvironment, environment.EnvironmentName+" / gate "+environment.GateState, []string{"environment", environment.EnvironmentName}, evidenceIDs, focus)
	b.addEdge(graph.EdgeTargetedEnvironment, jobNode, environmentNode, evidenceIDs, eventText(event), false, "", focus)
	crossed := environment.JobStarted && (environment.GateState == "approved" || environment.GateState == "bypassed" || environment.GateState == "crossed" || environment.GateState == "not-required")
	if !crossed {
		return
	}
	b.addEdge(graph.EdgeCrossedEnvironmentGate, jobNode, environmentNode, evidenceIDs, eventText(event), false, "", focus)
	for _, secretName := range environment.SecretNames {
		name := secretName
		secret := b.secretNode(&name, "environment secret eligibility", evidenceIDs, focus)
		b.addEdge(graph.EdgeEnvironmentSecretEligible, environmentNode, secret, evidenceIDs, eventText(event), false, "", focus)
	}
}

func (b *graphBuilder) projectResource(resource model.ResourceExposure, sourceNode string, event model.EventInterval, focus string) {
	evidenceIDs := idsToStrings(resource.EvidenceIDs)
	nodeType, directEdge := resourceGraphTypes(resource.Kind)
	if nodeType == "" {
		return
	}
	resourceNode := b.addNode(nodeType, string(resource.Kind)+" / "+resource.ResourceID, []string{"resource", string(resource.Kind), resource.ResourceID}, evidenceIDs, focus)
	if resource.Correlation == model.CorrelationObservedAfter {
		b.addEdge(graph.EdgeObservedAfter, sourceNode, resourceNode, evidenceIDs, eventText(event), true, graphCorrelationRule, focus)
		return
	}
	b.addEdge(directEdge, sourceNode, resourceNode, evidenceIDs, eventText(event), false, "", focus)
}

func resourceGraphTypes(kind model.ResourceExposureKind) (graph.NodeType, graph.EdgeType) {
	switch kind {
	case model.ResourceArtifact:
		return graph.NodeArtifact, graph.EdgeProducedArtifact
	case model.ResourcePackage:
		return graph.NodePackage, graph.EdgePublishedPackage
	case model.ResourceRelease:
		return graph.NodeRelease, graph.EdgeCreatedRelease
	case model.ResourceDeployment:
		return graph.NodeDeployment, graph.EdgeCreatedDeployment
	case model.ResourceRepositoryWrite:
		return graph.NodeRepositoryResource, graph.EdgeRepositoryWrite
	case model.ResourcePullRequestChange:
		return graph.NodePullRequestChange, graph.EdgePullRequestChange
	default:
		return "", ""
	}
}

func (b *graphBuilder) secretNode(name *model.SecretName, fallback string, evidenceIDs []string, focus string) string {
	label := fallback
	key := fallback
	if name != nil {
		label = string(*name)
		key = string(*name)
	}
	return b.addNode(graph.NodeSecretMetadata, label, []string{"secret-metadata", key}, evidenceIDs, focus)
}

func (b *graphBuilder) runNode(repositoryID model.RepositoryID, runID model.WorkflowRunID, evidenceIDs []string, focus string) string {
	return b.addNode(graph.NodeWorkflowRun, fmt.Sprintf("run %d", runID), []string{"run", strconv.FormatInt(int64(repositoryID), 10), strconv.FormatInt(int64(runID), 10)}, evidenceIDs, focus)
}

func (b *graphBuilder) attemptNode(identity model.RunAttemptIdentity, evidenceIDs []string, focus string) string {
	return b.addNode(graph.NodeRunAttempt, fmt.Sprintf("run %d / attempt %d", identity.RunID, identity.RunAttempt), []string{"attempt", strconv.FormatInt(int64(identity.RepositoryID), 10), strconv.FormatInt(int64(identity.RunID), 10), strconv.FormatUint(uint64(identity.RunAttempt), 10)}, evidenceIDs, focus)
}

func (b *graphBuilder) jobNode(identity model.JobExecutionIdentity, evidenceIDs []string, focus string) string {
	return b.addNode(graph.NodeJob, fmt.Sprintf("job %d", identity.JobID), []string{"job", identity.String()}, evidenceIDs, focus)
}

func (b *graphBuilder) stepNode(identity model.StepIdentity, evidenceIDs []string, focus string) string {
	return b.addNode(graph.NodeStep, identity.Key(), []string{"step", identity.Key()}, evidenceIDs, focus)
}

func (b *graphBuilder) addFactEdge(edgeType graph.EdgeType, source, target string, fact archive.Fact, focus string, inferred bool, rule string) {
	if len(fact.EvidenceIDs) == 0 {
		return
	}
	b.addEdge(edgeType, source, target, idsToStrings(fact.EvidenceIDs), eventText(fact.EventTime), inferred, rule, focus)
}

func (b *graphBuilder) addNode(nodeType graph.NodeType, label string, identity []string, evidenceIDs []string, focus string) string {
	id := deterministicID("gnode1", append([]string{string(nodeType)}, identity...)...)
	label = sanitize.Terminal(label, 4_096)
	if label == "" {
		label = "[unavailable]"
	}
	node, exists := b.nodes[id]
	if !exists {
		node = graph.Node{ID: id, Type: nodeType, Label: label}
	} else if label < node.Label {
		// Same typed identity should have one label. Selecting the lexical label
		// keeps hostile input order from influencing deterministic output.
		node.Label = label
	}
	node.EvidenceIDs = append(node.EvidenceIDs, evidenceIDs...)
	if focus != "" {
		node.FocusFindingIDs = append(node.FocusFindingIDs, focus)
	}
	b.nodes[id] = node
	return id
}

func (b *graphBuilder) addEdge(edgeType graph.EdgeType, source, target string, evidenceIDs []string, eventTime string, inferred bool, rule, focus string) {
	if source == "" || target == "" || source == target || len(evidenceIDs) == 0 {
		return
	}
	id := deterministicID("gedge1", string(edgeType), source, target, eventTime, rule, strconv.FormatBool(inferred))
	edge, exists := b.edges[id]
	if !exists {
		edge = graph.Edge{ID: id, Type: edgeType, Source: source, Target: target, EventTime: eventTime, Inferred: inferred, DerivationRule: rule}
	}
	edge.EvidenceIDs = append(edge.EvidenceIDs, evidenceIDs...)
	if focus != "" {
		edge.FocusFindingIDs = append(edge.FocusFindingIDs, focus)
	}
	b.edges[id] = edge
	for _, evidenceID := range evidenceIDs {
		b.addNode(graph.NodeEvidenceObject, evidenceID, []string{"evidence", evidenceID}, []string{evidenceID}, focus)
	}
}

func dependencyEdgeType(relation archive.DependencyRelation) graph.EdgeType {
	switch relation {
	case archive.DependencyWorkflowDeclaredAction:
		return graph.EdgeWorkflowDeclaredAction
	case archive.DependencyWorkflowCalledWorkflow:
		return graph.EdgeWorkflowCalledWorkflow
	case archive.DependencyActionContainsAction:
		return graph.EdgeActionContainsAction
	case archive.DependencyLocalActionResolvedTo:
		return graph.EdgeLocalActionResolvedTo
	case archive.DependencyRefResolvedTo:
		return graph.EdgeRefResolvedTo
	default:
		return ""
	}
}

func repositoryIDForGraph(idx index, repository string) (model.RepositoryID, bool) {
	for id, subject := range idx.repositories {
		if string(subject.Name) == repository {
			return id, true
		}
	}
	return 0, false
}

func factMatchesFinding(fact archive.Fact, finding report.Finding, repositoryID model.RepositoryID) bool {
	if fact.Subject.RepositoryID != repositoryID {
		return false
	}
	if finding.RunID > 0 && (fact.Subject.RunID == nil || int64(*fact.Subject.RunID) != finding.RunID) {
		return false
	}
	if finding.RunAttempt > 0 && (fact.Subject.RunAttempt == nil || int(*fact.Subject.RunAttempt) != finding.RunAttempt) {
		return false
	}
	if finding.JobID > 0 && (fact.Subject.JobID == nil || int64(*fact.Subject.JobID) != finding.JobID) {
		return false
	}
	if finding.StepIdentity != "" && fact.Subject.StepKey != "" && fact.Subject.StepKey != finding.StepIdentity {
		return false
	}
	return true
}

func evidenceIntersects(ids []model.EvidenceID, wanted map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := wanted[string(id)]; ok {
			return true
		}
	}
	return false
}

func evidenceStrings(fact archive.Fact) []string { return idsToStrings(fact.EvidenceIDs) }

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func uniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func actionReferenceLabel(repository model.RepositorySlug, subpath, ref string) string {
	name := string(repository)
	if subpath != "" {
		name += "/" + subpath
	}
	return name + "@" + ref
}

func actionIdentityLabel(repository model.RepositorySlug, subpath string, object model.GitObjectID) string {
	name := string(repository)
	if subpath != "" {
		name += "/" + subpath
	}
	return fmt.Sprintf("%s @ %s:%s", name, object.Algorithm, object.Value)
}
