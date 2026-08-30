package analyze

import (
	"fmt"
	"strconv"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

// The frozen v1 graph used name-only identities for several exposure nodes.
// Those identities cannot distinguish repository-scoped environments or
// otherwise ambiguous runner, secret, and resource observations. v2 omits
// those compatibility nodes and edges and reprojects them from typed facts.
func isV2ScopedExposureNode(nodeType graph.NodeType) bool {
	switch nodeType {
	case graph.NodeRunner, graph.NodeRunnerGroup, graph.NodeEnvironment,
		graph.NodeSecretMetadata, graph.NodeArtifact, graph.NodePackage,
		graph.NodeRelease, graph.NodeDeployment, graph.NodeRepositoryResource,
		graph.NodePullRequestChange:
		return true
	default:
		return false
	}
}

func isV2ScopedExposureEdge(edgeType graph.EdgeType) bool {
	switch edgeType {
	case graph.EdgeExecutedOnRunner, graph.EdgeRunnerInGroup,
		graph.EdgeReferencedSecret, graph.EdgePassedSecretTo,
		graph.EdgeInheritedSecret, graph.EdgeTargetedEnvironment,
		graph.EdgeCrossedEnvironmentGate, graph.EdgeEnvironmentGateSatisfied,
		graph.EdgeEnvironmentSecretEligible,
		graph.EdgeProducedArtifact, graph.EdgePublishedPackage,
		graph.EdgeCreatedRelease, graph.EdgeCreatedDeployment,
		graph.EdgeRepositoryWrite, graph.EdgePullRequestChange,
		graph.EdgeObservedAfter:
		return true
	default:
		return false
	}
}

type v2ScopedExposureBuilder struct {
	nodes   graphBuilder
	edges   map[string]graph.EdgeV2
	notices map[string]graph.ProjectionNotice
}

func newV2ScopedExposureBuilder() *v2ScopedExposureBuilder {
	return &v2ScopedExposureBuilder{
		nodes:   graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}},
		edges:   map[string]graph.EdgeV2{},
		notices: map[string]graph.ProjectionNotice{},
	}
}

func addV2ScopedExposureContext(idx index, findings []report.Finding, result *graph.GraphV2) error {
	builder := newV2ScopedExposureBuilder()
	for _, finding := range findings {
		execution, ok := findingExecutionForGraph(idx, finding)
		if !ok {
			continue
		}
		if finding.State != string(model.ConfirmedExecuted) {
			if err := builder.projectPendingEnvironment(idx, finding, execution); err != nil {
				return err
			}
			continue
		}
		for _, fact := range idx.exposures {
			if fact.Exposure == nil || fact.Exposure.Execution != execution {
				continue
			}
			exposure := fact.Exposure
			if exposure.StepKey != "" && finding.StepIdentity != "" && exposure.StepKey != finding.StepIdentity {
				continue
			}
			if err := builder.projectFact(fact, finding.FindingRevisionID); err != nil {
				return err
			}
		}
	}
	builder.mergeInto(result)
	return nil
}

func findingExecutionForGraph(idx index, finding report.Finding) (model.JobExecutionIdentity, bool) {
	if finding.RunID <= 0 || finding.RunAttempt <= 0 || finding.JobID <= 0 {
		return model.JobExecutionIdentity{}, false
	}
	repositoryID, ok := repositoryIDForGraph(idx, finding.Repository)
	if !ok {
		return model.JobExecutionIdentity{}, false
	}
	return model.JobExecutionIdentity{
		RepositoryID: repositoryID,
		RunID:        model.WorkflowRunID(finding.RunID),
		RunAttempt:   model.RunAttempt(finding.RunAttempt),
		JobID:        model.JobID(finding.JobID),
	}, true
}

func (b *v2ScopedExposureBuilder) projectPendingEnvironment(idx index, finding report.Finding, execution model.JobExecutionIdentity) error {
	for _, fact := range idx.exposures {
		if fact.Exposure == nil || fact.Exposure.Environment == nil || fact.Exposure.Execution != execution {
			continue
		}
		environment := *fact.Exposure.Environment
		if !isNarrowNonExecutedEnvironmentContext(idx, execution, environment) {
			continue
		}
		evidenceIDs := idsToStrings(fact.EvidenceIDs)
		jobNode := b.nodes.jobNode(execution, evidenceIDs, finding.FindingRevisionID)
		environmentNode := b.environmentNode(execution.RepositoryID, environment.EnvironmentName, evidenceIDs, finding.FindingRevisionID)
		if err := b.addEdge(graph.EdgeTargetedEnvironment, jobNode, environmentNode, evidenceIDs, fact.Exposure.EventTime, graph.EvidenceClassInference, graph.EnvironmentTargetPendingRule, finding.FindingRevisionID); err != nil {
			return fmt.Errorf("project pending environment target: %w", err)
		}
	}
	return nil
}

func (b *v2ScopedExposureBuilder) projectFact(fact archive.Fact, focus string) error {
	exposure := fact.Exposure
	switch {
	case exposure.Credential != nil:
		return b.projectCredential(exposure.Execution, exposure.StepKey, *exposure.Credential, exposure.EventTime, focus)
	case exposure.Resource != nil:
		return b.projectResource(exposure.Execution, exposure.StepKey, *exposure.Resource, exposure.EventTime, focus)
	case exposure.Runner != nil:
		return b.projectRunner(exposure.Execution, *exposure.Runner, idsToStrings(fact.EvidenceIDs), exposure.EventTime, focus)
	case exposure.Environment != nil:
		return b.projectEnvironment(exposure.Execution, *exposure.Environment, idsToStrings(fact.EvidenceIDs), exposure.EventTime, focus)
	default:
		return nil
	}
}

func (b *v2ScopedExposureBuilder) projectCredential(execution model.JobExecutionIdentity, stepKey string, credential model.CredentialExposure, event model.EventInterval, focus string) error {
	var edgeType graph.EdgeType
	switch credential.Kind {
	case model.ExposureSecretReferencedByJob:
		edgeType = graph.EdgeReferencedSecret
	case model.ExposureSecretPassedToStep:
		if stepKey == "" {
			return nil
		}
		edgeType = graph.EdgePassedSecretTo
	case model.ExposureReusableSecretMapped:
		edgeType = graph.EdgePassedSecretTo
	case model.ExposureReusableSecretInherited:
		edgeType = graph.EdgeInheritedSecret
	default:
		// Token capability and OIDC nodes have intentionally shared conceptual
		// identities and remain in the frozen-edge classification path.
		return nil
	}

	evidenceIDs := idsToStrings(credential.EvidenceIDs)
	class, rule, classified := v2CredentialEvidenceClass(credential)
	if !classified {
		b.addNotice(focus, edgeType, evidenceIDs)
		return nil
	}
	jobNode := b.nodes.jobNode(execution, evidenceIDs, focus)
	sourceNode := jobNode
	if stepKey != "" {
		sourceNode = b.nodes.addNode(graph.NodeStep, stepKey, []string{"step", stepKey}, evidenceIDs, focus)
	}
	secretNode := b.secretNode(execution, credential.SecretName, secretFallback(credential.Kind), evidenceIDs, focus)

	var source, target string
	switch edgeType {
	case graph.EdgeReferencedSecret:
		source, target = jobNode, secretNode
	case graph.EdgePassedSecretTo:
		source, target = secretNode, sourceNode
	case graph.EdgeInheritedSecret:
		source, target = sourceNode, secretNode
	}
	if err := b.addEdge(edgeType, source, target, evidenceIDs, event, class, rule, focus); err != nil {
		return fmt.Errorf("project scoped credential relationship: %w", err)
	}
	return nil
}

func v2CredentialEvidenceClass(credential model.CredentialExposure) (graph.EvidenceClass, string, bool) {
	if !credential.Basis.Valid() {
		return "", "", false
	}
	if credential.Basis == model.ExposureBasisRuntimeObserved {
		return graph.EvidenceClassExactObservation, "", true
	}
	return graph.EvidenceClassInference, "credential-relationship/" + string(credential.Basis) + "/v1", true
}

func secretFallback(kind model.CredentialExposureKind) string {
	if kind == model.ExposureReusableSecretInherited {
		return "inherited secret set (names not retained)"
	}
	return "named secret reference"
}

func (b *v2ScopedExposureBuilder) projectRunner(execution model.JobExecutionIdentity, runner archive.RunnerContextFact, evidenceIDs []string, event model.EventInterval, focus string) error {
	identity := []string{graph.SchemaVersionV2, "execution", execution.String(), "runner", runner.Classification, runner.RunnerName}
	if runner.RunnerID != nil {
		identity = append(identity, strconv.FormatInt(*runner.RunnerID, 10))
	} else {
		identity = append(identity, "runner-id-unavailable")
	}
	label := runner.Classification
	if runner.RunnerName != "" {
		label += " / " + runner.RunnerName
	}
	runnerNode := b.nodes.addNode(graph.NodeRunner, label, identity, evidenceIDs, focus)
	jobNode := b.nodes.jobNode(execution, evidenceIDs, focus)
	if err := b.addEdge(graph.EdgeExecutedOnRunner, jobNode, runnerNode, evidenceIDs, event, graph.EvidenceClassExactObservation, "", focus); err != nil {
		return fmt.Errorf("project scoped runner: %w", err)
	}
	if runner.RunnerGroup == "" && runner.RunnerGroupID == nil {
		return nil
	}
	groupLabel := runner.RunnerGroup
	if groupLabel == "" {
		groupLabel = "runner group ID " + strconv.FormatInt(*runner.RunnerGroupID, 10)
	}
	groupNode := b.nodes.addNode(
		graph.NodeRunnerGroup,
		groupLabel,
		runnerGroupIdentity(execution, runner),
		evidenceIDs,
		focus,
	)
	if err := b.addEdge(graph.EdgeRunnerInGroup, runnerNode, groupNode, evidenceIDs, event, graph.EvidenceClassExactObservation, "", focus); err != nil {
		return fmt.Errorf("project scoped runner group: %w", err)
	}
	return nil
}

func runnerGroupIdentity(execution model.JobExecutionIdentity, runner archive.RunnerContextFact) []string {
	identity := []string{graph.SchemaVersionV2, "execution", execution.String(), "runner-group", runner.RunnerGroup}
	if runner.RunnerGroupID != nil {
		identity = append(identity, "runner-group-id", strconv.FormatInt(*runner.RunnerGroupID, 10))
	}
	return identity
}

func (b *v2ScopedExposureBuilder) projectEnvironment(execution model.JobExecutionIdentity, environment archive.EnvironmentEligibilityFact, evidenceIDs []string, event model.EventInterval, focus string) error {
	jobNode := b.nodes.jobNode(execution, evidenceIDs, focus)
	environmentNode := b.environmentNode(execution.RepositoryID, environment.EnvironmentName, evidenceIDs, focus)
	if err := b.addEdge(graph.EdgeTargetedEnvironment, jobNode, environmentNode, evidenceIDs, event, graph.EvidenceClassInference, graph.EnvironmentTargetHistoricalRule, focus); err != nil {
		return fmt.Errorf("project scoped environment target: %w", err)
	}
	if environment.GateRequirementSatisfiedAt(event) {
		rule, ok := graph.EnvironmentGateSatisfiedRuleForState(environment.GateState)
		if !ok {
			return fmt.Errorf("project scoped environment gate: unsupported retained state %q", environment.GateState)
		}
		if err := b.addEdge(graph.EdgeEnvironmentGateSatisfied, jobNode, environmentNode, evidenceIDs, event, graph.EvidenceClassInference, rule, focus); err != nil {
			return fmt.Errorf("project scoped environment gate: %w", err)
		}
	}
	if !environment.GateRequirementSatisfiedAt(event) {
		return nil
	}
	for _, secretName := range environment.SecretNames {
		name := secretName
		secretNode := b.environmentSecretNode(execution, environment.EnvironmentName, &name, evidenceIDs, focus)
		if err := b.addEdge(graph.EdgeEnvironmentSecretEligible, environmentNode, secretNode, evidenceIDs, event, graph.EvidenceClassInference, graphEnvironmentEligibleRule, focus); err != nil {
			return fmt.Errorf("project scoped environment-secret eligibility: %w", err)
		}
	}
	return nil
}

func (b *v2ScopedExposureBuilder) projectResource(execution model.JobExecutionIdentity, stepKey string, resource model.ResourceExposure, event model.EventInterval, focus string) error {
	nodeType, directEdge := resourceGraphTypes(resource.Kind)
	if nodeType == "" {
		return nil
	}
	evidenceIDs := idsToStrings(resource.EvidenceIDs)
	jobNode := b.nodes.jobNode(execution, evidenceIDs, focus)
	sourceNode := jobNode
	if stepKey != "" {
		sourceNode = b.nodes.addNode(graph.NodeStep, stepKey, []string{"step", stepKey}, evidenceIDs, focus)
	}
	resourceNode := b.nodes.addNode(
		nodeType,
		string(resource.Kind)+" / "+resource.ResourceID,
		[]string{graph.SchemaVersionV2, "execution", execution.String(), "resource", string(resource.Kind), resource.ResourceID},
		evidenceIDs,
		focus,
	)
	if resource.Correlation == model.CorrelationObservedAfter {
		if err := b.addEdge(graph.EdgeObservedAfter, sourceNode, resourceNode, evidenceIDs, event, graph.EvidenceClassTemporalCorrelation, graphCorrelationRule, focus); err != nil {
			return fmt.Errorf("project scoped temporal resource: %w", err)
		}
		return nil
	}
	if err := b.addEdge(directEdge, sourceNode, resourceNode, evidenceIDs, event, graph.EvidenceClassExactObservation, "", focus); err != nil {
		return fmt.Errorf("project scoped resource: %w", err)
	}
	return nil
}

func (b *v2ScopedExposureBuilder) environmentNode(repositoryID model.RepositoryID, name string, evidenceIDs []string, focus string) string {
	// Gate state belongs to evidence-linked relationships, not to the stable
	// repository-environment label. This prevents a later pending attempt from
	// inheriting an earlier attempt's crossed-state presentation.
	return b.nodes.addNode(
		graph.NodeEnvironment,
		name,
		[]string{graph.SchemaVersionV2, "repository", strconv.FormatInt(int64(repositoryID), 10), "environment", name},
		evidenceIDs,
		focus,
	)
}

func (b *v2ScopedExposureBuilder) secretNode(execution model.JobExecutionIdentity, name *model.SecretName, fallback string, evidenceIDs []string, focus string) string {
	label, key := fallback, fallback
	if name != nil {
		label, key = string(*name), string(*name)
	}
	// The compact fact model does not retain whether a named secret originated
	// at repository, organization, or environment scope. Execution scoping is
	// therefore the conservative identity: it never asserts that equal names in
	// separate jobs refer to the same credential metadata object.
	return b.nodes.addNode(
		graph.NodeSecretMetadata,
		label,
		[]string{graph.SchemaVersionV2, "execution", execution.String(), "secret-metadata", key},
		evidenceIDs,
		focus,
	)
}

func (b *v2ScopedExposureBuilder) environmentSecretNode(execution model.JobExecutionIdentity, environmentName string, name *model.SecretName, evidenceIDs []string, focus string) string {
	label, key := "environment secret eligibility", "environment secret eligibility"
	if name != nil {
		label, key = string(*name), string(*name)
	}
	return b.nodes.addNode(
		graph.NodeSecretMetadata,
		label,
		[]string{graph.SchemaVersionV2, "execution", execution.String(), "environment", environmentName, "secret-metadata", key},
		evidenceIDs,
		focus,
	)
}

func (b *v2ScopedExposureBuilder) addEdge(edgeType graph.EdgeType, source, target string, evidenceIDs []string, event model.EventInterval, class graph.EvidenceClass, rule, focus string) error {
	edge, err := graph.NewEdgeV2(edgeType, source, target, evidenceIDs, eventText(event), class, rule, []string{focus})
	if err != nil {
		return err
	}
	if current, exists := b.edges[edge.ID]; exists {
		current.EvidenceIDs = append(current.EvidenceIDs, evidenceIDs...)
		current.FocusFindingIDs = append(current.FocusFindingIDs, focus)
		b.edges[edge.ID] = current
	} else {
		b.edges[edge.ID] = edge
	}
	for _, evidenceID := range evidenceIDs {
		b.nodes.addNode(graph.NodeEvidenceObject, evidenceID, []string{"evidence", evidenceID}, []string{evidenceID}, focus)
	}
	return nil
}

func (b *v2ScopedExposureBuilder) addNotice(focus string, relationship graph.EdgeType, evidenceIDs []string) {
	key := focus + "\x00" + string(relationship) + "\x00" + string(graph.ProjectionNoticeUnclassifiableLegacyBasis)
	notice := b.notices[key]
	if notice.Code == "" {
		notice = graph.ProjectionNotice{
			Code: graph.ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus,
			Relationship: relationship,
		}
	}
	notice.EvidenceIDs = append(notice.EvidenceIDs, evidenceIDs...)
	b.notices[key] = notice
}

func (b *v2ScopedExposureBuilder) mergeInto(result *graph.GraphV2) {
	nodeIndex := make(map[string]int, len(result.Nodes)+len(b.nodes.nodes))
	for index := range result.Nodes {
		nodeIndex[result.Nodes[index].ID] = index
	}
	for _, node := range b.nodes.nodes {
		if index, exists := nodeIndex[node.ID]; exists {
			current := &result.Nodes[index]
			current.EvidenceIDs = append(current.EvidenceIDs, node.EvidenceIDs...)
			current.FocusFindingIDs = append(current.FocusFindingIDs, node.FocusFindingIDs...)
			continue
		}
		nodeIndex[node.ID] = len(result.Nodes)
		result.Nodes = append(result.Nodes, node)
	}

	edgeIndex := make(map[string]int, len(result.Edges)+len(b.edges))
	for index := range result.Edges {
		edgeIndex[result.Edges[index].ID] = index
	}
	for _, edge := range b.edges {
		if index, exists := edgeIndex[edge.ID]; exists {
			current := &result.Edges[index]
			current.EvidenceIDs = append(current.EvidenceIDs, edge.EvidenceIDs...)
			current.FocusFindingIDs = append(current.FocusFindingIDs, edge.FocusFindingIDs...)
			continue
		}
		edgeIndex[edge.ID] = len(result.Edges)
		result.Edges = append(result.Edges, edge)
	}

	for _, notice := range b.notices {
		result.ProjectionNotices = append(result.ProjectionNotices, notice)
	}
}
