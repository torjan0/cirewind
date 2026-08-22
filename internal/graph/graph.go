// Package graph defines CIRewind's disposable evidence-linked graph projection.
package graph

import (
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/model"
)

const SchemaVersion = "cirewind.graph/v1alpha1"

const (
	maxNodes       = 100_000
	maxEdges       = 250_000
	maxIDBytes     = 2_048
	maxLabelBytes  = 4_096
	maxRuleBytes   = 256
	maxEventBytes  = 4_096
	maxEvidenceIDs = 10_000
)

// NodeType is a closed v0.1 graph vocabulary. Display names and hostile source
// values are labels, never node identities or node types.
type NodeType string

const (
	NodeRepository                 NodeType = "Repository"
	NodeWorkflowDefinition         NodeType = "WorkflowDefinition"
	NodeReusableWorkflowDefinition NodeType = "ReusableWorkflowDefinition"
	NodeWorkflowRun                NodeType = "WorkflowRun"
	NodeRunAttempt                 NodeType = "RunAttempt"
	NodeJob                        NodeType = "Job"
	NodeStep                       NodeType = "Step"
	NodeActionRepository           NodeType = "ActionRepository"
	NodeActionRef                  NodeType = "ActionRef"
	NodeActionCommit               NodeType = "ActionCommit"
	NodeImmutableActionPackage     NodeType = "ImmutableActionPackage"
	NodeActionDefinition           NodeType = "ActionDefinition"
	NodeRunner                     NodeType = "Runner"
	NodeRunnerGroup                NodeType = "RunnerGroup"
	NodeEnvironment                NodeType = "Environment"
	NodeTokenCapability            NodeType = "TokenCapability"
	NodeSecretMetadata             NodeType = "SecretMetadata"
	NodeOIDCProvider               NodeType = "OIDCProvider"
	NodeArtifact                   NodeType = "Artifact"
	NodePackage                    NodeType = "Package"
	NodeRelease                    NodeType = "Release"
	NodeDeployment                 NodeType = "Deployment"
	NodeRepositoryResource         NodeType = "RepositoryResource"
	NodePullRequestChange          NodeType = "PullRequestChange"
	NodeEvidenceObject             NodeType = "EvidenceObject"
	NodeFinding                    NodeType = "Finding"
)

func (t NodeType) valid() bool {
	switch t {
	case NodeRepository, NodeWorkflowDefinition, NodeReusableWorkflowDefinition,
		NodeWorkflowRun, NodeRunAttempt, NodeJob, NodeStep, NodeActionRepository,
		NodeActionRef, NodeActionCommit, NodeImmutableActionPackage,
		NodeActionDefinition, NodeRunner, NodeRunnerGroup, NodeEnvironment,
		NodeTokenCapability, NodeSecretMetadata, NodeOIDCProvider, NodeArtifact,
		NodePackage, NodeRelease, NodeDeployment, NodeRepositoryResource,
		NodePullRequestChange, NodeEvidenceObject, NodeFinding:
		return true
	default:
		return false
	}
}

// EdgeType is a closed relationship vocabulary. It deliberately separates
// preparation, execution, capability, eligibility, direct attribution, and
// temporal correlation.
type EdgeType string

const (
	EdgeRunInRepository           EdgeType = "RUN_IN_REPOSITORY"
	EdgeAttemptOfRun              EdgeType = "ATTEMPT_OF_RUN"
	EdgeJobExecutedInAttempt      EdgeType = "JOB_EXECUTED_IN_ATTEMPT"
	EdgeStepInJob                 EdgeType = "STEP_IN_JOB"
	EdgeRunInstantiatedWorkflow   EdgeType = "RUN_INSTANTIATED_WORKFLOW"
	EdgeWorkflowDeclaredAction    EdgeType = "WORKFLOW_DECLARED_ACTION"
	EdgeWorkflowCalledWorkflow    EdgeType = "WORKFLOW_CALLED_WORKFLOW"
	EdgeActionContainsAction      EdgeType = "ACTION_CONTAINS_ACTION"
	EdgeLocalActionResolvedTo     EdgeType = "LOCAL_ACTION_RESOLVED_TO"
	EdgeRefResolvedTo             EdgeType = "REF_RESOLVED_TO"
	EdgePackageSourceCommit       EdgeType = "PACKAGE_SOURCE_COMMIT"
	EdgeJobPreparedAction         EdgeType = "JOB_PREPARED_ACTION"
	EdgeStepDownloadedAction      EdgeType = "STEP_DOWNLOADED_ACTION"
	EdgeStepExecutedAction        EdgeType = "STEP_EXECUTED_ACTION"
	EdgeExecutedOnRunner          EdgeType = "EXECUTED_ON_RUNNER"
	EdgeRunnerInGroup             EdgeType = "RUNNER_IN_GROUP"
	EdgeHadTokenPermission        EdgeType = "HAD_TOKEN_PERMISSION"
	EdgeReferencedSecret          EdgeType = "REFERENCED_SECRET"
	EdgePassedSecretTo            EdgeType = "PASSED_SECRET_TO"
	EdgeInheritedSecret           EdgeType = "INHERITED_SECRET"
	EdgeTargetedEnvironment       EdgeType = "TARGETED_ENVIRONMENT"
	EdgeCrossedEnvironmentGate    EdgeType = "CROSSED_ENVIRONMENT_GATE"
	EdgeEnvironmentSecretEligible EdgeType = "ENVIRONMENT_SECRET_ELIGIBLE"
	EdgeCouldMintOIDC             EdgeType = "COULD_MINT_OIDC"
	EdgeProducedArtifact          EdgeType = "PRODUCED_ARTIFACT"
	EdgePublishedPackage          EdgeType = "PUBLISHED_PACKAGE"
	EdgeCreatedRelease            EdgeType = "CREATED_RELEASE"
	EdgeCreatedDeployment         EdgeType = "CREATED_DEPLOYMENT"
	EdgeRepositoryWrite           EdgeType = "REPOSITORY_WRITE"
	EdgePullRequestChange         EdgeType = "PULL_REQUEST_CHANGE"
	EdgeObservedAfter             EdgeType = "OBSERVED_AFTER"
	EdgeFindingAbout              EdgeType = "FINDING_ABOUT"
	EdgeSupportedByEvidence       EdgeType = "SUPPORTED_BY_EVIDENCE"
	EdgeContradicts               EdgeType = "CONTRADICTS"
)

type Node struct {
	ID          string   `json:"id"`
	Type        NodeType `json:"type"`
	Label       string   `json:"label"`
	EvidenceIDs []string `json:"evidenceIds,omitempty"`
	// FocusFindingIDs is presentation-only membership in the affected
	// subgraph. It is not evidence and never changes edge semantics.
	FocusFindingIDs []string `json:"focusFindingIds,omitempty"`
}

type Edge struct {
	ID              string   `json:"id"`
	Type            EdgeType `json:"type"`
	Source          string   `json:"source"`
	Target          string   `json:"target"`
	EvidenceIDs     []string `json:"evidenceIds"`
	DerivationRule  string   `json:"derivationRule,omitempty"`
	EventTime       string   `json:"eventTime,omitempty"`
	Inferred        bool     `json:"inferred,omitempty"`
	FocusFindingIDs []string `json:"focusFindingIds,omitempty"`
}

type Graph struct {
	SchemaVersion string `json:"schemaVersion"`
	Nodes         []Node `json:"nodes"`
	Edges         []Edge `json:"edges"`
}

type endpointRule struct {
	sources map[NodeType]struct{}
	targets map[NodeType]struct{}
}

func endpoint(types ...NodeType) map[NodeType]struct{} {
	result := make(map[NodeType]struct{}, len(types))
	for _, nodeType := range types {
		result[nodeType] = struct{}{}
	}
	return result
}

var endpointRules = map[EdgeType]endpointRule{
	EdgeRunInRepository:           {endpoint(NodeRepository), endpoint(NodeWorkflowRun)},
	EdgeAttemptOfRun:              {endpoint(NodeRunAttempt), endpoint(NodeWorkflowRun)},
	EdgeJobExecutedInAttempt:      {endpoint(NodeRunAttempt), endpoint(NodeJob)},
	EdgeStepInJob:                 {endpoint(NodeJob), endpoint(NodeStep)},
	EdgeRunInstantiatedWorkflow:   {endpoint(NodeWorkflowRun), endpoint(NodeWorkflowDefinition)},
	EdgeWorkflowDeclaredAction:    {endpoint(NodeWorkflowDefinition), endpoint(NodeActionRef, NodeActionCommit, NodeImmutableActionPackage, NodeActionRepository)},
	EdgeWorkflowCalledWorkflow:    {endpoint(NodeWorkflowDefinition, NodeRunAttempt), endpoint(NodeActionRef, NodeReusableWorkflowDefinition)},
	EdgeActionContainsAction:      {endpoint(NodeActionDefinition), endpoint(NodeActionRef, NodeActionCommit, NodeImmutableActionPackage, NodeActionRepository, NodeActionDefinition)},
	EdgeLocalActionResolvedTo:     {endpoint(NodeWorkflowDefinition, NodeActionDefinition), endpoint(NodeActionDefinition)},
	EdgeRefResolvedTo:             {endpoint(NodeActionRef), endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeReusableWorkflowDefinition, NodeActionDefinition)},
	EdgePackageSourceCommit:       {endpoint(NodeImmutableActionPackage), endpoint(NodeActionCommit)},
	EdgeJobPreparedAction:         {endpoint(NodeJob), endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeActionRepository)},
	EdgeStepDownloadedAction:      {endpoint(NodeStep), endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeActionRepository)},
	EdgeStepExecutedAction:        {endpoint(NodeStep), endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeActionRepository)},
	EdgeExecutedOnRunner:          {endpoint(NodeJob), endpoint(NodeRunner)},
	EdgeRunnerInGroup:             {endpoint(NodeRunner), endpoint(NodeRunnerGroup)},
	EdgeHadTokenPermission:        {endpoint(NodeJob), endpoint(NodeTokenCapability)},
	EdgeReferencedSecret:          {endpoint(NodeJob, NodeStep, NodeWorkflowDefinition), endpoint(NodeSecretMetadata)},
	EdgePassedSecretTo:            {endpoint(NodeSecretMetadata), endpoint(NodeJob, NodeStep, NodeWorkflowDefinition)},
	EdgeInheritedSecret:           {endpoint(NodeJob, NodeWorkflowDefinition), endpoint(NodeSecretMetadata)},
	EdgeTargetedEnvironment:       {endpoint(NodeJob), endpoint(NodeEnvironment)},
	EdgeCrossedEnvironmentGate:    {endpoint(NodeJob), endpoint(NodeEnvironment)},
	EdgeEnvironmentSecretEligible: {endpoint(NodeEnvironment), endpoint(NodeSecretMetadata)},
	EdgeCouldMintOIDC:             {endpoint(NodeJob), endpoint(NodeOIDCProvider)},
	EdgeProducedArtifact:          {endpoint(NodeJob, NodeStep), endpoint(NodeArtifact)},
	EdgePublishedPackage:          {endpoint(NodeJob, NodeStep), endpoint(NodePackage)},
	EdgeCreatedRelease:            {endpoint(NodeJob, NodeStep), endpoint(NodeRelease)},
	EdgeCreatedDeployment:         {endpoint(NodeJob, NodeStep), endpoint(NodeDeployment)},
	EdgeRepositoryWrite:           {endpoint(NodeJob, NodeStep), endpoint(NodeRepositoryResource)},
	EdgePullRequestChange:         {endpoint(NodeJob, NodeStep), endpoint(NodePullRequestChange)},
	EdgeObservedAfter:             {endpoint(NodeJob, NodeStep), endpoint(NodeArtifact, NodePackage, NodeRelease, NodeDeployment, NodeRepositoryResource, NodePullRequestChange)},
	EdgeFindingAbout:              {endpoint(NodeFinding), endpoint(NodeRepository, NodeWorkflowDefinition, NodeReusableWorkflowDefinition, NodeWorkflowRun, NodeRunAttempt, NodeJob, NodeStep, NodeActionRepository, NodeActionRef, NodeActionCommit, NodeImmutableActionPackage, NodeActionDefinition)},
	// The direction matters: a finding is supported by an evidence object. A
	// repository does not support a finding merely because it is adjacent.
	EdgeSupportedByEvidence: {endpoint(NodeFinding), endpoint(NodeEvidenceObject)},
	EdgeContradicts:         {endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeReusableWorkflowDefinition, NodeActionDefinition), endpoint(NodeActionCommit, NodeImmutableActionPackage, NodeReusableWorkflowDefinition, NodeActionDefinition)},
}

func (g *Graph) NormalizeAndValidate() error {
	if g.SchemaVersion == "" {
		g.SchemaVersion = SchemaVersion
	}
	if g.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported graph schema %q", g.SchemaVersion)
	}
	if len(g.Nodes) > maxNodes || len(g.Edges) > maxEdges {
		return errors.New("graph exceeds the v0.1 node or edge limit")
	}
	nodes := make(map[string]NodeType, len(g.Nodes))
	for i := range g.Nodes {
		node := &g.Nodes[i]
		if err := boundedText(node.ID, maxIDBytes, false); err != nil || !node.Type.valid() {
			return fmt.Errorf("graph node %d has invalid identity or type", i)
		}
		if err := boundedText(node.Label, maxLabelBytes, false); err != nil {
			return fmt.Errorf("graph node %q has invalid label", node.ID)
		}
		if _, exists := nodes[node.ID]; exists {
			return fmt.Errorf("duplicate graph node %q", node.ID)
		}
		nodes[node.ID] = node.Type
		var err error
		if node.EvidenceIDs, err = normalizeEvidenceIDs(node.EvidenceIDs); err != nil {
			return fmt.Errorf("graph node %q: %w", node.ID, err)
		}
		if node.FocusFindingIDs, err = normalizeFindingIDs(node.FocusFindingIDs); err != nil {
			return fmt.Errorf("graph node %q: %w", node.ID, err)
		}
	}
	edges := make(map[string]bool, len(g.Edges))
	for i := range g.Edges {
		edge := &g.Edges[i]
		if err := boundedText(edge.ID, maxIDBytes, false); err != nil {
			return fmt.Errorf("graph edge %d has invalid identity", i)
		}
		sourceType, sourceOK := nodes[edge.Source]
		targetType, targetOK := nodes[edge.Target]
		rule, knownType := endpointRules[edge.Type]
		_, sourceAllowed := rule.sources[sourceType]
		_, targetAllowed := rule.targets[targetType]
		if !knownType || !sourceOK || !targetOK || edge.Source == edge.Target || !sourceAllowed || !targetAllowed {
			return fmt.Errorf("invalid graph edge %q (%s -> %s)", edge.ID, sourceType, targetType)
		}
		if edges[edge.ID] {
			return fmt.Errorf("duplicate graph edge %q", edge.ID)
		}
		edges[edge.ID] = true
		var err error
		if edge.EvidenceIDs, err = normalizeEvidenceIDs(edge.EvidenceIDs); err != nil {
			return fmt.Errorf("graph edge %q: %w", edge.ID, err)
		}
		if len(edge.EvidenceIDs) == 0 {
			return fmt.Errorf("graph edge %q lacks supporting evidence", edge.ID)
		}
		if edge.FocusFindingIDs, err = normalizeFindingIDs(edge.FocusFindingIDs); err != nil {
			return fmt.Errorf("graph edge %q: %w", edge.ID, err)
		}
		if err := boundedText(edge.EventTime, maxEventBytes, true); err != nil {
			return fmt.Errorf("graph edge %q has invalid event time", edge.ID)
		}
		if err := boundedText(edge.DerivationRule, maxRuleBytes, true); err != nil {
			return fmt.Errorf("graph edge %q has invalid derivation rule", edge.ID)
		}
		if edge.Inferred && edge.DerivationRule == "" {
			return fmt.Errorf("inferred graph edge %q lacks a derivation rule", edge.ID)
		}
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].ID < g.Edges[j].ID })
	return nil
}

func normalizeEvidenceIDs(values []string) ([]string, error) {
	values = sortedUnique(values)
	if len(values) > maxEvidenceIDs {
		return nil, errors.New("too many evidence IDs")
	}
	for _, value := range values {
		if err := model.EvidenceID(value).Validate(); err != nil {
			return nil, fmt.Errorf("invalid evidence ID: %w", err)
		}
	}
	return values, nil
}

func normalizeFindingIDs(values []string) ([]string, error) {
	values = sortedUnique(values)
	if len(values) > maxEvidenceIDs {
		return nil, errors.New("too many focus finding IDs")
	}
	for _, value := range values {
		if err := model.FindingRevisionID(value).Validate(); err != nil {
			return nil, fmt.Errorf("invalid focus finding revision ID: %w", err)
		}
	}
	return values, nil
}

func boundedText(value string, max int, emptyOK bool) error {
	if (!emptyOK && value == "") || len(value) > max || !utf8.ValidString(value) {
		return errors.New("text is empty, invalid UTF-8, or exceeds its limit")
	}
	for _, character := range value {
		if character == 0 || character == '\r' || (character < 0x20 && character != '\t' && character != '\n') || character == 0x7f {
			return errors.New("text contains a prohibited control character")
		}
	}
	return nil
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if value == "" || (write > 0 && result[write-1] == value) {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}
