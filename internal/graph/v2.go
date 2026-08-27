package graph

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
)

// SchemaVersionV2 is the v0.2 derived graph contract. It deliberately has a
// distinct edge identity namespace from the frozen v1 compatibility graph.
const SchemaVersionV2 = "cirewind.graph/v1alpha2"

const (
	// EdgeEnvironmentGateSatisfied is intentionally v0.2-only. The frozen v0.1
	// validator must not accept this relationship.
	EdgeEnvironmentGateSatisfied EdgeType = "ENVIRONMENT_GATE_SATISFIED"
	// DefinitionBasisHistoricalAtRunRule and its companions are closed source-
	// basis markers for exact dependency relationships. They keep current,
	// historical, and GitHub-recorded attempt metadata distinct even when a
	// finding state such as CONTRADICTORY_EVIDENCE masks the source basis.
	DefinitionBasisHistoricalAtRunRule        = "definition-basis/historical-at-run/v1"
	DefinitionBasisCurrentSnapshotRule        = "definition-basis/current-snapshot/v1"
	DefinitionBasisRuntimeAttemptMetadataRule = "definition-basis/runtime-attempt-metadata/v1"
	// EnvironmentGateSatisfied*Rule are the closed, identity-bearing joins
	// between a retained eligible gate state and job start. Keeping the state in
	// the derivation rule prevents distinct retained outcomes from collapsing.
	// Bypass, crossing, and absence of a required gate do not imply approval.
	EnvironmentGateSatisfiedApprovedRule    = "environment-gate-satisfied/approved/v1"
	EnvironmentGateSatisfiedBypassedRule    = "environment-gate-satisfied/bypassed/v1"
	EnvironmentGateSatisfiedCrossedRule     = "environment-gate-satisfied/crossed/v1"
	EnvironmentGateSatisfiedNotRequiredRule = "environment-gate-satisfied/not-required/v1"
	// EnvironmentSecretEligibilityRule derives named eligibility only after the
	// matching target and gate-satisfied relationships are present.
	EnvironmentSecretEligibilityRule = "environment-secret-eligibility/v1"
	// EnvironmentTargetHistoricalRule identifies the bounded join between an
	// exact historical workflow declaration and the corresponding API job.
	// The relationship is inferred because neither source alone proves the
	// joined job target.
	EnvironmentTargetHistoricalRule = "environment-target/historical-definition-and-job-state/v1"
	// EnvironmentTargetPendingRule is the narrower presentation-only join for a
	// waiting, pending, or otherwise unstarted non-executed job. It supports only
	// TARGETED_ENVIRONMENT and never gate crossing or secret eligibility.
	EnvironmentTargetPendingRule = "environment-target/pending-unstarted/v1"
)

// EnvironmentGateSatisfiedRuleForState returns the closed derivation rule for
// one retained gate outcome. The caller must separately prove job start and,
// for not-required, contemporaneous event time.
func EnvironmentGateSatisfiedRuleForState(state string) (string, bool) {
	switch state {
	case "approved":
		return EnvironmentGateSatisfiedApprovedRule, true
	case "bypassed":
		return EnvironmentGateSatisfiedBypassedRule, true
	case "crossed":
		return EnvironmentGateSatisfiedCrossedRule, true
	case "not-required":
		return EnvironmentGateSatisfiedNotRequiredRule, true
	default:
		return "", false
	}
}

// EnvironmentGateSatisfiedStateForRule recovers the retained outcome used by
// deterministic presentation. It never infers a state from labels.
func EnvironmentGateSatisfiedStateForRule(rule string) (string, bool) {
	switch rule {
	case EnvironmentGateSatisfiedApprovedRule:
		return "approved", true
	case EnvironmentGateSatisfiedBypassedRule:
		return "bypassed", true
	case EnvironmentGateSatisfiedCrossedRule:
		return "crossed", true
	case EnvironmentGateSatisfiedNotRequiredRule:
		return "not-required", true
	default:
		return "", false
	}
}

func retainedGateStateHasKnownEventTime(rule, eventTime string) bool {
	if rule != EnvironmentGateSatisfiedNotRequiredRule {
		return true
	}
	eventTime = strings.TrimSpace(eventTime)
	return eventTime != "" && !strings.EqualFold(eventTime, "unknown")
}

// TemporalPathSchemaVersion versions layout and SVG serialization, not the
// underlying forensic graph.
const TemporalPathSchemaVersion = "cirewind.temporal-evidence-path/v1alpha1"

// CaseKind describes trusted source provenance. Display labels and incident
// content must never select this value.
type CaseKind string

const (
	CaseKindSynthetic CaseKind = "synthetic"
	CaseKindCollected CaseKind = "collected"
	CaseKindMixed     CaseKind = "mixed"
	CaseKindUnknown   CaseKind = "unknown"
)

func (kind CaseKind) valid() bool {
	switch kind {
	case CaseKindSynthetic, CaseKindCollected, CaseKindMixed, CaseKindUnknown:
		return true
	default:
		return false
	}
}

// EvidenceClass is a closed description of the basis for one material edge.
// It is neither finding provenance nor severity.
type EvidenceClass string

const (
	EvidenceClassExactObservation    EvidenceClass = "EXACT_OBSERVATION"
	EvidenceClassInference           EvidenceClass = "INFERENCE"
	EvidenceClassTemporalCorrelation EvidenceClass = "TEMPORAL_CORRELATION"
	EvidenceClassContradiction       EvidenceClass = "CONTRADICTION"
)

func (class EvidenceClass) valid() bool {
	switch class {
	case EvidenceClassExactObservation, EvidenceClassInference,
		EvidenceClassTemporalCorrelation, EvidenceClassContradiction:
		return true
	default:
		return false
	}
}

// ExactIdentityKind describes an immutable identity used only to decide
// whether a NO_MATCH_CONFIRMED rerun is valid comparison context.
type ExactIdentityKind string

const (
	ExactIdentityActionCommitSHA   ExactIdentityKind = "ACTION_COMMIT_SHA"
	ExactIdentityPackageDigest     ExactIdentityKind = "IMMUTABLE_PACKAGE_DIGEST"
	ExactIdentityCalledWorkflowSHA ExactIdentityKind = "CALLED_WORKFLOW_SHA"
)

func (kind ExactIdentityKind) valid() bool {
	switch kind {
	case ExactIdentityActionCommitSHA, ExactIdentityPackageDigest, ExactIdentityCalledWorkflowSHA:
		return true
	default:
		return false
	}
}

// NodeV2 retains the frozen node shape while making the v2 API explicit.
type NodeV2 = Node

// EdgeV2 requires an explicit evidence basis. Inferred is intentionally absent.
// DerivationRule is mandatory for inference and may also carry one of the
// closed definition-basis markers on an exact dependency relationship.
type EdgeV2 struct {
	ID              string        `json:"id"`
	Type            EdgeType      `json:"type"`
	Source          string        `json:"source"`
	Target          string        `json:"target"`
	EvidenceIDs     []string      `json:"evidenceIds"`
	DerivationRule  string        `json:"derivationRule,omitempty"`
	EventTime       string        `json:"eventTime,omitempty"`
	EvidenceClass   EvidenceClass `json:"evidenceClass"`
	FocusFindingIDs []string      `json:"focusFindingIds,omitempty"`
}

// FindingIndexEntry supplies typed selection and sorting fields. Presentation
// code must never recover these values from human-readable graph labels.
type FindingIndexEntry struct {
	FindingRevisionID string                `json:"findingRevisionId"`
	State             model.FindingState    `json:"state"`
	ProvenanceLevel   model.ProvenanceLevel `json:"provenanceLevel"`
	Repository        string                `json:"repository"`
	WorkflowPath      string                `json:"workflowPath"`
	RunID             *model.WorkflowRunID  `json:"runId,omitempty"`
	RunAttempt        *model.RunAttempt     `json:"runAttempt,omitempty"`
	JobID             *model.JobID          `json:"jobId,omitempty"`
	StepIdentity      string                `json:"stepIdentity,omitempty"`
	IndicatorID       string                `json:"indicatorId"`
	ExactIdentityKind ExactIdentityKind     `json:"exactIdentityKind,omitempty"`
	ExactIdentity     string                `json:"exactIdentity,omitempty"`
	ExactKnownGood    bool                  `json:"exactKnownGood,omitempty"`
	CoverageClosed    bool                  `json:"coverageClosed,omitempty"`
	EvidenceGapReason string                `json:"evidenceGapReason,omitempty"`
}

// ProjectionNoticeCode is deliberately separate from canonical evidence gaps.
type ProjectionNoticeCode string

const ProjectionNoticeUnclassifiableLegacyBasis ProjectionNoticeCode = "UNCLASSIFIABLE_LEGACY_BASIS"

type ProjectionNotice struct {
	Code              ProjectionNoticeCode `json:"code"`
	FindingRevisionID string               `json:"findingRevisionId"`
	Relationship      EdgeType             `json:"relationship"`
	EvidenceIDs       []string             `json:"evidenceIds"`
}

type evidenceClassSet uint8

const (
	evidenceClassSetExact evidenceClassSet = 1 << iota
	evidenceClassSetInference
	evidenceClassSetTemporal
	evidenceClassSetContradiction
)

// evidenceClassesByRelationship is the fail-closed v1alpha2 relationship
// contract. A finding's provenance never supplies or upgrades an edge class.
// Relationships with both exact and inferred forms retain both propositions as
// distinct edges because EvidenceClass participates in the v2 edge identity.
var evidenceClassesByRelationship = map[EdgeType]evidenceClassSet{
	EdgeRunInRepository:           evidenceClassSetExact,
	EdgeAttemptOfRun:              evidenceClassSetExact,
	EdgeJobExecutedInAttempt:      evidenceClassSetExact,
	EdgeStepInJob:                 evidenceClassSetExact | evidenceClassSetInference,
	EdgeRunInstantiatedWorkflow:   evidenceClassSetExact,
	EdgeWorkflowDeclaredAction:    evidenceClassSetExact | evidenceClassSetInference,
	EdgeWorkflowCalledWorkflow:    evidenceClassSetExact,
	EdgeActionContainsAction:      evidenceClassSetExact,
	EdgeLocalActionResolvedTo:     evidenceClassSetExact,
	EdgeRefResolvedTo:             evidenceClassSetExact,
	EdgePackageSourceCommit:       evidenceClassSetExact,
	EdgeJobPreparedAction:         evidenceClassSetExact,
	EdgeStepDownloadedAction:      evidenceClassSetExact,
	EdgeStepExecutedAction:        evidenceClassSetExact,
	EdgeExecutedOnRunner:          evidenceClassSetExact,
	EdgeRunnerInGroup:             evidenceClassSetExact,
	EdgeHadTokenPermission:        evidenceClassSetExact | evidenceClassSetInference,
	EdgeReferencedSecret:          evidenceClassSetExact | evidenceClassSetInference,
	EdgePassedSecretTo:            evidenceClassSetExact | evidenceClassSetInference,
	EdgeInheritedSecret:           evidenceClassSetExact | evidenceClassSetInference,
	EdgeTargetedEnvironment:       evidenceClassSetExact | evidenceClassSetInference,
	EdgeCrossedEnvironmentGate:    evidenceClassSetExact | evidenceClassSetInference,
	EdgeEnvironmentGateSatisfied:  evidenceClassSetInference,
	EdgeEnvironmentSecretEligible: evidenceClassSetInference,
	EdgeCouldMintOIDC:             evidenceClassSetInference,
	EdgeProducedArtifact:          evidenceClassSetExact,
	EdgePublishedPackage:          evidenceClassSetExact,
	EdgeCreatedRelease:            evidenceClassSetExact,
	EdgeCreatedDeployment:         evidenceClassSetExact,
	EdgeRepositoryWrite:           evidenceClassSetExact,
	EdgePullRequestChange:         evidenceClassSetExact,
	EdgeObservedAfter:             evidenceClassSetTemporal,
	EdgeFindingAbout:              evidenceClassSetInference,
	EdgeSupportedByEvidence:       evidenceClassSetExact,
	EdgeContradicts:               evidenceClassSetContradiction,
}

// v2EndpointRules extends the frozen v0.1 graph vocabulary without making the
// v0.1 validator accept v0.2-only relationships.
var v2EndpointRules = func() map[EdgeType]endpointRule {
	rules := make(map[EdgeType]endpointRule, len(endpointRules)+1)
	for edgeType, rule := range endpointRules {
		rules[edgeType] = rule
	}
	rules[EdgeEnvironmentGateSatisfied] = endpointRule{
		sources: endpoint(NodeJob),
		targets: endpoint(NodeEnvironment),
	}
	return rules
}()

var legacyBasisNoticeRelationships = map[EdgeType]struct{}{
	EdgeHadTokenPermission: {},
	EdgeReferencedSecret:   {},
	EdgePassedSecretTo:     {},
	EdgeInheritedSecret:    {},
	EdgeCouldMintOIDC:      {},
}

var nonExecutedContextNodeTypes = map[NodeType]struct{}{
	NodeRunner:             {},
	NodeRunnerGroup:        {},
	NodeTokenCapability:    {},
	NodeSecretMetadata:     {},
	NodeOIDCProvider:       {},
	NodeArtifact:           {},
	NodePackage:            {},
	NodeRelease:            {},
	NodeDeployment:         {},
	NodeRepositoryResource: {},
	NodePullRequestChange:  {},
}

var nonExecutedContextEdgeTypes = map[EdgeType]struct{}{
	EdgeExecutedOnRunner:          {},
	EdgeRunnerInGroup:             {},
	EdgeHadTokenPermission:        {},
	EdgeReferencedSecret:          {},
	EdgePassedSecretTo:            {},
	EdgeInheritedSecret:           {},
	EdgeCrossedEnvironmentGate:    {},
	EdgeEnvironmentGateSatisfied:  {},
	EdgeEnvironmentSecretEligible: {},
	EdgeCouldMintOIDC:             {},
	EdgeProducedArtifact:          {},
	EdgePublishedPackage:          {},
	EdgeCreatedRelease:            {},
	EdgeCreatedDeployment:         {},
	EdgeRepositoryWrite:           {},
	EdgePullRequestChange:         {},
	EdgeObservedAfter:             {},
}

// GraphV2 is a complete machine-readable derived projection. SVG selection is
// bounded separately and never mutates this graph.
type GraphV2 struct {
	SchemaVersion     string              `json:"schemaVersion"`
	CaseKind          CaseKind            `json:"caseKind"`
	Nodes             []NodeV2            `json:"nodes"`
	Edges             []EdgeV2            `json:"edges"`
	FindingIndex      []FindingIndexEntry `json:"findingIndex"`
	ProjectionNotices []ProjectionNotice  `json:"projectionNotices,omitempty"`
}

// StableEdgeIDV2 returns a v2-only, length-delimited identity. Evidence IDs and
// focus membership do not define the material relationship and therefore are
// not identity inputs.
func StableEdgeIDV2(edgeType EdgeType, source, target, eventTime string, class EvidenceClass, derivationRule string) (string, error) {
	if _, ok := v2EndpointRules[edgeType]; !ok {
		return "", fmt.Errorf("unknown edge type %q", edgeType)
	}
	if source == "" || target == "" || source == target {
		return "", errors.New("edge identity requires distinct nonempty endpoints")
	}
	if !class.valid() {
		return "", fmt.Errorf("unknown evidence class %q", class)
	}
	eventTime = strings.TrimSpace(eventTime)
	derivationRule = strings.TrimSpace(derivationRule)
	if err := boundedText(eventTime, maxEventBytes, true); err != nil {
		return "", fmt.Errorf("invalid event time: %w", err)
	}
	if err := boundedText(derivationRule, maxRuleBytes, true); err != nil {
		return "", fmt.Errorf("invalid derivation rule: %w", err)
	}
	hash := sha256.New()
	for _, part := range []string{SchemaVersionV2, string(edgeType), source, target, eventTime, string(class), derivationRule} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(part))
	}
	return "gedge2:" + fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// NewEdgeV2 constructs an edge with its canonical v2 identity.
func NewEdgeV2(edgeType EdgeType, source, target string, evidenceIDs []string, eventTime string, class EvidenceClass, derivationRule string, focusFindingIDs []string) (EdgeV2, error) {
	eventTime = strings.TrimSpace(eventTime)
	derivationRule = strings.TrimSpace(derivationRule)
	id, err := StableEdgeIDV2(edgeType, source, target, eventTime, class, derivationRule)
	if err != nil {
		return EdgeV2{}, err
	}
	return EdgeV2{
		ID: id, Type: edgeType, Source: source, Target: target,
		EvidenceIDs: append([]string(nil), evidenceIDs...), EventTime: eventTime,
		EvidenceClass: class, DerivationRule: derivationRule,
		FocusFindingIDs: append([]string(nil), focusFindingIDs...),
	}, nil
}

// NormalizeAndValidate canonicalizes a trusted, in-process projector result and
// rejects invalid graph semantics. It is not a decoder or validator for
// attacker-supplied graph.json bytes: the public JSON schema is the serialized
// output contract, and graph.json is never consumed as an input authority.
// Callers that must preserve input should operate on CloneGraphV2.
func (g *GraphV2) NormalizeAndValidate() error {
	if g.Nodes == nil {
		g.Nodes = []NodeV2{}
	}
	if g.Edges == nil {
		g.Edges = []EdgeV2{}
	}
	if g.FindingIndex == nil {
		g.FindingIndex = []FindingIndexEntry{}
	}
	if g.ProjectionNotices == nil {
		g.ProjectionNotices = []ProjectionNotice{}
	}
	if g.SchemaVersion == "" {
		g.SchemaVersion = SchemaVersionV2
	}
	if g.SchemaVersion != SchemaVersionV2 {
		return fmt.Errorf("unsupported graph schema %q", g.SchemaVersion)
	}
	if !g.CaseKind.valid() {
		return fmt.Errorf("invalid case kind %q", g.CaseKind)
	}
	if len(g.Nodes) > maxNodes || len(g.Edges) > maxEdges || len(g.FindingIndex) > maxNodes || len(g.ProjectionNotices) > maxNodes {
		return errors.New("graph exceeds the v0.2 node, edge, finding-index, or projection-notice limit")
	}

	findings := make(map[string]FindingIndexEntry, len(g.FindingIndex))
	for i := range g.FindingIndex {
		entry := &g.FindingIndex[i]
		if err := validateFindingIndexEntry(*entry); err != nil {
			return fmt.Errorf("finding index %d: %w", i, err)
		}
		if _, exists := findings[entry.FindingRevisionID]; exists {
			return fmt.Errorf("duplicate finding index entry %q", entry.FindingRevisionID)
		}
		findings[entry.FindingRevisionID] = *entry
	}

	nodes := make(map[string]NodeType, len(g.Nodes))
	nodeFocus := make(map[string]map[string]struct{}, len(g.Nodes))
	nonExecutedEnvironments := make(map[string]map[string]struct{})
	for i := range g.Nodes {
		node := &g.Nodes[i]
		safeID, truncatedID := sanitizeSVGText(node.ID, maxIDBytes)
		if err := boundedText(node.ID, maxIDBytes, false); err != nil || truncatedID || safeID != node.ID || !node.Type.valid() {
			return fmt.Errorf("graph node %d has invalid identity or type", i)
		}
		label, _ := sanitizeSVGText(node.Label, maxLabelBytes)
		if label == "" {
			label = "[unavailable]"
		}
		node.Label = label
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
		nodeFocus[node.ID] = make(map[string]struct{}, len(node.FocusFindingIDs))
		for _, findingID := range node.FocusFindingIDs {
			finding, ok := findings[findingID]
			if !ok {
				return fmt.Errorf("graph node %q references absent finding %q", node.ID, findingID)
			}
			if finding.State != model.ConfirmedExecuted {
				if _, prohibited := nonExecutedContextNodeTypes[node.Type]; prohibited {
					return fmt.Errorf("graph node %q adds %s context to non-executed finding %q", node.ID, node.Type, findingID)
				}
				if node.Type == NodeEnvironment {
					if nonExecutedEnvironments[findingID] == nil {
						nonExecutedEnvironments[findingID] = make(map[string]struct{})
					}
					nonExecutedEnvironments[findingID][node.ID] = struct{}{}
				}
			}
			nodeFocus[node.ID][findingID] = struct{}{}
		}
	}

	edges := make(map[string]struct{}, len(g.Edges))
	qualifiedPendingEnvironment := make(map[string]map[string]struct{})
	type environmentPair struct{ job, environment string }
	targetedEnvironments := make(map[string]map[environmentPair]struct{})
	satisfiedEnvironments := make(map[string]map[environmentPair]struct{})
	eligibleEnvironments := make(map[string]map[string]struct{})
	for i := range g.Edges {
		edge := &g.Edges[i]
		edge.EventTime = strings.TrimSpace(edge.EventTime)
		edge.DerivationRule = strings.TrimSpace(edge.DerivationRule)
		sourceType, sourceOK := nodes[edge.Source]
		targetType, targetOK := nodes[edge.Target]
		rule, knownType := v2EndpointRules[edge.Type]
		_, sourceAllowed := rule.sources[sourceType]
		_, targetAllowed := rule.targets[targetType]
		if !knownType || !sourceOK || !targetOK || edge.Source == edge.Target || !sourceAllowed || !targetAllowed {
			return fmt.Errorf("invalid graph edge %q (%s -> %s)", edge.ID, sourceType, targetType)
		}
		if !edge.EvidenceClass.valid() {
			return fmt.Errorf("graph edge %q has invalid evidence class %q", edge.ID, edge.EvidenceClass)
		}
		if !relationshipAllowsEvidenceClass(edge.Type, edge.EvidenceClass) {
			return fmt.Errorf("graph edge %q relationship %s cannot use evidence class %s", edge.ID, edge.Type, edge.EvidenceClass)
		}
		if edge.Type == EdgeObservedAfter && edge.EvidenceClass != EvidenceClassTemporalCorrelation {
			return fmt.Errorf("OBSERVED_AFTER edge %q is not temporal correlation", edge.ID)
		}
		if edge.EvidenceClass == EvidenceClassTemporalCorrelation && edge.Type != EdgeObservedAfter {
			return fmt.Errorf("temporal-correlation edge %q is not OBSERVED_AFTER", edge.ID)
		}
		if edge.Type == EdgeContradicts && edge.EvidenceClass != EvidenceClassContradiction {
			return fmt.Errorf("CONTRADICTS edge %q is not contradictory", edge.ID)
		}
		if edge.EvidenceClass == EvidenceClassContradiction && edge.Type != EdgeContradicts {
			return fmt.Errorf("contradiction edge %q is not CONTRADICTS", edge.ID)
		}
		if edge.EvidenceClass == EvidenceClassInference && edge.DerivationRule == "" {
			return fmt.Errorf("inferred graph edge %q lacks a derivation rule", edge.ID)
		}
		if edge.Type == EdgeEnvironmentGateSatisfied {
			if _, ok := EnvironmentGateSatisfiedStateForRule(edge.DerivationRule); !ok {
				return fmt.Errorf("inferred ENVIRONMENT_GATE_SATISFIED edge %q has an unsupported derivation rule", edge.ID)
			}
			if !retainedGateStateHasKnownEventTime(edge.DerivationRule, edge.EventTime) {
				return fmt.Errorf("inferred ENVIRONMENT_GATE_SATISFIED edge %q has unknown event time for not-required state", edge.ID)
			}
		}
		if edge.Type == EdgeEnvironmentSecretEligible && edge.DerivationRule != EnvironmentSecretEligibilityRule {
			return fmt.Errorf("ENVIRONMENT_SECRET_ELIGIBLE edge %q has an unsupported derivation rule", edge.ID)
		}
		if err := boundedText(edge.EventTime, maxEventBytes, true); err != nil {
			return fmt.Errorf("graph edge %q has invalid event time", edge.ID)
		}
		if err := boundedText(edge.DerivationRule, maxRuleBytes, true); err != nil {
			return fmt.Errorf("graph edge %q has invalid derivation rule", edge.ID)
		}
		expected, err := StableEdgeIDV2(edge.Type, edge.Source, edge.Target, edge.EventTime, edge.EvidenceClass, edge.DerivationRule)
		if err != nil || edge.ID != expected {
			return fmt.Errorf("graph edge %q does not have its canonical v2 identity", edge.ID)
		}
		if _, exists := edges[edge.ID]; exists {
			return fmt.Errorf("duplicate graph edge %q", edge.ID)
		}
		edges[edge.ID] = struct{}{}
		if edge.EvidenceIDs, err = normalizeEvidenceIDs(edge.EvidenceIDs); err != nil {
			return fmt.Errorf("graph edge %q: %w", edge.ID, err)
		}
		if len(edge.EvidenceIDs) == 0 {
			return fmt.Errorf("graph edge %q lacks supporting evidence", edge.ID)
		}
		if edge.FocusFindingIDs, err = normalizeFindingIDs(edge.FocusFindingIDs); err != nil {
			return fmt.Errorf("graph edge %q: %w", edge.ID, err)
		}
		if len(edge.FocusFindingIDs) == 0 {
			return fmt.Errorf("graph edge %q lacks finding focus membership", edge.ID)
		}
		for _, findingID := range edge.FocusFindingIDs {
			finding, ok := findings[findingID]
			if !ok {
				return fmt.Errorf("graph edge %q references absent finding %q", edge.ID, findingID)
			}
			if err := validateEdgeFindingContext(*edge, finding); err != nil {
				return fmt.Errorf("graph edge %q: %w", edge.ID, err)
			}
			if finding.State != model.ConfirmedExecuted && edge.Type == EdgeTargetedEnvironment {
				if qualifiedPendingEnvironment[findingID] == nil {
					qualifiedPendingEnvironment[findingID] = make(map[string]struct{})
				}
				qualifiedPendingEnvironment[findingID][edge.Target] = struct{}{}
			}
			switch edge.Type {
			case EdgeTargetedEnvironment:
				if targetedEnvironments[findingID] == nil {
					targetedEnvironments[findingID] = make(map[environmentPair]struct{})
				}
				targetedEnvironments[findingID][environmentPair{job: edge.Source, environment: edge.Target}] = struct{}{}
			case EdgeEnvironmentGateSatisfied:
				if satisfiedEnvironments[findingID] == nil {
					satisfiedEnvironments[findingID] = make(map[environmentPair]struct{})
				}
				satisfiedEnvironments[findingID][environmentPair{job: edge.Source, environment: edge.Target}] = struct{}{}
			case EdgeEnvironmentSecretEligible:
				if eligibleEnvironments[findingID] == nil {
					eligibleEnvironments[findingID] = make(map[string]struct{})
				}
				eligibleEnvironments[findingID][edge.Source] = struct{}{}
			}
			if _, ok := nodeFocus[edge.Source][findingID]; !ok {
				return fmt.Errorf("graph edge %q focus %q is absent from source", edge.ID, findingID)
			}
			if _, ok := nodeFocus[edge.Target][findingID]; !ok {
				return fmt.Errorf("graph edge %q focus %q is absent from target", edge.ID, findingID)
			}
		}
	}
	for findingID, pairs := range satisfiedEnvironments {
		for pair := range pairs {
			if _, ok := targetedEnvironments[findingID][pair]; !ok {
				return fmt.Errorf("ENVIRONMENT_GATE_SATISFIED for environment %q lacks the same-focus TARGETED_ENVIRONMENT relationship in finding %q", pair.environment, findingID)
			}
		}
	}
	for findingID, environmentIDs := range eligibleEnvironments {
		for environmentID := range environmentIDs {
			qualified := false
			for pair := range satisfiedEnvironments[findingID] {
				if pair.environment == environmentID {
					qualified = true
					break
				}
			}
			if !qualified {
				return fmt.Errorf("ENVIRONMENT_SECRET_ELIGIBLE for environment %q lacks the same-focus target and gate-requirement relationship in finding %q", environmentID, findingID)
			}
		}
	}
	for findingID, environmentIDs := range nonExecutedEnvironments {
		for environmentID := range environmentIDs {
			if _, ok := qualifiedPendingEnvironment[findingID][environmentID]; !ok {
				return fmt.Errorf("environment node %q lacks a narrow pending target relationship for non-executed finding %q", environmentID, findingID)
			}
		}
	}

	type projectionNoticeKey struct {
		findingRevisionID string
		relationship      EdgeType
		code              ProjectionNoticeCode
	}
	type projectionNoticeAggregate struct {
		notice      ProjectionNotice
		evidenceIDs map[string]struct{}
	}
	noticeByKey := make(map[projectionNoticeKey]*projectionNoticeAggregate, len(g.ProjectionNotices))
	for i := range g.ProjectionNotices {
		notice := g.ProjectionNotices[i]
		if notice.Code != ProjectionNoticeUnclassifiableLegacyBasis {
			return fmt.Errorf("projection notice %d has invalid code %q", i, notice.Code)
		}
		if _, ok := findings[notice.FindingRevisionID]; !ok {
			return fmt.Errorf("projection notice references absent finding %q", notice.FindingRevisionID)
		}
		if _, ok := legacyBasisNoticeRelationships[notice.Relationship]; !ok {
			return fmt.Errorf("projection notice has invalid relationship %q", notice.Relationship)
		}
		var err error
		if notice.EvidenceIDs, err = normalizeEvidenceIDs(notice.EvidenceIDs); err != nil || len(notice.EvidenceIDs) == 0 {
			return fmt.Errorf("projection notice %d requires valid evidence IDs", i)
		}
		key := projectionNoticeKey{findingRevisionID: notice.FindingRevisionID, relationship: notice.Relationship, code: notice.Code}
		aggregate := noticeByKey[key]
		if aggregate == nil {
			aggregate = &projectionNoticeAggregate{
				notice: notice, evidenceIDs: make(map[string]struct{}, len(notice.EvidenceIDs)),
			}
			aggregate.notice.EvidenceIDs = nil
			noticeByKey[key] = aggregate
		}
		for _, evidenceID := range notice.EvidenceIDs {
			if _, exists := aggregate.evidenceIDs[evidenceID]; exists {
				continue
			}
			if len(aggregate.evidenceIDs) == maxEvidenceIDs {
				return fmt.Errorf("projection notice %d has too many combined evidence IDs", i)
			}
			aggregate.evidenceIDs[evidenceID] = struct{}{}
		}
	}
	g.ProjectionNotices = make([]ProjectionNotice, 0, len(noticeByKey))
	for _, aggregate := range noticeByKey {
		aggregate.notice.EvidenceIDs = make([]string, 0, len(aggregate.evidenceIDs))
		for evidenceID := range aggregate.evidenceIDs {
			aggregate.notice.EvidenceIDs = append(aggregate.notice.EvidenceIDs, evidenceID)
		}
		sort.Strings(aggregate.notice.EvidenceIDs)
		g.ProjectionNotices = append(g.ProjectionNotices, aggregate.notice)
	}

	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool { return g.Edges[i].ID < g.Edges[j].ID })
	sort.Slice(g.FindingIndex, func(i, j int) bool { return g.FindingIndex[i].FindingRevisionID < g.FindingIndex[j].FindingRevisionID })
	sort.Slice(g.ProjectionNotices, func(i, j int) bool {
		a, b := g.ProjectionNotices[i], g.ProjectionNotices[j]
		return a.FindingRevisionID+"\x00"+string(a.Relationship)+"\x00"+string(a.Code) < b.FindingRevisionID+"\x00"+string(b.Relationship)+"\x00"+string(b.Code)
	})
	return nil
}

func relationshipAllowsEvidenceClass(edgeType EdgeType, class EvidenceClass) bool {
	allowed, ok := evidenceClassesByRelationship[edgeType]
	if !ok {
		return false
	}
	var candidate evidenceClassSet
	switch class {
	case EvidenceClassExactObservation:
		candidate = evidenceClassSetExact
	case EvidenceClassInference:
		candidate = evidenceClassSetInference
	case EvidenceClassTemporalCorrelation:
		candidate = evidenceClassSetTemporal
	case EvidenceClassContradiction:
		candidate = evidenceClassSetContradiction
	default:
		return false
	}
	return allowed&candidate != 0
}

func validateEdgeFindingContext(edge EdgeV2, finding FindingIndexEntry) error {
	if finding.State == model.ConfirmedExecuted {
		return nil
	}
	if _, prohibited := nonExecutedContextEdgeTypes[edge.Type]; prohibited {
		return fmt.Errorf("relationship %s adds credential, runner, gate-crossing, or resource context to non-executed finding %q", edge.Type, finding.FindingRevisionID)
	}
	if edge.Type == EdgeTargetedEnvironment &&
		(edge.EvidenceClass != EvidenceClassInference || edge.DerivationRule != EnvironmentTargetPendingRule) {
		return fmt.Errorf("TARGETED_ENVIRONMENT on non-executed finding %q requires the narrow pending-unstarted inference rule", finding.FindingRevisionID)
	}
	// CONFIRMED_DOWNLOADED is specifically the proposition that download or
	// preparation was demonstrated without a corresponding lifecycle start. An
	// exact lifecycle edge can legitimately appear in other states—for example,
	// a known-good execution with incomplete negative coverage remains an
	// UNKNOWN_EVIDENCE_GAP—without proving that the incident identity executed.
	if edge.Type == EdgeStepExecutedAction && finding.State == model.ConfirmedDownloaded {
		return errors.New("STEP_EXECUTED_ACTION is incompatible with CONFIRMED_DOWNLOADED")
	}
	return nil
}

func validateFindingIndexEntry(entry FindingIndexEntry) error {
	if err := model.FindingRevisionID(entry.FindingRevisionID).Validate(); err != nil {
		return fmt.Errorf("invalid finding revision ID: %w", err)
	}
	if !entry.State.Valid() || !entry.ProvenanceLevel.Valid() {
		return errors.New("invalid finding state or provenance")
	}
	for _, field := range []struct{ name, value string }{
		{"repository", entry.Repository},
		{"indicator ID", entry.IndicatorID},
	} {
		if err := boundedText(field.value, 4_096, false); err != nil {
			return fmt.Errorf("invalid %s", field.name)
		}
	}
	// Repository-scoped evidence gaps and retained literal observations can
	// legitimately lack a workflow identity. Preserve that absence instead of
	// manufacturing a path for presentation.
	if err := boundedText(entry.WorkflowPath, 4_096, true); err != nil {
		return errors.New("invalid workflow path")
	}
	if entry.RunAttempt != nil && entry.RunID == nil {
		return errors.New("run attempt requires run ID")
	}
	if entry.JobID != nil && entry.RunAttempt == nil {
		return errors.New("job ID requires run attempt")
	}
	if entry.StepIdentity != "" && entry.JobID == nil {
		return errors.New("step identity requires job ID")
	}
	if entry.RunID != nil {
		if err := entry.RunID.Validate(); err != nil {
			return err
		}
	}
	if entry.RunAttempt != nil {
		if err := entry.RunAttempt.Validate(); err != nil {
			return err
		}
	}
	if entry.JobID != nil {
		if err := entry.JobID.Validate(); err != nil {
			return err
		}
	}
	if err := boundedText(entry.StepIdentity, 4_096, true); err != nil {
		return errors.New("invalid step identity")
	}
	// The reason is retained machine evidence and can originate in a hostile API
	// error. Preserve bounded valid UTF-8 here; all display sinks sanitize it.
	if err := boundedRetainedText(entry.EvidenceGapReason, 4_096, true); err != nil {
		return errors.New("invalid evidence gap reason")
	}
	if entry.State == model.UnknownEvidenceGap && entry.EvidenceGapReason == "" {
		return errors.New("UNKNOWN_EVIDENCE_GAP requires a reason")
	}
	if entry.ExactIdentityKind == "" && entry.ExactIdentity != "" || entry.ExactIdentityKind != "" && entry.ExactIdentity == "" {
		return errors.New("exact identity kind and value must appear together")
	}
	if entry.ExactIdentityKind != "" && !entry.ExactIdentityKind.valid() {
		return fmt.Errorf("invalid exact identity kind %q", entry.ExactIdentityKind)
	}
	if err := boundedText(entry.ExactIdentity, 512, true); err != nil {
		return errors.New("invalid exact identity")
	}
	if entry.ExactKnownGood && entry.ExactIdentity == "" {
		return errors.New("exact known-good comparison requires an exact identity")
	}
	return nil
}

// IsKnownGoodComparison applies the narrow rerun comparison predicate. It does
// not conclude that an organization, workflow, or current tag is safe.
func IsKnownGoodComparison(anchor, candidate FindingIndexEntry) bool {
	if anchor.State != model.ConfirmedExecuted && anchor.State != model.ConfirmedDownloaded {
		return false
	}
	if candidate.State != model.NoMatchConfirmed || !candidate.ExactKnownGood || !candidate.CoverageClosed {
		return false
	}
	if anchor.RunID == nil || anchor.RunAttempt == nil || candidate.RunID == nil || candidate.RunAttempt == nil {
		return false
	}
	if *anchor.RunAttempt == *candidate.RunAttempt || *anchor.RunID != *candidate.RunID {
		return false
	}
	return anchor.IndicatorID == candidate.IndicatorID &&
		anchor.Repository == candidate.Repository &&
		anchor.WorkflowPath == candidate.WorkflowPath &&
		anchor.ExactIdentityKind.valid() && anchor.ExactIdentity != "" &&
		anchor.ExactIdentityKind == candidate.ExactIdentityKind &&
		candidate.ExactIdentityKind.valid() && candidate.ExactIdentity != "" &&
		anchor.ExactIdentity != candidate.ExactIdentity
}

// CloneGraphV2 returns a deep-enough clone for normalization and presentation.
func CloneGraphV2(source GraphV2) GraphV2 {
	result := source
	result.Nodes = append([]NodeV2(nil), source.Nodes...)
	for i := range result.Nodes {
		result.Nodes[i].EvidenceIDs = append([]string(nil), source.Nodes[i].EvidenceIDs...)
		result.Nodes[i].FocusFindingIDs = append([]string(nil), source.Nodes[i].FocusFindingIDs...)
	}
	result.Edges = append([]EdgeV2(nil), source.Edges...)
	for i := range result.Edges {
		result.Edges[i].EvidenceIDs = append([]string(nil), source.Edges[i].EvidenceIDs...)
		result.Edges[i].FocusFindingIDs = append([]string(nil), source.Edges[i].FocusFindingIDs...)
	}
	result.FindingIndex = append([]FindingIndexEntry(nil), source.FindingIndex...)
	result.ProjectionNotices = append([]ProjectionNotice(nil), source.ProjectionNotices...)
	for i := range result.ProjectionNotices {
		result.ProjectionNotices[i].EvidenceIDs = append([]string(nil), source.ProjectionNotices[i].EvidenceIDs...)
	}
	return result
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func findingSortKey(entry FindingIndexEntry) string {
	run, attempt, job := "", "", ""
	if entry.RunID != nil {
		run = fmt.Sprintf("%020d", *entry.RunID)
	}
	if entry.RunAttempt != nil {
		attempt = fmt.Sprintf("%010d", *entry.RunAttempt)
	}
	if entry.JobID != nil {
		job = fmt.Sprintf("%020d", *entry.JobID)
	}
	return strings.Join([]string{entry.Repository, entry.WorkflowPath, run, attempt, job, entry.StepIdentity, entry.IndicatorID, entry.FindingRevisionID}, "\x00")
}
