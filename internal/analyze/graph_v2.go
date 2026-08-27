package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

const (
	graphOIDCCapabilityRule      = OIDCCapabilityRuleVersion
	graphEnvironmentEligibleRule = graph.EnvironmentSecretEligibilityRule
)

type edgeClassification struct {
	class       graph.EvidenceClass
	rule        string
	evidenceIDs []string
	omit        bool
}

type exactIdentityCandidate struct {
	kind  graph.ExactIdentityKind
	value string
}

type findingExactIdentityBinding struct {
	component incident.Component
	eligible  map[string]struct{}
	knownGood map[string]struct{}
}

// buildGraphV2 projects explicit evidence classes from the typed facts that
// produced the frozen v1 graph. The renderer only validates these classes; it
// never guesses semantics from an edge name or color.
func buildGraphV2(idx index, legacy graph.Graph, findings []report.Finding, pack *incident.ValidatedPack, kind report.CaseKind) (graph.GraphV2, error) {
	result := graph.GraphV2{
		SchemaVersion: graph.SchemaVersionV2,
		CaseKind:      graphCaseKind(kind),
		FindingIndex:  buildFindingIndex(idx, findings, pack),
	}
	for _, node := range legacy.Nodes {
		if isV2ScopedExposureNode(node.Type) {
			continue
		}
		projected := node
		projected.EvidenceIDs = append([]string(nil), node.EvidenceIDs...)
		projected.FocusFindingIDs = append([]string(nil), node.FocusFindingIDs...)
		result.Nodes = append(result.Nodes, projected)
	}
	for _, edge := range legacy.Edges {
		if isV2ScopedExposureEdge(edge.Type) {
			continue
		}
		classes := classificationsForEdge(idx, edge)
		for _, classified := range classes {
			if classified.omit {
				for _, findingID := range edge.FocusFindingIDs {
					result.ProjectionNotices = append(result.ProjectionNotices, graph.ProjectionNotice{
						Code: graph.ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: findingID,
						Relationship: edge.Type, EvidenceIDs: append([]string(nil), classified.evidenceIDs...),
					})
				}
				continue
			}
			projected, err := graph.NewEdgeV2(edge.Type, edge.Source, edge.Target, classified.evidenceIDs, edge.EventTime, classified.class, classified.rule, edge.FocusFindingIDs)
			if err != nil {
				return graph.GraphV2{}, fmt.Errorf("project v0.2 edge %s: %w", edge.ID, err)
			}
			result.Edges = append(result.Edges, projected)
		}
	}
	// Scope-sensitive exposure identities are deliberately reprojected from
	// typed facts instead of copied from the frozen compatibility graph. The v1
	// projector predates repository/execution scoping for these node types and
	// must remain byte-for-byte unchanged for retained cases.
	if err := addV2ScopedExposureContext(idx, findings, &result); err != nil {
		return graph.GraphV2{}, err
	}
	if err := result.NormalizeAndValidate(); err != nil {
		return graph.GraphV2{}, err
	}
	return result, nil
}

// isNarrowNonExecutedEnvironmentContext admits only the presentation-only
// target context described by the v0.2 evidence-path contract. A started job,
// an eligible secret, a lifecycle observation, or ambiguous job state must not
// acquire environment reachability merely because the finding was not a
// confirmed execution.
func isNarrowNonExecutedEnvironmentContext(idx index, execution model.JobExecutionIdentity, environment archive.EnvironmentEligibilityFact) bool {
	if environment.JobStarted || environment.GateState != "pending" || len(environment.SecretNames) != 0 {
		return false
	}
	job, ok := idx.jobs[execution.String()]
	if !ok || job.Conclusion != "" {
		return false
	}
	switch job.Status {
	case "waiting", "pending", "queued", "requested":
	default:
		return false
	}
	for _, fact := range idx.actions {
		if fact.ActionOccurrence != nil &&
			fact.ActionOccurrence.Observation.Execution == execution &&
			fact.ActionOccurrence.Observation.Kind.SupportsExecuted() {
			return false
		}
	}
	return true
}

func graphCaseKind(kind report.CaseKind) graph.CaseKind {
	switch kind {
	case report.CaseKindSynthetic:
		return graph.CaseKindSynthetic
	case report.CaseKindCollected:
		return graph.CaseKindCollected
	case report.CaseKindMixed:
		return graph.CaseKindMixed
	default:
		return graph.CaseKindUnknown
	}
}

func classificationsForEdge(idx index, edge graph.Edge) []edgeClassification {
	switch edge.Type {
	case graph.EdgeContradicts:
		return []edgeClassification{{class: graph.EvidenceClassContradiction, rule: edge.DerivationRule, evidenceIDs: edge.EvidenceIDs}}
	case graph.EdgeObservedAfter:
		return []edgeClassification{{class: graph.EvidenceClassTemporalCorrelation, rule: edge.DerivationRule, evidenceIDs: edge.EvidenceIDs}}
	case graph.EdgeHadTokenPermission, graph.EdgeReferencedSecret, graph.EdgePassedSecretTo, graph.EdgeInheritedSecret, graph.EdgeCouldMintOIDC:
		return credentialClassifications(idx, edge)
	case graph.EdgeCrossedEnvironmentGate:
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: "environment-gate-from-job-state/v1", evidenceIDs: edge.EvidenceIDs}}
	case graph.EdgeEnvironmentSecretEligible:
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: graphEnvironmentEligibleRule, evidenceIDs: edge.EvidenceIDs}}
	}
	if !edge.Inferred {
		switch edge.Type {
		case graph.EdgeWorkflowDeclaredAction, graph.EdgeWorkflowCalledWorkflow, graph.EdgeLocalActionResolvedTo:
			if classified, ok := dependencyDefinitionClassifications(idx, edge); ok {
				return classified
			}
		}
	}
	if edge.Inferred {
		rule := edge.DerivationRule
		if rule == "" {
			rule = graphFindingRule
		}
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: rule, evidenceIDs: edge.EvidenceIDs}}
	}
	return []edgeClassification{{class: graph.EvidenceClassExactObservation, rule: edge.DerivationRule, evidenceIDs: edge.EvidenceIDs}}
}

// dependencyDefinitionClassifications recovers the temporal source basis from
// typed dependency facts without changing the byte-frozen v1 graph. One v1
// edge can aggregate more than one basis, so v2 splits those propositions and
// retains only the evidence IDs supporting each basis.
func dependencyDefinitionClassifications(idx index, edge graph.Edge) ([]edgeClassification, bool) {
	groups := make(map[string][]string)
	for _, fact := range idx.dependencies {
		if !dependencyFactProjectsEdge(fact, edge) {
			continue
		}
		rule := definitionBasisRule(fact.Dependency.Basis)
		if rule == "" {
			continue
		}
		edgeEvidence := stringSet(edge.EvidenceIDs)
		for _, evidenceID := range idsToStrings(fact.EvidenceIDs) {
			if _, ok := edgeEvidence[evidenceID]; ok {
				groups[rule] = append(groups[rule], evidenceID)
			}
		}
	}
	if len(groups) == 0 {
		return nil, false
	}
	rules := make([]string, 0, len(groups))
	for rule := range groups {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	result := make([]edgeClassification, 0, len(rules))
	for _, rule := range rules {
		result = append(result, edgeClassification{
			class:       graph.EvidenceClassExactObservation,
			rule:        rule,
			evidenceIDs: sortedUniqueStrings(groups[rule]),
		})
	}
	return result, true
}

func dependencyFactProjectsEdge(fact archive.Fact, edge graph.Edge) bool {
	if fact.Dependency == nil || dependencyEdgeType(fact.Dependency.Relation) != edge.Type || !evidenceIntersects(fact.EvidenceIDs, stringSet(edge.EvidenceIDs)) {
		return false
	}
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	source := builder.dependencySource(*fact.Dependency, edge.EvidenceIDs, "")
	target, _, _ := builder.dependencyTarget(*fact.Dependency, edge.EvidenceIDs, "")
	return source == edge.Source && target == edge.Target && eventText(fact.Dependency.EventTime) == edge.EventTime
}

func definitionBasisRule(basis archive.DefinitionBasis) string {
	switch basis {
	case archive.DefinitionHistoricalAtRun:
		return graph.DefinitionBasisHistoricalAtRunRule
	case archive.DefinitionCurrentSnapshot:
		return graph.DefinitionBasisCurrentSnapshotRule
	case archive.DefinitionRuntimeAttemptMetadata:
		return graph.DefinitionBasisRuntimeAttemptMetadataRule
	default:
		return ""
	}
}

func credentialClassifications(idx index, edge graph.Edge) []edgeClassification {
	type key struct {
		class graph.EvidenceClass
		rule  string
		omit  bool
	}
	groups := map[key][]string{}
	for _, fact := range idx.exposures {
		if !credentialFactProjectsEdge(fact, edge) {
			continue
		}
		credential := fact.Exposure.Credential
		ids := idsToStrings(credential.EvidenceIDs)
		if !credential.Basis.Valid() {
			groups[key{omit: true}] = append(groups[key{omit: true}], ids...)
			continue
		}
		if edge.Type == graph.EdgeCouldMintOIDC {
			groups[key{class: graph.EvidenceClassInference, rule: graphOIDCCapabilityRule}] = append(groups[key{class: graph.EvidenceClassInference, rule: graphOIDCCapabilityRule}], ids...)
			continue
		}
		if credential.Basis == model.ExposureBasisRuntimeObserved {
			groups[key{class: graph.EvidenceClassExactObservation}] = append(groups[key{class: graph.EvidenceClassExactObservation}], ids...)
			continue
		}
		rule := "credential-relationship/" + string(credential.Basis) + "/v1"
		groups[key{class: graph.EvidenceClassInference, rule: rule}] = append(groups[key{class: graph.EvidenceClassInference, rule: rule}], ids...)
	}
	if len(groups) == 0 {
		// A v1 archive may retain a legal exposure whose original basis is not
		// classifiable under v0.2. Preserve the finding and omit only the visual
		// relationship rather than inventing certainty.
		return []edgeClassification{{omit: true, evidenceIDs: edge.EvidenceIDs}}
	}
	keys := make([]key, 0, len(groups))
	for group := range groups {
		keys = append(keys, group)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := string(keys[i].class) + "\x00" + keys[i].rule
		right := string(keys[j].class) + "\x00" + keys[j].rule
		if left != right {
			return left < right
		}
		return !keys[i].omit && keys[j].omit
	})
	result := make([]edgeClassification, 0, len(keys))
	for _, group := range keys {
		result = append(result, edgeClassification{class: group.class, rule: group.rule, omit: group.omit, evidenceIDs: sortedUniqueStrings(groups[group])})
	}
	return result
}

// credentialFactProjectsEdge joins the evidence basis to the exact legacy
// proposition that produced the edge. Evidence objects commonly support more
// than one permission, secret relationship, or job, so evidence-ID overlap and
// credential kind alone are not a safe join.
func credentialFactProjectsEdge(fact archive.Fact, edge graph.Edge) bool {
	if fact.Exposure == nil || fact.Exposure.Credential == nil || !credentialSupportsEdge(fact.Exposure.Credential.Kind, edge.Type) {
		return false
	}
	credentialEvidence := idsToStrings(fact.Exposure.Credential.EvidenceIDs)
	if !stringSetsIntersect(credentialEvidence, edge.EvidenceIDs) {
		return false
	}
	exposure := fact.Exposure
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	jobNode := builder.jobNode(exposure.Execution, credentialEvidence, "")
	sourceNode := jobNode
	if exposure.StepKey != "" {
		sourceNode = builder.addNode(graph.NodeStep, exposure.StepKey, []string{"step", exposure.StepKey}, credentialEvidence, "")
	}
	builder.projectCredential(*exposure.Credential, sourceNode, jobNode, exposure.StepKey != "", exposure.EventTime, "")
	for _, projected := range builder.edges {
		if projected.Type == edge.Type && projected.Source == edge.Source && projected.Target == edge.Target && projected.EventTime == edge.EventTime {
			return true
		}
	}
	return false
}

func stringSetsIntersect(left, right []string) bool {
	wanted := stringSet(right)
	for _, value := range left {
		if _, ok := wanted[value]; ok {
			return true
		}
	}
	return false
}

func credentialSupportsEdge(kind model.CredentialExposureKind, edge graph.EdgeType) bool {
	switch edge {
	case graph.EdgeHadTokenPermission:
		return kind == model.ExposureGitHubTokenPermission
	case graph.EdgeCouldMintOIDC:
		return kind == model.ExposureGitHubTokenPermission
	case graph.EdgeReferencedSecret:
		return kind == model.ExposureSecretReferencedByJob
	case graph.EdgePassedSecretTo:
		return kind == model.ExposureSecretPassedToStep || kind == model.ExposureReusableSecretMapped
	case graph.EdgeInheritedSecret:
		return kind == model.ExposureReusableSecretInherited
	default:
		return false
	}
}

func buildFindingIndex(idx index, findings []report.Finding, pack *incident.ValidatedPack) []graph.FindingIndexEntry {
	identityBindings := findingExactIdentityBindings(pack)
	result := make([]graph.FindingIndexEntry, 0, len(findings))
	for _, finding := range findings {
		entry := graph.FindingIndexEntry{
			FindingRevisionID: finding.FindingRevisionID,
			State:             model.FindingState(finding.State),
			ProvenanceLevel:   model.ProvenanceLevel(finding.Provenance),
			Repository:        finding.Repository,
			WorkflowPath:      finding.Workflow,
			StepIdentity:      finding.StepIdentity,
			IndicatorID:       finding.IndicatorID,
			CoverageClosed:    findingIndexCoverageClosed(idx, finding),
		}
		if finding.RunID > 0 {
			value := model.WorkflowRunID(finding.RunID)
			entry.RunID = &value
		}
		if finding.RunAttempt > 0 {
			value := model.RunAttempt(finding.RunAttempt)
			entry.RunAttempt = &value
		}
		if finding.JobID > 0 {
			value := model.JobID(finding.JobID)
			entry.JobID = &value
		}
		if len(finding.EvidenceGaps) > 0 {
			entry.EvidenceGapReason = strings.Join(sortedUniqueStrings(finding.EvidenceGaps), "; ")
		}
		binding, bound := identityBindings[finding.IndicatorID]
		if bound {
			entry.ExactIdentityKind, entry.ExactIdentity = findingExactIdentity(idx, finding, binding)
			_, entry.ExactKnownGood = binding.knownGood[exactIdentityKey(entry.ExactIdentityKind, entry.ExactIdentity)]
			entry.ExactKnownGood = entry.ExactIdentity != "" && entry.ExactKnownGood
		}
		result = append(result, entry)
	}
	return result
}

func findingExactIdentityBindings(pack *incident.ValidatedPack) map[string]findingExactIdentityBinding {
	bindings := map[string]findingExactIdentityBinding{}
	if pack == nil {
		return bindings
	}
	components := make(map[string]incident.Component, len(pack.Pack.Spec.Components))
	for _, component := range pack.Pack.Spec.Components {
		components[component.ID] = component
	}
	knownGood := make(map[string]map[string]struct{})
	for _, good := range pack.Pack.Spec.KnownGood {
		kind, identity := incidentExactIdentity(good.Kind, good.Value)
		if kind == "" || identity == "" {
			continue
		}
		if knownGood[good.ComponentID] == nil {
			knownGood[good.ComponentID] = map[string]struct{}{}
		}
		knownGood[good.ComponentID][exactIdentityKey(kind, identity)] = struct{}{}
	}
	for _, indicator := range pack.Pack.Spec.Indicators {
		component, exists := components[indicator.ComponentID]
		if !exists {
			continue
		}
		binding := findingExactIdentityBinding{
			component: component,
			eligible:  map[string]struct{}{},
			knownGood: knownGood[indicator.ComponentID],
		}
		for key := range binding.knownGood {
			binding.eligible[key] = struct{}{}
		}
		kind, identity := incidentExactIdentity(indicator.Kind, indicator.Value)
		if kind != "" && identity != "" {
			binding.eligible[exactIdentityKey(kind, identity)] = struct{}{}
		}
		bindings[indicator.ID] = binding
	}
	return bindings
}

func findingIndexCoverageClosed(idx index, finding report.Finding) bool {
	if finding.State != string(model.NoMatchConfirmed) || len(finding.EvidenceGaps) != 0 || finding.RunID <= 0 || finding.RunAttempt <= 0 || finding.JobID <= 0 {
		return false
	}
	repositoryID, found := repositoryIDForGraph(idx, finding.Repository)
	if !found {
		return false
	}
	runID := model.WorkflowRunID(finding.RunID)
	attempt := model.RunAttempt(finding.RunAttempt)
	jobID := model.JobID(finding.JobID)
	subject := archive.FactSubject{
		RepositoryID: repositoryID,
		RunID:        &runID,
		RunAttempt:   &attempt,
		JobID:        &jobID,
		StepKey:      finding.StepIdentity,
	}
	coverageIDs, closed := requiredNegativeCoverageClosed(idx, subject)
	if !closed || len(coverageIDs) != len(finding.CollectionCoverage) {
		return false
	}
	for index, id := range coverageIDs {
		if string(id) != finding.CollectionCoverage[index] {
			return false
		}
	}
	return true
}

func incidentExactIdentity(kind string, value incident.IndicatorValue) (graph.ExactIdentityKind, string) {
	switch kind {
	case "action-commit":
		if value.GitObject != nil {
			return graph.ExactIdentityActionCommitSHA, value.GitObject.Algorithm + ":" + value.GitObject.Value
		}
	case "digest":
		return graph.ExactIdentityPackageDigest, value.Subject + ":" + value.Algorithm + ":" + value.Digest
	case "reusable-workflow-commit":
		if value.GitObject != nil {
			return graph.ExactIdentityCalledWorkflowSHA, value.GitObject.Algorithm + ":" + value.GitObject.Value
		}
	}
	return "", ""
}

func exactIdentityKey(kind graph.ExactIdentityKind, value string) string {
	return string(kind) + "\x00" + value
}

func findingExactIdentity(idx index, finding report.Finding, binding findingExactIdentityBinding) (graph.ExactIdentityKind, string) {
	repositoryID, found := repositoryIDForGraph(idx, finding.Repository)
	if !found {
		return "", ""
	}
	wanted := stringSet(finding.EvidenceIDs)
	candidates := map[string]exactIdentityCandidate{}
	addCandidate := func(candidate exactIdentityCandidate) {
		key := exactIdentityKey(candidate.kind, candidate.value)
		if _, eligible := binding.eligible[key]; eligible {
			candidates[key] = candidate
		}
	}
	for _, fact := range idx.actions {
		if fact.ActionOccurrence == nil || !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wanted) {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if !componentMatches(binding.component, string(observation.ActionRepository), observation.ActionSubpath) {
			continue
		}
		if observation.SourceObjectID != nil {
			object := model.GitObjectID(*observation.SourceObjectID)
			addCandidate(exactIdentityCandidate{graph.ExactIdentityActionCommitSHA, string(object.Algorithm) + ":" + object.Value})
		}
		if observation.PackageDigest != nil {
			digest := *observation.PackageDigest
			addCandidate(exactIdentityCandidate{graph.ExactIdentityPackageDigest, string(digest.Subject) + ":" + string(digest.Algorithm) + ":" + digest.Value})
		}
	}
	for _, fact := range idx.dependencies {
		if fact.Dependency == nil || !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wanted) {
			continue
		}
		dependency := fact.Dependency
		if !componentMatches(binding.component, string(dependency.TargetRepository), dependency.TargetPath) || dependency.TargetCalledWorkflowObjectID == nil {
			continue
		}
		object := model.GitObjectID(*dependency.TargetCalledWorkflowObjectID)
		addCandidate(exactIdentityCandidate{graph.ExactIdentityCalledWorkflowSHA, string(object.Algorithm) + ":" + object.Value})
	}
	// Evidence IDs identify retained objects, not individual lines within a
	// shared setup log. More than one distinct incident-eligible identity in
	// that evidence cannot be bound safely to this derived finding.
	if len(candidates) != 1 {
		return "", ""
	}
	for _, candidate := range candidates {
		return candidate.kind, candidate.value
	}
	return "", ""
}
