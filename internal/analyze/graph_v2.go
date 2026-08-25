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
	graphEnvironmentGateRule     = "environment-gate-from-job-state/v1"
	graphEnvironmentEligibleRule = "environment-secret-eligibility/v1"
)

type edgeClassification struct {
	class       graph.EvidenceClass
	rule        string
	evidenceIDs []string
	omit        bool
}

// buildGraphV2 projects explicit evidence classes from the typed facts that
// produced the frozen v1 graph. The renderer only validates these classes; it
// never guesses semantics from an edge name or color.
func buildGraphV2(idx index, legacy graph.Graph, findings []report.Finding, pack *incident.ValidatedPack, kind report.CaseKind) (graph.GraphV2, error) {
	result := graph.GraphV2{
		SchemaVersion: graph.SchemaVersionV2,
		CaseKind:      graphCaseKind(kind),
		Nodes:         make([]graph.NodeV2, len(legacy.Nodes)),
		FindingIndex:  buildFindingIndex(idx, findings, pack),
	}
	for index, node := range legacy.Nodes {
		result.Nodes[index] = node
		result.Nodes[index].EvidenceIDs = append([]string(nil), node.EvidenceIDs...)
		result.Nodes[index].FocusFindingIDs = append([]string(nil), node.FocusFindingIDs...)
	}
	for _, edge := range legacy.Edges {
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
	// The frozen v1 graph attaches exposure context only to confirmed execution
	// findings. v0.2 additionally presents an exact environment target for an
	// unstarted or otherwise non-executed job, because that absence is the fact
	// that prevents environment-secret eligibility. This augments only the v2
	// projection and never turns targeting into gate crossing or secret access.
	if err := addNonExecutedEnvironmentContext(idx, findings, &result); err != nil {
		return graph.GraphV2{}, err
	}
	if err := result.NormalizeAndValidate(); err != nil {
		return graph.GraphV2{}, err
	}
	return result, nil
}

func addNonExecutedEnvironmentContext(idx index, findings []report.Finding, result *graph.GraphV2) error {
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	for _, finding := range findings {
		if finding.State == string(model.ConfirmedExecuted) || finding.RunID <= 0 || finding.RunAttempt <= 0 || finding.JobID <= 0 {
			continue
		}
		repositoryID, ok := repositoryIDForGraph(idx, finding.Repository)
		if !ok {
			continue
		}
		execution := model.JobExecutionIdentity{RepositoryID: repositoryID, RunID: model.WorkflowRunID(finding.RunID), RunAttempt: model.RunAttempt(finding.RunAttempt), JobID: model.JobID(finding.JobID)}
		for _, fact := range idx.exposures {
			if fact.Exposure == nil || fact.Exposure.Environment == nil || fact.Exposure.Execution != execution {
				continue
			}
			environment := *fact.Exposure.Environment
			if !isNarrowNonExecutedEnvironmentContext(idx, execution, environment) {
				continue
			}
			evidenceIDs := idsToStrings(fact.EvidenceIDs)
			jobNode := builder.jobNode(execution, evidenceIDs, finding.FindingRevisionID)
			environmentNode := builder.addNode(
				graph.NodeEnvironment,
				environment.EnvironmentName+" / gate "+environment.GateState,
				[]string{"environment", environment.EnvironmentName},
				evidenceIDs,
				finding.FindingRevisionID,
			)
			builder.addEdge(
				graph.EdgeTargetedEnvironment,
				jobNode,
				environmentNode,
				evidenceIDs,
				eventText(fact.Exposure.EventTime),
				false,
				"",
				finding.FindingRevisionID,
			)
		}
	}
	nodeIndex := make(map[string]int, len(result.Nodes))
	for index := range result.Nodes {
		nodeIndex[result.Nodes[index].ID] = index
	}
	for _, node := range builder.nodes {
		if index, exists := nodeIndex[node.ID]; exists {
			current := &result.Nodes[index]
			current.EvidenceIDs = append(current.EvidenceIDs, node.EvidenceIDs...)
			current.FocusFindingIDs = append(current.FocusFindingIDs, node.FocusFindingIDs...)
			if node.Label < current.Label {
				current.Label = node.Label
			}
			continue
		}
		nodeIndex[node.ID] = len(result.Nodes)
		result.Nodes = append(result.Nodes, node)
	}
	for _, edge := range builder.edges {
		for _, classified := range classificationsForEdge(idx, edge) {
			if classified.omit {
				continue
			}
			projected, err := graph.NewEdgeV2(edge.Type, edge.Source, edge.Target, classified.evidenceIDs, edge.EventTime, classified.class, classified.rule, edge.FocusFindingIDs)
			if err != nil {
				return fmt.Errorf("project v0.2 environment edge %s: %w", edge.ID, err)
			}
			result.Edges = append(result.Edges, projected)
		}
	}
	return nil
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
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: graphEnvironmentGateRule, evidenceIDs: edge.EvidenceIDs}}
	case graph.EdgeEnvironmentSecretEligible:
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: graphEnvironmentEligibleRule, evidenceIDs: edge.EvidenceIDs}}
	}
	if edge.Inferred {
		rule := edge.DerivationRule
		if rule == "" {
			rule = graphFindingRule
		}
		return []edgeClassification{{class: graph.EvidenceClassInference, rule: rule, evidenceIDs: edge.EvidenceIDs}}
	}
	return []edgeClassification{{class: graph.EvidenceClassExactObservation, evidenceIDs: edge.EvidenceIDs}}
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
	indicatorComponents := make(map[string]string)
	indicatorIdentityKinds := make(map[string]graph.ExactIdentityKind)
	knownGood := make(map[string]map[string]bool)
	if pack != nil {
		for _, indicator := range pack.Pack.Spec.Indicators {
			indicatorComponents[indicator.ID] = indicator.ComponentID
			indicatorIdentityKinds[indicator.ID], _ = incidentExactIdentity(indicator.Kind, indicator.Value)
		}
		for _, good := range pack.Pack.Spec.KnownGood {
			identityKind, identity := incidentExactIdentity(good.Kind, good.Value)
			if identity == "" {
				continue
			}
			if knownGood[good.ComponentID] == nil {
				knownGood[good.ComponentID] = map[string]bool{}
			}
			knownGood[good.ComponentID][string(identityKind)+"\x00"+identity] = true
		}
	}
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
		entry.ExactIdentityKind, entry.ExactIdentity = findingExactIdentity(idx, finding, indicatorIdentityKinds[finding.IndicatorID])
		componentID := indicatorComponents[finding.IndicatorID]
		entry.ExactKnownGood = entry.ExactIdentity != "" && knownGood[componentID][string(entry.ExactIdentityKind)+"\x00"+entry.ExactIdentity]
		result = append(result, entry)
	}
	return result
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

func findingExactIdentity(idx index, finding report.Finding, preferred graph.ExactIdentityKind) (graph.ExactIdentityKind, string) {
	repositoryID, found := repositoryIDForGraph(idx, finding.Repository)
	if !found {
		return "", ""
	}
	wanted := stringSet(finding.EvidenceIDs)
	var candidates []struct {
		kind  graph.ExactIdentityKind
		value string
	}
	for _, fact := range idx.actions {
		if fact.ActionOccurrence == nil || !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wanted) {
			continue
		}
		observation := fact.ActionOccurrence.Observation
		if observation.SourceObjectID != nil {
			object := model.GitObjectID(*observation.SourceObjectID)
			candidates = append(candidates, struct {
				kind  graph.ExactIdentityKind
				value string
			}{graph.ExactIdentityActionCommitSHA, string(object.Algorithm) + ":" + object.Value})
		}
		if observation.PackageDigest != nil {
			digest := *observation.PackageDigest
			candidates = append(candidates, struct {
				kind  graph.ExactIdentityKind
				value string
			}{graph.ExactIdentityPackageDigest, string(digest.Subject) + ":" + string(digest.Algorithm) + ":" + digest.Value})
		}
	}
	for _, fact := range idx.dependencies {
		if fact.Dependency == nil || !factMatchesFinding(fact, finding, repositoryID) || !evidenceIntersects(fact.EvidenceIDs, wanted) || fact.Dependency.TargetCalledWorkflowObjectID == nil {
			continue
		}
		object := model.GitObjectID(*fact.Dependency.TargetCalledWorkflowObjectID)
		candidates = append(candidates, struct {
			kind  graph.ExactIdentityKind
			value string
		}{graph.ExactIdentityCalledWorkflowSHA, string(object.Algorithm) + ":" + object.Value})
	}
	if len(candidates) == 0 {
		return "", ""
	}
	if preferred != "" {
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if candidate.kind == preferred {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return string(candidates[i].kind)+"\x00"+candidates[i].value < string(candidates[j].kind)+"\x00"+candidates[j].value
	})
	return candidates[0].kind, candidates[0].value
}
