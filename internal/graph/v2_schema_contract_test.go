package graph

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/torjan0/cirewind/internal/model"
)

func TestGraphV2SchemaVocabularyMatchesClosedGoContract(t *testing.T) {
	t.Parallel()
	document := loadGraphV2SchemaDocument(t)
	defs := schemaObject(t, document, "$defs")

	wantNodeTypes := []string{
		string(NodeRepository), string(NodeWorkflowDefinition), string(NodeReusableWorkflowDefinition),
		string(NodeWorkflowRun), string(NodeRunAttempt), string(NodeJob), string(NodeStep),
		string(NodeActionRepository), string(NodeActionRef), string(NodeActionCommit),
		string(NodeImmutableActionPackage), string(NodeActionDefinition), string(NodeRunner),
		string(NodeRunnerGroup), string(NodeEnvironment), string(NodeTokenCapability),
		string(NodeSecretMetadata), string(NodeOIDCProvider), string(NodeArtifact), string(NodePackage),
		string(NodeRelease), string(NodeDeployment), string(NodeRepositoryResource),
		string(NodePullRequestChange), string(NodeEvidenceObject), string(NodeFinding),
	}
	for _, value := range wantNodeTypes {
		if !NodeType(value).valid() {
			t.Fatalf("schema test contains noncanonical Go node type %q", value)
		}
	}
	assertSameStringSet(t, "node types", schemaStrings(t, schemaObject(t, defs, "nodeType"), "enum"), wantNodeTypes)

	wantEdgeTypes := make([]string, 0, len(v2EndpointRules))
	for edgeType := range v2EndpointRules {
		wantEdgeTypes = append(wantEdgeTypes, string(edgeType))
	}
	assertSameStringSet(t, "edge types", schemaStrings(t, schemaObject(t, defs, "edgeType"), "enum"), wantEdgeTypes)

	rootProperties := schemaObject(t, document, "properties")
	assertSameStringSet(t, "case kinds", schemaStrings(t, schemaObject(t, rootProperties, "caseKind"), "enum"), []string{
		string(CaseKindSynthetic), string(CaseKindCollected), string(CaseKindMixed), string(CaseKindUnknown),
	})

	edgeProperties := schemaObject(t, schemaObject(t, defs, "edge"), "properties")
	assertSameStringSet(t, "evidence classes", schemaStrings(t, schemaObject(t, edgeProperties, "evidenceClass"), "enum"), []string{
		string(EvidenceClassExactObservation), string(EvidenceClassInference),
		string(EvidenceClassTemporalCorrelation), string(EvidenceClassContradiction),
	})

	findingProperties := schemaObject(t, schemaObject(t, defs, "findingIndex"), "properties")
	wantStates := make([]string, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		wantStates = append(wantStates, string(state))
	}
	assertSameStringSet(t, "finding states", schemaStrings(t, schemaObject(t, findingProperties, "state"), "enum"), wantStates)
	wantProvenance := make([]string, 0, len(model.ProvenanceLevels()))
	for _, level := range model.ProvenanceLevels() {
		wantProvenance = append(wantProvenance, string(level))
	}
	assertSameStringSet(t, "provenance levels", schemaStrings(t, schemaObject(t, findingProperties, "provenanceLevel"), "enum"), wantProvenance)
	assertSameStringSet(t, "exact identity kinds", schemaStrings(t, schemaObject(t, findingProperties, "exactIdentityKind"), "enum"), []string{
		string(ExactIdentityActionCommitSHA), string(ExactIdentityPackageDigest), string(ExactIdentityCalledWorkflowSHA),
	})

	noticeProperties := schemaObject(t, schemaObject(t, defs, "notice"), "properties")
	if got := schemaString(t, schemaObject(t, noticeProperties, "code"), "const"); got != string(ProjectionNoticeUnclassifiableLegacyBasis) {
		t.Fatalf("projection notice code = %q, want %q", got, ProjectionNoticeUnclassifiableLegacyBasis)
	}
	wantNoticeRelationships := make([]string, 0, len(legacyBasisNoticeRelationships))
	for relationship := range legacyBasisNoticeRelationships {
		wantNoticeRelationships = append(wantNoticeRelationships, string(relationship))
	}
	assertSameStringSet(t, "projection notice relationships", schemaStrings(t, schemaObject(t, noticeProperties, "relationship"), "enum"), wantNoticeRelationships)
}

func TestGraphV2SchemaEvidenceClassMatrixMatchesGoValidator(t *testing.T) {
	t.Parallel()
	schema := compileGraphV2Schema(t)
	focus := findingID("d")
	classes := []EvidenceClass{
		EvidenceClassExactObservation,
		EvidenceClassInference,
		EvidenceClassTemporalCorrelation,
		EvidenceClassContradiction,
	}

	for edgeType, endpoints := range v2EndpointRules {
		edgeType, endpoints := edgeType, endpoints
		t.Run(string(edgeType), func(t *testing.T) {
			t.Parallel()
			for _, class := range classes {
				class := class
				t.Run(string(class), func(t *testing.T) {
					sourceType := firstNodeType(endpoints.sources)
					targetType := firstNodeType(endpoints.targets)
					rule := ""
					if class == EvidenceClassInference {
						rule = "schema-parity-test/v1"
						if edgeType == EdgeEnvironmentGateSatisfied {
							rule = EnvironmentGateSatisfiedApprovedRule
						}
						if edgeType == EdgeEnvironmentSecretEligible {
							rule = EnvironmentSecretEligibilityRule
						}
					}
					edge, err := NewEdgeV2(edgeType, "source", "target", []string{evidenceID("d")}, "unknown", class, rule, []string{focus})
					if err != nil {
						t.Fatal(err)
					}
					value := GraphV2{
						SchemaVersion: SchemaVersionV2,
						CaseKind:      CaseKindSynthetic,
						Nodes: []NodeV2{
							{ID: "source", Type: sourceType, Label: "source", FocusFindingIDs: []string{focus}},
							{ID: "target", Type: targetType, Label: "target", FocusFindingIDs: []string{focus}},
						},
						Edges:        []EdgeV2{edge},
						FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
					}
					if edgeType == EdgeEnvironmentGateSatisfied {
						targeted, edgeErr := NewEdgeV2(EdgeTargetedEnvironment, "source", "target", []string{evidenceID("e")}, "unknown", EvidenceClassInference, EnvironmentTargetHistoricalRule, []string{focus})
						if edgeErr != nil {
							t.Fatal(edgeErr)
						}
						value.Edges = append(value.Edges, targeted)
					}
					if edgeType == EdgeEnvironmentSecretEligible {
						value.Nodes = append(value.Nodes, NodeV2{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}})
						targeted, edgeErr := NewEdgeV2(EdgeTargetedEnvironment, "job", "source", []string{evidenceID("e")}, "unknown", EvidenceClassInference, EnvironmentTargetHistoricalRule, []string{focus})
						if edgeErr != nil {
							t.Fatal(edgeErr)
						}
						satisfied, edgeErr := NewEdgeV2(EdgeEnvironmentGateSatisfied, "job", "source", []string{evidenceID("f")}, "unknown", EvidenceClassInference, EnvironmentGateSatisfiedApprovedRule, []string{focus})
						if edgeErr != nil {
							t.Fatal(edgeErr)
						}
						value.Edges = append(value.Edges, targeted, satisfied)
					}
					codeValue := CloneGraphV2(value)
					codeAccepted := codeValue.NormalizeAndValidate() == nil
					schemaAccepted := graphV2SchemaAccepts(t, schema, value)
					want := relationshipAllowsEvidenceClass(edgeType, class)
					if codeAccepted != want || schemaAccepted != want {
						t.Fatalf("relationship/class acceptance drift: Go=%t schema=%t want=%t", codeAccepted, schemaAccepted, want)
					}
				})
			}
		})
	}
}

func TestGraphV2SchemaEnvironmentGateStateRulesMatchGoValidator(t *testing.T) {
	t.Parallel()
	schema := compileGraphV2Schema(t)
	focus := findingID("e")
	target, err := NewEdgeV2(
		EdgeTargetedEnvironment, "job", "environment", []string{evidenceID("e")}, "unknown",
		EvidenceClassInference, EnvironmentTargetHistoricalRule, []string{focus},
	)
	if err != nil {
		t.Fatal(err)
	}
	base := GraphV2{
		SchemaVersion: SchemaVersionV2,
		CaseKind:      CaseKindSynthetic,
		Nodes: []NodeV2{
			{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}},
			{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
		},
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
	}
	for _, rule := range []string{
		EnvironmentGateSatisfiedApprovedRule,
		EnvironmentGateSatisfiedBypassedRule,
		EnvironmentGateSatisfiedCrossedRule,
		EnvironmentGateSatisfiedNotRequiredRule,
		"environment-gate-satisfied-from-retained-state/v1",
	} {
		t.Run(rule, func(t *testing.T) {
			eventTime := "unknown"
			if rule == EnvironmentGateSatisfiedNotRequiredRule {
				eventTime = "2026-08-26T12:00:00Z"
			}
			satisfied, edgeErr := NewEdgeV2(
				EdgeEnvironmentGateSatisfied, "job", "environment", []string{evidenceID("f")}, eventTime,
				EvidenceClassInference, rule, []string{focus},
			)
			if edgeErr != nil {
				t.Fatal(edgeErr)
			}
			value := CloneGraphV2(base)
			value.Edges = []EdgeV2{target, satisfied}
			_, acceptedRule := EnvironmentGateSatisfiedStateForRule(rule)
			codeAccepted := value.NormalizeAndValidate() == nil
			schemaAccepted := graphV2SchemaAccepts(t, schema, value)
			if codeAccepted != acceptedRule || schemaAccepted != acceptedRule {
				t.Fatalf("gate-state rule acceptance drift: Go=%t schema=%t want=%t", codeAccepted, schemaAccepted, acceptedRule)
			}
		})
	}
	for _, eventTime := range []string{"", "unknown", "UNKNOWN", "Unknown", "uNkNoWn", " unknown ", "unknown ", "\tunknown\n"} {
		t.Run("not-required/"+eventTime, func(t *testing.T) {
			satisfied, edgeErr := NewEdgeV2(
				EdgeEnvironmentGateSatisfied, "job", "environment", []string{evidenceID("f")}, eventTime,
				EvidenceClassInference, EnvironmentGateSatisfiedNotRequiredRule, []string{focus},
			)
			if edgeErr != nil {
				t.Fatal(edgeErr)
			}
			// Exercise the serialized schema with the exact noncanonical input;
			// NewEdgeV2 intentionally trims trusted projector output.
			satisfied.EventTime = eventTime
			value := CloneGraphV2(base)
			value.Edges = []EdgeV2{target, satisfied}
			if value.NormalizeAndValidate() == nil || graphV2SchemaAccepts(t, schema, value) {
				t.Fatal("unknown-time not-required edge was accepted")
			}
		})
	}
}

func TestGraphV2NormalizationBoundaryProducesCanonicalSchemaValidOutput(t *testing.T) {
	t.Parallel()
	// Trusted projectors may construct normalization forms that are not public
	// graph.json instances. In particular, a missing in-process schema default,
	// nil required slices, and hostile display controls are normalized before
	// serialization. This test fixes that boundary explicitly.
	value := GraphV2{
		CaseKind: CaseKindSynthetic,
		Nodes: []NodeV2{{
			ID: "finding", Type: NodeFinding, Label: "hostile\u001b[31m\u202ename",
			EvidenceIDs: []string{evidenceID("e"), evidenceID("e")},
		}},
	}
	if err := value.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != SchemaVersionV2 || value.Edges == nil || value.FindingIndex == nil {
		t.Fatalf("normalizer did not materialize the serialized contract: %#v", value)
	}
	if value.Nodes[0].Label == "hostile\u001b[31m\u202ename" || len(value.Nodes[0].EvidenceIDs) != 1 {
		t.Fatalf("normalizer did not sanitize/deduplicate trusted projector output: %#v", value.Nodes[0])
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !graphV2SchemaAccepts(t, compileGraphV2Schema(t), value) {
		t.Fatal("normalized serialized output violates the public schema")
	}
	var decoded GraphV2
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, after) {
		t.Fatalf("serialized graph was not already canonical\nbefore: %s\nafter:  %s", encoded, after)
	}
}

func loadGraphV2SchemaDocument(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../schema/graph-v1alpha2.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func compileGraphV2Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("../../schema/graph-v1alpha2.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	const schemaURL = "https://schemas.invalid/cirewind/graph-v1alpha2.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func graphV2SchemaAccepts(t *testing.T, schema *jsonschema.Schema, value GraphV2) bool {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal(encoded, &instance); err != nil {
		t.Fatal(err)
	}
	return schema.Validate(instance) == nil
}

func firstNodeType(values map[NodeType]struct{}) NodeType {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, string(value))
	}
	sort.Strings(items)
	return NodeType(items[0])
}

func schemaObject(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	object, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("schema field %q is %T, want object", key, value[key])
	}
	return object
}

func schemaString(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	text, ok := value[key].(string)
	if !ok {
		t.Fatalf("schema field %q is %T, want string", key, value[key])
	}
	return text
}

func schemaStrings(t *testing.T, value map[string]any, key string) []string {
	t.Helper()
	raw, ok := value[key].([]any)
	if !ok {
		t.Fatalf("schema field %q is %T, want array", key, value[key])
	}
	result := make([]string, len(raw))
	for i, item := range raw {
		var ok bool
		result[i], ok = item.(string)
		if !ok {
			t.Fatalf("schema field %q item %d is %T, want string", key, i, item)
		}
	}
	return result
}

func assertSameStringSet(t *testing.T, label string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s drift\nschema: %v\nGo:     %v", label, got, want)
	}
}
