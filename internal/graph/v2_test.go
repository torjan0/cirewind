package graph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func TestGraphV2RequiresCanonicalExplicitEvidenceClassAndIdentity(t *testing.T) {
	t.Parallel()
	focus := findingID("a")
	edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", []string{evidenceID("a")}, "2026-08-19T10:30:00Z", EvidenceClassExactObservation, "", []string{focus})
	if err != nil {
		t.Fatal(err)
	}
	g := GraphV2{
		CaseKind:     CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: NodeActionCommit, Label: "B", FocusFindingIDs: []string{focus}},
		}, Edges: []EdgeV2{edge},
	}
	if err := g.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.Edges[0].ID, "gedge2:") {
		t.Fatalf("v2 ID=%q", g.Edges[0].ID)
	}

	for name, mutate := range map[string]func(*GraphV2){
		"missing class":    func(value *GraphV2) { value.Edges[0].EvidenceClass = "" },
		"wrong ID":         func(value *GraphV2) { value.Edges[0].ID = "gedge2:" + strings.Repeat("0", 64) },
		"missing evidence": func(value *GraphV2) { value.Edges[0].EvidenceIDs = nil },
		"missing focus":    func(value *GraphV2) { value.Edges[0].FocusFindingIDs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			broken := CloneGraphV2(g)
			mutate(&broken)
			if err := broken.NormalizeAndValidate(); err == nil {
				t.Fatal("invalid v2 graph accepted")
			}
		})
	}
}

func TestRelationshipEvidenceClassContractIsClosedAndEnforced(t *testing.T) {
	t.Parallel()
	for edgeType := range v2EndpointRules {
		if _, ok := evidenceClassesByRelationship[edgeType]; !ok {
			t.Errorf("relationship %s lacks an evidence-class contract", edgeType)
		}
	}
	for edgeType := range evidenceClassesByRelationship {
		if _, ok := v2EndpointRules[edgeType]; !ok {
			t.Errorf("evidence-class contract contains unknown relationship %s", edgeType)
		}
	}

	tests := []struct {
		name      string
		edgeType  EdgeType
		class     EvidenceClass
		wantValid bool
	}{
		{name: "runtime lifecycle is exact", edgeType: EdgeStepExecutedAction, class: EvidenceClassExactObservation, wantValid: true},
		{name: "runtime lifecycle cannot be inferred", edgeType: EdgeStepExecutedAction, class: EvidenceClassInference},
		{name: "OIDC capability is inferred", edgeType: EdgeCouldMintOIDC, class: EvidenceClassInference, wantValid: true},
		{name: "OIDC capability cannot be exact", edgeType: EdgeCouldMintOIDC, class: EvidenceClassExactObservation},
		{name: "environment eligibility is inferred", edgeType: EdgeEnvironmentSecretEligible, class: EvidenceClassInference, wantValid: true},
		{name: "environment target is exact", edgeType: EdgeTargetedEnvironment, class: EvidenceClassExactObservation, wantValid: true},
		{name: "historical environment target can be inferred", edgeType: EdgeTargetedEnvironment, class: EvidenceClassInference, wantValid: true},
		{name: "observed-after is temporal", edgeType: EdgeObservedAfter, class: EvidenceClassTemporalCorrelation, wantValid: true},
		{name: "observed-after cannot be exact", edgeType: EdgeObservedAfter, class: EvidenceClassExactObservation},
		{name: "contradiction has contradiction class", edgeType: EdgeContradicts, class: EvidenceClassContradiction, wantValid: true},
		{name: "token permission can be observed", edgeType: EdgeHadTokenPermission, class: EvidenceClassExactObservation, wantValid: true},
		{name: "token permission can be inferred", edgeType: EdgeHadTokenPermission, class: EvidenceClassInference, wantValid: true},
		{name: "historical declaration can be observed", edgeType: EdgeWorkflowDeclaredAction, class: EvidenceClassExactObservation, wantValid: true},
		{name: "declaration reachability can be inferred", edgeType: EdgeWorkflowDeclaredAction, class: EvidenceClassInference, wantValid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := relationshipAllowsEvidenceClass(test.edgeType, test.class); got != test.wantValid {
				t.Fatalf("relationshipAllowsEvidenceClass(%s, %s)=%t, want %t", test.edgeType, test.class, got, test.wantValid)
			}
		})
	}

	focus := findingID("9")
	edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", []string{evidenceID("9")}, "unknown", EvidenceClassInference, "invalid-inference/v1", []string{focus})
	if err != nil {
		t.Fatal(err)
	}
	invalid := GraphV2{
		SchemaVersion: SchemaVersionV2,
		CaseKind:      CaseKindSynthetic,
		FindingIndex:  []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
		},
		Edges: []EdgeV2{edge},
	}
	if err := invalid.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "cannot use evidence class") {
		t.Fatalf("incompatible relationship/class was accepted: %v", err)
	}
}

func TestGraphV2RejectsExposureContextOnNonExecutedLanes(t *testing.T) {
	t.Parallel()
	focus := findingID("8")
	finding := testFinding(focus, model.ConfirmedDownloaded)

	t.Run("credential node", func(t *testing.T) {
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{finding},
			Nodes:        []NodeV2{{ID: "token", Type: NodeTokenCapability, Label: "contents: write", FocusFindingIDs: []string{focus}}},
		}
		if err := g.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "non-executed finding") {
			t.Fatalf("non-executed credential context was accepted: %v", err)
		}
	})

	t.Run("affected step execution", func(t *testing.T) {
		edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", []string{evidenceID("8")}, "unknown", EvidenceClassExactObservation, "", []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{finding},
			Nodes: []NodeV2{
				{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
				{ID: "commit", Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{edge},
		}
		if err := g.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "incompatible with CONFIRMED_DOWNLOADED") {
			t.Fatalf("downloaded-only lane accepted affected-step execution: %v", err)
		}
	})

	t.Run("environment gate crossing", func(t *testing.T) {
		edge, err := NewEdgeV2(EdgeCrossedEnvironmentGate, "job", "environment", []string{evidenceID("8")}, "unknown", EvidenceClassInference, "environment-gate-from-job-state/v1", []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{finding},
			Nodes: []NodeV2{
				{ID: "job", Type: NodeJob, Label: "waiting job", FocusFindingIDs: []string{focus}},
				{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{edge},
		}
		if err := g.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "gate-crossing") {
			t.Fatalf("non-executed environment gate crossing was accepted: %v", err)
		}
	})

	t.Run("narrow environment target", func(t *testing.T) {
		edge, err := NewEdgeV2(EdgeTargetedEnvironment, "job", "environment", []string{evidenceID("8")}, "unknown", EvidenceClassInference, EnvironmentTargetPendingRule, []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{finding},
			Nodes: []NodeV2{
				{ID: "job", Type: NodeJob, Label: "waiting job", FocusFindingIDs: []string{focus}},
				{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{edge},
		}
		if err := g.NormalizeAndValidate(); err != nil {
			t.Fatalf("narrow environment target was rejected: %v", err)
		}

		for name, mutate := range map[string]func(*GraphV2){
			"exact target without pending predicate": func(value *GraphV2) {
				value.Edges[0].EvidenceClass = EvidenceClassExactObservation
				value.Edges[0].DerivationRule = ""
				value.Edges[0].ID, _ = StableEdgeIDV2(value.Edges[0].Type, value.Edges[0].Source, value.Edges[0].Target, value.Edges[0].EventTime, value.Edges[0].EvidenceClass, value.Edges[0].DerivationRule)
			},
			"unrelated inference rule": func(value *GraphV2) {
				value.Edges[0].DerivationRule = EnvironmentTargetHistoricalRule
				value.Edges[0].ID, _ = StableEdgeIDV2(value.Edges[0].Type, value.Edges[0].Source, value.Edges[0].Target, value.Edges[0].EventTime, value.Edges[0].EvidenceClass, value.Edges[0].DerivationRule)
			},
			"unlinked environment node": func(value *GraphV2) { value.Edges = nil },
		} {
			t.Run(name, func(t *testing.T) {
				changed := CloneGraphV2(g)
				mutate(&changed)
				if err := changed.NormalizeAndValidate(); err == nil {
					t.Fatal("non-executed environment context without the narrow pending predicate was accepted")
				}
			})
		}
	})
}

func TestGraphV2AggregatesDuplicateProjectionNotices(t *testing.T) {
	t.Parallel()
	focus := findingID("7")
	g := GraphV2{
		SchemaVersion: SchemaVersionV2,
		CaseKind:      CaseKindSynthetic,
		FindingIndex:  []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		ProjectionNotices: []ProjectionNotice{
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus, Relationship: EdgePassedSecretTo, EvidenceIDs: []string{evidenceID("b"), evidenceID("a")}},
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus, Relationship: EdgePassedSecretTo, EvidenceIDs: []string{evidenceID("c"), evidenceID("b")}},
		},
	}
	if err := g.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if len(g.ProjectionNotices) != 1 {
		t.Fatalf("projection notice count=%d, want 1", len(g.ProjectionNotices))
	}
	wantEvidence := []string{evidenceID("a"), evidenceID("b"), evidenceID("c")}
	if !slices.Equal(g.ProjectionNotices[0].EvidenceIDs, wantEvidence) {
		t.Fatalf("aggregated evidence=%v, want %v", g.ProjectionNotices[0].EvidenceIDs, wantEvidence)
	}
	if _, _, err := RenderGraphSVG(context.Background(), g, PathOptions{}); err != nil {
		t.Fatalf("aggregated projection notice did not render: %v", err)
	}
}

func TestGraphV2RequiresEnvironmentTargetAndSatisfiedGateBeforeNamedEligibility(t *testing.T) {
	t.Parallel()
	focus := findingID("6")
	makeEnvironmentEdge := func(edgeType EdgeType, source, target, evidence string, class EvidenceClass, rule string) EdgeV2 {
		t.Helper()
		edge, err := NewEdgeV2(edgeType, source, target, []string{evidence}, "unknown", class, rule, []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		return edge
	}
	target := makeEnvironmentEdge(EdgeTargetedEnvironment, "job", "environment", evidenceID("6"), EvidenceClassInference, EnvironmentTargetHistoricalRule)
	satisfied := makeEnvironmentEdge(EdgeEnvironmentGateSatisfied, "job", "environment", evidenceID("7"), EvidenceClassInference, EnvironmentGateSatisfiedCrossedRule)
	eligible := makeEnvironmentEdge(EdgeEnvironmentSecretEligible, "environment", "secret", evidenceID("8"), EvidenceClassInference, EnvironmentSecretEligibilityRule)
	base := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}},
			{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
			{ID: "secret", Type: NodeSecretMetadata, Label: "DEPLOY_KEY", FocusFindingIDs: []string{focus}},
		},
	}
	for _, test := range []struct {
		name    string
		edges   []EdgeV2
		wantErr bool
	}{
		{name: "complete chain", edges: []EdgeV2{target, satisfied, eligible}},
		{name: "eligibility lacks gate satisfaction", edges: []EdgeV2{target, eligible}, wantErr: true},
		{name: "gate satisfaction lacks target", edges: []EdgeV2{satisfied, eligible}, wantErr: true},
		{name: "eligibility alone", edges: []EdgeV2{eligible}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := CloneGraphV2(base)
			candidate.Edges = append([]EdgeV2(nil), test.edges...)
			err := candidate.NormalizeAndValidate()
			if (err != nil) != test.wantErr {
				t.Fatalf("NormalizeAndValidate() error=%v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestEnvironmentGateSatisfiedRetainsClosedStateInEdgeIdentity(t *testing.T) {
	t.Parallel()
	focus := findingID("9")
	target, err := NewEdgeV2(
		EdgeTargetedEnvironment, "job", "environment", []string{evidenceID("9")},
		"2026-08-26T12:00:00Z", EvidenceClassInference, EnvironmentTargetHistoricalRule, []string{focus},
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		state string
		rule  string
		text  string
	}{
		{state: "approved", rule: EnvironmentGateSatisfiedApprovedRule, text: "retained approval"},
		{state: "bypassed", rule: EnvironmentGateSatisfiedBypassedRule, text: "retained bypass; approval not inferred"},
		{state: "crossed", rule: EnvironmentGateSatisfiedCrossedRule, text: "retained crossing"},
		{state: "not-required", rule: EnvironmentGateSatisfiedNotRequiredRule, text: "contemporaneously not required; approval not inferred"},
	}
	edges := []EdgeV2{target}
	seenIDs := make(map[string]struct{}, len(tests))
	for index, test := range tests {
		rule, ok := EnvironmentGateSatisfiedRuleForState(test.state)
		if !ok || rule != test.rule {
			t.Fatalf("state %q resolved to %q, ok=%t", test.state, rule, ok)
		}
		state, ok := EnvironmentGateSatisfiedStateForRule(test.rule)
		if !ok || state != test.state {
			t.Fatalf("rule %q resolved to %q, ok=%t", test.rule, state, ok)
		}
		edge, edgeErr := NewEdgeV2(
			EdgeEnvironmentGateSatisfied, "job", "environment", []string{evidenceID(string(rune('a' + index)))},
			"2026-08-26T12:00:00Z", EvidenceClassInference, test.rule, []string{focus},
		)
		if edgeErr != nil {
			t.Fatal(edgeErr)
		}
		if _, exists := seenIDs[edge.ID]; exists {
			t.Fatalf("retained gate state collapsed edge identity: %s", edge.ID)
		}
		seenIDs[edge.ID] = struct{}{}
		if got := relationshipText(edge, []EdgeV2{target, edge}, testFinding(focus, model.ConfirmedExecuted)); !strings.Contains(got, test.text) {
			t.Fatalf("state %q relationship text=%q, want phrase %q", test.state, got, test.text)
		}
		edges = append(edges, edge)
	}
	value := GraphV2{
		SchemaVersion: SchemaVersionV2,
		CaseKind:      CaseKindSynthetic,
		Nodes: []NodeV2{
			{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}},
			{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
		},
		Edges:        edges,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
	}
	if err := value.NormalizeAndValidate(); err != nil {
		t.Fatalf("closed gate-state edges were rejected: %v", err)
	}
	unknownTime := CloneGraphV2(value)
	for index := range unknownTime.Edges {
		if unknownTime.Edges[index].DerivationRule != EnvironmentGateSatisfiedNotRequiredRule {
			continue
		}
		unknownTime.Edges[index].EventTime = "unknown"
		unknownTime.Edges[index].ID, _ = StableEdgeIDV2(
			unknownTime.Edges[index].Type, unknownTime.Edges[index].Source, unknownTime.Edges[index].Target,
			unknownTime.Edges[index].EventTime, unknownTime.Edges[index].EvidenceClass, unknownTime.Edges[index].DerivationRule,
		)
	}
	if err := unknownTime.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "unknown event time for not-required") {
		t.Fatalf("unknown-time not-required edge error=%v", err)
	}

	invalid := CloneGraphV2(value)
	invalid.Edges[1].DerivationRule = "environment-gate-satisfied-from-retained-state/v1"
	invalid.Edges[1].ID, _ = StableEdgeIDV2(
		invalid.Edges[1].Type, invalid.Edges[1].Source, invalid.Edges[1].Target,
		invalid.Edges[1].EventTime, invalid.Edges[1].EvidenceClass, invalid.Edges[1].DerivationRule,
	)
	if err := invalid.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "unsupported derivation rule") {
		t.Fatalf("generic gate-state rule error=%v", err)
	}
}

func TestGraphV2RejectsLegacyBasisNoticeForNonCredentialRelationship(t *testing.T) {
	t.Parallel()
	focus := findingID("7")
	g := GraphV2{
		SchemaVersion: SchemaVersionV2,
		CaseKind:      CaseKindSynthetic,
		FindingIndex:  []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		ProjectionNotices: []ProjectionNotice{{
			Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus,
			Relationship: EdgeStepExecutedAction, EvidenceIDs: []string{evidenceID("a")},
		}},
	}
	if err := g.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "invalid relationship") {
		t.Fatalf("noncredential legacy-basis notice was accepted: %v", err)
	}
}

func TestGraphV2ProjectionNoticeAggregationIsOrderIndependentAndBounded(t *testing.T) {
	focus := findingID("7")
	const count = 5_000
	notices := make([]ProjectionNotice, count)
	for index := range notices {
		notices[index] = ProjectionNotice{
			Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus,
			Relationship: EdgePassedSecretTo, EvidenceIDs: []string{indexedEvidenceID(index)},
		}
	}
	normalize := func(input []ProjectionNotice) GraphV2 {
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex:      []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
			ProjectionNotices: input,
		}
		if err := g.NormalizeAndValidate(); err != nil {
			t.Fatal(err)
		}
		return g
	}
	forward := normalize(append([]ProjectionNotice(nil), notices...))
	slices.Reverse(notices)
	reversed := normalize(notices)
	if !reflect.DeepEqual(forward.ProjectionNotices, reversed.ProjectionNotices) {
		t.Fatal("projection-notice aggregation depends on source order")
	}
	if len(forward.ProjectionNotices) != 1 || len(forward.ProjectionNotices[0].EvidenceIDs) != count {
		t.Fatalf("unexpected aggregated notice shape: %#v", forward.ProjectionNotices)
	}

	tooMany := make([]string, maxEvidenceIDs+1)
	for index := range tooMany {
		tooMany[index] = indexedEvidenceID(index)
	}
	overLimit := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		ProjectionNotices: []ProjectionNotice{
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus, Relationship: EdgePassedSecretTo, EvidenceIDs: tooMany[:maxEvidenceIDs/2]},
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus, Relationship: EdgePassedSecretTo, EvidenceIDs: tooMany[maxEvidenceIDs/2:]},
		},
	}
	if err := overLimit.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "too many combined evidence IDs") {
		t.Fatalf("combined projection-notice evidence limit was not enforced: %v", err)
	}
}

func BenchmarkGraphV2ProjectionNoticeAggregation5000(b *testing.B) {
	focus := findingID("7")
	notices := make([]ProjectionNotice, 5_000)
	for index := range notices {
		notices[index] = ProjectionNotice{
			Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus,
			Relationship: EdgePassedSecretTo, EvidenceIDs: []string{indexedEvidenceID(index)},
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex:      []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
			ProjectionNotices: append([]ProjectionNotice(nil), notices...),
		}
		if err := g.NormalizeAndValidate(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestProjectionNoticePresentationBoundsVisualRefsAndPreservesAccessibleEvidence(t *testing.T) {
	focus := findingID("7")
	evidenceIDs := make([]string, HardPathEvidenceIDs)
	for index := range evidenceIDs {
		evidenceIDs[index] = indexedEvidenceID(index)
	}
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		ProjectionNotices: []ProjectionNotice{{
			Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: focus,
			Relationship: EdgeHadTokenPermission, EvidenceIDs: evidenceIDs,
		}},
	}
	path, data, err := RenderGraphSVG(context.Background(), g, PathOptions{MaxEvidenceIDs: HardPathEvidenceIDs})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 || len(path.Lanes[0].Notices) != 1 {
		t.Fatalf("unexpected projection-notice path: %+v", path.Counts)
	}
	full, visible := PresentProjectionNotice(path.Lanes[0].Notices[0], path.EvidenceKey)
	for _, want := range []string{"E001", "E002", "E003", "E004", "E005", "+507 more"} {
		if !strings.Contains(visible, want) {
			t.Fatalf("bounded notice %q lacks %q", visible, want)
		}
	}
	if strings.Contains(visible, "E006") || strings.Contains(visible, "ev1:") {
		t.Fatalf("bounded notice exposed excess or full evidence identities: %q", visible)
	}
	for _, want := range []string{evidenceIDs[0], evidenceIDs[len(evidenceIDs)/2], evidenceIDs[len(evidenceIDs)-1]} {
		if !strings.Contains(full, want) {
			t.Fatalf("complete notice text lacks evidence %q", want)
		}
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	inNotice, depth := false, 0
	var descText, visualText string
	current := ""
	for {
		token, decodeErr := decoder.Token()
		if decodeErr != nil {
			if decodeErr == io.EOF {
				break
			}
			t.Fatal(decodeErr)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if !inNotice && value.Name.Local == "g" {
				for _, attribute := range value.Attr {
					if attribute.Name.Local == "data-projection-notice" && attribute.Value == "true" {
						inNotice, depth = true, 1
					}
				}
			} else if inNotice {
				depth++
				current = value.Name.Local
			}
		case xml.CharData:
			if inNotice && current == "desc" {
				descText += string(value)
			}
			if inNotice && current == "text" {
				visualText += string(value)
			}
		case xml.EndElement:
			if inNotice {
				if depth == 1 && value.Name.Local == "g" {
					inNotice = false
				} else {
					depth--
					current = ""
				}
			}
		}
	}
	if descText != full || !strings.Contains(visualText, visible) {
		t.Fatalf("notice accessible/visual text mismatch: desc=%q visual=%q", descText, visualText)
	}
}

func TestStableEdgeIDV2SeparatesClassRuleAndLegacyNamespace(t *testing.T) {
	t.Parallel()
	arguments := func(class EvidenceClass, rule string) string {
		id, err := StableEdgeIDV2(EdgeHadTokenPermission, "job", "token", "unknown", class, rule)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	exact := arguments(EvidenceClassExactObservation, "")
	inferredA := arguments(EvidenceClassInference, "static-a/v1")
	inferredB := arguments(EvidenceClassInference, "static-b/v1")
	if exact == inferredA || inferredA == inferredB {
		t.Fatal("class or rule did not participate in v2 edge identity")
	}
	for _, id := range []string{exact, inferredA, inferredB} {
		if strings.HasPrefix(id, "gedge1:") || !strings.HasPrefix(id, "gedge2:") {
			t.Fatalf("cross-version identity %q", id)
		}
	}
}

func TestKnownGoodComparisonPredicateIsNarrow(t *testing.T) {
	t.Parallel()
	run := model.WorkflowRunID(42)
	first := model.RunAttempt(1)
	second := model.RunAttempt(2)
	anchor := testFinding(findingID("a"), model.ConfirmedExecuted)
	anchor.RunID, anchor.RunAttempt = &run, &first
	anchor.ExactIdentityKind, anchor.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("1", 40)
	candidate := testFinding(findingID("b"), model.NoMatchConfirmed)
	candidate.RunID, candidate.RunAttempt = &run, &second
	candidate.ExactIdentityKind, candidate.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("0", 40)
	candidate.ExactKnownGood, candidate.CoverageClosed = true, true
	if !IsKnownGoodComparison(anchor, candidate) {
		t.Fatal("valid same-run exact known-good rerun was not selected")
	}
	for name, mutate := range map[string]func(*FindingIndexEntry){
		"same attempt":    func(value *FindingIndexEntry) { value.RunAttempt = &first },
		"other indicator": func(value *FindingIndexEntry) { value.IndicatorID = "other" },
		"not exact good":  func(value *FindingIndexEntry) { value.ExactKnownGood = false },
		"open coverage":   func(value *FindingIndexEntry) { value.CoverageClosed = false },
		"wrong state":     func(value *FindingIndexEntry) { value.State = model.CurrentReferenceOnly },
	} {
		t.Run(name, func(t *testing.T) {
			changed := candidate
			mutate(&changed)
			if IsKnownGoodComparison(anchor, changed) {
				t.Fatal("unrelated negative admitted as comparison")
			}
		})
	}
}

func TestPathIncludesOnlyTypedSameRunKnownGoodComparison(t *testing.T) {
	t.Parallel()
	run := model.WorkflowRunID(77)
	attemptOne, attemptTwo := model.RunAttempt(1), model.RunAttempt(2)
	executedID, noMatchID := findingID("a"), findingID("b")
	executed := testFinding(executedID, model.ConfirmedExecuted)
	executed.RunID, executed.RunAttempt = &run, &attemptOne
	executed.ExactIdentityKind, executed.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("1", 40)
	noMatch := testFinding(noMatchID, model.NoMatchConfirmed)
	noMatch.RunID, noMatch.RunAttempt = &run, &attemptTwo
	noMatch.ExactIdentityKind, noMatch.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("0", 40)
	noMatch.ExactKnownGood, noMatch.CoverageClosed = true, true
	nodes := []NodeV2{
		{ID: "step-b", Type: NodeStep, Label: "attempt 1 step", FocusFindingIDs: []string{executedID}},
		{ID: "commit-b", Type: NodeActionCommit, Label: "B", FocusFindingIDs: []string{executedID}},
		{ID: "attempt-a", Type: NodeRunAttempt, Label: "attempt 2", FocusFindingIDs: []string{noMatchID}},
		{ID: "run-a", Type: NodeWorkflowRun, Label: "run 77", FocusFindingIDs: []string{noMatchID}},
	}
	edgeOne, err := NewEdgeV2(EdgeStepExecutedAction, "step-b", "commit-b", []string{evidenceID("a")}, "unknown", EvidenceClassExactObservation, "", []string{executedID})
	if err != nil {
		t.Fatal(err)
	}
	edgeTwo, err := NewEdgeV2(EdgeAttemptOfRun, "attempt-a", "run-a", []string{evidenceID("b")}, "unknown", EvidenceClassExactObservation, "", []string{noMatchID})
	if err != nil {
		t.Fatal(err)
	}
	g := GraphV2{SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic, Nodes: nodes, Edges: []EdgeV2{edgeOne, edgeTwo}, FindingIndex: []FindingIndexEntry{executed, noMatch}}
	path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 2 || path.Lanes[1].Finding.State != model.NoMatchConfirmed {
		t.Fatalf("known-good comparison lanes=%v", laneStates(path.Lanes))
	}

	unrelated := CloneGraphV2(g)
	unrelated.FindingIndex[1].Repository = "fixture/other"
	path, err = BuildTemporalEvidencePath(context.Background(), unrelated, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 {
		t.Fatalf("unrelated no-match became visual comparison: %v", laneStates(path.Lanes))
	}
}

func laneStates(lanes []TemporalEvidenceLane) []model.FindingState {
	result := make([]model.FindingState, len(lanes))
	for i := range lanes {
		result[i] = lanes[i].Finding.State
	}
	return result
}

func testFinding(id string, state model.FindingState) FindingIndexEntry {
	entry := FindingIndexEntry{
		FindingRevisionID: id, State: state, ProvenanceLevel: model.L3Strong,
		Repository: "fixture/repository", WorkflowPath: ".github/workflows/demo.yml",
		IndicatorID: "fixture-indicator",
	}
	if state == model.UnknownEvidenceGap {
		entry.ProvenanceLevel = model.L0Unknown
		entry.EvidenceGapReason = "logs expired"
	}
	return entry
}

func testGraphV2(t *testing.T) GraphV2 {
	t.Helper()
	executed, gap, inferred, conflict := findingID("a"), findingID("b"), findingID("c"), findingID("d")
	focusExecuted := []string{executed}
	nodes := []NodeV2{
		{ID: "job", Type: NodeJob, Label: "job & <deploy>", FocusFindingIDs: focusExecuted},
		{ID: "step", Type: NodeStep, Label: "build\x1b[2J\n</text><script>alert(1)</script>\u202e", FocusFindingIDs: focusExecuted},
		{ID: "commit", Type: NodeActionCommit, Label: strings.Repeat("harmless-B-", 45), FocusFindingIDs: focusExecuted},
		{ID: "token", Type: NodeTokenCapability, Label: "contents: write", FocusFindingIDs: focusExecuted},
		{ID: "deploy", Type: NodeDeployment, Label: "deployment observed later", FocusFindingIDs: focusExecuted},
		{ID: "workflow-gap", Type: NodeWorkflowDefinition, Label: "missing historical workflow", FocusFindingIDs: []string{gap}},
		{ID: "workflow-static", Type: NodeWorkflowDefinition, Label: "historical wrapper", FocusFindingIDs: []string{inferred}},
		{ID: "ref-static", Type: NodeActionRef, Label: "fixture/action@v1", FocusFindingIDs: []string{inferred}},
		{ID: "commit-static", Type: NodeActionCommit, Label: "runtime B", FocusFindingIDs: []string{conflict}},
		{ID: "commit-yaml", Type: NodeActionCommit, Label: "declared A", FocusFindingIDs: []string{conflict}},
	}
	makeEdge := func(edgeType EdgeType, source, target, evidence string, class EvidenceClass, rule, finding string) EdgeV2 {
		edge, err := NewEdgeV2(edgeType, source, target, []string{evidence}, "2026-08-19T10:30:00Z", class, rule, []string{finding})
		if err != nil {
			t.Fatal(err)
		}
		return edge
	}
	edges := []EdgeV2{
		makeEdge(EdgeStepExecutedAction, "step", "commit", evidenceID("a"), EvidenceClassExactObservation, "", executed),
		makeEdge(EdgeHadTokenPermission, "job", "token", evidenceID("b"), EvidenceClassInference, "credential-relationship/historical-definition-flow/v1", executed),
		makeEdge(EdgeObservedAfter, "step", "deploy", evidenceID("c"), EvidenceClassTemporalCorrelation, "", executed),
		makeEdge(EdgeWorkflowDeclaredAction, "workflow-static", "ref-static", evidenceID("d"), EvidenceClassInference, "historical-mutable-ref/v1", inferred),
		makeEdge(EdgeContradicts, "commit-static", "commit-yaml", evidenceID("e"), EvidenceClassContradiction, "runtime-static-contradiction/v1", conflict),
	}
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		Nodes: nodes, Edges: edges,
		FindingIndex: []FindingIndexEntry{
			testFinding(executed, model.ConfirmedExecuted), testFinding(gap, model.UnknownEvidenceGap),
			testFinding(inferred, model.RunInWindowMutableRef), testFinding(conflict, model.ContradictoryEvidence),
		},
		ProjectionNotices: []ProjectionNotice{
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: executed, Relationship: EdgePassedSecretTo, EvidenceIDs: []string{evidenceID("f")}},
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: executed, Relationship: EdgeInheritedSecret, EvidenceIDs: []string{evidenceID("0")}},
		},
	}
	return g
}

func TestTemporalPathAndSVGAreDeterministicOrderIndependentAndDoNotMutate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	firstInput := testGraphV2(t)
	original := CloneGraphV2(firstInput)
	firstPath, first, err := RenderGraphSVG(ctx, firstInput, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstInput, original) {
		t.Fatal("renderer mutated source graph")
	}

	secondInput := CloneGraphV2(firstInput)
	slices.Reverse(secondInput.Nodes)
	slices.Reverse(secondInput.Edges)
	slices.Reverse(secondInput.FindingIndex)
	slices.Reverse(secondInput.ProjectionNotices)
	for i := range secondInput.Nodes {
		slices.Reverse(secondInput.Nodes[i].EvidenceIDs)
		slices.Reverse(secondInput.Nodes[i].FocusFindingIDs)
	}
	for i := range secondInput.Edges {
		slices.Reverse(secondInput.Edges[i].EvidenceIDs)
		slices.Reverse(secondInput.Edges[i].FocusFindingIDs)
	}
	for i := range secondInput.ProjectionNotices {
		slices.Reverse(secondInput.ProjectionNotices[i].EvidenceIDs)
	}
	secondPath, second, err := RenderGraphSVG(ctx, secondInput, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("reversed source ordering changed SVG bytes")
	}
	if !reflect.DeepEqual(firstPath, secondPath) {
		t.Fatal("reversed source ordering changed presentation model")
	}
	if len(first) > MaxSVGBytes {
		t.Fatalf("SVG exceeds hard byte limit: %d", len(first))
	}
	renderedEdges := 0
	for _, lane := range firstPath.Lanes {
		renderedEdges += len(lane.Edges)
	}
	if got := bytes.Count(first, []byte(`data-route-underlay="true"`)); got != renderedEdges {
		t.Fatalf("route underlays=%d, want one per rendered edge (%d)", got, renderedEdges)
	}
	if got := bytes.Count(first, []byte(`aria-hidden="true" data-route-underlay="true"`)); got != renderedEdges {
		t.Fatalf("inert route underlays=%d, want %d", got, renderedEdges)
	}
	if got := bytes.Count(first, []byte(`stroke-linejoin="round" stroke-linecap="butt" aria-hidden="true" data-route-underlay="true"`)); got != renderedEdges {
		t.Fatalf("bounded-junction route underlays=%d, want %d", got, renderedEdges)
	}
	wantDigest := "36dfdd2ddeaa0ad9389370390ee3231dfe5f39ea7d4752af8701258b8ce1a95a"
	if got := fmt.Sprintf("%x", sha256.Sum256(first)); got != wantDigest {
		t.Fatalf("cross-platform SVG golden digest=%s, want %s", got, wantDigest)
	}
}

func TestValidateTemporalEvidencePathFailsClosedWithoutSerialization(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemporalEvidencePath(path); err != nil {
		t.Fatal(err)
	}
	path.Lanes[0].Edges[0].RelationshipText = "unsupported causal claim"
	if err := ValidateTemporalEvidencePath(path); err == nil {
		t.Fatal("noncanonical report relationship wording was accepted")
	}
}

func TestSVGIsValidInertXMLWithRequiredVisualSemantics(t *testing.T) {
	t.Parallel()
	_, data, err := RenderGraphSVG(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allowedElements := map[string]bool{"svg": true, "title": true, "desc": true, "g": true, "rect": true, "line": true, "polyline": true, "polygon": true, "circle": true, "text": true, "tspan": true, "style": true}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatal(err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !allowedElements[start.Name.Local] {
			t.Fatalf("active or unknown SVG element %q", start.Name.Local)
		}
		for _, attr := range start.Attr {
			name := strings.ToLower(attr.Name.Local)
			if strings.HasPrefix(name, "on") || name == "href" || name == "style" || strings.Contains(strings.ToLower(attr.Value), "url(") || strings.HasPrefix(strings.ToLower(attr.Value), "data:") {
				t.Fatalf("unsafe SVG attribute %s=%q", name, attr.Value)
			}
		}
	}
	text := string(data)
	if strings.Count(text, "<style>") != 1 || !strings.Contains(text, "<style>"+forcedColorStylesheet+"</style>") {
		t.Fatal("SVG lacks the fixed forced-colors policy")
	}
	for _, required := range []string{
		colorExact, colorInference, colorTemporal, colorContradiction, colorGap,
		"stroke-dasharray=\"10 7\"", "stroke-dasharray=\"2 7\"",
		"step execution began", "inferred", "observed after — causation not established",
		"contradicts", "UNKNOWN_EVIDENCE_GAP", "visual relationship omitted — legacy evidence basis unavailable",
		"contents: write", "ui-monospace, monospace", "role=\"img\"",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("SVG lacks %q", required)
		}
	}
	for _, prohibited := range []string{"<script", "foreignObject", "javascript:", "cloud role assumed", "attack path", "executed on runner"} {
		if strings.Contains(text, prohibited) {
			t.Errorf("SVG contains prohibited content %q", prohibited)
		}
	}
	if !strings.Contains(text, "&lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("hostile label was not safely XML escaped")
	}
}

func TestTemporalPathLimitsOmitWholeSlicesWithoutDanglingEdges(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{MaxFindingLanes: 1, MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 || path.Counts.OmittedFindings != path.Counts.TotalFindings-1 {
		t.Fatalf("unexpected bounded selection: %+v", path.Counts)
	}
	for _, lane := range path.Lanes {
		nodes := map[string]bool{}
		for _, node := range lane.Nodes {
			nodes[node.Node.ID] = true
		}
		for _, edge := range lane.Edges {
			if !nodes[edge.Edge.Source] || !nodes[edge.Edge.Target] {
				t.Fatalf("dangling visual edge %s", edge.Edge.ID)
			}
		}
	}
	if _, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{MaxFindingLanes: HardPathFindingLanes + 1}); err == nil {
		t.Fatal("over-hard lane budget accepted")
	}
}

func TestTemporalPathHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildTemporalEvidencePath(ctx, testGraphV2(t), PathOptions{}); !errorsIsCanceled(err) {
		t.Fatalf("Build error=%v", err)
	}
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderSVG(ctx, path); !errorsIsCanceled(err) {
		t.Fatalf("Render error=%v", err)
	}
}

func errorsIsCanceled(err error) bool { return err == context.Canceled }

func TestVisibleLabelUsesBoundedRuneGeometry(t *testing.T) {
	t.Parallel()
	lines := visibleLabelLines(strings.Repeat("🙂", 200))
	if len(lines) > 3 {
		t.Fatalf("line count=%d", len(lines))
	}
	totalBytes := 0
	for _, line := range lines {
		if len([]rune(line)) > 32 {
			t.Fatalf("line exceeds 32 runes: %q", line)
		}
		totalBytes += len(line)
	}
	if totalBytes > 192+len("…") {
		t.Fatalf("visible label bytes=%d", totalBytes)
	}
	if !strings.HasSuffix(lines[len(lines)-1], "…") {
		t.Fatal("truncated label lacks visible ellipsis")
	}
}

func TestAcceptedPaletteMeetsLightBackgroundContrastFloors(t *testing.T) {
	t.Parallel()
	for _, color := range []string{colorText} {
		if ratio := contrastRatio(color, colorBackground); ratio < 4.5 {
			t.Errorf("text color %s contrast %.2f < 4.5", color, ratio)
		}
	}
	for _, color := range []string{colorExact, colorInference, colorTemporal, colorContradiction, colorGap, colorBorder} {
		if ratio := contrastRatio(color, colorBackground); ratio < 3 {
			t.Errorf("graph color %s contrast %.2f < 3", color, ratio)
		}
	}
}

func contrastRatio(left, right string) float64 {
	l1, l2 := relativeLuminance(left), relativeLuminance(right)
	if l2 > l1 {
		l1, l2 = l2, l1
	}
	return (l1 + .05) / (l2 + .05)
}

func relativeLuminance(color string) float64 {
	channels := make([]float64, 3)
	for i := range channels {
		value, _ := strconv.ParseUint(color[1+i*2:3+i*2], 16, 8)
		channel := float64(value) / 255
		if channel <= .04045 {
			channels[i] = channel / 12.92
		} else {
			channels[i] = math.Pow((channel+.055)/1.055, 2.4)
		}
	}
	return .2126*channels[0] + .7152*channels[1] + .0722*channels[2]
}
