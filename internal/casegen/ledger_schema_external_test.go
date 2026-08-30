package casegen_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/torjan0/cirewind/internal/casegen"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/report"
)

const (
	testSchemaBase   = "https://schemas.invalid/cirewind/"
	evidenceSchemaID = testSchemaBase + "evidence-v1alpha1.json"
	findingsSchemaID = testSchemaBase + "findings-v1alpha1.json"
	incidentSchemaID = testSchemaBase + "incident-v1alpha1.json"
	ledgerSchemaID   = testSchemaBase + "evidence-ledger-v1alpha1.json"
	metadataSchemaID = testSchemaBase + "collection-metadata-v1alpha2.json"
	graphSchemaID    = testSchemaBase + "graph-v1alpha2.json"
)

func TestApplicationSchemasUseRelativeLocalIDsAndCompile(t *testing.T) {
	t.Parallel()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})

	resources := []struct {
		name string
		path string
	}{
		{"evidence-v1alpha1.json", "../../schema/evidence-v1alpha1.json"},
		{"findings-v1alpha1.json", "../../schema/findings-v1alpha1.json"},
		{"incident-v1alpha1.json", "../../schema/incident-v1alpha1.json"},
		{"evidence-ledger-v1alpha1.json", "../../schema/evidence-ledger-v1alpha1.json"},
		{"collection-metadata-v1alpha2.json", "../../schema/collection-metadata-v1alpha2.json"},
		{"graph-v1alpha2.json", "../../schema/graph-v1alpha2.json"},
	}
	for _, resource := range resources {
		data, err := os.ReadFile(resource.path)
		if err != nil {
			t.Fatal(err)
		}
		var header map[string]any
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatalf("decode schema header %s: %v", resource.path, err)
		}
		if got := header["$id"]; got != resource.name {
			t.Fatalf("schema %s $id = %v, want relative filename %q", resource.path, got, resource.name)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema %s: %v", resource.path, err)
		}
		if err := compiler.AddResource(testSchemaBase+resource.name, document); err != nil {
			t.Fatalf("add local schema resource %s: %v", resource.name, err)
		}
	}
	for _, resource := range resources {
		if _, err := compiler.Compile(testSchemaBase + resource.name); err != nil {
			t.Fatalf("compile local schema %s: %v", resource.name, err)
		}
	}
}

func TestGeneratedV02CaseConformsToPublicSchemasAndStrictCodeContracts(t *testing.T) {
	ctx := context.Background()
	snapshot, pack, derived := fixture(t, ctx)
	output := filepath.Join(t.TempDir(), "case")
	if err := casegen.Generate(ctx, casegen.Options{
		Output: output, Snapshot: snapshot, Pack: pack, Case: derived.Case,
	}); err != nil {
		t.Fatal(err)
	}

	metadataBytes := readCaseFile(t, output, "collection-metadata.json")
	graphBytes := readCaseFile(t, output, "graph.json")
	metadataValue := decodeSchemaInstance(t, metadataBytes)
	graphValue := decodeSchemaInstance(t, graphBytes)
	if err := compileApplicationSchema(t, metadataSchemaID).Validate(metadataValue); err != nil {
		t.Fatalf("generated collection-metadata.json violates %s: %v", metadataSchemaID, err)
	}
	if err := compileApplicationSchema(t, graphSchemaID).Validate(graphValue); err != nil {
		t.Fatalf("generated graph.json violates %s: %v", graphSchemaID, err)
	}

	metadataObject := metadataValue.(map[string]any)
	if got := metadataObject["caseContractVersion"]; got != "cirewind.case/v1alpha2" {
		t.Fatalf("caseContractVersion = %v", got)
	}
	if got := metadataObject["caseKind"]; got != "synthetic" {
		t.Fatalf("caseKind = %v, want synthetic", got)
	}
	if got := metadataObject["rawMaterialized"]; got != false {
		t.Fatalf("rawMaterialized = %v, want false", got)
	}

	var metadata report.Metadata
	if err := decodeStrictJSONDocument(metadataBytes, &metadata); err != nil {
		t.Fatalf("strictly decode generated collection metadata: %v", err)
	}
	if err := report.WriteMetadataJSON(io.Discard, metadata); err != nil {
		t.Fatalf("code contract rejects schema-valid collection metadata: %v", err)
	}
	var typedGraph graph.GraphV2
	if err := decodeStrictJSONDocument(graphBytes, &typedGraph); err != nil {
		t.Fatalf("strictly decode generated graph: %v", err)
	}
	if err := typedGraph.NormalizeAndValidate(); err != nil {
		t.Fatalf("code contract rejects schema-valid graph: %v", err)
	}
	var graphRoundTrip bytes.Buffer
	if err := report.WriteGraphV2JSON(&graphRoundTrip, typedGraph); err != nil {
		t.Fatalf("rewrite generated graph through code contract: %v", err)
	}
	if !bytes.Equal(graphBytes, graphRoundTrip.Bytes()) {
		t.Fatal("generated graph.json was not canonical before strict code/schema round trip")
	}
}

func TestV02PublicSchemasRejectUnknownFieldsAndClosedEnumDrift(t *testing.T) {
	ctx := context.Background()
	snapshot, pack, derived := fixture(t, ctx)
	output := filepath.Join(t.TempDir(), "case")
	if err := casegen.Generate(ctx, casegen.Options{
		Output: output, Snapshot: snapshot, Pack: pack, Case: derived.Case,
	}); err != nil {
		t.Fatal(err)
	}

	metadataSchema := compileApplicationSchema(t, metadataSchemaID)
	metadata := decodeSchemaInstance(t, readCaseFile(t, output, "collection-metadata.json"))
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown top-level field", func(value map[string]any) { value["unexpected"] = true }},
		{"unknown case kind", func(value map[string]any) { value["caseKind"] = "fixture-shaped-but-untrusted" }},
		{"mismatched case contract", func(value map[string]any) { value["caseContractVersion"] = "cirewind.case/v1alpha1" }},
		{"missing raw materialization flag", func(value map[string]any) { delete(value, "rawMaterialized") }},
		{"unknown coverage field", func(value map[string]any) { value["coverage"].(map[string]any)["logsAssumedSafe"] = 1 }},
	} {
		t.Run("metadata/"+test.name, func(t *testing.T) {
			malformed := cloneJSONValue(t, metadata).(map[string]any)
			test.mutate(malformed)
			if err := metadataSchema.Validate(malformed); err == nil {
				t.Fatalf("metadata schema accepted %s", test.name)
			}
		})
	}

	graphSchema := compileApplicationSchema(t, graphSchemaID)
	graphValue := decodeSchemaInstance(t, readCaseFile(t, output, "graph.json"))
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown top-level field", func(value map[string]any) { value["attackPath"] = true }},
		{"unknown case kind", func(value map[string]any) { value["caseKind"] = "trusted" }},
		{"unknown node type", func(value map[string]any) { firstObject(value, "nodes")["type"] = "CloudRole" }},
		{"unknown edge field", func(value map[string]any) { firstObject(value, "edges")["caused"] = true }},
		{"unknown evidence class", func(value map[string]any) { firstObject(value, "edges")["evidenceClass"] = "ASSUMED" }},
		{"inference without derivation rule", func(value map[string]any) {
			edge := firstObjectWhere(value, "edges", "evidenceClass", "INFERENCE")
			delete(edge, "derivationRule")
		}},
		{"temporal class on non-temporal relation", func(value map[string]any) {
			edge := firstObjectNotWhere(value, "edges", "type", "OBSERVED_AFTER")
			edge["evidenceClass"] = "TEMPORAL_CORRELATION"
		}},
		{"exact OIDC capability", func(value map[string]any) {
			edge := firstObjectWhere(value, "edges", "type", "COULD_MINT_OIDC")
			edge["evidenceClass"] = "EXACT_OBSERVATION"
			delete(edge, "derivationRule")
		}},
		{"inferred lifecycle execution", func(value map[string]any) {
			edge := firstObjectWhere(value, "edges", "type", "STEP_EXECUTED_ACTION")
			edge["evidenceClass"] = "INFERENCE"
			edge["derivationRule"] = "invalid-lifecycle-inference/v1"
		}},
		{"temporal environment target", func(value map[string]any) {
			edge := firstObjectWhere(value, "edges", "type", "TARGETED_ENVIRONMENT")
			edge["evidenceClass"] = "TEMPORAL_CORRELATION"
			delete(edge, "derivationRule")
		}},
		{"unknown finding state", func(value map[string]any) { firstObject(value, "findingIndex")["state"] = "LIKELY_COMPROMISED" }},
		{"unknown provenance", func(value map[string]any) { firstObject(value, "findingIndex")["provenanceLevel"] = "L5_ABSOLUTE" }},
		{"evidence gap without reason", func(value map[string]any) {
			finding := firstObjectWhere(value, "findingIndex", "state", "UNKNOWN_EVIDENCE_GAP")
			delete(finding, "evidenceGapReason")
		}},
		{"attempt without run identity", func(value map[string]any) {
			finding := firstObjectWithField(value, "findingIndex", "runAttempt")
			delete(finding, "runId")
		}},
		{"legacy-basis notice on noncredential relationship", func(value map[string]any) {
			finding := firstObject(value, "findingIndex")
			edge := firstObject(value, "edges")
			value["projectionNotices"] = []any{map[string]any{
				"code": "UNCLASSIFIABLE_LEGACY_BASIS", "findingRevisionId": finding["findingRevisionId"],
				"relationship": "STEP_EXECUTED_ACTION", "evidenceIds": edge["evidenceIds"],
			}}
		}},
	} {
		t.Run("graph/"+test.name, func(t *testing.T) {
			malformed := cloneJSONValue(t, graphValue).(map[string]any)
			test.mutate(malformed)
			if err := graphSchema.Validate(malformed); err == nil {
				t.Fatalf("graph schema accepted %s", test.name)
			}
		})
	}

	unknownMetadata := cloneJSONValue(t, metadata).(map[string]any)
	unknownMetadata["unexpected"] = true
	var decodedMetadata report.Metadata
	if err := decodeStrictJSONDocument(mustMarshalJSON(t, unknownMetadata), &decodedMetadata); err == nil {
		t.Fatal("strict metadata decoder accepted an unknown field")
	}
	invalidMetadata := cloneJSONValue(t, metadata).(map[string]any)
	invalidMetadata["caseKind"] = "trusted"
	decodedMetadata = report.Metadata{}
	if err := decodeStrictJSONDocument(mustMarshalJSON(t, invalidMetadata), &decodedMetadata); err != nil {
		t.Fatalf("typed metadata decode unexpectedly rejected a string enum before validation: %v", err)
	}
	if err := report.WriteMetadataJSON(io.Discard, decodedMetadata); err == nil {
		t.Fatal("metadata code validator accepted an unknown case kind")
	}

	unknownGraph := cloneJSONValue(t, graphValue).(map[string]any)
	firstObject(unknownGraph, "edges")["caused"] = true
	var decodedGraph graph.GraphV2
	if err := decodeStrictJSONDocument(mustMarshalJSON(t, unknownGraph), &decodedGraph); err == nil {
		t.Fatal("strict graph decoder accepted an unknown edge field")
	}
	invalidGraph := cloneJSONValue(t, graphValue).(map[string]any)
	firstObject(invalidGraph, "edges")["evidenceClass"] = "ASSUMED"
	decodedGraph = graph.GraphV2{}
	if err := decodeStrictJSONDocument(mustMarshalJSON(t, invalidGraph), &decodedGraph); err != nil {
		t.Fatalf("typed graph decode unexpectedly rejected a string enum before validation: %v", err)
	}
	if err := decodedGraph.NormalizeAndValidate(); err == nil {
		t.Fatal("graph code validator accepted an unknown evidence class")
	}
}

func TestGeneratedDemoEvidenceLedgerConformsToDraft202012Schema(t *testing.T) {
	ctx := context.Background()
	snapshot, pack, derived := fixture(t, ctx)
	output := filepath.Join(t.TempDir(), "case")
	if err := casegen.Generate(ctx, casegen.Options{
		Output:   output,
		Snapshot: snapshot,
		Pack:     pack,
		Case:     derived.Case,
	}); err != nil {
		t.Fatal(err)
	}

	schema := compileLedgerSchema(t)
	file, err := os.Open(filepath.Join(output, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNumber := 0
	var firstRecord map[string]any
	var sessionID any
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			t.Fatalf("evidence.jsonl line %d is blank", lineNumber)
		}
		instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
		if err != nil {
			t.Fatalf("decode evidence.jsonl line %d: %v", lineNumber, err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("evidence.jsonl line %d violates %s: %v", lineNumber, ledgerSchemaID, err)
		}
		record, ok := instance.(map[string]any)
		if !ok {
			t.Fatalf("evidence.jsonl line %d is not an object", lineNumber)
		}
		if got := record["sequence"]; got != json.Number(strconv.Itoa(lineNumber)) {
			t.Fatalf("evidence.jsonl line %d has sequence %v", lineNumber, got)
		}
		if lineNumber == 1 {
			sessionID = record["sessionId"]
		} else if record["sessionId"] != sessionID {
			t.Fatalf("evidence.jsonl line %d changed sessionId", lineNumber)
		}
		if firstRecord == nil {
			encoded, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &firstRecord); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	wantRecords := len(snapshot.Evidence) + len(derived.Case.Findings)
	if lineNumber != wantRecords {
		t.Fatalf("validated %d ledger records, want %d", lineNumber, wantRecords)
	}
	if firstRecord == nil {
		t.Fatal("generated demo evidence ledger is empty")
	}

	malformed := cloneJSONValue(t, firstRecord).(map[string]any)
	malformed["recordType"] = "finding_revision"
	if err := schema.Validate(malformed); err == nil {
		t.Fatal("ledger schema accepted an evidence envelope framed as a finding revision")
	}
	malformedWrapper := cloneJSONValue(t, firstRecord).(map[string]any)
	delete(malformedWrapper, "sequence")
	if err := schema.Validate(malformedWrapper); err == nil {
		t.Fatal("ledger schema accepted a record without its sequence")
	}
}

func compileLedgerSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	// Every application schema is registered below. Any unresolved reference
	// must fail instead of falling back to a filesystem or network loader.
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	for _, resource := range []struct {
		id   string
		path string
	}{
		{evidenceSchemaID, "../../schema/evidence-v1alpha1.json"},
		{findingsSchemaID, "../../schema/findings-v1alpha1.json"},
		{ledgerSchemaID, "../../schema/evidence-ledger-v1alpha1.json"},
	} {
		data, err := os.ReadFile(resource.path)
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema %s: %v", resource.path, err)
		}
		if err := compiler.AddResource(resource.id, document); err != nil {
			t.Fatalf("add local schema resource %s: %v", resource.id, err)
		}
	}
	compiled, err := compiler.Compile(ledgerSchemaID)
	if err != nil {
		t.Fatalf("compile local ledger schema: %v", err)
	}
	return compiled
}

func compileApplicationSchema(t *testing.T, schemaID string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	// Application schemas use only locally registered resources. A missing
	// dependency must fail the test rather than trigger filesystem or network
	// resolution.
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	for _, resource := range []struct {
		id   string
		path string
	}{
		{evidenceSchemaID, "../../schema/evidence-v1alpha1.json"},
		{findingsSchemaID, "../../schema/findings-v1alpha1.json"},
		{incidentSchemaID, "../../schema/incident-v1alpha1.json"},
		{ledgerSchemaID, "../../schema/evidence-ledger-v1alpha1.json"},
		{metadataSchemaID, "../../schema/collection-metadata-v1alpha2.json"},
		{graphSchemaID, "../../schema/graph-v1alpha2.json"},
	} {
		data, err := os.ReadFile(resource.path)
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema %s: %v", resource.path, err)
		}
		if err := compiler.AddResource(resource.id, document); err != nil {
			t.Fatalf("add local schema resource %s: %v", resource.id, err)
		}
	}
	compiled, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatalf("compile local schema %s: %v", schemaID, err)
	}
	return compiled
}

func readCaseFile(t *testing.T, output, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(output, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeSchemaInstance(t *testing.T, data []byte) any {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func decodeStrictJSONDocument(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func firstObject(value map[string]any, field string) map[string]any {
	return value[field].([]any)[0].(map[string]any)
}

func firstObjectWhere(value map[string]any, field, key string, want any) map[string]any {
	for _, item := range value[field].([]any) {
		object := item.(map[string]any)
		if object[key] == want {
			return object
		}
	}
	panic("fixture lacks required object for schema drift test")
}

func firstObjectNotWhere(value map[string]any, field, key string, unwanted any) map[string]any {
	for _, item := range value[field].([]any) {
		object := item.(map[string]any)
		if object[key] != unwanted {
			return object
		}
	}
	panic("fixture lacks required contrasting object for schema drift test")
}

func firstObjectWithField(value map[string]any, field, key string) map[string]any {
	for _, item := range value[field].([]any) {
		object := item.(map[string]any)
		if _, ok := object[key]; ok {
			return object
		}
	}
	panic("fixture lacks required field for schema drift test")
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneJSONValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}
