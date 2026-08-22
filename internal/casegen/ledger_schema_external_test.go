package casegen_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/torjan0/cirewind/internal/casegen"
)

const (
	testSchemaBase   = "https://schemas.invalid/cirewind/"
	evidenceSchemaID = testSchemaBase + "evidence-v1alpha1.json"
	findingsSchemaID = testSchemaBase + "findings-v1alpha1.json"
	incidentSchemaID = testSchemaBase + "incident-v1alpha1.json"
	ledgerSchemaID   = testSchemaBase + "evidence-ledger-v1alpha1.json"
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
