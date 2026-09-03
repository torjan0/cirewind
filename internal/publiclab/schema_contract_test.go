package publiclab

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestObjectManifestSchemaAcceptsGeneratedArtifact(t *testing.T) {
	schemaBytes, err := os.ReadFile("../../schema/public-lab-object-manifest-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("https://cirewind.dev/schema/public-lab-object-manifest-v1alpha1.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://cirewind.dev/schema/public-lab-object-manifest-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifact.Manifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("generated object manifest violates schema: %v", err)
	}

	var hostile map[string]any
	if err := json.Unmarshal(artifact.Manifest, &hostile); err != nil {
		t.Fatal(err)
	}
	hostile["unexpected"] = true
	encoded, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	instance, err = jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted an unknown top-level property")
	}
}
