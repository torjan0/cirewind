package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestValidateSyntheticPacks(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		filepath.Join("..", "..", "testdata", "incidents", "valid-minimal.yaml"),
		filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Validate(context.Background(), data)
		if err != nil {
			t.Fatalf("Validate(%s): %v", path, err)
		}
		if len(result.OriginalSHA256) != 64 || len(result.CanonicalSHA256) != 64 {
			t.Fatalf("invalid hashes: %#v", result)
		}
		if !json.Valid(result.CanonicalJSON) {
			t.Fatalf("canonical output is not JSON: %s", result.CanonicalJSON)
		}
		if bytes.Contains(result.CanonicalJSON, []byte(`"L4"`)) || !bytes.Contains(result.CanonicalJSON, []byte(`"L4_CERTAIN"`)) {
			t.Fatalf("canonical provenance drift: %s", result.CanonicalJSON)
		}
	}
}

func TestCanonicalizationIgnoresCommentsAndNormalizesSets(t *testing.T) {
	t.Parallel()
	base := readFixture(t, "valid-minimal.yaml")
	variant := bytes.Replace(base, []byte("  sources:\n"), []byte("  labels: [zeta, alpha]\n  sources:\n"), 1)
	baseWithLabels := bytes.Replace(base, []byte("  sources:\n"), []byte("  labels: [alpha, zeta]\n  sources:\n"), 1)
	variant = append([]byte("# harmless comment\n"), variant...)

	a, err := Validate(context.Background(), baseWithLabels)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Validate(context.Background(), variant)
	if err != nil {
		t.Fatal(err)
	}
	if a.CanonicalSHA256 != b.CanonicalSHA256 || !bytes.Equal(a.CanonicalJSON, b.CanonicalJSON) {
		t.Fatalf("canonical forms differ:\n%s\n%s", a.CanonicalJSON, b.CanonicalJSON)
	}
	if a.OriginalSHA256 == b.OriginalSHA256 {
		t.Fatal("different original bytes received the same original-byte hash")
	}
}

func TestStrictYAMLRejections(t *testing.T) {
	t.Parallel()
	base := string(readFixture(t, "valid-minimal.yaml"))
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{name: "bom", data: append([]byte{0xef, 0xbb, 0xbf}, []byte(base)...), code: "BOM_FORBIDDEN"},
		{name: "multiple documents", data: []byte(base + "\n---\n{}\n"), code: "MULTIPLE_DOCUMENTS"},
		{name: "anchor", data: []byte(strings.Replace(base, "title: Minimal synthetic test", "title: &title Minimal synthetic test", 1)), code: "ANCHOR_FORBIDDEN"},
		{name: "alias", data: []byte(strings.Replace(base, "title: Minimal synthetic test", "title: &title Minimal synthetic test\n  notes: *title", 1)), code: "ALIAS_FORBIDDEN"},
		{name: "merge key", data: []byte(strings.Replace(base, "metadata:\n", "metadata:\n  <<: {}\n", 1)), code: "MERGE_KEY_FORBIDDEN"},
		{name: "custom tag", data: []byte(strings.Replace(base, "title: Minimal synthetic test", "title: !unsafe Minimal synthetic test", 1)), code: "CUSTOM_TAG_FORBIDDEN"},
		{name: "duplicate key", data: []byte(strings.Replace(base, "kind: GitHubActionsIncident", "kind: GitHubActionsIncident\nkind: GitHubActionsIncident", 1)), code: "DUPLICATE_KEY"},
		{name: "non string key", data: []byte(base + "1: value\n"), code: "NON_STRING_KEY"},
		{name: "unknown field", data: []byte(strings.Replace(base, "  id: CIR-TEST-001", "  id: CIR-TEST-001\n  executable: true", 1)), code: "UNKNOWN_FIELD"},
		{name: "implicit timestamp", data: []byte(strings.Replace(base, `publishedAt: "2026-08-20T00:00:00Z"`, `publishedAt: 2026-08-20T00:00:00Z`, 1)), code: "IMPLICIT_TIMESTAMP"},
		{name: "float", data: []byte(strings.Replace(base, "packVersion: 1.0.0", "packVersion: .nan", 1)), code: "FLOAT_FORBIDDEN"},
		{name: "old provenance spelling", data: []byte(strings.Replace(base, "L4_CERTAIN", "L4", 1)), code: "INVALID_PROVENANCE"},
		{name: "regex field", data: []byte(strings.Replace(base, "          value: \"1111111111111111111111111111111111111111\"", "          value: \"1111111111111111111111111111111111111111\"\n        regex: .+", 1)), code: "UNKNOWN_FIELD"},
		{name: "component aliases undefined", data: []byte(strings.Replace(base, "      repository:\n", "      aliases: []\n      repository:\n", 1)), code: "UNKNOWN_FIELD"},
		{name: "active markup", data: []byte(strings.Replace(base, "title: Minimal synthetic test", "title: <script>synthetic</script>", 1)), code: "ACTIVE_MARKUP"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Validate(context.Background(), tc.data)
			assertDiagnostic(t, err, tc.code)
		})
	}
}

func TestParseLimitsAndCancellation(t *testing.T) {
	t.Parallel()
	if _, err := ValidateReader(context.Background(), bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxPackBytes+1))); !errors.Is(err, errPackTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
	base := string(readFixture(t, "valid-minimal.yaml"))
	largeScalar := strings.Replace(base, "Synthetic test pack.", strings.Repeat("a", MaxScalarBytes+1), 1)
	_, err := Validate(context.Background(), []byte(largeScalar))
	assertDiagnostic(t, err, "SCALAR_LIMIT")

	var deep strings.Builder
	for i := 0; i < MaxYAMLDepth+2; i++ {
		deep.WriteString(strings.Repeat("  ", i))
		deep.WriteString(fmt.Sprintf("k%d:\n", i))
	}
	deep.WriteString(strings.Repeat("  ", MaxYAMLDepth+2) + "value\n")
	_, err = Validate(context.Background(), []byte(deep.String()))
	assertDiagnostic(t, err, "DEPTH_LIMIT")

	var tooManyMap strings.Builder
	for i := 0; i <= MaxMapEntries; i++ {
		fmt.Fprintf(&tooManyMap, "k%d: value\n", i)
	}
	_, err = Validate(context.Background(), []byte(tooManyMap.String()))
	assertDiagnostic(t, err, "MAPPING_LIMIT")

	var tooManySequence strings.Builder
	for i := 0; i <= MaxSeqEntries; i++ {
		tooManySequence.WriteString("- value\n")
	}
	_, err = Validate(context.Background(), []byte(tooManySequence.String()))
	assertDiagnostic(t, err, "SEQUENCE_LIMIT")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Validate(ctx, []byte(base)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Validate error = %v", err)
	}
}

func TestAllIndicatorKindsAndNormalization(t *testing.T) {
	t.Parallel()
	trueValue := true
	tests := []struct {
		name          string
		kind          string
		componentType string
		value         IndicatorValue
		window        bool
		check         func(t *testing.T, got IndicatorValue)
	}{
		{name: "action commit", kind: "action-commit", componentType: "github-action", value: IndicatorValue{GitObject: &GitObject{Algorithm: "sha1", Value: strings.Repeat("A", 40)}}},
		{name: "workflow commit", kind: "reusable-workflow-commit", componentType: "reusable-workflow", value: IndicatorValue{GitObject: &GitObject{Algorithm: "sha1", Value: strings.Repeat("B", 40)}, Path: ".github/workflows/reuse.yaml"}},
		{name: "mutable action", kind: "mutable-action-ref", componentType: "github-action", value: IndicatorValue{Ref: "v1"}, window: true},
		{name: "mutable workflow", kind: "mutable-workflow-ref", componentType: "reusable-workflow", value: IndicatorValue{Ref: "stable/v1", Path: ".github/workflows/reuse.yaml"}, window: true},
		{name: "digest", kind: "digest", componentType: "github-action", value: IndicatorValue{Subject: "github-action-package", Algorithm: "sha256", Digest: strings.Repeat("C", 64)}},
		{name: "literal", kind: "log-literal", componentType: "github-action", value: IndicatorValue{Literal: "harmless marker", CaseSensitive: &trueValue, Scope: "step"}},
		{name: "domain", kind: "domain", componentType: "github-action", value: IndicatorValue{Domain: "EXAMPLE.INVALID", Match: "exact"}, check: func(t *testing.T, got IndicatorValue) {
			if got.Domain != "example.invalid" {
				t.Fatalf("domain = %q", got.Domain)
			}
		}},
		{name: "IP", kind: "ip-address", componentType: "github-action", value: IndicatorValue{Address: "::ffff:192.0.2.1"}, check: func(t *testing.T, got IndicatorValue) {
			if got.Address != "192.0.2.1" {
				t.Fatalf("address = %q", got.Address)
			}
		}},
		{name: "repository", kind: "repository-name", componentType: "repository", value: IndicatorValue{Owner: "Example", Name: "Harmless"}, check: func(t *testing.T, got IndicatorValue) {
			if got.Owner != "example" || got.Name != "harmless" {
				t.Fatalf("repository = %q/%q", got.Owner, got.Name)
			}
		}},
		{name: "release", kind: "release-version", componentType: "embedded-tool", value: IndicatorValue{Version: "1.2.3"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := makePackForIndicator(t, tc.kind, tc.componentType, tc.value, tc.window)
			result, err := Validate(context.Background(), data)
			if err != nil {
				t.Fatal(err)
			}
			if tc.check != nil {
				tc.check(t, result.Pack.Spec.Indicators[0].Value)
			}
		})
	}
}

func TestSemanticRejectionsAreLocated(t *testing.T) {
	t.Parallel()
	base := string(readFixture(t, "valid-minimal.yaml"))
	tests := []struct {
		name string
		data string
		code string
	}{
		{name: "short SHA", data: strings.Replace(base, strings.Repeat("1", 40), "1234", 1), code: "INVALID_GIT_OBJECT"},
		{name: "unknown source", data: strings.Replace(base, "- fixture\n", "- missing-source\n", 1), code: "UNKNOWN_SOURCE_REF"},
		{name: "unsafe path", data: strings.Replace(base, "name: Harmless", "name: Harmless\n      subpaths: [../escape]", 1), code: "INVALID_PATH"},
		{name: "source URL userinfo", data: strings.Replace(base, "https://example.invalid/fixture", "https://user@example.invalid/fixture", 1), code: "INVALID_SOURCE_URL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(context.Background(), []byte(tc.data))
			ve := assertDiagnostic(t, err, tc.code)
			for _, d := range ve.Diagnostics {
				if d.Code == tc.code && d.Line <= 0 {
					t.Fatalf("diagnostic lacks source location: %#v", d)
				}
			}
		})
	}
}

func TestIndicatorAndConflictRejections(t *testing.T) {
	t.Parallel()
	trueValue := true
	mutable := string(makePackForIndicator(t, "mutable-action-ref", "github-action", IndicatorValue{Ref: "v1"}, true))
	digest := string(makePackForIndicator(t, "digest", "github-action", IndicatorValue{Subject: "github-action-package", Algorithm: "sha256", Digest: strings.Repeat("c", 64)}, false))
	literal := string(makePackForIndicator(t, "log-literal", "github-action", IndicatorValue{Literal: "marker", CaseSensitive: &trueValue, Scope: "step"}, false))
	synthetic, err := os.ReadFile(filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data string
		code string
	}{
		{name: "unsafe ref", data: strings.Replace(mutable, `ref: "v1"`, `ref: "../bad"`, 1), code: "INVALID_GIT_REF"},
		{name: "immutable ref in mutable field", data: strings.Replace(mutable, `ref: "v1"`, `ref: "1111111111111111111111111111111111111111"`, 1), code: "INVALID_GIT_REF"},
		{name: "digest namespace", data: strings.Replace(digest, `subject: "github-action-package"`, `subject: "unknown-package"`, 1), code: "INVALID_DIGEST_SUBJECT"},
		{name: "case folding", data: strings.Replace(literal, "caseSensitive: true", "caseSensitive: false", 1), code: "UNSUPPORTED_CASE_FOLD"},
		{name: "affected known good conflict", data: strings.Replace(string(synthetic), strings.Repeat("0", 40), strings.Repeat("1", 40), 1), code: "AFFECTED_KNOWN_GOOD_CONFLICT"},
		{name: "ambiguous exposure predicate", data: strings.Replace(string(synthetic), "        whenStates:\n", "        exposurePredicates: {}\n        whenStates:\n", 1), code: "UNKNOWN_FIELD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Validate(context.Background(), []byte(tc.data))
			assertDiagnostic(t, err, tc.code)
		})
	}
}

func TestSchemaIsValidJSONAndUsesCanonicalProvenance(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "incident-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("incident schema is not valid JSON")
	}
	for _, value := range []string{"L4_CERTAIN", "L3_STRONG", "L2_PROBABLE", "L1_POSSIBLE", "L0_UNKNOWN"} {
		if !bytes.Contains(data, []byte(value)) {
			t.Fatalf("schema lacks %s", value)
		}
	}
}

func TestDiagnosticsEscapeHostileKeys(t *testing.T) {
	t.Parallel()
	base := string(readFixture(t, "valid-minimal.yaml"))
	hostile := strings.Replace(base, "metadata:\n", "metadata:\n  \"bad\\u001b[2J\\u202e\": value\n", 1)
	_, err := Validate(context.Background(), []byte(hostile))
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error = %T %v", err, err)
	}
	text := validation.Error()
	if strings.ContainsRune(text, '\x1b') || strings.ContainsRune(text, '\u202e') {
		t.Fatalf("unsafe diagnostic %q", text)
	}
}

func FuzzValidate(f *testing.F) {
	f.Add(readFixtureForFuzz(f, "valid-minimal.yaml"))
	f.Add([]byte("apiVersion: cirewind.dev/v1alpha1\nkind: GitHubActionsIncident\n"))
	f.Add([]byte("a: &x [*x]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxPackBytes+1 {
			data = data[:MaxPackBytes+1]
		}
		_, _ = Validate(context.Background(), data)
	})
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "incidents", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readFixtureForFuzz(f *testing.F, name string) []byte {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "incidents", name))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func assertDiagnostic(t *testing.T, err error, code string) *ValidationError {
	t.Helper()
	if err == nil {
		t.Fatalf("Validate succeeded; want diagnostic %s", code)
	}
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error %T %v is not ValidationError", err, err)
	}
	for _, diagnostic := range validation.Diagnostics {
		if diagnostic.Code == code {
			return validation
		}
	}
	t.Fatalf("diagnostics %#v do not contain %s", validation.Diagnostics, code)
	return nil
}

func makePackForIndicator(t *testing.T, kind, componentType string, value IndicatorValue, withWindow bool) []byte {
	t.Helper()
	valueJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var valueMap map[string]any
	if err := json.Unmarshal(valueJSON, &valueMap); err != nil {
		t.Fatal(err)
	}
	valueYAML := renderValueYAML(valueMap, 8)
	workflowPaths := ""
	if componentType == "reusable-workflow" {
		workflowPaths = "\n      workflowPaths:\n        - .github/workflows/reuse.yaml"
	}
	windows := ""
	windowRefs := ""
	if withWindow {
		windows = `
  windows:
    - id: exposure
      start: "2026-08-20T00:00:00Z"
      end: "2026-08-21T00:00:00Z"
      bounds: "[)"
      sourcePrecision: second
      approximation: exact
      sourceRefs: [fixture]
`
		windowRefs = "      windowRefs: [exposure]\n"
	}
	return []byte(fmt.Sprintf(`apiVersion: cirewind.dev/v1alpha1
kind: GitHubActionsIncident
metadata:
  id: CIR-TEST-KIND
  packVersion: 1.0.0
  title: Indicator kind fixture
  publishedAt: "2026-08-20T00:00:00Z"
  updatedAt: "2026-08-20T00:00:00Z"
  sources:
    - id: fixture
      type: synthetic-fixture
      title: Fixture
      publisher: CIRewind test maintainers
      url: https://example.invalid/fixture
      retrievedAt: "2026-08-20T00:00:00Z"
spec:
  description: Synthetic indicator fixture.
  components:
    - id: component
      type: %s
      repository:
        owner: Example
        name: Harmless%s
%s  indicators:
    - id: indicator
      componentId: component
      kind: %s
      value:
%s%s      confidence: L4_CERTAIN
      sourceRefs: [fixture]
`, componentType, workflowPaths, windows, kind, valueYAML, windowRefs))
}

func renderValueYAML(value map[string]any, indent int) string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	// Stable rendering keeps failures reproducible.
	sort.Strings(keys)
	var out strings.Builder
	prefix := strings.Repeat(" ", indent)
	for _, key := range keys {
		v := value[key]
		switch typed := v.(type) {
		case map[string]any:
			out.WriteString(prefix + key + ":\n")
			out.WriteString(renderValueYAML(typed, indent+2))
		case string:
			encoded, _ := json.Marshal(typed)
			out.WriteString(prefix + key + ": " + string(encoded) + "\n")
		case bool:
			out.WriteString(fmt.Sprintf("%s%s: %t\n", prefix, key, typed))
		}
	}
	return out.String()
}
