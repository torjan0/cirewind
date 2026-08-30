package packreview

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type nullArrayDocumentSpec struct {
	name   string
	typeOf reflect.Type
	paths  []string
	read   func(context.Context, string) error
}

func TestStrictJSONRejectsNullForEverySchemaArray(t *testing.T) {
	for _, spec := range reviewJSONDocumentSpecs() {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			want := append([]string(nil), spec.paths...)
			sort.Strings(want)
			got := schemaArrayPaths(spec.typeOf)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("null-array corpus drift: Go slice paths %v, declared schema-array paths %v", got, want)
			}
			for _, pointer := range want {
				pointer := pointer
				t.Run(strings.NewReplacer("/", "_", "*", "item").Replace(strings.TrimPrefix(pointer, "/")), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "input.json")
					mustWrite(t, path, nullJSONAtPointer(t, pointer))
					err := spec.read(context.Background(), path)
					assertProblemCode(t, err, "NULL_ARRAY")
				})
			}
		})
	}
}

func TestStrictJSONRejectsNullArrayElements(t *testing.T) {
	for _, spec := range reviewJSONDocumentSpecs() {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			for _, pointer := range spec.paths {
				pointer := pointer
				t.Run(strings.NewReplacer("/", "_", "*", "item").Replace(strings.TrimPrefix(pointer, "/")), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "input.json")
					mustWrite(t, path, nullArrayElementJSONAtPointer(t, pointer))
					err := spec.read(context.Background(), path)
					assertProblemCode(t, err, "NULL_VALUE")
				})
			}
		})
	}
}

func TestStrictJSONRequiresEveryNonOmitEmptyField(t *testing.T) {
	for _, spec := range reviewJSONDocumentSpecs() {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			shape := populatedRequiredJSONShape(spec.typeOf)
			for _, pointer := range requiredSchemaFieldPaths(spec.typeOf) {
				pointer := pointer
				t.Run(strings.NewReplacer("/", "_", "*", "item").Replace(strings.TrimPrefix(pointer, "/")), func(t *testing.T) {
					mutated := cloneJSONShape(t, shape)
					removeJSONFieldAtPointer(t, mutated, pointer)
					data, err := json.Marshal(mutated)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(t.TempDir(), "input.json")
					mustWrite(t, path, append(data, '\n'))
					err = spec.read(context.Background(), path)
					assertProblemAtCode(t, err, "MISSING_FIELD", concreteJSONPointer(pointer))
				})
			}
		})
	}
}

func TestStrictJSONRejectsNullForNonNullableFields(t *testing.T) {
	for _, spec := range reviewJSONDocumentSpecs() {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			baseShape := populatedRequiredJSONShape(spec.typeOf)
			for _, field := range schemaFieldPaths(spec.typeOf) {
				field := field
				if field.kind == reflect.Slice || field.kind == reflect.Array || field.kind == reflect.Map {
					continue // The exhaustive collection corpus above owns these diagnostics.
				}
				t.Run(strings.NewReplacer("/", "_", "*", "item").Replace(strings.TrimPrefix(field.path, "/")), func(t *testing.T) {
					shape := cloneJSONShape(t, baseShape)
					setJSONFieldAtPointer(t, shape, field.path, nil)
					data, marshalErr := json.Marshal(shape)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					path := filepath.Join(t.TempDir(), "input.json")
					mustWrite(t, path, append(data, '\n'))
					err := spec.read(context.Background(), path)
					if field.nullAllowed {
						if err != nil {
							t.Fatalf("schema-nullable field was rejected: %v", err)
						}
						return
					}
					assertProblemCode(t, err, "NULL_VALUE")
				})
			}
		})
	}
}

func reviewJSONDocumentSpecs() []nullArrayDocumentSpec {
	return []nullArrayDocumentSpec{
		{
			name: "review packet", typeOf: reflect.TypeOf(Packet{}), read: strictJSONError[Packet],
			paths: []string{"/conflictIds", "/preparation/authors", "/preparation/sourceTranscribers"},
		},
		{
			name: "review policy", typeOf: reflect.TypeOf(ReviewPolicy{}), read: strictJSONError[ReviewPolicy],
			paths: []string{"/eligibleMaintainers", "/profiles", "/profiles/*/requiredAnyApprovalScopes", "/profiles/*/requiredOutsideScopes"},
		},
		{
			name: "source ledger", typeOf: reflect.TypeOf(SourceLedger{}), read: strictJSONError[SourceLedger],
			paths: []string{"/sources", "/sources/*/conflictIds"},
		},
		{
			name: "claim ledger", typeOf: reflect.TypeOf(ClaimLedger{}), read: strictJSONError[ClaimLedger],
			paths: []string{"/claims", "/claims/*/conflictIds", "/claims/*/sourceIds", "/claims/*/sourceLocations"},
		},
		{
			name: "conflict ledger", typeOf: reflect.TypeOf(ConflictLedger{}), read: strictJSONError[ConflictLedger],
			paths: []string{"/conflicts", "/conflicts/*/claimIds", "/conflicts/*/competingSourceIds", "/conflicts/*/selectedSourceIds"},
		},
		{
			name: "review assertion", typeOf: reflect.TypeOf(ReviewAssertion{}), read: strictJSONError[ReviewAssertion],
			paths: []string{"/commands", "/commands/*/arguments", "/knownLimitations", "/scopes", "/sourceObjectsChecked"},
		},
		{
			name: "review record", typeOf: reflect.TypeOf(Review{}), read: strictJSONError[Review],
			paths: []string{"/commands", "/commands/*/arguments", "/knownLimitations", "/scopes", "/sourceObjectsChecked"},
		},
		{
			name: "platform snapshot", typeOf: reflect.TypeOf(PlatformApprovalSnapshot{}), read: strictJSONError[PlatformApprovalSnapshot],
			paths: []string{"/approvals"},
		},
		{
			name: "promotion record", typeOf: reflect.TypeOf(PromotionRecord{}), read: strictJSONError[PromotionRecord],
			paths: []string{"/approvalIds"},
		},
		{
			name: "review registry", typeOf: reflect.TypeOf(Registry{}), read: strictJSONError[Registry],
			paths: []string{"/records", "/records/*/approvalIds"},
		},
		{
			name: "expected findings", typeOf: reflect.TypeOf(ExpectedFindings{}), read: strictJSONError[ExpectedFindings],
			paths: []string{"/findings", "/findings/*/coverageAssessmentIds", "/findings/*/evidenceGapCodes", "/findings/*/evidenceIds", "/forbidden"},
		},
		{
			name: "fixture index", typeOf: reflect.TypeOf(FixtureIndex{}), read: strictJSONError[FixtureIndex],
			paths: []string{"/scenarios"},
		},
		{
			name: "candidate validation", typeOf: reflect.TypeOf(CandidateValidation{}), read: strictJSONError[CandidateValidation],
			paths: []string{},
		},
	}
}

func TestStrictJSONDistinguishesOmittedEmptyAndNonemptyArrays(t *testing.T) {
	t.Run("optional omitted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "conflicts.json")
		mustWrite(t, path, mustCanonical(t, ConflictLedger{
			SchemaVersion: ConflictsSchema,
			Conflicts: []Conflict{{
				ConflictID: "synthetic-optional-array", ClaimIDs: []string{}, CompetingSourceIDs: []string{},
			}},
		}))
		if _, _, err := readStrictJSON[ConflictLedger](context.Background(), path); err != nil {
			t.Fatalf("optional selectedSourceIds omission was rejected: %v", err)
		}
	})

	t.Run("required empty allowed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "registry.json")
		mustWrite(t, path, mustCanonical(t, Registry{SchemaVersion: RegistrySchema, Records: []RegistryRecord{}}))
		registry, _, err := readStrictJSON[Registry](context.Background(), path)
		if err != nil {
			t.Fatalf("schema-valid empty records array was rejected: %v", err)
		}
		var semantic problems
		validateRegistry(registry, &semantic)
		if err := semantic.err(); err != nil {
			t.Fatalf("semantically allowed empty records array was rejected: %v", err)
		}
	})

	t.Run("required nonempty enforced semantically", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sources.json")
		mustWrite(t, path, mustCanonical(t, SourceLedger{SchemaVersion: SourcesSchema, Sources: []SourceRecord{}}))
		ledger, _, err := readStrictJSON[SourceLedger](context.Background(), path)
		if err != nil {
			t.Fatalf("empty array should reach semantic cardinality validation: %v", err)
		}
		var semantic problems
		validateSources(ledger, &semantic)
		assertProblemCode(t, semantic.err(), "SOURCE_COUNT")
	})
}

func strictJSONError[T any](ctx context.Context, path string) error {
	_, _, err := readStrictJSON[T](ctx, path)
	return err
}

func schemaArrayPaths(value reflect.Type) []string {
	var result []string
	var walk func(reflect.Type, string)
	walk = func(current reflect.Type, pointer string) {
		current = indirectType(current)
		if current == nil || current.Kind() != reflect.Struct {
			return
		}
		for index := 0; index < current.NumField(); index++ {
			field := current.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fieldPointer := pointer + "/" + escapeJSONPointerToken(name)
			fieldType := indirectType(field.Type)
			if fieldType == nil {
				continue
			}
			switch fieldType.Kind() {
			case reflect.Slice, reflect.Array:
				result = append(result, fieldPointer)
				walk(fieldType.Elem(), fieldPointer+"/*")
			case reflect.Struct:
				walk(fieldType, fieldPointer)
			}
		}
	}
	walk(value, "")
	sort.Strings(result)
	return result
}

type schemaFieldPath struct {
	path        string
	kind        reflect.Kind
	required    bool
	nullAllowed bool
}

func schemaFieldPaths(value reflect.Type) []schemaFieldPath {
	var result []schemaFieldPath
	var walk func(reflect.Type, string)
	walk = func(current reflect.Type, pointer string) {
		current = indirectType(current)
		if current == nil || current.Kind() != reflect.Struct {
			return
		}
		for _, field := range jsonStructFields(current) {
			fieldPointer := pointer + "/" + escapeJSONPointerToken(field.name)
			fieldType := indirectType(field.typeOf)
			kind := reflect.Invalid
			if fieldType != nil {
				kind = fieldType.Kind()
			}
			result = append(result, schemaFieldPath{path: fieldPointer, kind: kind, required: field.required, nullAllowed: field.nullAllowed})
			switch kind {
			case reflect.Struct:
				walk(fieldType, fieldPointer)
			case reflect.Slice, reflect.Array:
				walk(fieldType.Elem(), fieldPointer+"/*")
			}
		}
	}
	walk(value, "")
	sort.Slice(result, func(left, right int) bool { return result[left].path < result[right].path })
	return result
}

func requiredSchemaFieldPaths(value reflect.Type) []string {
	fields := schemaFieldPaths(value)
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field.required {
			result = append(result, field.path)
		}
	}
	return result
}

func populatedRequiredJSONShape(value reflect.Type) any {
	value = indirectType(value)
	if value == nil {
		return nil
	}
	switch value.Kind() {
	case reflect.Struct:
		result := make(map[string]any)
		for _, field := range jsonStructFields(value) {
			if !field.required {
				continue
			}
			if field.nullAllowed {
				result[field.name] = nil
				continue
			}
			result[field.name] = populatedRequiredJSONShape(field.typeOf)
		}
		return result
	case reflect.Slice, reflect.Array:
		element := indirectType(value.Elem())
		if element != nil && element.Kind() == reflect.Struct {
			return []any{populatedRequiredJSONShape(element)}
		}
		return []any{}
	case reflect.Map:
		return map[string]any{}
	case reflect.Bool:
		return false
	case reflect.String:
		return ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return 0
	default:
		return ""
	}
}

func cloneJSONShape(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func setJSONFieldAtPointer(t *testing.T, value any, pointer string, replacement any) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	current := value
	for index, part := range parts {
		if part == "*" {
			items, ok := current.([]any)
			if !ok || len(items) == 0 {
				t.Fatalf("pointer %s does not identify a populated array", pointer)
			}
			current = items[0]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("pointer %s does not identify an object at %s", pointer, part)
		}
		if index == len(parts)-1 {
			object[part] = replacement
			return
		}
		next, exists := object[part]
		if !exists {
			next = map[string]any{}
			object[part] = next
		}
		current = next
	}
}

func removeJSONFieldAtPointer(t *testing.T, value any, pointer string) {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	current := value
	for index, part := range parts {
		if part == "*" {
			items, ok := current.([]any)
			if !ok || len(items) == 0 {
				t.Fatalf("pointer %s does not identify a populated array", pointer)
			}
			current = items[0]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("pointer %s does not identify an object at %s", pointer, part)
		}
		if index == len(parts)-1 {
			delete(object, part)
			return
		}
		current = object[part]
	}
}

func concreteJSONPointer(pointer string) string {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	for index := range parts {
		if parts[index] == "*" {
			parts[index] = "0"
		}
	}
	return "/" + strings.Join(parts, "/")
}

func assertProblemAtCode(t *testing.T, err error, code, pointer string) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("got %v, want validation error %s at %s", err, code, pointer)
	}
	for _, problem := range validation.Problems {
		if problem.Code == code && strings.HasSuffix(problem.Path, pointer) {
			return
		}
	}
	t.Fatalf("got problems %+v, want code %s at %s", validation.Problems, code, pointer)
}

func nullJSONAtPointer(t *testing.T, pointer string) []byte {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var build func(int) any
	build = func(index int) any {
		if index == len(parts) {
			return nil
		}
		if parts[index] == "*" {
			return []any{build(index + 1)}
		}
		return map[string]any{parts[index]: build(index + 1)}
	}
	data, err := json.Marshal(build(0))
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func nullArrayElementJSONAtPointer(t *testing.T, pointer string) []byte {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var build func(int) any
	build = func(index int) any {
		if index == len(parts) {
			return []any{nil}
		}
		if parts[index] == "*" {
			return []any{build(index + 1)}
		}
		return map[string]any{parts[index]: build(index + 1)}
	}
	data, err := json.Marshal(build(0))
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
