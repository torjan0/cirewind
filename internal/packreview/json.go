package packreview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/evidence"
)

const (
	maxJSONFileBytes   = 16 << 20
	maxJSONDepth       = 64
	maxJSONObjectKeys  = 4096
	maxJSONArrayValues = 25_000
)

func readStrictJSON[T any](ctx context.Context, path string) (T, []byte, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, nil, err
	}
	data, err := readBoundedRegularContext(ctx, path, maxJSONFileBytes+1)
	if err != nil {
		return zero, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxJSONFileBytes {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: "SIZE_LIMIT", Path: path, Message: "JSON file exceeds 16 MiB"}}}
	}
	if len(data) == 0 || !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: "INVALID_JSON_ENCODING", Path: path, Message: "JSON must be non-empty UTF-8 without a byte-order mark"}}}
	}
	// Enforce duplicate-key and structural limits before decoding into the
	// destination type. A typed decode may otherwise allocate attacker-chosen
	// slice or map sizes before the bounded structural walk sees the input.
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: strictJSONProblemCode(err), Path: path, Message: boundedError(err)}}}
	}
	if problem, found, err := validateTypedJSONShape(data, reflect.TypeOf((*T)(nil)).Elem()); err != nil {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: "STRICT_JSON", Path: path, Message: boundedError(err)}}}
	} else if found {
		problem.Path = path + problem.Path
		return zero, nil, &ValidationError{Problems: []Problem{problem}}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&zero); err != nil {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: "STRICT_JSON", Path: path, Message: boundedError(err)}}}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, nil, &ValidationError{Problems: []Problem{{Code: "TRAILING_JSON", Path: path, Message: "exactly one JSON value is required"}}}
	}
	return zero, data, nil
}

// validateTypedJSONShape distinguishes an omitted optional field from a
// present JSON null before decoding loses that distinction. The review schemas
// permit null only for Claim.canonicalPointer; all other scalar, object, array,
// map, and array-element positions reject it. It also enforces presence for
// non-omitempty fields, including false-valued booleans that a typed decode
// cannot distinguish from absence. A token walk avoids constructing a second
// attacker-sized generic object tree after the structural limits pass.
func validateTypedJSONShape(data []byte, expected reflect.Type) (Problem, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(reflect.Type, string, bool) (Problem, bool, error)
	walk = func(want reflect.Type, pointer string, nullAllowed bool) (Problem, bool, error) {
		token, err := decoder.Token()
		if err != nil {
			return Problem{}, false, err
		}
		if token == nil {
			if nullAllowed || want == nil || collectionKind(want) == reflect.Interface {
				return Problem{}, false, nil
			}
			switch collectionKind(want) {
			case reflect.Slice, reflect.Array:
				return Problem{Code: "NULL_ARRAY", Path: pointer, Message: "JSON array field must be an array, not null"}, true, nil
			case reflect.Map:
				return Problem{Code: "NULL_OBJECT", Path: pointer, Message: "JSON object field must be an object, not null"}, true, nil
			default:
				return Problem{Code: "NULL_VALUE", Path: pointer, Message: "JSON field does not permit null"}, true, nil
			}
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return Problem{}, false, nil
		}
		want = indirectType(want)
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return Problem{}, false, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return Problem{}, false, errors.New("object key is not a string")
				}
				var child reflect.Type
				childNullAllowed := false
				if want != nil {
					switch want.Kind() {
					case reflect.Struct:
						if field, ok := jsonStructField(want, key); ok {
							child = field.typeOf
							childNullAllowed = field.nullAllowed
							seen[key] = struct{}{}
						} else {
							return Problem{Code: "STRICT_JSON", Path: pointer + "/" + escapeJSONPointerToken(key), Message: "unknown JSON field"}, true, nil
						}
					case reflect.Map:
						child = want.Elem()
					}
				}
				problem, found, err := walk(child, pointer+"/"+escapeJSONPointerToken(key), childNullAllowed)
				if err != nil || found {
					return problem, found, err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return Problem{}, false, err
			}
			if want != nil && want.Kind() == reflect.Struct {
				for _, field := range jsonStructFields(want) {
					if !field.required {
						continue
					}
					if _, ok := seen[field.name]; !ok {
						return Problem{Code: "MISSING_FIELD", Path: pointer + "/" + escapeJSONPointerToken(field.name), Message: "required JSON field is missing"}, true, nil
					}
				}
			}
			return Problem{}, false, nil
		case '[':
			var child reflect.Type
			if want != nil && (want.Kind() == reflect.Slice || want.Kind() == reflect.Array) {
				child = want.Elem()
			}
			for index := 0; decoder.More(); index++ {
				problem, found, err := walk(child, pointer+"/"+strconv.Itoa(index), false)
				if err != nil || found {
					return problem, found, err
				}
			}
			_, err := decoder.Token()
			return Problem{}, false, err
		default:
			return Problem{}, false, errors.New("unexpected JSON delimiter")
		}
	}
	problem, found, err := walk(expected, "", false)
	if err != nil || found {
		return problem, found, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Problem{}, false, errors.New("multiple JSON values")
	}
	return Problem{}, false, nil
}

func collectionKind(value reflect.Type) reflect.Kind {
	value = indirectType(value)
	if value == nil {
		return reflect.Invalid
	}
	return value.Kind()
}

func indirectType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return value
}

type jsonFieldExpectation struct {
	name        string
	typeOf      reflect.Type
	required    bool
	nullAllowed bool
}

func jsonStructFields(value reflect.Type) []jsonFieldExpectation {
	result := make([]jsonFieldExpectation, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")
		jsonName := tag[0]
		if jsonName == "-" {
			continue
		}
		if jsonName == "" {
			jsonName = field.Name
		}
		required := true
		for _, option := range tag[1:] {
			if option == "omitempty" {
				required = false
			}
		}
		result = append(result, jsonFieldExpectation{
			name: jsonName, typeOf: field.Type, required: required,
			nullAllowed: field.Tag.Get("jsonnull") == "allow",
		})
	}
	return result
}

func jsonStructField(value reflect.Type, name string) (jsonFieldExpectation, bool) {
	for _, field := range jsonStructFields(value) {
		if field.name == name {
			return field, true
		}
	}
	return jsonFieldExpectation{}, false
}

func escapeJSONPointerToken(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func strictJSONProblemCode(err error) string {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "duplicate object key "):
		return "DUPLICATE_JSON_KEY"
	case message == "multiple JSON values":
		return "TRAILING_JSON"
	case strings.HasPrefix(message, "JSON nesting exceeds "),
		strings.HasPrefix(message, "JSON object exceeds "),
		strings.HasPrefix(message, "JSON array exceeds "):
		return "JSON_STRUCTURE_LIMIT"
	default:
		return "STRICT_JSON"
	}
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxJSONDepth {
			return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			members := 0
			for decoder.More() {
				members++
				if members > maxJSONObjectKeys {
					return fmt.Errorf("JSON object exceeds %d members", maxJSONObjectKeys)
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			values := 0
			for decoder.More() {
				values++
				if values > maxJSONArrayValues {
					return fmt.Errorf("JSON array exceeds %d values", maxJSONArrayValues)
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(1); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func marshalCanonical(value any) ([]byte, error) {
	data, err := evidence.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func marshalIndented(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 1024 {
		text = text[:1024]
	}
	return text
}

// scanLines reads a bounded text manifest while rejecting oversized lines.
func scanLines(data []byte, maxLine int, fn func(string) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLine)
	for scanner.Scan() {
		if err := fn(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}
