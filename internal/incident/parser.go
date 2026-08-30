package incident

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

var errPackTooLarge = errors.New("incident pack exceeds the 2 MiB hard limit")
var yamlErrorLine = regexp.MustCompile(`(?:^| )line ([0-9]+)(?::([0-9]+))?`)

// ValidateReader reads at most MaxPackBytes+1 bytes and validates one pack.
// It never follows references found in the document.
func ValidateReader(ctx context.Context, r io.Reader) (*ValidatedPack, error) {
	if r == nil {
		return nil, errors.New("incident pack reader is nil")
	}
	limited := &io.LimitedReader{R: r, N: MaxPackBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read incident pack: %w", err)
	}
	if len(data) > MaxPackBytes {
		return nil, errPackTooLarge
	}
	return Validate(ctx, data)
}

// Validate performs strict structural and semantic validation and returns a
// normalized pack plus deterministic canonical JSON and hashes.
func Validate(ctx context.Context, data []byte) (*ValidatedPack, error) {
	return ValidateForPolicy(ctx, data, PolicyVersion)
}

// ValidateForPolicy validates with an explicitly selected compatible policy.
// An unknown version fails closed rather than being interpreted under the
// current rules.
func ValidateForPolicy(ctx context.Context, data []byte, version string) (*ValidatedPack, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policy, supported := ResolveValidatorPolicy(version)
	if !supported {
		return nil, &ValidationError{Diagnostics: []Diagnostic{{
			Code: "UNSUPPORTED_VALIDATOR_POLICY", Path: "$", Message: "requested incident validator policy is not supported",
		}}}
	}
	return validateForResolvedPolicy(ctx, data, policy)
}

func validateForResolvedPolicy(ctx context.Context, data []byte, policy ValidatorPolicyIdentity) (*ValidatedPack, error) {
	original := sha256.Sum256(data)
	if len(data) > MaxPackBytes {
		return nil, errPackTooLarge
	}
	if len(data) == 0 {
		return nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "EMPTY_DOCUMENT", Path: "$", Message: "incident pack is empty"}}}
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "BOM_FORBIDDEN", Path: "$", Line: 1, Column: 1, Message: "UTF-8 byte-order marks are forbidden"}}}
	}
	if !utf8.Valid(data) {
		return nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "INVALID_UTF8", Path: "$", Message: "incident pack must be valid UTF-8"}}}
	}

	root, loc, err := parseDocument(ctx, data)
	if err != nil {
		return nil, err
	}

	var shape diagnosticSet
	validateShape(ctx, root, reflect.TypeOf(Pack{}), "$", loc, &shape)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := shape.err(); err != nil {
		return nil, err
	}

	var pack Pack
	if err := root.Decode(&pack); err != nil {
		return nil, &ValidationError{Diagnostics: []Diagnostic{{
			Code: "DECODE_ERROR", Path: "$", Line: root.Line, Column: root.Column,
			Message: fmt.Sprintf("typed decoding failed: %q", boundedText(err.Error(), 1024)),
		}}}
	}

	var semantic diagnosticSet
	validateAndNormalize(&pack, loc, &semantic)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := semantic.err(); err != nil {
		return nil, err
	}

	canonical, err := canonicalJSON(pack)
	if err != nil {
		return nil, fmt.Errorf("canonicalize incident pack: %w", err)
	}
	canonicalHash := sha256.Sum256(canonical)
	return &ValidatedPack{
		Pack:            pack,
		OriginalSHA256:  hex.EncodeToString(original[:]),
		CanonicalJSON:   canonical,
		CanonicalSHA256: hex.EncodeToString(canonicalHash[:]),
		ValidatorPolicy: policy.Version,
	}, nil
}

func parseDocument(ctx context.Context, data []byte) (*yaml.Node, locations, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		line, column := yamlErrorPosition(err)
		return nil, nil, &ValidationError{Diagnostics: []Diagnostic{{
			Code: "YAML_SYNTAX", Path: "$", Line: line, Column: column, Message: fmt.Sprintf("YAML parsing failed: %q", boundedText(err.Error(), 1024)),
		}}}
	}
	if len(document.Content) != 1 {
		return nil, nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "EMPTY_DOCUMENT", Path: "$", Message: "incident pack must contain one non-empty YAML document"}}}
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "MULTIPLE_DOCUMENTS", Path: "$", Line: extra.Line, Column: extra.Column, Message: "exactly one YAML document is allowed"}}}
		}
		line, column := yamlErrorPosition(err)
		return nil, nil, &ValidationError{Diagnostics: []Diagnostic{{Code: "YAML_SYNTAX", Path: "$", Line: line, Column: column, Message: fmt.Sprintf("trailing YAML parsing failed: %q", boundedText(err.Error(), 1024))}}}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	root := document.Content[0]
	loc := locations{"$": {line: root.Line, column: root.Column}}
	var ds diagnosticSet
	stats := astStats{}
	inspectAST(ctx, root, "$", 1, loc, &stats, &ds)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := ds.err(); err != nil {
		return nil, nil, err
	}
	return root, loc, nil
}

type astStats struct {
	nodes      int
	mapEntries int
	seqEntries int
	exhausted  bool
}

func inspectAST(ctx context.Context, node *yaml.Node, path string, depth int, loc locations, stats *astStats, ds *diagnosticSet) {
	if node == nil || stats.exhausted || len(ds.items) >= maxDiagnostics {
		if len(ds.items) >= maxDiagnostics {
			ds.truncated = true
		}
		return
	}
	if stats.nodes&255 == 0 && ctx.Err() != nil {
		return
	}
	stats.nodes++
	if stats.nodes > MaxYAMLNodes {
		ds.add("NODE_LIMIT", path, node.Line, node.Column, "YAML node count exceeds %d", MaxYAMLNodes)
		stats.exhausted = true
		return
	}
	if depth > MaxYAMLDepth {
		ds.add("DEPTH_LIMIT", path, node.Line, node.Column, "YAML nesting depth exceeds %d", MaxYAMLDepth)
		return
	}
	loc[path] = position{line: node.Line, column: node.Column}
	if node.Anchor != "" {
		ds.add("ANCHOR_FORBIDDEN", path, node.Line, node.Column, "YAML anchors are forbidden")
	}
	if node.Kind == yaml.AliasNode {
		ds.add("ALIAS_FORBIDDEN", path, node.Line, node.Column, "YAML aliases are forbidden")
		return
	}
	if !standardYAMLTag(node.Tag) {
		ds.add("CUSTOM_TAG_FORBIDDEN", path, node.Line, node.Column, "custom YAML tag %q is forbidden", node.Tag)
	}
	if node.Tag == "!!timestamp" {
		ds.add("IMPLICIT_TIMESTAMP", path, node.Line, node.Column, "timestamps must be quoted strings and parsed explicitly")
	}
	if node.Tag == "!!float" {
		ds.add("FLOAT_FORBIDDEN", path, node.Line, node.Column, "floating-point YAML values, including NaN and infinity, are forbidden")
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > MaxScalarBytes {
		ds.add("SCALAR_LIMIT", path, node.Line, node.Column, "scalar exceeds %d bytes", MaxScalarBytes)
	}

	switch node.Kind {
	case yaml.MappingNode:
		entries := len(node.Content) / 2
		stats.mapEntries += entries
		if stats.mapEntries > MaxMapEntries {
			ds.add("MAPPING_LIMIT", path, node.Line, node.Column, "mapping entry count exceeds %d", MaxMapEntries)
			stats.exhausted = true
			return
		}
		seen := make(map[string]position, entries)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			keyPath := fmt.Sprintf("%s.<key:%d>", path, i/2)
			inspectAST(ctx, key, keyPath, depth+1, loc, stats, ds)
			if key.Value == "<<" || key.Tag == "!!merge" {
				ds.add("MERGE_KEY_FORBIDDEN", keyPath, key.Line, key.Column, "YAML merge keys are forbidden")
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				ds.add("NON_STRING_KEY", path, key.Line, key.Column, "mapping keys must be strings")
				inspectAST(ctx, value, keyPath+".value", depth+1, loc, stats, ds)
				continue
			}
			childPath := joinPath(path, key.Value)
			loc[childPath] = position{line: value.Line, column: value.Column}
			if first, ok := seen[key.Value]; ok {
				ds.add("DUPLICATE_KEY", childPath, key.Line, key.Column, "duplicate key %q; first declared at line %d column %d", key.Value, first.line, first.column)
			} else {
				seen[key.Value] = position{line: key.Line, column: key.Column}
			}
			inspectAST(ctx, value, childPath, depth+1, loc, stats, ds)
		}
	case yaml.SequenceNode:
		stats.seqEntries += len(node.Content)
		if stats.seqEntries > MaxSeqEntries {
			ds.add("SEQUENCE_LIMIT", path, node.Line, node.Column, "sequence entry count exceeds %d", MaxSeqEntries)
			stats.exhausted = true
			return
		}
		for i, child := range node.Content {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			loc[childPath] = position{line: child.Line, column: child.Column}
			inspectAST(ctx, child, childPath, depth+1, loc, stats, ds)
		}
	}
}

func standardYAMLTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool", "!!null", "!!timestamp", "!!float", "!!merge":
		return true
	default:
		return false
	}
}

func validateShape(ctx context.Context, node *yaml.Node, typ reflect.Type, path string, loc locations, ds *diagnosticSet) {
	if node == nil || ctx.Err() != nil || len(ds.items) >= maxDiagnostics {
		if len(ds.items) >= maxDiagnostics {
			ds.truncated = true
		}
		return
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			shapeMismatch(node, path, "mapping", ds)
			return
		}
		fields := yamlFields(typ)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				continue
			}
			childPath := joinPath(path, key.Value)
			fieldType, ok := fields[key.Value]
			if !ok {
				ds.add("UNKNOWN_FIELD", childPath, key.Line, key.Column, "unknown field %q", key.Value)
				continue
			}
			validateShape(ctx, value, fieldType, childPath, loc, ds)
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			shapeMismatch(node, path, "sequence", ds)
			return
		}
		for i, child := range node.Content {
			validateShape(ctx, child, typ.Elem(), fmt.Sprintf("%s[%d]", path, i), loc, ds)
		}
	case reflect.String:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
			shapeMismatch(node, path, "string", ds)
		}
	case reflect.Bool:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			shapeMismatch(node, path, "boolean", ds)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
			shapeMismatch(node, path, "integer", ds)
		}
	default:
		ds.add("INTERNAL_SCHEMA", path, node.Line, node.Column, "unsupported validator field kind %s", typ.Kind())
	}
}

func yamlFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if name == "" {
			name = field.Name
		}
		if name != "-" {
			fields[name] = field.Type
		}
	}
	return fields
}

func shapeMismatch(node *yaml.Node, path, expected string, ds *diagnosticSet) {
	ds.add("TYPE_MISMATCH", path, node.Line, node.Column, "expected %s, found YAML %s", expected, yamlKind(node))
}

func yamlKind(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.ScalarNode:
		return strings.TrimPrefix(node.Tag, "!!")
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

func joinPath(parent, key string) string {
	if simplePathKey(key) {
		if parent == "$" {
			return "$." + key
		}
		return parent + "." + key
	}
	if len(key) > 128 {
		key = key[:128] + "..."
	}
	return parent + "[" + strconv.Quote(key) + "]"
}

func simplePathKey(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func boundedText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func yamlErrorPosition(err error) (int, int) {
	match := yamlErrorLine.FindStringSubmatch(err.Error())
	if len(match) < 2 {
		return 0, 0
	}
	line, _ := strconv.Atoi(match[1])
	column := 1
	if len(match) > 2 && match[2] != "" {
		column, _ = strconv.Atoi(match[2])
	}
	return line, column
}
