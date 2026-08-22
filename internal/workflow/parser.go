// Package workflow parses historical GitHub workflow and Action metadata as
// bounded hostile data. It never evaluates expressions or executes content.
package workflow

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type Limits struct {
	MaxBytes           int
	MaxNodes           int
	MaxDepth           int
	MaxAliases         int
	MaxAliasBytes      int
	MaxScalarBytes     int
	MaxExpressionBytes int
}

func DefaultLimits() Limits {
	return Limits{MaxBytes: 4 << 20, MaxNodes: 200_000, MaxDepth: 64, MaxAliases: 100, MaxAliasBytes: 4 << 20, MaxScalarBytes: 1 << 20, MaxExpressionBytes: 64 << 10}
}

type Diagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
}

type SourceSpan struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type ReferenceKind string

const (
	ReferenceRepository       ReferenceKind = "repository-action"
	ReferenceReusableWorkflow ReferenceKind = "reusable-workflow"
	ReferenceLocalWorkspace   ReferenceKind = "local-workspace"
	ReferenceSelfRepository   ReferenceKind = "self-repository"
	ReferenceDocker           ReferenceKind = "docker"
	ReferenceDynamic          ReferenceKind = "dynamic"
)

type Reference struct {
	Kind       ReferenceKind `json:"kind"`
	Raw        string        `json:"raw"`
	Owner      string        `json:"owner,omitempty"`
	Repository string        `json:"repository,omitempty"`
	Subpath    string        `json:"subpath,omitempty"`
	Ref        string        `json:"ref,omitempty"`
	Span       SourceSpan    `json:"span"`
}

// SecretReferenceScope records where an expression occurs without asserting
// that GitHub supplied a non-empty value or that a process read it. In
// particular, a reference in one step is not a job-wide reference and cannot
// be attributed to a sibling step.
type SecretReferenceScope string

const (
	SecretReferenceWorkflowField       SecretReferenceScope = "workflow-field"
	SecretReferenceWorkflowEnvironment SecretReferenceScope = "workflow-environment"
	SecretReferenceJobField            SecretReferenceScope = "job-field"
	SecretReferenceJobEnvironment      SecretReferenceScope = "job-environment"
	SecretReferenceStepField           SecretReferenceScope = "step-field"
	SecretReferenceStepEnvironment     SecretReferenceScope = "step-environment"
	SecretReferenceStepInput           SecretReferenceScope = "step-input"
	SecretReferenceStepCommand         SecretReferenceScope = "step-command"
)

type SecretReference struct {
	Name        string               `json:"name"`
	Destination string               `json:"destination"`
	Scope       SecretReferenceScope `json:"scope"`
	Span        SourceSpan           `json:"span"`
}

type SecretMapping struct {
	TargetName string     `json:"targetName"`
	SourceName string     `json:"sourceName,omitempty"`
	Dynamic    bool       `json:"dynamic,omitempty"`
	Span       SourceSpan `json:"span"`
}

type Step struct {
	Ordinal    int               `json:"ordinal"`
	ID         string            `json:"id,omitempty"`
	Name       string            `json:"name,omitempty"`
	Uses       *Reference        `json:"uses,omitempty"`
	Condition  string            `json:"condition,omitempty"`
	SecretRefs []SecretReference `json:"secretRefs,omitempty"`
	Span       SourceSpan        `json:"span"`
}

type Job struct {
	ID             string            `json:"id"`
	Name           string            `json:"name,omitempty"`
	Uses           *Reference        `json:"uses,omitempty"`
	Steps          []Step            `json:"steps,omitempty"`
	Permissions    map[string]string `json:"permissions,omitempty"`
	Environment    string            `json:"environment,omitempty"`
	SecretsInherit bool              `json:"secretsInherit,omitempty"`
	SecretMappings []SecretMapping   `json:"secretMappings,omitempty"`
	// SecretRefs contains only job-level fields. Step references and reusable
	// workflow secret mappings are retained on Steps and SecretMappings.
	SecretRefs []SecretReference `json:"secretRefs,omitempty"`
	Span       SourceSpan        `json:"span"`
}

type Workflow struct {
	Name        string            `json:"name,omitempty"`
	Triggers    []string          `json:"triggers,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Jobs        []Job             `json:"jobs"`
	// SecretRefs contains only workflow-level fields outside jobs.
	SecretRefs []SecretReference `json:"secretRefs,omitempty"`
}

type ActionMetadata struct {
	Name   string            `json:"name,omitempty"`
	Using  string            `json:"using"`
	Main   string            `json:"main,omitempty"`
	Pre    string            `json:"pre,omitempty"`
	Post   string            `json:"post,omitempty"`
	Image  string            `json:"image,omitempty"`
	Steps  []Step            `json:"steps,omitempty"`
	Inputs map[string]string `json:"inputs,omitempty"`
	IsLeaf bool              `json:"isLeaf"`
}

var (
	expressionPattern  = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	secretDotPattern   = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
	secretIndexPattern = regexp.MustCompile(`(?i)secrets\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\]`)
)

func ParseWorkflow(data []byte, limits Limits) (*Workflow, []Diagnostic, error) {
	root, diagnostics, err := parseDocument(data, limits)
	if err != nil {
		return nil, diagnostics, err
	}
	root = dereference(root)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, diagnostics, errors.New("workflow document must be a mapping")
	}
	workflow := &Workflow{}
	workflow.Name = scalar(mappingValue(root, "name"))
	workflow.Permissions = parsePermissions(mappingValue(root, "permissions"))
	workflow.Triggers = parseTriggers(mappingValue(root, "on"))
	workflow.SecretRefs = collectWorkflowSecrets(root)
	jobsNode := dereference(mappingValue(root, "jobs"))
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		return nil, diagnostics, errors.New("workflow jobs must be a mapping")
	}
	for i := 0; i < len(jobsNode.Content); i += 2 {
		jobKey, jobSource := jobsNode.Content[i], jobsNode.Content[i+1]
		jobNode := dereference(jobSource)
		if jobNode == nil {
			diagnostics = append(diagnostics, diagnostic("MALFORMED_JOB", jobSource, "jobs."+jobKey.Value, "job alias could not be resolved"))
			continue
		}
		if jobNode.Kind != yaml.MappingNode {
			diagnostics = append(diagnostics, diagnostic("MALFORMED_JOB", jobNode, "jobs."+jobKey.Value, "job must be a mapping"))
			continue
		}
		job := Job{ID: jobKey.Value, Name: scalar(mappingValue(jobNode, "name")), Permissions: parsePermissions(mappingValue(jobNode, "permissions")), Span: span(jobSource, "jobs."+jobKey.Value)}
		job.Environment = parseEnvironment(mappingValue(jobNode, "environment"))
		job.SecretRefs = collectJobSecrets(jobNode, "jobs."+jobKey.Value)
		if usesNode := mappingValue(jobNode, "uses"); usesNode != nil {
			if usesValue := dereference(usesNode); usesValue != nil && usesValue.Kind == yaml.ScalarNode {
				ref := parseReference(usesValue.Value, true, span(usesNode, "jobs."+jobKey.Value+".uses"))
				job.Uses = &ref
			}
		}
		parseJobSecrets(jobNode, &job, "jobs."+jobKey.Value+".secrets")
		if stepsNode := mappingValue(jobNode, "steps"); stepsNode != nil {
			stepsNode = dereference(stepsNode)
			if stepsNode == nil {
				diagnostics = append(diagnostics, diagnostic("MALFORMED_STEPS", jobSource, "jobs."+jobKey.Value+".steps", "steps alias could not be resolved"))
				workflow.Jobs = append(workflow.Jobs, job)
				continue
			}
			if stepsNode.Kind != yaml.SequenceNode {
				diagnostics = append(diagnostics, diagnostic("MALFORMED_STEPS", stepsNode, "jobs."+jobKey.Value+".steps", "steps must be a sequence"))
			} else {
				job.Steps = parseSteps(stepsNode, "jobs."+jobKey.Value+".steps")
			}
		}
		workflow.Jobs = append(workflow.Jobs, job)
	}
	sort.Slice(workflow.Jobs, func(i, j int) bool { return workflow.Jobs[i].ID < workflow.Jobs[j].ID })
	return workflow, diagnostics, nil
}

func ParseAction(data []byte, limits Limits) (*ActionMetadata, []Diagnostic, error) {
	root, diagnostics, err := parseDocument(data, limits)
	if err != nil {
		return nil, diagnostics, err
	}
	root = dereference(root)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, diagnostics, errors.New("Action metadata must be a mapping")
	}
	runs := dereference(mappingValue(root, "runs"))
	if runs == nil || runs.Kind != yaml.MappingNode {
		return nil, diagnostics, errors.New("Action metadata runs must be a mapping")
	}
	metadata := &ActionMetadata{Name: scalar(mappingValue(root, "name")), Using: strings.ToLower(scalar(mappingValue(runs, "using"))), Main: scalar(mappingValue(runs, "main")), Pre: scalar(mappingValue(runs, "pre")), Post: scalar(mappingValue(runs, "post")), Image: scalar(mappingValue(runs, "image"))}
	if metadata.Using == "" {
		return nil, diagnostics, errors.New("Action metadata runs.using is required")
	}
	if steps := mappingValue(runs, "steps"); steps != nil {
		steps = dereference(steps)
		if steps == nil {
			return nil, diagnostics, errors.New("Action metadata runs.steps alias could not be resolved")
		}
		if steps.Kind != yaml.SequenceNode {
			diagnostics = append(diagnostics, diagnostic("MALFORMED_STEPS", steps, "runs.steps", "composite steps must be a sequence"))
		} else {
			metadata.Steps = parseSteps(steps, "runs.steps")
		}
	}
	metadata.IsLeaf = metadata.Using != "composite"
	return metadata, diagnostics, nil
}

func parseDocument(data []byte, limits Limits) (*yaml.Node, []Diagnostic, error) {
	if limits.MaxBytes <= 0 || limits.MaxNodes <= 0 || limits.MaxDepth <= 0 || limits.MaxScalarBytes <= 0 {
		return nil, nil, errors.New("invalid workflow parser limits")
	}
	if len(data) == 0 || len(data) > limits.MaxBytes {
		return nil, nil, fmt.Errorf("YAML byte length %d exceeds bounds", len(data))
	}
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return nil, nil, errors.New("YAML must be UTF-8 without BOM")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, fmt.Errorf("decode YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, nil, errors.New("multiple YAML documents are not allowed")
		}
		return nil, nil, fmt.Errorf("decode trailing YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return nil, nil, errors.New("YAML document has no root")
	}
	root := document.Content[0]
	state := validationState{limits: limits, aliases: map[*yaml.Node]bool{}}
	state.walk(root, 1, "$", nil)
	if len(state.diagnostics) > 0 {
		return nil, state.diagnostics, errors.New("workflow YAML failed structural validation")
	}
	return root, nil, nil
}

type validationState struct {
	limits      Limits
	nodes       int
	aliasCount  int
	aliasBytes  int
	aliases     map[*yaml.Node]bool
	diagnostics []Diagnostic
}

func (s *validationState) walk(node *yaml.Node, depth int, pointer string, stack map[*yaml.Node]bool) {
	if node == nil || len(s.diagnostics) > 32 {
		return
	}
	s.nodes++
	if s.nodes > s.limits.MaxNodes {
		s.diagnostics = append(s.diagnostics, diagnostic("YAML_NODE_LIMIT", node, pointer, "node limit exceeded"))
		return
	}
	if depth > s.limits.MaxDepth {
		s.diagnostics = append(s.diagnostics, diagnostic("YAML_DEPTH_LIMIT", node, pointer, "depth limit exceeded"))
		return
	}
	if len(node.Value) > s.limits.MaxScalarBytes {
		s.diagnostics = append(s.diagnostics, diagnostic("YAML_SCALAR_LIMIT", node, pointer, "scalar limit exceeded"))
	}
	if strings.Contains(node.Value, "${{") && len(node.Value) > s.limits.MaxExpressionBytes {
		s.diagnostics = append(s.diagnostics, diagnostic("EXPRESSION_SIZE_LIMIT", node, pointer, "expression limit exceeded"))
	}
	if strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		s.diagnostics = append(s.diagnostics, diagnostic("CUSTOM_YAML_TAG", node, pointer, "custom YAML tags are unsupported"))
	}
	if node.Kind == yaml.AliasNode {
		s.aliasCount++
		if s.aliasCount > s.limits.MaxAliases || node.Alias == nil {
			s.diagnostics = append(s.diagnostics, diagnostic("YAML_ALIAS_LIMIT", node, pointer, "alias limit exceeded or target missing"))
			return
		}
		if stack == nil {
			stack = map[*yaml.Node]bool{}
		}
		if stack[node.Alias] {
			s.diagnostics = append(s.diagnostics, diagnostic("YAML_ALIAS_CYCLE", node, pointer, "alias cycle"))
			return
		}
		s.aliasBytes += estimateNodeBytes(node.Alias, map[*yaml.Node]bool{})
		if s.aliasBytes > s.limits.MaxAliasBytes {
			s.diagnostics = append(s.diagnostics, diagnostic("YAML_ALIAS_EXPANSION_LIMIT", node, pointer, "alias expansion limit exceeded"))
			return
		}
		copyStack := make(map[*yaml.Node]bool, len(stack)+1)
		for key, value := range stack {
			copyStack[key] = value
		}
		copyStack[node.Alias] = true
		s.walk(node.Alias, depth+1, pointer+".@alias", copyStack)
		return
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				s.diagnostics = append(s.diagnostics, diagnostic("NON_STRING_YAML_KEY", key, pointer, "mapping key must be a string"))
				continue
			}
			if key.Value == "<<" || key.Tag == "!!merge" {
				s.diagnostics = append(s.diagnostics, diagnostic("YAML_MERGE_KEY", key, pointer, "merge keys are unsupported"))
			}
			if seen[key.Value] {
				s.diagnostics = append(s.diagnostics, diagnostic("DUPLICATE_YAML_KEY", key, pointer+"."+key.Value, "duplicate mapping key"))
			}
			seen[key.Value] = true
			s.walk(node.Content[i+1], depth+1, pointer+"."+key.Value, stack)
		}
		return
	}
	for i, child := range node.Content {
		s.walk(child, depth+1, fmt.Sprintf("%s[%d]", pointer, i), stack)
	}
}

func estimateNodeBytes(node *yaml.Node, seen map[*yaml.Node]bool) int {
	if node == nil || seen[node] {
		return 0
	}
	seen[node] = true
	total := len(node.Value)
	for _, child := range node.Content {
		total += estimateNodeBytes(child, seen)
	}
	return total
}

// dereference returns the semantic YAML node represented by an alias while
// leaving callers free to retain the alias node's source location. Structural
// validation has already bounded expansion and rejected cycles, but the local
// cycle guard keeps this helper fail-closed if it is ever used independently.
func dereference(node *yaml.Node) *yaml.Node {
	seen := map[*yaml.Node]bool{}
	for node != nil && node.Kind == yaml.AliasNode {
		if node.Alias == nil || seen[node] {
			return nil
		}
		seen[node] = true
		node = node.Alias
	}
	return node
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	mapping = dereference(mapping)
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func scalar(node *yaml.Node) string {
	node = dereference(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func parseTriggers(node *yaml.Node) []string {
	node = dereference(node)
	if node == nil {
		return nil
	}
	var result []string
	switch node.Kind {
	case yaml.ScalarNode:
		result = append(result, node.Value)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			child = dereference(child)
			if child == nil {
				continue
			}
			if child.Kind == yaml.ScalarNode {
				result = append(result, child.Value)
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			result = append(result, node.Content[i].Value)
		}
	}
	sort.Strings(result)
	return dedupe(result)
}

func parsePermissions(node *yaml.Node) map[string]string {
	node = dereference(node)
	if node == nil {
		return nil
	}
	result := map[string]string{}
	if node.Kind == yaml.ScalarNode {
		result["*"] = strings.ToLower(node.Value)
		return result
	}
	if node.Kind != yaml.MappingNode {
		return result
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		result[strings.ToLower(node.Content[i].Value)] = strings.ToLower(scalar(node.Content[i+1]))
	}
	return result
}

func parseEnvironment(node *yaml.Node) string {
	node = dereference(node)
	if node == nil {
		return ""
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	return scalar(mappingValue(node, "name"))
}

func parseJobSecrets(node *yaml.Node, job *Job, pointer string) {
	secrets := mappingValue(node, "secrets")
	if secrets == nil {
		return
	}
	secrets = dereference(secrets)
	if secrets == nil {
		return
	}
	if secrets.Kind == yaml.ScalarNode && strings.EqualFold(secrets.Value, "inherit") {
		job.SecretsInherit = true
		return
	}
	if secrets.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(secrets.Content); i += 2 {
		target, value := secrets.Content[i], secrets.Content[i+1]
		names := secretNames(scalar(value))
		mapping := SecretMapping{TargetName: strings.ToUpper(target.Value), Dynamic: len(names) != 1, Span: span(value, pointer+"."+target.Value)}
		if len(names) == 1 {
			mapping.SourceName = names[0]
		}
		job.SecretMappings = append(job.SecretMappings, mapping)
	}
}

func parseSteps(node *yaml.Node, pointer string) []Step {
	node = dereference(node)
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var steps []Step
	for ordinal, childSource := range node.Content {
		child := dereference(childSource)
		if child == nil {
			continue
		}
		if child.Kind != yaml.MappingNode {
			continue
		}
		stepPointer := fmt.Sprintf("%s[%d]", pointer, ordinal)
		step := Step{Ordinal: ordinal + 1, ID: scalar(mappingValue(child, "id")), Name: scalar(mappingValue(child, "name")), Condition: scalar(mappingValue(child, "if")), SecretRefs: collectStepSecrets(child, stepPointer), Span: span(childSource, stepPointer)}
		if uses := mappingValue(child, "uses"); uses != nil {
			if usesValue := dereference(uses); usesValue != nil && usesValue.Kind == yaml.ScalarNode {
				ref := parseReference(usesValue.Value, false, span(uses, stepPointer+".uses"))
				step.Uses = &ref
			}
		}
		steps = append(steps, step)
	}
	return steps
}

func parseReference(value string, reusable bool, location SourceSpan) Reference {
	ref := Reference{Raw: value, Span: location}
	if strings.Contains(value, "${{") {
		ref.Kind = ReferenceDynamic
		return ref
	}
	if strings.HasPrefix(value, "docker://") {
		ref.Kind = ReferenceDocker
		ref.Subpath = strings.TrimPrefix(value, "docker://")
		return ref
	}
	if strings.HasPrefix(value, "./") {
		ref.Kind = ReferenceLocalWorkspace
		ref.Subpath = strings.TrimPrefix(value, "./")
		return ref
	}
	if strings.HasPrefix(value, "$/") && !strings.Contains(value, "@") {
		ref.Kind = ReferenceSelfRepository
		ref.Subpath = strings.TrimPrefix(value, "$/")
		return ref
	}
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		ref.Kind = ReferenceDynamic
		return ref
	}
	segments := strings.Split(value[:at], "/")
	if len(segments) < 2 {
		ref.Kind = ReferenceDynamic
		return ref
	}
	ref.Owner, ref.Repository, ref.Ref = strings.ToLower(segments[0]), strings.ToLower(segments[1]), value[at+1:]
	if len(segments) > 2 {
		ref.Subpath = strings.Join(segments[2:], "/")
	}
	if reusable || strings.HasPrefix(ref.Subpath, ".github/workflows/") {
		ref.Kind = ReferenceReusableWorkflow
	} else {
		ref.Kind = ReferenceRepository
	}
	return ref
}

func collectWorkflowSecrets(node *yaml.Node) []SecretReference {
	return collectMappingSecrets(node, "workflow", map[string]bool{"jobs": true}, func(key string) SecretReferenceScope {
		if key == "env" {
			return SecretReferenceWorkflowEnvironment
		}
		return SecretReferenceWorkflowField
	})
}

func collectJobSecrets(node *yaml.Node, pointer string) []SecretReference {
	// Steps and reusable-workflow secret mappings have their own models. Do not
	// fold either into job-level references.
	return collectMappingSecrets(node, pointer, map[string]bool{"steps": true, "secrets": true}, func(key string) SecretReferenceScope {
		if key == "env" {
			return SecretReferenceJobEnvironment
		}
		return SecretReferenceJobField
	})
}

func collectStepSecrets(node *yaml.Node, pointer string) []SecretReference {
	return collectMappingSecrets(node, pointer, nil, func(key string) SecretReferenceScope {
		switch key {
		case "env":
			return SecretReferenceStepEnvironment
		case "with":
			return SecretReferenceStepInput
		case "run":
			return SecretReferenceStepCommand
		default:
			return SecretReferenceStepField
		}
	})
}

func collectMappingSecrets(node *yaml.Node, pointer string, excluded map[string]bool, scopeFor func(string) SecretReferenceScope) []SecretReference {
	var result []SecretReference
	node = dereference(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if excluded[key.Value] {
			continue
		}
		destination := pointer + "." + key.Value
		result = append(result, collectSecrets(value, destination, scopeFor(key.Value))...)
	}
	return sortSecretReferences(result)
}

func collectSecrets(node *yaml.Node, destination string, scope SecretReferenceScope) []SecretReference {
	var result []SecretReference
	var walk func(*yaml.Node, string)
	walk = func(current *yaml.Node, pointer string) {
		current = dereference(current)
		if current == nil {
			return
		}
		switch current.Kind {
		case yaml.ScalarNode:
			for _, name := range secretNames(current.Value) {
				result = append(result, SecretReference{Name: name, Destination: destination, Scope: scope, Span: span(current, pointer)})
			}
		case yaml.MappingNode:
			// Mapping keys are syntax, not expression-bearing values. Visiting only
			// values also prevents a hostile key that resembles secrets.NAME from
			// becoming a false reference.
			for i := 0; i+1 < len(current.Content); i += 2 {
				key, value := current.Content[i], current.Content[i+1]
				walk(value, pointer+"."+key.Value)
			}
		case yaml.SequenceNode:
			for i, child := range current.Content {
				walk(child, fmt.Sprintf("%s[%d]", pointer, i))
			}
		}
	}
	walk(node, destination)
	return sortSecretReferences(result)
}

func sortSecretReferences(result []SecretReference) []SecretReference {
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Scope != result[j].Scope {
			return result[i].Scope < result[j].Scope
		}
		return result[i].Span.Path < result[j].Span.Path
	})
	unique := result[:0]
	for _, item := range result {
		if len(unique) == 0 || item.Name != unique[len(unique)-1].Name || item.Scope != unique[len(unique)-1].Scope || item.Span.Path != unique[len(unique)-1].Span.Path {
			unique = append(unique, item)
		}
	}
	return unique
}

func secretNames(value string) []string {
	var result []string
	// A plain string containing "secrets.NAME" is not a GitHub expression and
	// therefore is not evidence that the workflow requested a secret.
	for _, expression := range expressionPattern.FindAllStringSubmatch(value, -1) {
		for _, match := range secretDotPattern.FindAllStringSubmatch(expression[1], -1) {
			result = append(result, strings.ToUpper(match[1]))
		}
		for _, match := range secretIndexPattern.FindAllStringSubmatch(expression[1], -1) {
			result = append(result, strings.ToUpper(match[1]))
		}
	}
	sort.Strings(result)
	return dedupe(result)
}

func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func span(node *yaml.Node, pointer string) SourceSpan {
	return SourceSpan{Path: pointer, Line: node.Line, Column: node.Column}
}
func diagnostic(code string, node *yaml.Node, pointer, message string) Diagnostic {
	return Diagnostic{Code: code, Path: pointer, Line: node.Line, Column: node.Column, Message: message}
}

// NormalizeRepositoryPath validates a parsed repository-relative path before
// it is used in a GitHub content route. It is never used as a local path.
func NormalizeRepositoryPath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") || strings.Contains(strings.ToLower(value), "%2e") {
		return "", errors.New("unsafe repository path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return "", errors.New("non-canonical repository path")
	}
	return clean, nil
}
