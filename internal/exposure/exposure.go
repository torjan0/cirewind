// Package exposure derives conservative credential, runner, and downstream
// resource propositions. It never retrieves or represents secret values.
package exposure

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Basis string

const (
	BasisRuntimeObserved Basis = "runtime-observed"
	BasisStaticInferred  Basis = "static-inferred"
)

type Permission struct {
	Name        string
	Access      string
	Basis       Basis
	EvidenceIDs []string
}

type SecretFlowKind string

const (
	SecretExistsMetadata      SecretFlowKind = "SECRET_EXISTS_METADATA"
	SecretReferencedByJob     SecretFlowKind = "SECRET_REFERENCED_BY_JOB"
	SecretPassedToStep        SecretFlowKind = "SECRET_PASSED_TO_STEP"
	ReusableSecretMapped      SecretFlowKind = "REUSABLE_SECRET_MAPPED"
	ReusableSecretInherited   SecretFlowKind = "REUSABLE_SECRET_INHERITED"
	EnvironmentSecretEligible SecretFlowKind = "ENVIRONMENT_SECRET_ELIGIBLE"
)

type SecretFlow struct {
	Name            string
	Kind            SecretFlowKind
	DestinationStep string
	CallHop         int
	EvidenceIDs     []string
}

type EnvironmentGate struct {
	Name        string
	Targeted    bool
	Crossed     bool
	JobStarted  bool
	EvidenceIDs []string
}

type Runner struct {
	Classification string
	ID             int64
	Name           string
	Group          string
	Labels         []string
	EvidenceIDs    []string
}

type Interval struct {
	Start time.Time
	End   time.Time
}

type SynchronizationEdge struct {
	FromStep    string
	ToStep      string
	EvidenceIDs []string
}

type Resource struct {
	Kind          string
	Name          string
	EventTime     time.Time
	DirectRun     bool
	DirectJob     bool
	DirectStepKey string
	EvidenceIDs   []string
}

type Input struct {
	AffectedStepKey          string
	AffectedLifecycleStarted bool
	JobStarted               bool
	Permissions              []Permission
	SecretFlows              []SecretFlow
	Environment              EnvironmentGate
	Runner                   Runner
	AffectedInterval         Interval
	StepIntervals            map[string]Interval
	Synchronization          []SynchronizationEdge
	Resources                []Resource
}

type Fact struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name,omitempty"`
	Capability  string   `json:"capability,omitempty"`
	Basis       string   `json:"basis"`
	Conclusion  string   `json:"conclusion"`
	EvidenceIDs []string `json:"evidenceIds"`
}

type Result struct {
	Credentials []Fact `json:"credentials,omitempty"`
	Resources   []Fact `json:"resources,omitempty"`
}

func Analyze(input Input) Result {
	var result Result
	if input.AffectedLifecycleStarted {
		permissions := effectivePermissions(input.Permissions)
		for _, permission := range permissions {
			result.Credentials = append(result.Credentials, Fact{Kind: "GITHUB_TOKEN", Name: permission.Name, Capability: permission.Access, Basis: string(permission.Basis), Conclusion: fmt.Sprintf("The affected lifecycle could use the job token permission %s: %s; repository activity was not established.", permission.Name, permission.Access), EvidenceIDs: sortedUnique(permission.EvidenceIDs)})
			if permission.Name == "id-token" && permission.Access == "write" {
				result.Credentials = append(result.Credentials, Fact{Kind: "OIDC_MINTING_CAPABILITY", Capability: "id-token: write", Basis: string(permission.Basis), Conclusion: "The affected lifecycle could request a GitHub OIDC token; no token request, relying-party trust, exchange, cloud identity, or role assumption was established.", EvidenceIDs: sortedUnique(permission.EvidenceIDs)})
			}
		}
	}

	for _, flow := range input.SecretFlows {
		name := strings.ToUpper(flow.Name)
		switch flow.Kind {
		case SecretExistsMetadata:
			// Existence is retained as metadata, never elevated into affected-step exposure.
			continue
		case SecretReferencedByJob:
			// This proposition is context about a job-scoped reference, not a
			// reachability edge. A step-scoped flow must use SecretPassedToStep
			// and identify its destination. Reject a destination here so callers
			// cannot accidentally relabel a sibling-step reference as job-wide.
			if input.JobStarted && input.AffectedLifecycleStarted && flow.DestinationStep == "" {
				result.Credentials = append(result.Credentials, Fact{Kind: string(flow.Kind), Name: name, Basis: "historical-definition-reference", Conclusion: "The started job's historical definition contained a job-scoped reference to this secret name. Retained evidence does not establish that the reference flowed into, or was readable by, the affected step; value availability, use, and exfiltration were not established.", EvidenceIDs: sortedUnique(flow.EvidenceIDs)})
			}
		case SecretPassedToStep:
			if input.AffectedLifecycleStarted && flow.DestinationStep == input.AffectedStepKey {
				result.Credentials = append(result.Credentials, Fact{Kind: string(flow.Kind), Name: name, Basis: "historical-definition-flow", Conclusion: "The exact historical definition passed the named secret reference to the affected step. Retained evidence does not establish a non-empty value, read, use, or exfiltration.", EvidenceIDs: sortedUnique(flow.EvidenceIDs)})
			}
		case ReusableSecretMapped:
			if flow.CallHop == 1 {
				result.Credentials = append(result.Credentials, Fact{Kind: string(flow.Kind), Name: name, Basis: "reusable-workflow-call", Conclusion: "The named secret was mapped to the directly called workflow; this alone does not establish that an affected job or step received or read it.", EvidenceIDs: sortedUnique(flow.EvidenceIDs)})
			}
		case ReusableSecretInherited:
			if flow.CallHop == 1 {
				conclusion := "The caller declared secrets: inherit for one direct call hop; the eligible name set and affected-step access remain unknown."
				if name != "" {
					conclusion = "The named eligible secret was inherited for one direct call hop; an affected-step reference, value, read, use, or exfiltration was not established."
				}
				result.Credentials = append(result.Credentials, Fact{Kind: string(flow.Kind), Name: name, Basis: "reusable-workflow-call", Conclusion: conclusion, EvidenceIDs: sortedUnique(flow.EvidenceIDs)})
			}
		case EnvironmentSecretEligible:
			if input.Environment.Targeted && input.Environment.Crossed && input.Environment.JobStarted && input.AffectedLifecycleStarted && (flow.DestinationStep == "" || flow.DestinationStep == input.AffectedStepKey) {
				evidence := append(append([]string{}, flow.EvidenceIDs...), input.Environment.EvidenceIDs...)
				result.Credentials = append(result.Credentials, Fact{Kind: string(flow.Kind), Name: name, Basis: "environment-gate-and-job-start", Conclusion: "The named environment secret reference became eligible after the environment gate and job start; a value, read, use, or exfiltration was not established.", EvidenceIDs: sortedUnique(evidence)})
			}
		}
	}

	if input.AffectedLifecycleStarted {
		runner := input.Runner
		switch runner.Classification {
		case "self-hosted":
			result.Resources = append(result.Resources, Fact{Kind: "SELF_HOSTED_RUNNER", Name: runner.Name, Basis: "runner-observation", Conclusion: "The affected job used a self-hosted runner; persistence, endpoint compromise, lateral movement, and internal-network reachability were not determined.", EvidenceIDs: sortedUnique(runner.EvidenceIDs)})
		case "github-hosted":
			result.Resources = append(result.Resources, Fact{Kind: "GITHUB_HOSTED_RUNNER", Name: runner.Name, Basis: "runner-observation", Conclusion: "The affected job used a GitHub-hosted runner under the retained runner evidence.", EvidenceIDs: sortedUnique(runner.EvidenceIDs)})
		}
	}

	for _, resource := range input.Resources {
		if !input.AffectedLifecycleStarted {
			continue
		}
		fact := Fact{Kind: strings.ToUpper(resource.Kind), Name: resource.Name, EvidenceIDs: sortedUnique(resource.EvidenceIDs)}
		switch {
		case resource.DirectStepKey != "" && resource.DirectStepKey == input.AffectedStepKey:
			fact.Basis = "direct-step-attribution"
			fact.Conclusion = "The resource was directly attributed to the affected step; malicious intent or attacker control was not established."
		case resource.DirectJob:
			fact.Basis = "direct-job-attribution"
			fact.Conclusion = "The resource was created by the same affected job; malicious intent or causation by the affected Action was not established."
		case resource.DirectRun:
			fact.Basis = "direct-run-attribution"
			fact.Conclusion = "The resource was associated with the affected run; attempt, job, step, malicious intent, and causation were not established."
		case observedAfter(input, resource):
			fact.Basis = "temporal-correlation"
			fact.Conclusion = "The resource was observed after the affected lifecycle; causation and attacker control were not established."
		default:
			continue
		}
		result.Resources = append(result.Resources, fact)
	}
	sortFacts(result.Credentials)
	sortFacts(result.Resources)
	return result
}

func effectivePermissions(input []Permission) []Permission {
	hasRuntime := false
	for _, permission := range input {
		if permission.Basis == BasisRuntimeObserved {
			hasRuntime = true
			break
		}
	}
	byName := map[string]Permission{}
	for _, permission := range input {
		if hasRuntime && permission.Basis != BasisRuntimeObserved {
			continue
		}
		name := strings.ToLower(permission.Name)
		if name == "" {
			continue
		}
		permission.Name = name
		permission.Access = strings.ToLower(permission.Access)
		if previous, ok := byName[name]; ok {
			permission.EvidenceIDs = append(previous.EvidenceIDs, permission.EvidenceIDs...)
		}
		permission.EvidenceIDs = sortedUnique(permission.EvidenceIDs)
		byName[name] = permission
	}
	result := make([]Permission, 0, len(byName))
	for _, permission := range byName {
		result = append(result, permission)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func observedAfter(input Input, resource Resource) bool {
	if resource.EventTime.IsZero() || input.AffectedInterval.End.IsZero() {
		return false
	}
	return resource.EventTime.After(input.AffectedInterval.End) || resource.EventTime.Equal(input.AffectedInterval.End)
}

// HappensBefore returns true only for non-overlapping intervals or an explicit
// synchronization edge. YAML/API ordering alone is deliberately absent.
func HappensBefore(fromStep, toStep string, intervals map[string]Interval, edges []SynchronizationEdge) bool {
	from, fromOK := intervals[fromStep]
	to, toOK := intervals[toStep]
	if fromOK && toOK && !from.End.IsZero() && !to.Start.IsZero() && from.End.Before(to.Start) {
		return true
	}
	for _, edge := range edges {
		if edge.FromStep == fromStep && edge.ToStep == toStep && len(edge.EvidenceIDs) > 0 {
			return true
		}
	}
	return false
}

func sortFacts(facts []Fact) {
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Kind != facts[j].Kind {
			return facts[i].Kind < facts[j].Kind
		}
		if facts[i].Name != facts[j].Name {
			return facts[i].Name < facts[j].Name
		}
		return facts[i].Basis < facts[j].Basis
	})
}
func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}
