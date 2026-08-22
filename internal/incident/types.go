// Package incident validates and canonicalizes declarative CIRewind incident
// packs. It has no network, process, template, or filesystem side effects.
package incident

import "github.com/torjan0/cirewind/internal/model"

const (
	APIVersion     = "cirewind.dev/v1alpha1"
	Kind           = "GitHubActionsIncident"
	PolicyVersion  = "incident-validator-v1alpha1.1"
	MaxPackBytes   = 2 << 20
	MaxYAMLNodes   = 20_000
	MaxYAMLDepth   = 32
	MaxMapEntries  = 5_000
	MaxSeqEntries  = 5_000
	MaxScalarBytes = 64 << 10
)

type Pack struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	ID          string   `json:"id" yaml:"id"`
	PackVersion string   `json:"packVersion" yaml:"packVersion"`
	Title       string   `json:"title" yaml:"title"`
	PublishedAt string   `json:"publishedAt" yaml:"publishedAt"`
	UpdatedAt   string   `json:"updatedAt" yaml:"updatedAt"`
	Labels      []string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Sources     []Source `json:"sources" yaml:"sources"`
}

type Source struct {
	ID             string `json:"id" yaml:"id"`
	Type           string `json:"type" yaml:"type"`
	Title          string `json:"title" yaml:"title"`
	Publisher      string `json:"publisher" yaml:"publisher"`
	URL            string `json:"url" yaml:"url"`
	PublishedAt    string `json:"publishedAt,omitempty" yaml:"publishedAt,omitempty"`
	RetrievedAt    string `json:"retrievedAt" yaml:"retrievedAt"`
	SourceRevision string `json:"sourceRevision,omitempty" yaml:"sourceRevision,omitempty"`
	SourceSHA256   string `json:"sourceSha256,omitempty" yaml:"sourceSha256,omitempty"`
	TimePrecision  string `json:"timePrecision,omitempty" yaml:"timePrecision,omitempty"`
	Notes          string `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type Spec struct {
	Description string       `json:"description" yaml:"description"`
	Components  []Component  `json:"components" yaml:"components"`
	Windows     []Window     `json:"windows,omitempty" yaml:"windows,omitempty"`
	Indicators  []Indicator  `json:"indicators" yaml:"indicators"`
	KnownGood   []KnownGood  `json:"knownGood,omitempty" yaml:"knownGood,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

type Component struct {
	ID            string     `json:"id" yaml:"id"`
	Type          string     `json:"type" yaml:"type"`
	Repository    Repository `json:"repository" yaml:"repository"`
	Subpaths      []string   `json:"subpaths,omitempty" yaml:"subpaths,omitempty"`
	WorkflowPaths []string   `json:"workflowPaths,omitempty" yaml:"workflowPaths,omitempty"`
}

type Repository struct {
	Owner string `json:"owner" yaml:"owner"`
	Name  string `json:"name" yaml:"name"`
	ID    *int64 `json:"id,omitempty" yaml:"id,omitempty"`
}

type Window struct {
	ID              string   `json:"id" yaml:"id"`
	Start           string   `json:"start,omitempty" yaml:"start,omitempty"`
	End             string   `json:"end,omitempty" yaml:"end,omitempty"`
	Bounds          string   `json:"bounds" yaml:"bounds"`
	SourcePrecision string   `json:"sourcePrecision" yaml:"sourcePrecision"`
	Approximation   string   `json:"approximation" yaml:"approximation"`
	OriginalClaim   string   `json:"originalClaim,omitempty" yaml:"originalClaim,omitempty"`
	SourceRefs      []string `json:"sourceRefs" yaml:"sourceRefs"`
	Notes           string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type Indicator struct {
	ID          string                `json:"id" yaml:"id"`
	ComponentID string                `json:"componentId" yaml:"componentId"`
	Kind        string                `json:"kind" yaml:"kind"`
	Value       IndicatorValue        `json:"value" yaml:"value"`
	WindowRefs  []string              `json:"windowRefs,omitempty" yaml:"windowRefs,omitempty"`
	Confidence  model.ProvenanceLevel `json:"confidence" yaml:"confidence"`
	SourceRefs  []string              `json:"sourceRefs" yaml:"sourceRefs"`
	Notes       string                `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// IndicatorValue is a closed union. Validation permits only the fields for the
// enclosing indicator kind; irrelevant fields are rejected.
type IndicatorValue struct {
	GitObject     *GitObject `json:"gitObject,omitempty" yaml:"gitObject,omitempty"`
	Ref           string     `json:"ref,omitempty" yaml:"ref,omitempty"`
	Path          string     `json:"path,omitempty" yaml:"path,omitempty"`
	Subject       string     `json:"subject,omitempty" yaml:"subject,omitempty"`
	Algorithm     string     `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Digest        string     `json:"digest,omitempty" yaml:"digest,omitempty"`
	Platform      string     `json:"platform,omitempty" yaml:"platform,omitempty"`
	Literal       string     `json:"literal,omitempty" yaml:"literal,omitempty"`
	CaseSensitive *bool      `json:"caseSensitive,omitempty" yaml:"caseSensitive,omitempty"`
	Scope         string     `json:"scope,omitempty" yaml:"scope,omitempty"`
	Domain        string     `json:"domain,omitempty" yaml:"domain,omitempty"`
	Match         string     `json:"match,omitempty" yaml:"match,omitempty"`
	Address       string     `json:"address,omitempty" yaml:"address,omitempty"`
	Owner         string     `json:"owner,omitempty" yaml:"owner,omitempty"`
	Name          string     `json:"name,omitempty" yaml:"name,omitempty"`
	Version       string     `json:"version,omitempty" yaml:"version,omitempty"`
}

type GitObject struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Value     string `json:"value" yaml:"value"`
}

type KnownGood struct {
	ID          string                `json:"id" yaml:"id"`
	ComponentID string                `json:"componentId" yaml:"componentId"`
	Kind        string                `json:"kind" yaml:"kind"`
	Value       IndicatorValue        `json:"value" yaml:"value"`
	Confidence  model.ProvenanceLevel `json:"confidence" yaml:"confidence"`
	SourceRefs  []string              `json:"sourceRefs" yaml:"sourceRefs"`
	Notes       string                `json:"notes,omitempty" yaml:"notes,omitempty"`
}

type Remediation struct {
	Guidance                   []string          `json:"guidance" yaml:"guidance"`
	CredentialRotationTriggers []RotationTrigger `json:"credentialRotationTriggers,omitempty" yaml:"credentialRotationTriggers,omitempty"`
}

type RotationTrigger struct {
	ID         string                `json:"id" yaml:"id"`
	WhenStates []model.FindingState  `json:"whenStates" yaml:"whenStates"`
	Guidance   string                `json:"guidance" yaml:"guidance"`
	Confidence model.ProvenanceLevel `json:"confidence" yaml:"confidence"`
	SourceRefs []string              `json:"sourceRefs" yaml:"sourceRefs"`
}

type ValidatedPack struct {
	Pack            Pack
	OriginalSHA256  string
	CanonicalJSON   []byte
	CanonicalSHA256 string
	ValidatorPolicy string
}
