// Package report produces deterministic, offline, escaped CIRewind case views.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const (
	FindingsSchema   = "cirewind.findings/v1alpha1"
	MetadataSchema   = "cirewind.collection-metadata/v1alpha1"
	MetadataSchemaV2 = "cirewind.collection-metadata/v1alpha2"
	CaseContractV2   = "cirewind.case/v1alpha2"
	// RetainedLegacyUnclassifiedBasis preserves a legal empty v1 source basis
	// in schema-valid presentation output without assigning an evidence class.
	// The typed graph still omits the corresponding relationship.
	RetainedLegacyUnclassifiedBasis = "legacy-unclassified"
	stylesheet                      = `:root{color-scheme:only light;color:#111827;background:#FFFFFF;font-family:system-ui,sans-serif}*,*::before,*::after{box-sizing:border-box}body{max-width:110rem;margin:auto;padding:1.5rem;line-height:1.45;overflow-wrap:anywhere;color:#111827;background:#FFFFFF}h1,h2{line-height:1.2}:focus-visible{outline:.2rem solid currentColor;outline-offset:.2rem}.warning{border:.2rem solid #b45309;padding:1rem;font-weight:700}.synthetic{border:.2rem solid #005a9c;padding:1rem;font-weight:700}.classification-unknown{border:.2rem solid #5f6368;padding:1rem;font-weight:700}.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.8rem}.count{border:1px solid #888;padding:.8rem}.count strong{display:block;font-size:1.8rem}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #888;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}code{overflow-wrap:anywhere}.state{font-weight:700}.muted{opacity:.8}details{margin:.5rem 0}.graph{display:grid;grid-template-columns:1fr 1fr;gap:1rem}.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.7rem;border:1px solid #888;padding:1rem;margin:1rem 0}.filters label{display:grid;gap:.25rem}.filters select{min-width:0;width:100%;max-width:100%}.filters button{align-self:end;min-height:2.2rem}.empty{padding:.7rem;border:1px dashed #888}.temporal-path{overflow:auto;max-width:100%;max-height:75vh;border:1px solid #334155;background:#fff;padding:.5rem}.temporal-path:focus{outline:.2rem solid #005a9c;outline-offset:-.2rem;box-shadow:inset 0 0 0 .2rem #005a9c}.temporal-path svg{display:block;width:auto;height:auto;min-width:0;max-width:none;background:#fff;forced-color-adjust:none}.path-fallback>section{border-block-start:1px solid #888;padding-block:.7rem}.path-legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.5rem}.path-legend span{border:1px solid #888;padding:.45rem}.path-table{font-size:.82rem}[hidden]{display:none!important}@media(max-width:50rem){.graph{grid-template-columns:1fr}}@media(max-width:20rem){body{padding:.75rem}.counts,.filters,.path-legend{grid-template-columns:minmax(0,1fr)}.filters{padding:.75rem}table{table-layout:fixed}}`
	filterScript                    = `"use strict";(()=>{const controls=[...document.querySelectorAll("[data-filter]")],items=[...document.querySelectorAll("[data-finding-item]")],graphItems=[...document.querySelectorAll("[data-graph-item]")],visibleCount=document.getElementById("visible-count"),visibleLabel=document.getElementById("visible-count-label"),empty=document.getElementById("filter-empty"),visualShown=document.getElementById("visual-shown"),visualShownLabel=document.getElementById("visual-shown-label"),visualOmitted=document.getElementById("visual-omitted"),visualOmittedLabel=document.getElementById("visual-omitted-label"),visualStatus=document.getElementById("filter-visual-status"),noMatchStatus=document.getElementById("filter-no-match-status"),textLink=document.getElementById("temporal-path-text-link"),textDetails=document.getElementById("temporal-path-text"),textSummary=document.getElementById("temporal-path-text-summary");const has=(value,token)=>(" "+(value||"")+" ").includes(" "+token+" "),noun=(count,singular,plural)=>count===1?singular:plural;const matches=item=>controls.every(control=>!control.value||(control.dataset.multi==="true"?has(item.dataset[control.dataset.filter],control.value):item.dataset[control.dataset.filter]===control.value));const apply=()=>{const visible=new Set(),shown=new Set();let count=0;for(const item of items){const show=matches(item);item.toggleAttribute("hidden",!show);if(show){visible.add(item.dataset.revision);if(item.dataset.counted==="true")count++}}for(const item of graphItems){const focus=(item.dataset.findings||"").split(" ").filter(Boolean),show=focus.length===0||focus.some(id=>visible.has(id));item.toggleAttribute("hidden",!show);if(show&&item.dataset.visualLane==="true"&&item.dataset.revision)shown.add(item.dataset.revision)}visibleCount.textContent=String(count);if(visibleLabel)visibleLabel.textContent=noun(count,"finding visible","findings visible");empty.hidden=count!==0;const omitted=Math.max(0,count-shown.size);if(visualShown){visualShown.textContent=String(shown.size);visualOmitted.textContent=String(omitted);if(visualShownLabel)visualShownLabel.textContent=noun(shown.size,"matching finding shown","matching findings shown");if(visualOmittedLabel)visualOmittedLabel.textContent=noun(omitted,"matching finding omitted","matching findings omitted")}if(visualStatus)visualStatus.textContent=" "+String(shown.size)+" "+noun(shown.size,"matching finding shown","matching findings shown")+" in the visual; "+String(omitted)+" "+noun(omitted,"finding omitted","findings omitted")+" from the visual.";if(noMatchStatus)noMatchStatus.textContent=count===0?" No findings match every selected filter.":""};for(const control of controls)control.addEventListener("change",apply);document.getElementById("filter-reset").addEventListener("click",()=>{for(const control of controls)control.value="";apply()});if(textLink&&textDetails&&textSummary)textLink.addEventListener("click",()=>{textDetails.open=true;textSummary.focus()});apply()})();`
)

type CaseKind string

const (
	CaseKindSynthetic CaseKind = "synthetic"
	CaseKindCollected CaseKind = "collected"
	CaseKindMixed     CaseKind = "mixed"
	CaseKindUnknown   CaseKind = "unknown"
)

func (kind CaseKind) Valid() bool {
	return kind == CaseKindSynthetic || kind == CaseKindCollected || kind == CaseKindMixed || kind == CaseKindUnknown
}

type Exposure struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name,omitempty"`
	Capability  string   `json:"capability,omitempty"`
	Basis       string   `json:"basis"`
	Conclusion  string   `json:"conclusion"`
	EvidenceIDs []string `json:"evidenceIds"`
}

type Finding struct {
	FindingID             string     `json:"findingId"`
	FindingRevisionID     string     `json:"findingRevisionId"`
	IncidentID            string     `json:"incidentId"`
	IndicatorID           string     `json:"indicatorId"`
	Repository            string     `json:"repository"`
	Workflow              string     `json:"workflow,omitempty"`
	RunID                 int64      `json:"runId,omitempty"`
	RunAttempt            int        `json:"runAttempt,omitempty"`
	JobID                 int64      `json:"jobId,omitempty"`
	StepIdentity          string     `json:"stepIdentity,omitempty"`
	State                 string     `json:"state"`
	Provenance            string     `json:"provenance"`
	Conclusion            string     `json:"conclusion"`
	EventTime             string     `json:"eventTime,omitempty"`
	EvidenceIDs           []string   `json:"evidenceIds"`
	Assumptions           []string   `json:"assumptions"`
	EvidenceGaps          []string   `json:"evidenceGaps"`
	ContradictoryEvidence []string   `json:"contradictoryEvidence"`
	CredentialExposure    []Exposure `json:"potentialCredentialExposure"`
	ResourceExposure      []Exposure `json:"potentialResourceExposure"`
	RemediationGuidance   []string   `json:"remediationGuidance"`
	CollectionCoverage    []string   `json:"collectionCoverage"`
	// DerivationRuleVersion participates in the immutable revision identity and
	// SQLite provenance record. It is intentionally omitted from presentation
	// JSON because it is an internal persistence contract, not a report field.
	DerivationRuleVersion string `json:"-"`
}

type Coverage struct {
	Partial                      bool     `json:"partial"`
	RepositoriesRequested        int      `json:"repositoriesRequested"`
	RepositoriesAccessible       int      `json:"repositoriesAccessible"`
	RepositoriesDenied           int      `json:"repositoriesDenied"`
	RunsEnumerated               int      `json:"runsEnumerated"`
	AttemptsEnumerated           int      `json:"attemptsEnumerated"`
	JobsEnumerated               int      `json:"jobsEnumerated"`
	LogsRetrieved                int      `json:"logsRetrieved"`
	LogsMissing                  int      `json:"logsMissing"`
	WorkflowDefinitionsRetrieved int      `json:"workflowDefinitionsRetrieved"`
	ActionDefinitionsRetrieved   int      `json:"actionDefinitionsRetrieved"`
	OptionalCapabilitiesDenied   []string `json:"optionalCapabilitiesDenied,omitempty"`
	IncompleteEvidence           []string `json:"incompleteEvidence,omitempty"`
}

type Metadata struct {
	SchemaVersion       string   `json:"schemaVersion"`
	CaseContractVersion string   `json:"caseContractVersion,omitempty"`
	CaseKind            CaseKind `json:"caseKind,omitempty"`
	CaseID              string   `json:"caseId"`
	Mode                string   `json:"mode"`
	IncidentID          string   `json:"incidentId"`
	IncidentPackVersion string   `json:"incidentPackVersion"`
	CanonicalPackSHA256 string   `json:"canonicalPackSha256"`
	SourcePackSHA256    string   `json:"sourcePackSha256"`
	EngineVersion       string   `json:"engineVersion"`
	AnalysisTime        string   `json:"analysisTime"`
	GitHubAPIVersion    string   `json:"githubApiVersion,omitempty"`
	RawLogsRetained     bool     `json:"rawLogsRetained"`
	RawMaterialized     *bool    `json:"rawMaterialized,omitempty"`
	WatchHorizonDays    int      `json:"watchHorizonDays,omitempty"`
	Coverage            Coverage `json:"coverage"`
	LimitPolicy         string   `json:"limitPolicy"`
	Warnings            []string `json:"warnings,omitempty"`
}

type Case struct {
	Metadata     Metadata                   `json:"metadata"`
	Findings     []Finding                  `json:"findings"`
	Graph        graph.Graph                `json:"-"` // frozen v1 compatibility projection
	GraphV2      graph.GraphV2              `json:"graph"`
	TemporalPath graph.TemporalEvidencePath `json:"-"` // deterministic presentation derived from GraphV2

	// retainedLegacyCredentialBasis is enabled only by the analyzer when its
	// source snapshot came through the retained-v1 compatibility reader. It is
	// not serialized and does not change canonical findings or counts.
	retainedLegacyCredentialBasis bool
}

// EnableRetainedLegacyCredentialBasis allows only the report exposure basis
// compatibility required to replay retained v1alpha1 facts. Normal v2 cases
// remain strict and must never call this for newly collected input.
func EnableRetainedLegacyCredentialBasis(c *Case) {
	if c != nil {
		c.retainedLegacyCredentialBasis = true
	}
}

type Counts struct {
	TotalFindings         int
	ConfirmedExecuted     int
	ConfirmedDownloaded   int
	MutableRefExposure    int
	UnknownGaps           int
	ContradictoryEvidence int
	NoMatchConfirmed      int
	WriteTokenJobs        int
	NamedSecretFlows      int
	OIDCCapableJobs       int
	SelfHostedJobs        int
}

type filterOption struct {
	Key   string
	Label string
}

type findingView struct {
	Finding
	Occurrence        string
	ComparisonContext bool
	RepositoryFilter  string
	IndicatorFilter   string
	StateFilter       string
	ProvenanceFilter  string
	CredentialFilter  string
	RunnerFilter      string
}

type graphNodeView struct {
	graph.Node
	Focus string
}

type graphEdgeView struct {
	graph.Edge
	Focus string
}

type reportFilters struct {
	Repositories []filterOption
	Indicators   []filterOption
	States       []filterOption
	Provenance   []filterOption
	Credentials  []filterOption
	Runners      []filterOption
}

func (c *Case) NormalizeAndValidate() error {
	if c.Findings == nil {
		c.Findings = []Finding{}
	}
	if err := normalizeMetadata(&c.Metadata); err != nil {
		return err
	}
	seen := map[string]bool{}
	seenLogical := map[string]int{}
	for i := range c.Findings {
		f := &c.Findings[i]
		if f.FindingID == "" || f.FindingRevisionID == "" || f.State == "" || f.Provenance == "" || f.Conclusion == "" {
			return fmt.Errorf("finding %d lacks required fields", i)
		}
		if err := model.FindingID(f.FindingID).Validate(); err != nil {
			return fmt.Errorf("finding %d ID: %w", i, err)
		}
		if err := model.FindingRevisionID(f.FindingRevisionID).Validate(); err != nil {
			return fmt.Errorf("finding %d revision ID: %w", i, err)
		}
		if seen[f.FindingRevisionID] {
			return fmt.Errorf("duplicate finding revision %q", f.FindingRevisionID)
		}
		if previous, exists := seenLogical[f.FindingID]; exists {
			return fmt.Errorf("multiple finding revisions selected for logical finding %q (indexes %d and %d, states %s and %s)", f.FindingID, previous, i, c.Findings[previous].State, f.State)
		}
		if !model.FindingState(f.State).Valid() {
			return fmt.Errorf("finding %q has non-canonical state %q", f.FindingID, f.State)
		}
		if !model.ProvenanceLevel(f.Provenance).Valid() {
			return fmt.Errorf("finding %q has non-canonical provenance %q", f.FindingID, f.Provenance)
		}
		if f.State == string(model.UnknownEvidenceGap) && len(f.EvidenceGaps) == 0 {
			return fmt.Errorf("finding %q uses UNKNOWN_EVIDENCE_GAP without a gap", f.FindingID)
		}
		if f.State == string(model.NoMatchConfirmed) && (len(f.EvidenceIDs) == 0 || len(f.CollectionCoverage) == 0 || len(f.EvidenceGaps) != 0) {
			return fmt.Errorf("finding %q uses NO_MATCH_CONFIRMED without closed evidence coverage", f.FindingID)
		}
		seen[f.FindingRevisionID] = true
		seenLogical[f.FindingID] = i
		if len(f.EvidenceIDs) == 0 && len(f.EvidenceGaps) == 0 {
			return fmt.Errorf("finding %q has neither evidence nor explicit gap", f.FindingID)
		}
		f.EvidenceIDs = sortedUnique(f.EvidenceIDs)
		for _, id := range f.EvidenceIDs {
			if err := model.EvidenceID(id).Validate(); err != nil {
				return fmt.Errorf("finding %q evidence ID: %w", f.FindingID, err)
			}
		}
		f.Assumptions = sortedUnique(f.Assumptions)
		f.EvidenceGaps = sortedUnique(f.EvidenceGaps)
		f.ContradictoryEvidence = sortedUnique(f.ContradictoryEvidence)
		f.RemediationGuidance = sortedUnique(f.RemediationGuidance)
		f.CollectionCoverage = sortedUnique(f.CollectionCoverage)
		for _, id := range f.CollectionCoverage {
			if err := model.CoverageAssessmentID(id).Validate(); err != nil {
				return fmt.Errorf("finding %q coverage ID: %w", f.FindingID, err)
			}
		}
		var err error
		if f.CredentialExposure, err = normalizeExposures(f.CredentialExposure, true, c.retainedLegacyCredentialBasis); err != nil {
			return fmt.Errorf("finding %q credential exposure: %w", f.FindingID, err)
		}
		if f.ResourceExposure, err = normalizeExposures(f.ResourceExposure, false, false); err != nil {
			return fmt.Errorf("finding %q resource exposure: %w", f.FindingID, err)
		}
		if f.State != string(model.ConfirmedExecuted) && (len(f.CredentialExposure) != 0 || len(f.ResourceExposure) != 0) {
			return fmt.Errorf("finding %q: credential or resource reachability requires a separate CONFIRMED_EXECUTED proposition", f.FindingID)
		}
	}
	sort.Slice(c.Findings, func(i, j int) bool {
		a, b := c.Findings[i], c.Findings[j]
		if a.Repository != b.Repository {
			return a.Repository < b.Repository
		}
		if a.RunID != b.RunID {
			return a.RunID < b.RunID
		}
		if a.RunAttempt != b.RunAttempt {
			return a.RunAttempt < b.RunAttempt
		}
		if a.JobID != b.JobID {
			return a.JobID < b.JobID
		}
		if a.StepIdentity != b.StepIdentity {
			return a.StepIdentity < b.StepIdentity
		}
		if a.State != b.State {
			return a.State < b.State
		}
		return a.FindingRevisionID < b.FindingRevisionID
	})
	if err := c.Graph.NormalizeAndValidate(); err != nil {
		return err
	}
	if c.Metadata.SchemaVersion == MetadataSchemaV2 {
		if err := c.GraphV2.NormalizeAndValidate(); err != nil {
			return err
		}
		return validateFindingIndexParity(c.Findings, c.GraphV2.FindingIndex)
	}
	return nil
}

// validateFindingIndexParity prevents presentation-only graph metadata from
// drifting away from the canonical report findings. The graph may add exact
// identity and coverage fields, but every field duplicated from Finding must
// describe the same immutable finding revision and execution scope.
func validateFindingIndexParity(findings []Finding, index []graph.FindingIndexEntry) error {
	if len(findings) != len(index) {
		return errors.New("finding-index parity: report and graph finding counts differ")
	}
	byRevision := make(map[string]graph.FindingIndexEntry, len(index))
	for _, entry := range index {
		byRevision[entry.FindingRevisionID] = entry
	}
	for _, finding := range findings {
		entry, ok := byRevision[finding.FindingRevisionID]
		if !ok {
			return fmt.Errorf("finding-index parity: graph lacks report finding revision %q", finding.FindingRevisionID)
		}
		if entry.State != model.FindingState(finding.State) {
			return fmt.Errorf("finding-index parity: state differs for revision %q", finding.FindingRevisionID)
		}
		if entry.ProvenanceLevel != model.ProvenanceLevel(finding.Provenance) {
			return fmt.Errorf("finding-index parity: provenance differs for revision %q", finding.FindingRevisionID)
		}
		if entry.Repository != finding.Repository {
			return fmt.Errorf("finding-index parity: repository differs for revision %q", finding.FindingRevisionID)
		}
		if entry.WorkflowPath != finding.Workflow {
			return fmt.Errorf("finding-index parity: workflow differs for revision %q", finding.FindingRevisionID)
		}
		if !optionalWorkflowRunIDEquals(entry.RunID, finding.RunID) {
			return fmt.Errorf("finding-index parity: run ID differs for revision %q", finding.FindingRevisionID)
		}
		if !optionalRunAttemptEquals(entry.RunAttempt, finding.RunAttempt) {
			return fmt.Errorf("finding-index parity: run attempt differs for revision %q", finding.FindingRevisionID)
		}
		if !optionalJobIDEquals(entry.JobID, finding.JobID) {
			return fmt.Errorf("finding-index parity: job ID differs for revision %q", finding.FindingRevisionID)
		}
		if entry.StepIdentity != finding.StepIdentity {
			return fmt.Errorf("finding-index parity: step identity differs for revision %q", finding.FindingRevisionID)
		}
		if entry.IndicatorID != finding.IndicatorID {
			return fmt.Errorf("finding-index parity: indicator ID differs for revision %q", finding.FindingRevisionID)
		}
		if entry.EvidenceGapReason != strings.Join(finding.EvidenceGaps, "; ") {
			return fmt.Errorf("finding-index parity: evidence-gap reason differs for revision %q", finding.FindingRevisionID)
		}
	}
	return nil
}

func optionalWorkflowRunIDEquals(actual *model.WorkflowRunID, expected int64) bool {
	if expected == 0 {
		return actual == nil
	}
	return actual != nil && int64(*actual) == expected
}

func optionalRunAttemptEquals(actual *model.RunAttempt, expected int) bool {
	if expected == 0 {
		return actual == nil
	}
	return expected > 0 && actual != nil && uint64(*actual) == uint64(expected)
}

func optionalJobIDEquals(actual *model.JobID, expected int64) bool {
	if expected == 0 {
		return actual == nil
	}
	return actual != nil && int64(*actual) == expected
}

func (c Case) Counts() Counts {
	result := Counts{TotalFindings: len(c.Findings)}
	writeJobs, oidcJobs, selfHostedJobs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, finding := range c.Findings {
		switch finding.State {
		case string(model.ConfirmedExecuted):
			result.ConfirmedExecuted++
		case string(model.ConfirmedDownloaded):
			result.ConfirmedDownloaded++
		case string(model.RunInWindowMutableRef):
			result.MutableRefExposure++
		case string(model.UnknownEvidenceGap):
			result.UnknownGaps++
		case string(model.ContradictoryEvidence):
			result.ContradictoryEvidence++
		case string(model.NoMatchConfirmed):
			result.NoMatchConfirmed++
		}
		jobKey := fmt.Sprintf("%s:%d:%d:%d", finding.Repository, finding.RunID, finding.RunAttempt, finding.JobID)
		for _, exposure := range finding.CredentialExposure {
			if exposure.Kind == string(model.ExposureGitHubTokenPermission) && strings.HasSuffix(strings.ToLower(exposure.Capability), ":write") {
				writeJobs[jobKey] = true
			}
			switch exposure.Kind {
			case string(model.ExposureSecretPassedToStep), string(model.ExposureReusableSecretMapped), string(model.ExposureEnvironmentSecretEligible):
				if exposure.Name != "" {
					result.NamedSecretFlows++
				}
			}
			if exposure.Kind == string(model.ExposureOIDCMintingCapability) {
				oidcJobs[jobKey] = true
			}
		}
		for _, exposure := range finding.ResourceExposure {
			if exposure.Kind == "SELF_HOSTED_RUNNER" {
				selfHostedJobs[jobKey] = true
			}
		}
	}
	result.WriteTokenJobs = len(writeJobs)
	result.OIDCCapableJobs = len(oidcJobs)
	result.SelfHostedJobs = len(selfHostedJobs)
	return result
}

func WriteFindingsJSON(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	envelope := struct {
		SchemaVersion string    `json:"schemaVersion"`
		Findings      []Finding `json:"findings"`
	}{FindingsSchema, c.Findings}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(envelope)
}

func WriteMetadataJSON(writer io.Writer, metadata Metadata) error {
	if err := normalizeMetadata(&metadata); err != nil {
		return err
	}
	metadata.Coverage.OptionalCapabilitiesDenied = sortedUnique(metadata.Coverage.OptionalCapabilitiesDenied)
	metadata.Coverage.IncompleteEvidence = sortedUnique(metadata.Coverage.IncompleteEvidence)
	metadata.Warnings = sortedUnique(metadata.Warnings)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(metadata)
}

func normalizeMetadata(metadata *Metadata) error {
	if metadata.SchemaVersion == "" {
		metadata.SchemaVersion = MetadataSchema
	}
	switch metadata.SchemaVersion {
	case MetadataSchema:
		if metadata.CaseContractVersion != "" || metadata.CaseKind != "" || metadata.RawMaterialized != nil {
			return errors.New("legacy collection metadata cannot carry v0.2 case-contract fields")
		}
	case MetadataSchemaV2:
		if metadata.CaseContractVersion != CaseContractV2 {
			return fmt.Errorf("metadata schema %s requires case contract %s", MetadataSchemaV2, CaseContractV2)
		}
		if !metadata.CaseKind.Valid() {
			return fmt.Errorf("invalid case kind %q", metadata.CaseKind)
		}
		if metadata.RawMaterialized == nil {
			return errors.New("v0.2 collection metadata requires rawMaterialized")
		}
	default:
		return fmt.Errorf("unsupported metadata schema %q", metadata.SchemaVersion)
	}
	return nil
}

func WriteGraphJSON(writer io.Writer, value graph.Graph) error {
	if err := value.NormalizeAndValidate(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WriteGraphV2JSON(writer io.Writer, value graph.GraphV2) error {
	if err := value.NormalizeAndValidate(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WriteAffectedRunsCSV(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	csvWriter := csv.NewWriter(writer)
	// Preserve the original column order for existing named-column consumers.
	// The appended context prevents the legacy filename from implying every row
	// is an affected run. Indicator and revision IDs keep otherwise identical
	// propositions distinct and traceable.
	header := []string{"repository", "workflow", "run_id", "run_attempt", "job_id", "step_identity", "state", "provenance", "conclusion", "evidence_ids", "evidence_gaps", "finding_context", "indicator_id", "finding_revision_id"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	comparisonRevisions := knownGoodComparisonRevisions(c.GraphV2.FindingIndex)
	for _, finding := range c.Findings {
		row := []string{finding.Repository, finding.Workflow, optionalInt64(finding.RunID), optionalInt(finding.RunAttempt), optionalInt64(finding.JobID), finding.StepIdentity, finding.State, finding.Provenance, finding.Conclusion, strings.Join(finding.EvidenceIDs, ";"), strings.Join(finding.EvidenceGaps, ";"), affectedRunsCSVContext(finding, comparisonRevisions), finding.IndicatorID, finding.FindingRevisionID}
		for i := range row {
			row[i] = sanitize.CSVCell(row[i])
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

func affectedRunsCSVContext(finding Finding, comparisonRevisions map[string]bool) string {
	if comparisonRevisions[finding.FindingRevisionID] {
		return "known-good-rerun-comparison-not-affected-run"
	}
	switch model.FindingState(finding.State) {
	case model.NoMatchConfirmed:
		return "scope-closed-no-match-not-affected-run"
	case model.CurrentReferenceOnly:
		return "current-reference-only-no-historical-run"
	}
	if finding.RunID == 0 {
		return "finding-without-run-identity"
	}
	return "run-scoped-finding"
}

func optionalInt64(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func optionalInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func WriteSummaryMarkdown(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	if c.Metadata.SchemaVersion == MetadataSchemaV2 {
		return writeSummaryMarkdownV2(writer, c)
	}
	return writeSummaryMarkdownV1(writer, c)
}

// writeSummaryMarkdownV1 preserves the frozen v0.1 Markdown byte contract.
func writeSummaryMarkdownV1(writer io.Writer, c Case) error {
	counts := c.Counts()
	coverageWord := "complete"
	if c.Metadata.Coverage.Partial {
		coverageWord = "PARTIAL — conclusions are limited by evidence gaps"
	}
	fmt.Fprintf(writer, "# CIRewind incident handoff\n\nCase: `%s`  \nIncident: `%s`  \nCoverage: **%s**  \nPack SHA-256: `%s`\n\n", markdownText(c.Metadata.CaseID), markdownText(c.Metadata.IncidentID), coverageWord, c.Metadata.CanonicalPackSHA256)
	writeSummaryMarkdownSections(writer, c, counts)
	return nil
}

func writeSummaryMarkdownV2(writer io.Writer, c Case) error {
	classification := ""
	switch c.Metadata.CaseKind {
	case CaseKindSynthetic:
		classification = "SYNTHETIC DEMONSTRATION: this case contains harmless fixture evidence, not a real incident or collected organization result."
	case CaseKindCollected:
		classification = "COLLECTED CASE: this case was derived from collected GitHub evidence; conclusions remain bounded by recorded collection coverage."
	case CaseKindMixed:
		classification = "MIXED-PROVENANCE CASE: this case combines collected and synthetic or otherwise mixed source provenance; review provenance before operational use."
	case CaseKindUnknown:
		classification = "UNKNOWN CASE CLASSIFICATION: source provenance was not sufficient to classify this case as synthetic, collected, or mixed."
	}
	coverageWord := "complete"
	coverageNotice := "COVERAGE CLOSED: coverage is closed for the evidence classes requested by this case."
	if c.Metadata.Coverage.Partial {
		coverageWord = "PARTIAL — conclusions are limited by evidence gaps"
		coverageNotice = "PARTIAL COVERAGE: some material evidence is unavailable. Totals and conclusions are limited to retained evidence."
	}
	fmt.Fprintf(writer, "# CIRewind incident handoff\n\n> **%s**\n>\n> **%s**\n\nCase: `%s`  \nIncident: `%s`  \nCoverage: **%s**  \nPack SHA-256: `%s`\n\n", classification, coverageNotice, markdownText(c.Metadata.CaseID), markdownText(c.Metadata.IncidentID), coverageWord, c.Metadata.CanonicalPackSHA256)
	writeSummaryMarkdownSectionsV2(writer, c, c.Counts())
	return nil
}

func writeSummaryMarkdownSections(writer io.Writer, c Case, counts Counts) {
	fmt.Fprintf(writer, "## Finding summary\n\n- Confirmed executions: %d\n- Prepared/downloaded without demonstrated execution: %d\n- Mutable-reference window exposures: %d\n- Unknown evidence gaps: %d\n\n", counts.ConfirmedExecuted, counts.ConfirmedDownloaded, counts.MutableRefExposure, counts.UnknownGaps)
	fmt.Fprint(writer, "## Findings\n\n")
	for _, finding := range c.Findings {
		fmt.Fprintf(writer, "- `%s` / `%s` — %s (`%s`; evidence: `%s`)\n", finding.State, finding.Provenance, markdownText(finding.Conclusion), markdownText(finding.FindingRevisionID), markdownText(strings.Join(finding.EvidenceIDs, ", ")))
	}
	fmt.Fprint(writer, "\n## Methodology invariants\n\n")
	for _, invariant := range invariants {
		fmt.Fprintf(writer, "- %s\n", markdownText(invariant))
	}
	fmt.Fprint(writer, "\nVerify this case with `cirewind verify CASE_DIR`. The SHA-256 manifest supports integrity checking; it is not an authenticity signature or legal chain-of-custody certification.\n")
}

func writeSummaryMarkdownSectionsV2(writer io.Writer, c Case, counts Counts) {
	fmt.Fprintf(writer, "## Finding summary\n\n- Total findings: %d\n- Confirmed executions: %d\n- Prepared/downloaded without demonstrated execution: %d\n- Mutable-reference window exposures: %d\n- Unknown evidence gaps: %d\n- Contradictory-evidence findings: %d\n- Scope-closed no-match findings: %d\n\n", counts.TotalFindings, counts.ConfirmedExecuted, counts.ConfirmedDownloaded, counts.MutableRefExposure, counts.UnknownGaps, counts.ContradictoryEvidence, counts.NoMatchConfirmed)
	fmt.Fprint(writer, "## Findings\n\n")
	comparisonRevisions := knownGoodComparisonRevisions(c.GraphV2.FindingIndex)
	for _, finding := range c.Findings {
		scope := findingOccurrence(finding)
		if scope == "" {
			scope = "no run-attempt/job identity"
		}
		comparison := ""
		if comparisonRevisions[finding.FindingRevisionID] {
			comparison = "; comparison context only, not an affected run"
		}
		fmt.Fprintf(writer, "- `%s` / `%s` — %s (indicator: `%s`; workflow: `%s`; scope: `%s`%s; revision: `%s`; evidence: `%s`)\n", finding.State, finding.Provenance, markdownText(finding.Conclusion), markdownText(finding.IndicatorID), markdownText(finding.Workflow), markdownText(scope), comparison, markdownText(finding.FindingRevisionID), markdownText(strings.Join(finding.EvidenceIDs, ", ")))
	}
	fmt.Fprint(writer, "\n## Methodology invariants\n\n")
	for _, invariant := range invariants {
		fmt.Fprintf(writer, "- %s\n", markdownText(invariant))
	}
	fmt.Fprint(writer, "\nVerify this case with `cirewind verify CASE_DIR`. The SHA-256 manifest supports integrity checking; it is not an authenticity signature or legal chain-of-custody certification.\n")
}

func WriteHTML(writer io.Writer, c Case) error {
	return WriteHTMLContext(context.Background(), writer, c)
}

// WriteHTMLContext renders the self-contained report while honoring caller
// cancellation during graph re-projection and template output. WriteHTML remains
// the compatibility wrapper for callers without a lifecycle context.
func WriteHTMLContext(ctx context.Context, writer io.Writer, c Case) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	hasTemporalPath := c.Metadata.SchemaVersion == MetadataSchemaV2
	var temporal temporalPathView
	if hasTemporalPath {
		if string(c.Metadata.CaseKind) != string(c.GraphV2.CaseKind) || string(c.Metadata.CaseKind) != string(c.TemporalPath.CaseKind) {
			return errors.New("case classification disagrees across metadata, graph, and temporal evidence path")
		}
		if err := graph.ValidateRenderableTemporalEvidencePath(ctx, c.GraphV2, c.TemporalPath, graph.PathOptions{}); err != nil {
			return fmt.Errorf("temporal evidence path: %w", err)
		}
		temporal = buildTemporalPathView(c.TemporalPath)
	}
	styleHash := sha256.Sum256([]byte(stylesheet))
	scriptHash := sha256.Sum256([]byte(filterScript))
	csp := "default-src 'none'; img-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(styleHash[:]) + "'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(scriptHash[:]) + "'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
	sharedGuidance := sharedRemediationGuidance(c.Findings)
	findings, filters := buildFindingViews(c.Findings, sharedGuidance, knownGoodComparisonRevisions(c.GraphV2.FindingIndex))
	displayCase := c
	displayCase.Metadata = presentationMetadata(c.Metadata)
	nodes := make([]graphNodeView, len(c.Graph.Nodes))
	for index, node := range c.Graph.Nodes {
		displayNode := node
		displayNode.ID = presentationText(displayNode.ID, 4096)
		displayNode.Label = presentationText(displayNode.Label, 16<<10)
		nodes[index] = graphNodeView{Node: displayNode, Focus: strings.Join(node.FocusFindingIDs, " ")}
	}
	edges := make([]graphEdgeView, len(c.Graph.Edges))
	for index, edge := range c.Graph.Edges {
		displayEdge := edge
		displayEdge.ID = presentationText(displayEdge.ID, 4096)
		displayEdge.Source = presentationText(displayEdge.Source, 4096)
		displayEdge.Target = presentationText(displayEdge.Target, 4096)
		edges[index] = graphEdgeView{Edge: displayEdge, Focus: strings.Join(edge.FocusFindingIDs, " ")}
	}
	data := struct {
		Case                  Case
		Counts                Counts
		CSP                   string
		Invariants            []string
		Findings              []findingView
		Nodes                 []graphNodeView
		Edges                 []graphEdgeView
		Filters               reportFilters
		HasTemporalPath       bool
		Temporal              temporalPathView
		SharedGuidance        []string
		Synthetic             bool
		UnknownClassification bool
	}{
		Case: displayCase, Counts: c.Counts(), CSP: csp, Invariants: invariants,
		Findings: findings, Nodes: nodes, Edges: edges, Filters: filters,
		HasTemporalPath: hasTemporalPath, Temporal: temporal, SharedGuidance: presentationStrings(sharedGuidance, 4096),
		Synthetic:             c.Metadata.CaseKind == CaseKindSynthetic,
		UnknownClassification: c.Metadata.SchemaVersion == MetadataSchemaV2 && c.Metadata.CaseKind == CaseKindUnknown,
	}
	return reportTemplate.Execute(contextWriter{ctx: ctx, destination: writer}, data)
}

type contextWriter struct {
	ctx         context.Context
	destination io.Writer
}

func (w contextWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.destination.Write(data)
}

func buildFindingViews(findings []Finding, sharedGuidance []string, comparisonRevisions map[string]bool) ([]findingView, reportFilters) {
	views := make([]findingView, 0, len(findings))
	options := map[string]map[string]string{
		"repository": {}, "indicator": {}, "state": {}, "provenance": {}, "credential": {}, "runner": {},
	}
	for _, finding := range findings {
		credentialKinds, runnerKinds := findingFilterKinds(finding)
		residualGuidance := subtractStrings(finding.RemediationGuidance, sharedGuidance)
		displayFinding := presentationFinding(finding)
		displayFinding.RemediationGuidance = presentationStrings(residualGuidance, 16<<10)
		view := findingView{
			Finding:           displayFinding,
			Occurrence:        findingOccurrence(displayFinding),
			ComparisonContext: comparisonRevisions[finding.FindingRevisionID],
			RepositoryFilter:  filterKey(finding.Repository),
			IndicatorFilter:   filterKey(finding.IndicatorID),
			StateFilter:       filterKey(finding.State),
			ProvenanceFilter:  filterKey(finding.Provenance),
			CredentialFilter:  filterKeys(credentialKinds),
			RunnerFilter:      filterKeys(runnerKinds),
		}
		views = append(views, view)
		addFilterOption(options["repository"], finding.Repository)
		addFilterOption(options["indicator"], finding.IndicatorID)
		addFilterOption(options["state"], finding.State)
		addFilterOption(options["provenance"], finding.Provenance)
		for _, value := range credentialKinds {
			addFilterOption(options["credential"], value)
		}
		for _, value := range runnerKinds {
			addFilterOption(options["runner"], value)
		}
	}
	return views, reportFilters{
		Repositories: sortedFilterOptions(options["repository"]),
		Indicators:   sortedFilterOptions(options["indicator"]),
		States:       sortedFilterOptions(options["state"]),
		Provenance:   sortedFilterOptions(options["provenance"]),
		Credentials:  sortedFilterOptions(options["credential"]),
		Runners:      sortedFilterOptions(options["runner"]),
	}
}

func sharedRemediationGuidance(findings []Finding) []string {
	// Deduplicate only guidance that is literally repeated across two or more
	// findings. This is a presentation property, not a claim that the text is
	// case-wide or that its remediation trigger applies to every finding.
	if len(findings) < 2 {
		return []string{}
	}
	counts := make(map[string]int)
	for _, finding := range findings {
		seen := make(map[string]struct{}, len(finding.RemediationGuidance))
		for _, guidance := range finding.RemediationGuidance {
			if guidance == "" {
				continue
			}
			if _, duplicate := seen[guidance]; duplicate {
				continue
			}
			seen[guidance] = struct{}{}
			counts[guidance]++
		}
	}
	common := make([]string, 0)
	for guidance, count := range counts {
		if count == len(findings) {
			common = append(common, guidance)
		}
	}
	sort.Strings(common)
	return common
}

func knownGoodComparisonRevisions(index []graph.FindingIndexEntry) map[string]bool {
	result := make(map[string]bool)
	for _, candidate := range index {
		if candidate.State != model.NoMatchConfirmed {
			continue
		}
		for _, anchor := range index {
			if graph.IsKnownGoodComparison(anchor, candidate) {
				result[candidate.FindingRevisionID] = true
				break
			}
		}
	}
	return result
}

func subtractStrings(values, excluded []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	omit := make(map[string]struct{}, len(excluded))
	for _, value := range excluded {
		omit[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, found := omit[value]; !found {
			result = append(result, value)
		}
	}
	return result
}

func findingOccurrence(finding Finding) string {
	parts := make([]string, 0, 4)
	if finding.RunID != 0 {
		parts = append(parts, "run="+strconv.FormatInt(finding.RunID, 10))
	}
	if finding.RunAttempt != 0 {
		parts = append(parts, "attempt="+strconv.Itoa(finding.RunAttempt))
	}
	if finding.JobID != 0 {
		parts = append(parts, "job="+strconv.FormatInt(finding.JobID, 10))
	}
	if finding.StepIdentity != "" {
		parts = append(parts, "step="+finding.StepIdentity)
	}
	return strings.Join(parts, " ")
}

func presentationMetadata(value Metadata) Metadata {
	result := value
	result.SchemaVersion = presentationText(value.SchemaVersion, 4096)
	result.CaseContractVersion = presentationText(value.CaseContractVersion, 4096)
	result.CaseID = presentationText(value.CaseID, 4096)
	result.Mode = presentationText(value.Mode, 4096)
	result.IncidentID = presentationText(value.IncidentID, 4096)
	result.IncidentPackVersion = presentationText(value.IncidentPackVersion, 4096)
	result.CanonicalPackSHA256 = presentationText(value.CanonicalPackSHA256, 4096)
	result.SourcePackSHA256 = presentationText(value.SourcePackSHA256, 4096)
	result.EngineVersion = presentationText(value.EngineVersion, 4096)
	result.AnalysisTime = presentationText(value.AnalysisTime, 4096)
	result.GitHubAPIVersion = presentationText(value.GitHubAPIVersion, 4096)
	result.LimitPolicy = presentationText(value.LimitPolicy, 4096)
	result.Warnings = presentationStrings(value.Warnings, 4096)
	result.Coverage.OptionalCapabilitiesDenied = presentationStrings(value.Coverage.OptionalCapabilitiesDenied, 4096)
	result.Coverage.IncompleteEvidence = presentationStrings(value.Coverage.IncompleteEvidence, 4096)
	return result
}

func presentationFinding(value Finding) Finding {
	result := value
	result.FindingID = presentationText(value.FindingID, 4096)
	result.FindingRevisionID = presentationText(value.FindingRevisionID, 4096)
	result.IncidentID = presentationText(value.IncidentID, 4096)
	result.IndicatorID = presentationText(value.IndicatorID, 4096)
	result.Repository = presentationText(value.Repository, 4096)
	result.Workflow = presentationText(value.Workflow, 4096)
	result.StepIdentity = presentationText(value.StepIdentity, 4096)
	result.State = presentationText(value.State, 4096)
	result.Provenance = presentationText(value.Provenance, 4096)
	result.Conclusion = presentationText(value.Conclusion, 16<<10)
	result.EventTime = presentationText(value.EventTime, 4096)
	result.EvidenceIDs = presentationStrings(value.EvidenceIDs, 4096)
	result.Assumptions = presentationStrings(value.Assumptions, 16<<10)
	result.EvidenceGaps = presentationStrings(value.EvidenceGaps, 16<<10)
	result.ContradictoryEvidence = presentationStrings(value.ContradictoryEvidence, 16<<10)
	result.RemediationGuidance = presentationStrings(value.RemediationGuidance, 16<<10)
	result.CollectionCoverage = presentationStrings(value.CollectionCoverage, 4096)
	result.CredentialExposure = presentationExposures(value.CredentialExposure)
	result.ResourceExposure = presentationExposures(value.ResourceExposure)
	return result
}

func presentationExposures(values []Exposure) []Exposure {
	result := make([]Exposure, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Kind = presentationText(value.Kind, 4096)
		result[index].Name = presentationText(value.Name, 4096)
		result[index].Capability = presentationText(value.Capability, 4096)
		result[index].Basis = presentationText(value.Basis, 4096)
		result[index].Conclusion = presentationText(value.Conclusion, 16<<10)
		result[index].EvidenceIDs = presentationStrings(value.EvidenceIDs, 4096)
	}
	return result
}

func presentationStrings(values []string, maxBytes int) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = presentationText(value, maxBytes)
	}
	return result
}

func presentationText(value string, maxBytes int) string {
	result, _ := sanitize.Presentation(value, maxBytes)
	return result
}

func findingFilterKinds(finding Finding) (credentials, runners []string) {
	for _, exposure := range finding.CredentialExposure {
		credentials = append(credentials, exposure.Kind)
	}
	for _, exposure := range finding.ResourceExposure {
		if strings.HasSuffix(exposure.Kind, "_RUNNER") {
			runners = append(runners, exposure.Kind)
		}
	}
	return sortedUnique(credentials), sortedUnique(runners)
}

func addFilterOption(options map[string]string, label string) {
	if label != "" {
		options[filterKey(label)] = presentationText(label, 4096)
	}
}

func sortedFilterOptions(values map[string]string) []filterOption {
	result := make([]filterOption, 0, len(values))
	for key, label := range values {
		result = append(result, filterOption{Key: key, Label: label})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Label != result[j].Label {
			return result[i].Label < result[j].Label
		}
		return result[i].Key < result[j].Key
	})
	return result
}

func filterKey(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func filterKeys(values []string) string {
	keys := make([]string, 0, len(values))
	for _, value := range values {
		keys = append(keys, filterKey(value))
	}
	return strings.Join(keys, " ")
}

var invariants = []string{
	"Action downloaded != Action executed",
	"Repository possesses a secret != affected step could read that secret",
	"id-token: write != cloud role assumed",
	"Workflow ran during incident window != compromised SHA executed",
	"Current tag points to a safe commit != historical runs were safe",
	"No retained logs != no compromise",
	"Deployment followed an affected step != attacker caused the deployment",
	"Present-day workflow YAML != historical workflow definition",
}

func countLabel(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"countLabel": countLabel}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{{.CSP}}"><title>CIRewind case {{.Case.Metadata.CaseID}}</title><style>` + stylesheet + `</style></head><body>
<header><h1>CIRewind incident evidence</h1><p>Case <code>{{.Case.Metadata.CaseID}}</code> · incident <code>{{.Case.Metadata.IncidentID}}</code> · pack <code>{{.Case.Metadata.CanonicalPackSHA256}}</code></p>{{if .Synthetic}}<p class="synthetic">SYNTHETIC DEMONSTRATION: this case contains harmless fixture evidence, not a real incident or collected organization result.</p>{{else if .UnknownClassification}}<p class="classification-unknown">UNKNOWN CASE CLASSIFICATION: source provenance was not sufficient to classify this case as synthetic, collected, or mixed.</p>{{end}}{{if .Case.Metadata.Coverage.Partial}}<p class="warning">PARTIAL COVERAGE: some material evidence is unavailable. Totals and conclusions are limited to retained evidence.</p>{{else}}<p>Coverage is closed for the evidence classes requested by this case.</p>{{end}}</header>
<main><section><h2>Executive summary</h2><p><strong>{{.Counts.TotalFindings}}</strong> {{countLabel .Counts.TotalFindings "total finding" "total findings"}} · <strong>{{.Counts.ContradictoryEvidence}}</strong> {{countLabel .Counts.ContradictoryEvidence "contradictory-evidence finding" "contradictory-evidence findings"}} · <strong>{{.Counts.NoMatchConfirmed}}</strong> {{countLabel .Counts.NoMatchConfirmed "scope-closed no-match finding" "scope-closed no-match findings"}}.</p><div class="counts"><div class="count"><strong>{{.Counts.ConfirmedExecuted}}</strong> {{countLabel .Counts.ConfirmedExecuted "confirmed execution" "confirmed executions"}}</div><div class="count"><strong>{{.Counts.ConfirmedDownloaded}}</strong> {{countLabel .Counts.ConfirmedDownloaded "prepared/downloaded finding; execution not demonstrated" "prepared/downloaded findings; execution not demonstrated"}}</div><div class="count"><strong>{{.Counts.MutableRefExposure}}</strong> {{countLabel .Counts.MutableRefExposure "mutable-ref window exposure" "mutable-ref window exposures"}}</div><div class="count"><strong>{{.Counts.UnknownGaps}}</strong> {{countLabel .Counts.UnknownGaps "unknown evidence gap" "unknown evidence gaps"}}</div><div class="count"><strong>{{.Counts.WriteTokenJobs}}</strong> {{countLabel .Counts.WriteTokenJobs "job with observed or explicitly inferred write-capable token permissions" "jobs with observed or explicitly inferred write-capable token permissions"}}</div><div class="count"><strong>{{.Counts.NamedSecretFlows}}</strong> {{countLabel .Counts.NamedSecretFlows "named secret flow relationship" "named secret flow relationships"}}</div><div class="count"><strong>{{.Counts.OIDCCapableJobs}}</strong> {{countLabel .Counts.OIDCCapableJobs "job with OIDC minting capability" "jobs with OIDC minting capability"}}</div><div class="count"><strong>{{.Counts.SelfHostedJobs}}</strong> {{countLabel .Counts.SelfHostedJobs "affected job on a self-hosted runner" "affected jobs on self-hosted runners"}}</div></div></section>
<section><h2>Coverage and evidence gaps</h2><p>Repositories requested/accessed/denied: {{.Case.Metadata.Coverage.RepositoriesRequested}} / {{.Case.Metadata.Coverage.RepositoriesAccessible}} / {{.Case.Metadata.Coverage.RepositoriesDenied}}. Runs/attempts/jobs: {{.Case.Metadata.Coverage.RunsEnumerated}} / {{.Case.Metadata.Coverage.AttemptsEnumerated}} / {{.Case.Metadata.Coverage.JobsEnumerated}}. Retained attempt/job log coverage totals retrieved/missing: {{.Case.Metadata.Coverage.LogsRetrieved}} / {{.Case.Metadata.Coverage.LogsMissing}}. These totals combine typed per-scope coverage with retained aggregate or legacy lower bounds; scoped warnings below identify missing aggregate summaries.</p>{{range .Case.Metadata.Coverage.IncompleteEvidence}}<p class="warning">{{.}}</p>{{end}}</section>
<section><h2>Case filters</h2><div class="filters"><label>Finding state<select data-filter="state"><option value="">All states</option>{{range .Filters.States}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Repository<select data-filter="repository"><option value="">All repositories</option>{{range .Filters.Repositories}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Incident indicator<select data-filter="indicator"><option value="">All indicators</option>{{range .Filters.Indicators}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Evidence level<select data-filter="provenance"><option value="">All levels</option>{{range .Filters.Provenance}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Credential exposure<select data-filter="credentials" data-multi="true"><option value="">All credential contexts</option>{{range .Filters.Credentials}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Runner type<select data-filter="runners" data-multi="true"><option value="">All runner types</option>{{range .Filters.Runners}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><button id="filter-reset" type="button">Reset filters</button></div><p id="filter-status" role="status" aria-live="polite" aria-atomic="true"><strong id="visible-count">{{len .Findings}}</strong> <span id="visible-count-label">{{countLabel (len .Findings) "finding visible" "findings visible"}}</span>.{{if .HasTemporalPath}}<span id="filter-visual-status"> {{.Temporal.SelectedFindings}} {{countLabel .Temporal.SelectedFindings "matching finding shown" "matching findings shown"}} in the visual; {{.Temporal.OmittedFindings}} {{countLabel .Temporal.OmittedFindings "finding omitted" "findings omitted"}} from the visual.</span>{{end}}<span id="filter-no-match-status"></span></p><p id="filter-empty" class="empty" hidden>No findings match every selected filter.</p></section>
<section><h2>Run-attempt findings</h2><table><caption>Complete run-attempt and job finding set</caption><thead><tr><th>Repository</th><th>Indicator</th><th>Workflow / execution identity</th><th>State</th><th>Conclusion</th><th>Evidence</th></tr></thead><tbody>{{range .Findings}}<tr data-finding-item data-counted="true" data-revision="{{.FindingRevisionID}}" data-state="{{.StateFilter}}" data-repository="{{.RepositoryFilter}}" data-indicator="{{.IndicatorFilter}}" data-provenance="{{.ProvenanceFilter}}" data-credentials="{{.CredentialFilter}}" data-runners="{{.RunnerFilter}}"><td>{{.Repository}}</td><td><code>{{.IndicatorID}}</code></td><td>{{.Workflow}}{{if .Occurrence}}<br><code>{{.Occurrence}}</code>{{end}}</td><td><span class="state">{{.State}}</span><br>{{.Provenance}}{{if .ComparisonContext}}<br><strong>Comparison context; not an affected run.</strong>{{end}}</td><td>{{.Conclusion}}{{range .EvidenceGaps}}<div class="warning">Gap: {{.}}</div>{{end}}</td><td>{{range .EvidenceIDs}}<code>{{.}}</code><br>{{end}}</td></tr>{{end}}</tbody></table></section>
<section><h2>Credential, runner, and resource context</h2>{{if .SharedGuidance}}<aside><h3>Incident-pack guidance repeated across findings</h3><p>This text is shown once only because it appears identically on every finding. Deduplication does not change its scope, prove exposure, or establish that a remediation trigger applies.</p>{{range .SharedGuidance}}<p>{{.}}</p>{{end}}</aside>{{end}}{{range .Findings}}<details data-finding-item data-revision="{{.FindingRevisionID}}" data-state="{{.StateFilter}}" data-repository="{{.RepositoryFilter}}" data-indicator="{{.IndicatorFilter}}" data-provenance="{{.ProvenanceFilter}}" data-credentials="{{.CredentialFilter}}" data-runners="{{.RunnerFilter}}"><summary>{{.State}} — {{.Repository}} · indicator {{.IndicatorID}}{{if .Occurrence}} · {{.Occurrence}}{{end}}</summary>{{if .ComparisonContext}}<p><strong>Comparison context:</strong> this scope-closed known-good rerun is not an affected run and does not itself imply remediation.</p>{{end}}{{range .CredentialExposure}}<p><strong>{{.Kind}}</strong> {{.Name}}: {{.Conclusion}} <span class="muted">Basis: {{.Basis}}.</span></p>{{end}}{{range .ResourceExposure}}<p><strong>{{.Kind}}</strong> {{.Name}}: {{.Conclusion}} <span class="muted">Basis: {{.Basis}}.</span></p>{{end}}{{if .RemediationGuidance}}<h3>Incident-pack guidance associated with this finding</h3><p>This guidance does not independently prove credential exposure, resource impact, or a remediation trigger.</p>{{range .RemediationGuidance}}<p>{{.}}</p>{{end}}{{end}}</details>{{end}}</section>
<section><h2 id="temporal-path-heading">Temporal evidence path</h2><p>This bounded view is a derived presentation of evidence-backed relationships. It is not proof of exploitation or causation. Filters hide only whole pre-laid-out finding lanes and never create or alter relationships.</p>{{if .HasTemporalPath}}{{template "temporalPath" .Temporal}}{{else}}<p>This retained v0.1 report has no v0.2 temporal visual projection. Its typed compatibility graph remains available below.</p><details class="path-fallback"><summary>Legacy typed graph text view</summary><div class="graph"><div><h3>Nodes</h3><ul>{{range .Nodes}}<li data-graph-item data-findings="{{.Focus}}"><code>{{.Type}}:{{.ID}}</code> — {{.Label}}{{if .EvidenceIDs}}; evidence: {{range .EvidenceIDs}}<code>{{.}}</code> {{end}}{{end}}</li>{{end}}</ul></div><div><h3>Evidence-backed relationships</h3><ul>{{range .Edges}}<li data-graph-item data-findings="{{.Focus}}"><code>{{.Type}}</code>: {{.Source}} → {{.Target}} ({{range .EvidenceIDs}}<code>{{.}}</code> {{end}})</li>{{end}}</ul></div></div></details>{{end}}</section>
<section><h2>Methodology and limitations</h2><ul>{{range .Invariants}}<li>{{.}}</li>{{end}}</ul><p>CIRewind reports evidence-backed capability and reachability, not exploitation, exfiltration, cloud-role assumption, runner persistence, or downstream causation unless independent direct evidence establishes it.</p><p>The case manifest supports SHA-256 integrity verification. It is not an authenticity signature or legal chain-of-custody certification.</p></section></main><script>` + filterScript + `</script></body></html>` + temporalPathTemplate))

func markdownText(value string) string {
	value = sanitize.Terminal(value, 4096)
	replacer := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "#", "\\#", "|", "\\|")
	return replacer.Replace(value)
}
func sortedUnique(values []string) []string {
	if values == nil {
		return []string{}
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func normalizeExposures(values []Exposure, credential, allowRetainedLegacyBasis bool) ([]Exposure, error) {
	if values == nil {
		return []Exposure{}, nil
	}
	for index := range values {
		exposure := &values[index]
		if exposure.Kind == "" || exposure.Conclusion == "" || len(exposure.EvidenceIDs) == 0 {
			return nil, errors.New("exposure lacks kind, basis, conclusion, or evidence")
		}
		if credential {
			basis := model.CredentialExposureBasis(exposure.Basis)
			if !basis.Valid() {
				if !allowRetainedLegacyBasis || !safeLegacyBasis(exposure.Basis) {
					return nil, fmt.Errorf("invalid credential-exposure basis %q", exposure.Basis)
				}
			}
		} else if exposure.Basis == "" {
			return nil, errors.New("exposure lacks kind, basis, conclusion, or evidence")
		}
		exposure.EvidenceIDs = sortedUnique(exposure.EvidenceIDs)
		for _, id := range exposure.EvidenceIDs {
			if err := model.EvidenceID(id).Validate(); err != nil {
				return nil, fmt.Errorf("evidence ID: %w", err)
			}
		}
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i], values[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Capability != right.Capability {
			return left.Capability < right.Capability
		}
		return left.Basis < right.Basis
	})
	return values, nil
}

func safeLegacyBasis(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("_.:/-", char) {
			continue
		}
		return false
	}
	return true
}
