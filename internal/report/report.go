// Package report produces deterministic, offline, escaped CIRewind case views.
package report

import (
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
	FindingsSchema = "cirewind.findings/v1alpha1"
	MetadataSchema = "cirewind.collection-metadata/v1alpha1"
	stylesheet     = `:root{color-scheme:light dark;font-family:system-ui,sans-serif}body{max-width:110rem;margin:auto;padding:1.5rem;line-height:1.45}h1,h2{line-height:1.2}.warning{border:.2rem solid #b45309;padding:1rem;font-weight:700}.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.8rem}.count{border:1px solid #888;padding:.8rem}.count strong{display:block;font-size:1.8rem}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid #888;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}code{overflow-wrap:anywhere}.state{font-weight:700}.muted{opacity:.8}details{margin:.5rem 0}.graph{display:grid;grid-template-columns:1fr 1fr;gap:1rem}.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(13rem,1fr));gap:.7rem;border:1px solid #888;padding:1rem;margin:1rem 0}.filters label{display:grid;gap:.25rem}.filters button{align-self:end;min-height:2.2rem}.empty{padding:.7rem;border:1px dashed #888}@media(max-width:50rem){.graph{grid-template-columns:1fr}}`
	filterScript   = `"use strict";(()=>{const controls=[...document.querySelectorAll("[data-filter]")],items=[...document.querySelectorAll("[data-finding-item]")],graphItems=[...document.querySelectorAll("[data-graph-item]")],visibleCount=document.getElementById("visible-count"),empty=document.getElementById("filter-empty");const has=(value,token)=>(" "+(value||"")+" ").includes(" "+token+" ");const matches=item=>controls.every(control=>!control.value||(control.dataset.multi==="true"?has(item.dataset[control.dataset.filter],control.value):item.dataset[control.dataset.filter]===control.value));const apply=()=>{const visible=new Set();let count=0;for(const item of items){const show=matches(item);item.hidden=!show;if(show){visible.add(item.dataset.revision);if(item.dataset.counted==="true")count++}}for(const item of graphItems){const focus=(item.dataset.findings||"").split(" ").filter(Boolean);item.hidden=focus.length>0&&!focus.some(id=>visible.has(id))}visibleCount.textContent=String(count);empty.hidden=count!==0};for(const control of controls)control.addEventListener("change",apply);document.getElementById("filter-reset").addEventListener("click",()=>{for(const control of controls)control.value="";apply()});apply()})();`
)

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
	WatchHorizonDays    int      `json:"watchHorizonDays,omitempty"`
	Coverage            Coverage `json:"coverage"`
	LimitPolicy         string   `json:"limitPolicy"`
	Warnings            []string `json:"warnings,omitempty"`
}

type Case struct {
	Metadata Metadata    `json:"metadata"`
	Findings []Finding   `json:"findings"`
	Graph    graph.Graph `json:"graph"`
}

type Counts struct {
	ConfirmedExecuted   int
	ConfirmedDownloaded int
	MutableRefExposure  int
	UnknownGaps         int
	WriteTokenJobs      int
	NamedSecretFlows    int
	OIDCCapableJobs     int
	SelfHostedJobs      int
}

type filterOption struct {
	Key   string
	Label string
}

type findingView struct {
	Finding
	RepositoryFilter string
	IndicatorFilter  string
	StateFilter      string
	ProvenanceFilter string
	CredentialFilter string
	RunnerFilter     string
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
	if c.Metadata.SchemaVersion == "" {
		c.Metadata.SchemaVersion = MetadataSchema
	}
	if c.Metadata.SchemaVersion != MetadataSchema {
		return fmt.Errorf("unsupported metadata schema %q", c.Metadata.SchemaVersion)
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
		if f.CredentialExposure, err = normalizeExposures(f.CredentialExposure); err != nil {
			return fmt.Errorf("finding %q credential exposure: %w", f.FindingID, err)
		}
		if f.ResourceExposure, err = normalizeExposures(f.ResourceExposure); err != nil {
			return fmt.Errorf("finding %q resource exposure: %w", f.FindingID, err)
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
	return c.Graph.NormalizeAndValidate()
}

func (c Case) Counts() Counts {
	var result Counts
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
	if metadata.SchemaVersion == "" {
		metadata.SchemaVersion = MetadataSchema
	}
	metadata.Coverage.OptionalCapabilitiesDenied = sortedUnique(metadata.Coverage.OptionalCapabilitiesDenied)
	metadata.Coverage.IncompleteEvidence = sortedUnique(metadata.Coverage.IncompleteEvidence)
	metadata.Warnings = sortedUnique(metadata.Warnings)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(metadata)
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

func WriteAffectedRunsCSV(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	csvWriter := csv.NewWriter(writer)
	header := []string{"repository", "workflow", "run_id", "run_attempt", "job_id", "step_identity", "state", "provenance", "conclusion", "evidence_ids", "evidence_gaps"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}
	for _, finding := range c.Findings {
		row := []string{finding.Repository, finding.Workflow, strconv.FormatInt(finding.RunID, 10), strconv.Itoa(finding.RunAttempt), strconv.FormatInt(finding.JobID, 10), finding.StepIdentity, finding.State, finding.Provenance, finding.Conclusion, strings.Join(finding.EvidenceIDs, ";"), strings.Join(finding.EvidenceGaps, ";")}
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

func WriteSummaryMarkdown(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	counts := c.Counts()
	coverageWord := "complete"
	if c.Metadata.Coverage.Partial {
		coverageWord = "PARTIAL — conclusions are limited by evidence gaps"
	}
	fmt.Fprintf(writer, "# CIRewind incident handoff\n\nCase: `%s`  \nIncident: `%s`  \nCoverage: **%s**  \nPack SHA-256: `%s`\n\n", markdownText(c.Metadata.CaseID), markdownText(c.Metadata.IncidentID), coverageWord, c.Metadata.CanonicalPackSHA256)
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
	return nil
}

func WriteHTML(writer io.Writer, c Case) error {
	if err := c.NormalizeAndValidate(); err != nil {
		return err
	}
	styleHash := sha256.Sum256([]byte(stylesheet))
	scriptHash := sha256.Sum256([]byte(filterScript))
	csp := "default-src 'none'; img-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(styleHash[:]) + "'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(scriptHash[:]) + "'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
	findings, filters := buildFindingViews(c.Findings)
	nodes := make([]graphNodeView, len(c.Graph.Nodes))
	for index, node := range c.Graph.Nodes {
		nodes[index] = graphNodeView{Node: node, Focus: strings.Join(node.FocusFindingIDs, " ")}
	}
	edges := make([]graphEdgeView, len(c.Graph.Edges))
	for index, edge := range c.Graph.Edges {
		edges[index] = graphEdgeView{Edge: edge, Focus: strings.Join(edge.FocusFindingIDs, " ")}
	}
	data := struct {
		Case       Case
		Counts     Counts
		CSP        string
		Invariants []string
		Findings   []findingView
		Nodes      []graphNodeView
		Edges      []graphEdgeView
		Filters    reportFilters
	}{c, c.Counts(), csp, invariants, findings, nodes, edges, filters}
	return reportTemplate.Execute(writer, data)
}

func buildFindingViews(findings []Finding) ([]findingView, reportFilters) {
	views := make([]findingView, 0, len(findings))
	options := map[string]map[string]string{
		"repository": {}, "indicator": {}, "state": {}, "provenance": {}, "credential": {}, "runner": {},
	}
	for _, finding := range findings {
		credentialKinds, runnerKinds := findingFilterKinds(finding)
		view := findingView{
			Finding:          finding,
			RepositoryFilter: filterKey(finding.Repository),
			IndicatorFilter:  filterKey(finding.IndicatorID),
			StateFilter:      filterKey(finding.State),
			ProvenanceFilter: filterKey(finding.Provenance),
			CredentialFilter: filterKeys(credentialKinds),
			RunnerFilter:     filterKeys(runnerKinds),
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
		options[filterKey(label)] = label
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

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{{.CSP}}"><title>CIRewind case {{.Case.Metadata.CaseID}}</title><style>` + stylesheet + `</style></head><body>
<header><h1>CIRewind incident evidence</h1><p>Case <code>{{.Case.Metadata.CaseID}}</code> · incident <code>{{.Case.Metadata.IncidentID}}</code> · pack <code>{{.Case.Metadata.CanonicalPackSHA256}}</code></p>{{if .Case.Metadata.Coverage.Partial}}<p class="warning">PARTIAL COVERAGE: some material evidence is unavailable. Totals and conclusions are limited to retained evidence.</p>{{else}}<p>Coverage is closed for the evidence classes requested by this case.</p>{{end}}</header>
<main><section><h2>Executive summary</h2><div class="counts"><div class="count"><strong>{{.Counts.ConfirmedExecuted}}</strong>confirmed executions</div><div class="count"><strong>{{.Counts.ConfirmedDownloaded}}</strong>prepared/downloaded; execution not demonstrated</div><div class="count"><strong>{{.Counts.MutableRefExposure}}</strong>mutable-ref window exposures</div><div class="count"><strong>{{.Counts.UnknownGaps}}</strong>unknown evidence gaps</div><div class="count"><strong>{{.Counts.WriteTokenJobs}}</strong>jobs with observed or explicitly inferred write-capable token permissions</div><div class="count"><strong>{{.Counts.NamedSecretFlows}}</strong>named secret flow relationships</div><div class="count"><strong>{{.Counts.OIDCCapableJobs}}</strong>jobs with OIDC minting capability</div><div class="count"><strong>{{.Counts.SelfHostedJobs}}</strong>affected jobs on self-hosted runners</div></div></section>
<section><h2>Coverage and evidence gaps</h2><p>Repositories requested/accessed/denied: {{.Case.Metadata.Coverage.RepositoriesRequested}} / {{.Case.Metadata.Coverage.RepositoriesAccessible}} / {{.Case.Metadata.Coverage.RepositoriesDenied}}. Runs/attempts/jobs: {{.Case.Metadata.Coverage.RunsEnumerated}} / {{.Case.Metadata.Coverage.AttemptsEnumerated}} / {{.Case.Metadata.Coverage.JobsEnumerated}}. Logs retrieved/missing: {{.Case.Metadata.Coverage.LogsRetrieved}} / {{.Case.Metadata.Coverage.LogsMissing}}.</p>{{range .Case.Metadata.Coverage.IncompleteEvidence}}<p class="warning">{{.}}</p>{{end}}</section>
<section><h2>Case filters</h2><div class="filters"><label>Finding state<select data-filter="state"><option value="">All states</option>{{range .Filters.States}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Repository<select data-filter="repository"><option value="">All repositories</option>{{range .Filters.Repositories}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Incident indicator<select data-filter="indicator"><option value="">All indicators</option>{{range .Filters.Indicators}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Evidence level<select data-filter="provenance"><option value="">All levels</option>{{range .Filters.Provenance}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Credential exposure<select data-filter="credentials" data-multi="true"><option value="">All credential contexts</option>{{range .Filters.Credentials}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><label>Runner type<select data-filter="runners" data-multi="true"><option value="">All runner types</option>{{range .Filters.Runners}}<option value="{{.Key}}">{{.Label}}</option>{{end}}</select></label><button id="filter-reset" type="button">Reset filters</button></div><p><strong id="visible-count">{{len .Findings}}</strong> findings visible.</p><p id="filter-empty" class="empty" hidden>No findings match every selected filter.</p></section>
<section><h2>Affected attempts</h2><table><thead><tr><th>Repository</th><th>Workflow / execution identity</th><th>State</th><th>Conclusion</th><th>Evidence</th></tr></thead><tbody>{{range .Findings}}<tr data-finding-item data-counted="true" data-revision="{{.FindingRevisionID}}" data-state="{{.StateFilter}}" data-repository="{{.RepositoryFilter}}" data-indicator="{{.IndicatorFilter}}" data-provenance="{{.ProvenanceFilter}}" data-credentials="{{.CredentialFilter}}" data-runners="{{.RunnerFilter}}"><td>{{.Repository}}</td><td>{{.Workflow}}<br><code>run={{.RunID}} attempt={{.RunAttempt}} job={{.JobID}} step={{.StepIdentity}}</code></td><td><span class="state">{{.State}}</span><br>{{.Provenance}}</td><td>{{.Conclusion}}{{range .EvidenceGaps}}<div class="warning">Gap: {{.}}</div>{{end}}</td><td>{{range .EvidenceIDs}}<code>{{.}}</code><br>{{end}}</td></tr>{{end}}</tbody></table></section>
<section><h2>Credential, runner, and resource context</h2>{{range .Findings}}<details data-finding-item data-revision="{{.FindingRevisionID}}" data-state="{{.StateFilter}}" data-repository="{{.RepositoryFilter}}" data-indicator="{{.IndicatorFilter}}" data-provenance="{{.ProvenanceFilter}}" data-credentials="{{.CredentialFilter}}" data-runners="{{.RunnerFilter}}"><summary>{{.State}} — {{.Repository}} / run {{.RunID}} attempt {{.RunAttempt}} job {{.JobID}}</summary>{{range .CredentialExposure}}<p><strong>{{.Kind}}</strong> {{.Name}}: {{.Conclusion}} <span class="muted">Basis: {{.Basis}}.</span></p>{{end}}{{range .ResourceExposure}}<p><strong>{{.Kind}}</strong> {{.Name}}: {{.Conclusion}} <span class="muted">Basis: {{.Basis}}.</span></p>{{end}}{{if .RemediationGuidance}}<h3>Remediation guidance</h3>{{range .RemediationGuidance}}<p>{{.}}</p>{{end}}{{end}}</details>{{end}}</section>
<section><h2>Focused evidence graph</h2><p>Relationships are typed; every displayed edge carries one or more evidence IDs. Filters hide graph items outside the selected finding subgraph.</p><div class="graph"><div><h3>Nodes</h3><ul>{{range .Nodes}}<li data-graph-item data-findings="{{.Focus}}"><code>{{.Type}}:{{.ID}}</code> — {{.Label}}</li>{{end}}</ul></div><div><h3>Evidence-backed edges</h3><ul>{{range .Edges}}<li data-graph-item data-findings="{{.Focus}}"><code>{{.Type}}</code>: {{.Source}} → {{.Target}} ({{range .EvidenceIDs}}{{.}} {{end}})</li>{{end}}</ul></div></div></section>
<section><h2>Methodology and limitations</h2><ul>{{range .Invariants}}<li>{{.}}</li>{{end}}</ul><p>CIRewind reports evidence-backed capability and reachability, not exploitation, exfiltration, cloud-role assumption, runner persistence, or downstream causation unless independent direct evidence establishes it.</p><p>The case manifest supports SHA-256 integrity verification. It is not an authenticity signature or legal chain-of-custody certification.</p></section></main><script>` + filterScript + `</script></body></html>`))

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

func normalizeExposures(values []Exposure) ([]Exposure, error) {
	if values == nil {
		return []Exposure{}, nil
	}
	for index := range values {
		exposure := &values[index]
		if exposure.Kind == "" || exposure.Basis == "" || exposure.Conclusion == "" || len(exposure.EvidenceIDs) == 0 {
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
