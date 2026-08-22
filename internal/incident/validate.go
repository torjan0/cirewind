package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/model"
)

var (
	stableIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	metadataIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,100}$`)
	labelPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	semverPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	asciiNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

var sourceTypes = map[string]struct{}{
	"primary-advisory":         {},
	"github-advisory-database": {},
	"source-repository":        {},
	"vendor-incident-report":   {},
	"government-advisory":      {},
	"synthetic-fixture":        {},
}

var componentTypes = map[string]struct{}{
	"github-action": {}, "reusable-workflow": {}, "embedded-tool": {}, "repository": {},
}

var indicatorKinds = map[string]struct{}{
	"action-commit": {}, "reusable-workflow-commit": {}, "mutable-action-ref": {},
	"mutable-workflow-ref": {}, "digest": {}, "log-literal": {}, "domain": {},
	"ip-address": {}, "repository-name": {}, "release-version": {},
}

func validateAndNormalize(pack *Pack, loc locations, ds *diagnosticSet) {
	requirePresent(loc, ds, "$.apiVersion")
	requirePresent(loc, ds, "$.kind")
	requirePresent(loc, ds, "$.metadata")
	requirePresent(loc, ds, "$.spec")
	if pack.APIVersion != APIVersion {
		addAt(ds, loc, "UNSUPPORTED_API_VERSION", "$.apiVersion", "apiVersion must be exactly %q", APIVersion)
	}
	if pack.Kind != Kind {
		addAt(ds, loc, "INVALID_KIND", "$.kind", "kind must be exactly %q", Kind)
	}
	validateMetadata(&pack.Metadata, loc, ds)
	validateSpec(&pack.Spec, loc, ds)
	validateSourceReferenceClosure(pack, loc, ds)
	normalizeOrdering(pack)
}

func validateMetadata(m *Metadata, loc locations, ds *diagnosticSet) {
	required := []string{"id", "packVersion", "title", "publishedAt", "updatedAt", "sources"}
	for _, field := range required {
		requirePresent(loc, ds, "$.metadata."+field)
	}
	if !metadataIDPattern.MatchString(m.ID) {
		addAt(ds, loc, "INVALID_ID", "$.metadata.id", "incident ID must be 3-100 ASCII letters, digits, dot, underscore, or hyphen")
	}
	if !validSemver(m.PackVersion) {
		addAt(ds, loc, "INVALID_SEMVER", "$.metadata.packVersion", "packVersion must be canonical SemVer without a leading v")
	}
	validatePlainText(m.Title, 1, 200, false, "$.metadata.title", loc, ds)
	m.PublishedAt = normalizeTimestamp(m.PublishedAt, "$.metadata.publishedAt", loc, ds)
	m.UpdatedAt = normalizeTimestamp(m.UpdatedAt, "$.metadata.updatedAt", loc, ds)
	if published, err1 := time.Parse(time.RFC3339Nano, m.PublishedAt); err1 == nil {
		if updated, err2 := time.Parse(time.RFC3339Nano, m.UpdatedAt); err2 == nil && updated.Before(published) {
			addAt(ds, loc, "TIME_ORDER", "$.metadata.updatedAt", "updatedAt must not be earlier than publishedAt")
		}
	}
	for i := range m.Labels {
		path := fmt.Sprintf("$.metadata.labels[%d]", i)
		if !labelPattern.MatchString(m.Labels[i]) {
			addAt(ds, loc, "INVALID_LABEL", path, "label must be a lowercase conservative token")
		}
	}
	dedupeStrings(m.Labels, "$.metadata.labels", loc, ds)
	if len(m.Sources) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", "$.metadata.sources", "at least one source is required")
	}
	sourceIDs := make(map[string]struct{}, len(m.Sources))
	for i := range m.Sources {
		validateSource(&m.Sources[i], i, loc, ds)
		idPath := fmt.Sprintf("$.metadata.sources[%d].id", i)
		if _, exists := sourceIDs[m.Sources[i].ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", idPath, "duplicate source ID %q", m.Sources[i].ID)
		}
		sourceIDs[m.Sources[i].ID] = struct{}{}
	}
}

func validateSource(s *Source, index int, loc locations, ds *diagnosticSet) {
	base := fmt.Sprintf("$.metadata.sources[%d]", index)
	for _, field := range []string{"id", "type", "title", "publisher", "url", "retrievedAt"} {
		requirePresent(loc, ds, base+"."+field)
	}
	validateStableID(s.ID, base+".id", loc, ds)
	if _, ok := sourceTypes[s.Type]; !ok {
		addAt(ds, loc, "INVALID_SOURCE_TYPE", base+".type", "unsupported source type %q", s.Type)
	}
	validatePlainText(s.Title, 1, 300, false, base+".title", loc, ds)
	validatePlainText(s.Publisher, 1, 200, false, base+".publisher", loc, ds)
	s.URL = normalizeHTTPSURL(s.URL, base+".url", loc, ds)
	if _, present := loc[base+".publishedAt"]; present {
		s.PublishedAt = normalizeTimestamp(s.PublishedAt, base+".publishedAt", loc, ds)
	}
	s.RetrievedAt = normalizeTimestamp(s.RetrievedAt, base+".retrievedAt", loc, ds)
	if _, present := loc[base+".sourceRevision"]; present {
		validatePlainText(s.SourceRevision, 1, 300, false, base+".sourceRevision", loc, ds)
	}
	if _, present := loc[base+".sourceSha256"]; present {
		s.SourceSHA256 = normalizeSHA256(s.SourceSHA256, base+".sourceSha256", loc, ds)
	}
	if _, present := loc[base+".timePrecision"]; present {
		if !validPrecision(s.TimePrecision) {
			addAt(ds, loc, "INVALID_PRECISION", base+".timePrecision", "timePrecision must be second, minute, hour, day, or unknown")
		}
	}
	if _, present := loc[base+".notes"]; present {
		validatePlainText(s.Notes, 1, 4096, true, base+".notes", loc, ds)
	}
}

func validateSpec(s *Spec, loc locations, ds *diagnosticSet) {
	for _, field := range []string{"description", "components", "indicators"} {
		requirePresent(loc, ds, "$.spec."+field)
	}
	validatePlainText(s.Description, 1, 16_384, true, "$.spec.description", loc, ds)
	if len(s.Components) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", "$.spec.components", "at least one component is required")
	}
	componentIDs := make(map[string]string, len(s.Components))
	for i := range s.Components {
		validateComponent(&s.Components[i], i, loc, ds)
		path := fmt.Sprintf("$.spec.components[%d].id", i)
		if _, exists := componentIDs[s.Components[i].ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", path, "duplicate component ID %q", s.Components[i].ID)
		}
		componentIDs[s.Components[i].ID] = s.Components[i].Type
	}

	windowIDs := make(map[string]struct{}, len(s.Windows))
	for i := range s.Windows {
		validateWindow(&s.Windows[i], i, loc, ds)
		path := fmt.Sprintf("$.spec.windows[%d].id", i)
		if _, exists := windowIDs[s.Windows[i].ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", path, "duplicate window ID %q", s.Windows[i].ID)
		}
		windowIDs[s.Windows[i].ID] = struct{}{}
	}
	if len(s.Indicators) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", "$.spec.indicators", "at least one indicator is required")
	}
	indicatorIDs := make(map[string]struct{}, len(s.Indicators))
	indicatorKeys := make(map[string]string, len(s.Indicators))
	for i := range s.Indicators {
		validateIndicator(&s.Indicators[i], i, componentIDs, windowIDs, loc, ds)
		path := fmt.Sprintf("$.spec.indicators[%d].id", i)
		if _, exists := indicatorIDs[s.Indicators[i].ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", path, "duplicate indicator ID %q", s.Indicators[i].ID)
		}
		indicatorIDs[s.Indicators[i].ID] = struct{}{}
		key := claimKey(s.Indicators[i].ComponentID, s.Indicators[i].Kind, s.Indicators[i].Value)
		if first, exists := indicatorKeys[key]; exists && key != "" {
			addAt(ds, loc, "DUPLICATE_INDICATOR", path, "indicator duplicates normalized indicator %q", first)
		} else {
			indicatorKeys[key] = s.Indicators[i].ID
		}
	}

	knownIDs := make(map[string]struct{}, len(s.KnownGood))
	knownKeys := make(map[string]string, len(s.KnownGood))
	for i := range s.KnownGood {
		validateKnownGood(&s.KnownGood[i], i, componentIDs, loc, ds)
		path := fmt.Sprintf("$.spec.knownGood[%d].id", i)
		if _, exists := knownIDs[s.KnownGood[i].ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", path, "duplicate known-good ID %q", s.KnownGood[i].ID)
		}
		knownIDs[s.KnownGood[i].ID] = struct{}{}
		key := claimKey(s.KnownGood[i].ComponentID, s.KnownGood[i].Kind, s.KnownGood[i].Value)
		if affected, exists := indicatorKeys[key]; exists && key != "" {
			addAt(ds, loc, "AFFECTED_KNOWN_GOOD_CONFLICT", path, "identity is both affected by indicator %q and known-good", affected)
		}
		if first, exists := knownKeys[key]; exists && key != "" {
			addAt(ds, loc, "DUPLICATE_KNOWN_GOOD", path, "known-good identity duplicates %q", first)
		} else {
			knownKeys[key] = s.KnownGood[i].ID
		}
	}
	if s.Remediation != nil {
		validateRemediation(s.Remediation, loc, ds)
	}
}

func validateComponent(c *Component, index int, loc locations, ds *diagnosticSet) {
	base := fmt.Sprintf("$.spec.components[%d]", index)
	for _, field := range []string{"id", "type", "repository"} {
		requirePresent(loc, ds, base+"."+field)
	}
	validateStableID(c.ID, base+".id", loc, ds)
	if _, ok := componentTypes[c.Type]; !ok {
		addAt(ds, loc, "INVALID_COMPONENT_TYPE", base+".type", "unsupported component type %q", c.Type)
	}
	for _, field := range []string{"owner", "name"} {
		requirePresent(loc, ds, base+".repository."+field)
	}
	c.Repository.Owner = normalizeRepositoryName(c.Repository.Owner, base+".repository.owner", loc, ds)
	c.Repository.Name = normalizeRepositoryName(c.Repository.Name, base+".repository.name", loc, ds)
	if c.Repository.ID != nil && *c.Repository.ID <= 0 {
		addAt(ds, loc, "INVALID_REPOSITORY_ID", base+".repository.id", "repository ID must be positive")
	}
	for i := range c.Subpaths {
		p := fmt.Sprintf("%s.subpaths[%d]", base, i)
		c.Subpaths[i] = normalizeRepoPath(c.Subpaths[i], true, false, p, loc, ds)
	}
	dedupeStrings(c.Subpaths, base+".subpaths", loc, ds)
	for i := range c.WorkflowPaths {
		p := fmt.Sprintf("%s.workflowPaths[%d]", base, i)
		c.WorkflowPaths[i] = normalizeRepoPath(c.WorkflowPaths[i], false, true, p, loc, ds)
	}
	dedupeStrings(c.WorkflowPaths, base+".workflowPaths", loc, ds)
	if c.Type == "reusable-workflow" && len(c.WorkflowPaths) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", base+".workflowPaths", "reusable-workflow components require at least one exact workflow path")
	}
}

func validateWindow(w *Window, index int, loc locations, ds *diagnosticSet) {
	base := fmt.Sprintf("$.spec.windows[%d]", index)
	for _, field := range []string{"id", "bounds", "sourcePrecision", "approximation", "sourceRefs"} {
		requirePresent(loc, ds, base+"."+field)
	}
	validateStableID(w.ID, base+".id", loc, ds)
	if w.Start == "" && w.End == "" {
		addAt(ds, loc, "UNBOUNDED_WINDOW", base, "a window requires at least one endpoint")
	}
	if _, present := loc[base+".start"]; present {
		w.Start = normalizeTimestamp(w.Start, base+".start", loc, ds)
	}
	if _, present := loc[base+".end"]; present {
		w.End = normalizeTimestamp(w.End, base+".end", loc, ds)
	}
	if w.Start != "" && w.End != "" {
		start, e1 := time.Parse(time.RFC3339Nano, w.Start)
		end, e2 := time.Parse(time.RFC3339Nano, w.End)
		if e1 == nil && e2 == nil && !end.After(start) {
			addAt(ds, loc, "TIME_ORDER", base+".end", "window end must be later than start")
		}
	}
	if w.Bounds != "[)" && w.Bounds != "[]" && w.Bounds != "()" && w.Bounds != "(]" {
		addAt(ds, loc, "INVALID_BOUNDS", base+".bounds", "bounds must be one of [), [], (), or (]")
	}
	if !validPrecision(w.SourcePrecision) {
		addAt(ds, loc, "INVALID_PRECISION", base+".sourcePrecision", "sourcePrecision must be second, minute, hour, day, or unknown")
	}
	switch w.Approximation {
	case "exact", "source-rounded", "conservative-expanded", "unknown":
	default:
		addAt(ds, loc, "INVALID_APPROXIMATION", base+".approximation", "unsupported approximation %q", w.Approximation)
	}
	if w.Approximation != "exact" && strings.TrimSpace(w.OriginalClaim) == "" {
		addAt(ds, loc, "MISSING_ORIGINAL_CLAIM", base+".originalClaim", "non-exact windows require originalClaim")
	}
	if _, present := loc[base+".originalClaim"]; present {
		validatePlainText(w.OriginalClaim, 1, 4096, true, base+".originalClaim", loc, ds)
	}
	validateReferenceList(w.SourceRefs, base+".sourceRefs", loc, ds)
	if _, present := loc[base+".notes"]; present {
		validatePlainText(w.Notes, 1, 4096, true, base+".notes", loc, ds)
	}
}

func validateIndicator(ind *Indicator, index int, componentIDs map[string]string, windowIDs map[string]struct{}, loc locations, ds *diagnosticSet) {
	base := fmt.Sprintf("$.spec.indicators[%d]", index)
	for _, field := range []string{"id", "componentId", "kind", "value", "confidence", "sourceRefs"} {
		requirePresent(loc, ds, base+"."+field)
	}
	validateStableID(ind.ID, base+".id", loc, ds)
	validateComponentReference(ind.ComponentID, base+".componentId", componentIDs, loc, ds)
	if _, ok := indicatorKinds[ind.Kind]; !ok {
		addAt(ds, loc, "INVALID_INDICATOR_KIND", base+".kind", "unsupported indicator kind %q", ind.Kind)
	}
	validateConfidence(ind.Confidence, base+".confidence", loc, ds)
	validateReferenceList(ind.SourceRefs, base+".sourceRefs", loc, ds)
	if len(ind.WindowRefs) > 0 {
		validateReferenceList(ind.WindowRefs, base+".windowRefs", loc, ds)
	}
	for i, ref := range ind.WindowRefs {
		if _, ok := windowIDs[ref]; !ok {
			addAt(ds, loc, "UNKNOWN_WINDOW_REF", fmt.Sprintf("%s.windowRefs[%d]", base, i), "unknown window reference %q", ref)
		}
	}
	if (ind.Kind == "mutable-action-ref" || ind.Kind == "mutable-workflow-ref") && len(ind.WindowRefs) == 0 {
		addAt(ds, loc, "MISSING_WINDOW_REF", base+".windowRefs", "mutable-reference indicators require at least one window")
	}
	validateIndicatorValue(ind.Kind, &ind.Value, base+".value", loc, ds)
	validateComponentKind(ind.Kind, ind.ComponentID, componentIDs, base+".componentId", loc, ds)
	if _, present := loc[base+".notes"]; present {
		validatePlainText(ind.Notes, 1, 4096, true, base+".notes", loc, ds)
	}
}

func validateKnownGood(g *KnownGood, index int, componentIDs map[string]string, loc locations, ds *diagnosticSet) {
	base := fmt.Sprintf("$.spec.knownGood[%d]", index)
	for _, field := range []string{"id", "componentId", "kind", "value", "confidence", "sourceRefs"} {
		requirePresent(loc, ds, base+"."+field)
	}
	validateStableID(g.ID, base+".id", loc, ds)
	validateComponentReference(g.ComponentID, base+".componentId", componentIDs, loc, ds)
	if g.Kind != "action-commit" && g.Kind != "reusable-workflow-commit" && g.Kind != "digest" {
		addAt(ds, loc, "INVALID_KNOWN_GOOD_KIND", base+".kind", "knownGood permits only action-commit, reusable-workflow-commit, or digest")
	}
	validateConfidence(g.Confidence, base+".confidence", loc, ds)
	validateReferenceList(g.SourceRefs, base+".sourceRefs", loc, ds)
	validateIndicatorValue(g.Kind, &g.Value, base+".value", loc, ds)
	validateComponentKind(g.Kind, g.ComponentID, componentIDs, base+".componentId", loc, ds)
	if _, present := loc[base+".notes"]; present {
		validatePlainText(g.Notes, 1, 4096, true, base+".notes", loc, ds)
	}
}

func validateRemediation(r *Remediation, loc locations, ds *diagnosticSet) {
	base := "$.spec.remediation"
	requirePresent(loc, ds, base+".guidance")
	if len(r.Guidance) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", base+".guidance", "remediation guidance must not be empty")
	}
	for i, guidance := range r.Guidance {
		validatePlainText(guidance, 1, 4096, true, fmt.Sprintf("%s.guidance[%d]", base, i), loc, ds)
	}
	triggerIDs := make(map[string]struct{}, len(r.CredentialRotationTriggers))
	for i := range r.CredentialRotationTriggers {
		t := &r.CredentialRotationTriggers[i]
		p := fmt.Sprintf("%s.credentialRotationTriggers[%d]", base, i)
		for _, field := range []string{"id", "whenStates", "guidance", "confidence", "sourceRefs"} {
			requirePresent(loc, ds, p+"."+field)
		}
		validateStableID(t.ID, p+".id", loc, ds)
		if _, exists := triggerIDs[t.ID]; exists {
			addAt(ds, loc, "DUPLICATE_ID", p+".id", "duplicate rotation-trigger ID %q", t.ID)
		}
		triggerIDs[t.ID] = struct{}{}
		if len(t.WhenStates) == 0 {
			addAt(ds, loc, "REQUIRED_NONEMPTY", p+".whenStates", "rotation trigger requires at least one finding state")
		}
		seenStates := make(map[model.FindingState]int, len(t.WhenStates))
		for j, state := range t.WhenStates {
			if !state.Valid() {
				addAt(ds, loc, "INVALID_FINDING_STATE", fmt.Sprintf("%s.whenStates[%d]", p, j), "unsupported finding state %q", state)
			}
			if first, exists := seenStates[state]; exists {
				addAt(ds, loc, "DUPLICATE_VALUE", fmt.Sprintf("%s.whenStates[%d]", p, j), "duplicate finding state %q; first appears at index %d", state, first)
			} else {
				seenStates[state] = j
			}
		}
		validatePlainText(t.Guidance, 1, 4096, true, p+".guidance", loc, ds)
		validateConfidence(t.Confidence, p+".confidence", loc, ds)
		validateReferenceList(t.SourceRefs, p+".sourceRefs", loc, ds)
	}
}

func validateIndicatorValue(kind string, value *IndicatorValue, base string, loc locations, ds *diagnosticSet) {
	allowed := map[string]bool{}
	var required []string
	switch kind {
	case "action-commit":
		allowed["gitObject"] = true
		required = []string{"gitObject"}
	case "reusable-workflow-commit":
		allowed["gitObject"], allowed["path"] = true, true
		required = []string{"gitObject"}
	case "mutable-action-ref":
		allowed["ref"] = true
		required = []string{"ref"}
	case "mutable-workflow-ref":
		allowed["ref"], allowed["path"] = true, true
		required = []string{"ref", "path"}
	case "digest":
		allowed["subject"], allowed["algorithm"], allowed["digest"], allowed["path"], allowed["platform"] = true, true, true, true, true
		required = []string{"subject", "algorithm", "digest"}
	case "log-literal":
		allowed["literal"], allowed["caseSensitive"], allowed["scope"] = true, true, true
		required = []string{"literal", "caseSensitive", "scope"}
	case "domain":
		allowed["domain"], allowed["match"] = true, true
		required = []string{"domain", "match"}
	case "ip-address":
		allowed["address"] = true
		required = []string{"address"}
	case "repository-name":
		allowed["owner"], allowed["name"], allowed["path"] = true, true, true
		required = []string{"owner", "name"}
	case "release-version":
		allowed["version"] = true
		required = []string{"version"}
	default:
		return
	}
	all := []string{"gitObject", "ref", "path", "subject", "algorithm", "digest", "platform", "literal", "caseSensitive", "scope", "domain", "match", "address", "owner", "name", "version"}
	for _, field := range all {
		if _, present := loc[base+"."+field]; present && !allowed[field] {
			addAt(ds, loc, "IRRELEVANT_VALUE_FIELD", base+"."+field, "field %q is not valid for indicator kind %q", field, kind)
		}
	}
	for _, field := range required {
		requirePresent(loc, ds, base+"."+field)
	}

	if allowed["gitObject"] && value.GitObject != nil {
		requirePresent(loc, ds, base+".gitObject.algorithm")
		requirePresent(loc, ds, base+".gitObject.value")
		value.GitObject.Algorithm = strings.ToLower(value.GitObject.Algorithm)
		value.GitObject.Value = strings.ToLower(value.GitObject.Value)
		if !validGitObject(value.GitObject.Algorithm, value.GitObject.Value) {
			addAt(ds, loc, "INVALID_GIT_OBJECT", base+".gitObject", "gitObject requires sha1/40-hex or sha256/64-hex complete identity")
		}
	}
	if allowed["ref"] {
		validateGitRef(value.Ref, base+".ref", loc, ds)
	}
	if allowed["path"] {
		_, present := loc[base+".path"]
		if present {
			workflow := kind == "mutable-workflow-ref" || kind == "reusable-workflow-commit"
			value.Path = normalizeRepoPath(value.Path, false, workflow, base+".path", loc, ds)
		}
	}
	if kind == "digest" {
		value.Subject = strings.ToLower(value.Subject)
		value.Algorithm = strings.ToLower(value.Algorithm)
		value.Digest = strings.ToLower(value.Digest)
		switch value.Subject {
		case "github-action-package", "executable-file", "oci-manifest", "release-asset", "workflow-artifact":
		default:
			addAt(ds, loc, "INVALID_DIGEST_SUBJECT", base+".subject", "unsupported digest subject %q", value.Subject)
		}
		if value.Algorithm != "sha256" || !validHex(value.Digest, 64) {
			addAt(ds, loc, "INVALID_DIGEST", base+".digest", "v1alpha1 digest requires algorithm sha256 and 64 hexadecimal characters")
		}
		if _, present := loc[base+".platform"]; present {
			validatePlainText(value.Platform, 1, 200, false, base+".platform", loc, ds)
		}
	}
	if kind == "log-literal" {
		invalidLiteral := len(value.Literal) == 0 || len(value.Literal) > 4096 || !utf8.ValidString(value.Literal)
		for _, r := range value.Literal {
			if unicode.IsControl(r) || isBidiControl(r) {
				invalidLiteral = true
				break
			}
		}
		if invalidLiteral {
			addAt(ds, loc, "INVALID_LITERAL", base+".literal", "literal must be 1-4096 UTF-8 bytes without NUL, escape, or newline")
		}
		if value.CaseSensitive == nil || !*value.CaseSensitive {
			addAt(ds, loc, "UNSUPPORTED_CASE_FOLD", base+".caseSensitive", "v1alpha1 requires caseSensitive: true")
		}
		switch value.Scope {
		case "runner-control", "setup", "step", "any-retained-log":
		default:
			addAt(ds, loc, "INVALID_LITERAL_SCOPE", base+".scope", "unsupported literal scope %q", value.Scope)
		}
	}
	if kind == "domain" {
		value.Domain = normalizeDomain(value.Domain, base+".domain", loc, ds)
		if value.Match != "exact" && value.Match != "subdomains" {
			addAt(ds, loc, "INVALID_DOMAIN_MATCH", base+".match", "domain match must be exact or subdomains")
		}
	}
	if kind == "ip-address" {
		addr, err := netip.ParseAddr(value.Address)
		if err != nil {
			addAt(ds, loc, "INVALID_IP", base+".address", "address must be one canonical IPv4 or IPv6 address")
		} else {
			value.Address = addr.Unmap().String()
		}
	}
	if kind == "repository-name" {
		value.Owner = normalizeRepositoryName(value.Owner, base+".owner", loc, ds)
		value.Name = normalizeRepositoryName(value.Name, base+".name", loc, ds)
	}
	if kind == "release-version" {
		validatePlainText(value.Version, 1, 256, false, base+".version", loc, ds)
	}
}

func validateComponentKind(kind, componentID string, componentIDs map[string]string, path string, loc locations, ds *diagnosticSet) {
	componentType := componentIDs[componentID]
	if (kind == "action-commit" || kind == "mutable-action-ref") && componentType != "" && componentType != "github-action" {
		addAt(ds, loc, "COMPONENT_KIND_MISMATCH", path, "%s indicator requires a github-action component", kind)
	}
	if (kind == "reusable-workflow-commit" || kind == "mutable-workflow-ref") && componentType != "" && componentType != "reusable-workflow" {
		addAt(ds, loc, "COMPONENT_KIND_MISMATCH", path, "%s indicator requires a reusable-workflow component", kind)
	}
}

func validateComponentReference(value, path string, componentIDs map[string]string, loc locations, ds *diagnosticSet) {
	if value == "" {
		addAt(ds, loc, "COMPONENT_SCOPE_REQUIRED", path, "v1alpha1 requires componentId for every indicator and known-good identity")
		return
	}
	if _, ok := componentIDs[value]; !ok {
		addAt(ds, loc, "UNKNOWN_COMPONENT_REF", path, "unknown component reference %q", value)
	}
}

func validateConfidence(value model.ProvenanceLevel, path string, loc locations, ds *diagnosticSet) {
	if !value.Valid() {
		addAt(ds, loc, "INVALID_PROVENANCE", path, "confidence must be one of L4_CERTAIN, L3_STRONG, L2_PROBABLE, L1_POSSIBLE, or L0_UNKNOWN")
	}
}

func validateReferenceList(values []string, base string, loc locations, ds *diagnosticSet) {
	if len(values) == 0 {
		addAt(ds, loc, "REQUIRED_NONEMPTY", base, "reference list must not be empty")
		return
	}
	for i, value := range values {
		validateStableID(value, fmt.Sprintf("%s[%d]", base, i), loc, ds)
	}
	dedupeStrings(values, base, loc, ds)
}

func validateSourceReferenceClosure(pack *Pack, loc locations, ds *diagnosticSet) {
	known := make(map[string]struct{}, len(pack.Metadata.Sources))
	for _, source := range pack.Metadata.Sources {
		known[source.ID] = struct{}{}
	}
	check := func(refs []string, base string) {
		for i, ref := range refs {
			if _, ok := known[ref]; !ok {
				addAt(ds, loc, "UNKNOWN_SOURCE_REF", fmt.Sprintf("%s[%d]", base, i), "unknown source reference %q", ref)
			}
		}
	}
	for i := range pack.Spec.Windows {
		check(pack.Spec.Windows[i].SourceRefs, fmt.Sprintf("$.spec.windows[%d].sourceRefs", i))
	}
	for i := range pack.Spec.Indicators {
		check(pack.Spec.Indicators[i].SourceRefs, fmt.Sprintf("$.spec.indicators[%d].sourceRefs", i))
	}
	for i := range pack.Spec.KnownGood {
		check(pack.Spec.KnownGood[i].SourceRefs, fmt.Sprintf("$.spec.knownGood[%d].sourceRefs", i))
	}
	if pack.Spec.Remediation != nil {
		for i := range pack.Spec.Remediation.CredentialRotationTriggers {
			check(pack.Spec.Remediation.CredentialRotationTriggers[i].SourceRefs,
				fmt.Sprintf("$.spec.remediation.credentialRotationTriggers[%d].sourceRefs", i))
		}
	}
}

func normalizeOrdering(pack *Pack) {
	sort.Strings(pack.Metadata.Labels)
	sort.SliceStable(pack.Metadata.Sources, func(i, j int) bool {
		return pack.Metadata.Sources[i].ID < pack.Metadata.Sources[j].ID
	})
	for i := range pack.Spec.Components {
		sort.Strings(pack.Spec.Components[i].Subpaths)
		sort.Strings(pack.Spec.Components[i].WorkflowPaths)
	}
	sort.SliceStable(pack.Spec.Components, func(i, j int) bool {
		return pack.Spec.Components[i].ID < pack.Spec.Components[j].ID
	})
	for i := range pack.Spec.Windows {
		sort.Strings(pack.Spec.Windows[i].SourceRefs)
	}
	sort.SliceStable(pack.Spec.Windows, func(i, j int) bool {
		return pack.Spec.Windows[i].ID < pack.Spec.Windows[j].ID
	})
	for i := range pack.Spec.Indicators {
		sort.Strings(pack.Spec.Indicators[i].SourceRefs)
		sort.Strings(pack.Spec.Indicators[i].WindowRefs)
	}
	sort.SliceStable(pack.Spec.Indicators, func(i, j int) bool {
		return pack.Spec.Indicators[i].ID < pack.Spec.Indicators[j].ID
	})
	for i := range pack.Spec.KnownGood {
		sort.Strings(pack.Spec.KnownGood[i].SourceRefs)
	}
	sort.SliceStable(pack.Spec.KnownGood, func(i, j int) bool {
		return pack.Spec.KnownGood[i].ID < pack.Spec.KnownGood[j].ID
	})
	if pack.Spec.Remediation != nil {
		for i := range pack.Spec.Remediation.CredentialRotationTriggers {
			trigger := &pack.Spec.Remediation.CredentialRotationTriggers[i]
			sort.Slice(trigger.WhenStates, func(i, j int) bool { return trigger.WhenStates[i] < trigger.WhenStates[j] })
			sort.Strings(trigger.SourceRefs)
		}
		sort.SliceStable(pack.Spec.Remediation.CredentialRotationTriggers, func(i, j int) bool {
			return pack.Spec.Remediation.CredentialRotationTriggers[i].ID < pack.Spec.Remediation.CredentialRotationTriggers[j].ID
		})
	}
}

func validateStableID(value, path string, loc locations, ds *diagnosticSet) {
	if !stableIDPattern.MatchString(value) {
		addAt(ds, loc, "INVALID_ID", path, "ID must be 1-100 ASCII letters, digits, dot, underscore, or hyphen")
	}
}

func requirePresent(loc locations, ds *diagnosticSet, path string) {
	if _, ok := loc[path]; !ok {
		addAt(ds, loc, "REQUIRED_FIELD", path, "required field is missing")
	}
}

func validatePlainText(value string, minRunes, maxRunes int, multiline bool, path string, loc locations, ds *diagnosticSet) {
	if !utf8.ValidString(value) {
		addAt(ds, loc, "INVALID_UTF8", path, "text must be valid UTF-8")
		return
	}
	count := utf8.RuneCountInString(value)
	if count < minRunes || count > maxRunes {
		addAt(ds, loc, "TEXT_LENGTH", path, "text length must be between %d and %d Unicode code points", minRunes, maxRunes)
	}
	for _, r := range value {
		if (r == '\n' || r == '\t') && multiline {
			continue
		}
		if unicode.IsControl(r) || isBidiControl(r) {
			addAt(ds, loc, "CONTROL_CHARACTER", path, "plain text contains a forbidden control character")
			break
		}
	}
	if strings.Contains(value, "<") || strings.Contains(value, ">") {
		addAt(ds, loc, "ACTIVE_MARKUP", path, "embedded HTML or markup is forbidden in incident-pack prose")
	}
}

func normalizeTimestamp(value, path string, loc locations, ds *diagnosticSet) string {
	if !strings.HasSuffix(value, "Z") {
		addAt(ds, loc, "INVALID_TIMESTAMP", path, "timestamp must be a quoted RFC 3339 UTC instant ending in Z")
		return value
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		addAt(ds, loc, "INVALID_TIMESTAMP", path, "timestamp must be a quoted RFC 3339 UTC instant ending in Z")
		return value
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func normalizeHTTPSURL(value, path string, loc locations, ds *diagnosticSet) string {
	if len(value) == 0 || len(value) > 2048 {
		addAt(ds, loc, "INVALID_SOURCE_URL", path, "source URL must be a bounded HTTPS URL")
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		addAt(ds, loc, "INVALID_SOURCE_URL", path, "source URL must use HTTPS without user information, query, fragment, or non-default port")
		return value
	}
	if strings.ContainsAny(u.Host, "\r\n\t") || !isASCII(u.Hostname()) {
		addAt(ds, loc, "INVALID_SOURCE_URL", path, "source URL host is invalid")
		return value
	}
	u.Scheme = "https"
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func normalizeSHA256(value, path string, loc locations, ds *diagnosticSet) string {
	value = strings.ToLower(value)
	if !validHex(value, 64) {
		addAt(ds, loc, "INVALID_SHA256", path, "SHA-256 must contain exactly 64 hexadecimal characters")
	}
	return value
}

func normalizeRepositoryName(value, path string, loc locations, ds *diagnosticSet) string {
	if !asciiNamePattern.MatchString(value) || value == "." || value == ".." {
		addAt(ds, loc, "INVALID_REPOSITORY_NAME", path, "repository owner/name must be a bounded ASCII GitHub name")
	}
	return strings.ToLower(value)
}

func normalizeRepoPath(value string, allowRoot, workflow bool, fieldPath string, loc locations, ds *diagnosticSet) string {
	if value == "" && allowRoot {
		return value
	}
	lower := strings.ToLower(value)
	invalidEncoded := strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00")
	invalid := value == "" || len(value) > 4096 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || strings.Contains(value, "//") || invalidEncoded
	if !invalid {
		clean := path.Clean(value)
		invalid = clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../")
	}
	if workflow {
		invalid = invalid || !strings.HasPrefix(value, ".github/workflows/") || !(strings.HasSuffix(value, ".yml") || strings.HasSuffix(value, ".yaml"))
	}
	if invalid {
		kind := "repository-relative path"
		if workflow {
			kind = "exact .github/workflows/*.yml or *.yaml path"
		}
		addAt(ds, loc, "INVALID_PATH", fieldPath, "value must be a canonical %s without traversal or encoded traversal", kind)
	}
	return value
}

func validateGitRef(value, fieldPath string, loc locations, ds *diagnosticSet) {
	invalid := value == "" || len(value) > 1024 || !utf8.ValidString(value) || value == "@" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, ".lock") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") || strings.ContainsAny(value, " ~^:?*[\\")
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") || strings.HasSuffix(component, ".") {
			invalid = true
		}
	}
	lower := strings.ToLower(value)
	if validHex(lower, 40) || validHex(lower, 64) {
		invalid = true
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == 0x7f {
			invalid = true
			break
		}
	}
	if invalid {
		addAt(ds, loc, "INVALID_GIT_REF", fieldPath, "ref is not valid bounded git-check-ref-format syntax")
	}
}

func normalizeDomain(value, fieldPath string, loc locations, ds *diagnosticSet) string {
	value = strings.ToLower(value)
	invalid := value == "" || len(value) > 253 || strings.HasSuffix(value, ".") || strings.ContainsAny(value, "/:@[] ")
	if !invalid {
		for _, r := range value {
			if r > unicode.MaxASCII {
				invalid = true
				break
			}
		}
	}
	if !invalid {
		labels := strings.Split(value, ".")
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				invalid = true
				break
			}
			for _, r := range label {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
					invalid = true
					break
				}
			}
		}
	}
	if invalid {
		addAt(ds, loc, "INVALID_DOMAIN", fieldPath, "domain must already be canonical lowercase IDNA ASCII without URL components")
	}
	return value
}

func validGitObject(algorithm, value string) bool {
	switch algorithm {
	case "sha1":
		return validHex(value, 40)
	case "sha256":
		return validHex(value, 64)
	default:
		return false
	}
}

func validHex(value string, size int) bool {
	if len(value) != size || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validPrecision(value string) bool {
	return value == "second" || value == "minute" || value == "hour" || value == "day" || value == "unknown"
}

func validSemver(value string) bool {
	if !semverPattern.MatchString(value) {
		return false
	}
	main := strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(main, "-", 2)
	if len(parts) != 2 {
		return true
	}
	for _, identifier := range strings.Split(parts[1], ".") {
		allDigits := identifier != ""
		for _, r := range identifier {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func dedupeStrings(values []string, base string, loc locations, ds *diagnosticSet) {
	seen := make(map[string]int, len(values))
	for i, value := range values {
		if first, ok := seen[value]; ok {
			addAt(ds, loc, "DUPLICATE_VALUE", fmt.Sprintf("%s[%d]", base, i), "duplicate value %q; first appears at index %d", value, first)
		} else {
			seen[value] = i
		}
	}
}

func claimKey(componentID, kind string, value IndicatorValue) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return componentID + "\x00" + kind + "\x00" + hex.EncodeToString(h[:])
}

func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}
