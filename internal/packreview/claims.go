package packreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
)

type materialItem struct {
	Pointer           string
	Selector          string
	Role              string
	Value             any
	RequiredSourceIDs []string
	SourcePrecision   string
	Approximation     string
}

type omissionItem struct {
	Slot            string
	Selector        string
	Role            string
	SourcePrecision string
	Approximation   string
}

func validateClaims(ledger ClaimLedger, validated *incident.ValidatedPack, sources SourceLedger, conflicts ConflictLedger, packet Packet, p *problems) {
	if ledger.SchemaVersion != ClaimsSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", ClaimsSchema)
	}
	if len(ledger.Claims) == 0 || len(ledger.Claims) > 20_000 {
		p.add("CLAIM_COUNT", "/claims", "must contain 1-20000 claims")
	}
	items := materialInventory(validated.Pack)
	omissions := omissionInventory(validated.Pack)
	materialByPointer := make(map[string]materialItem, len(items))
	for _, item := range items {
		materialByPointer[item.Pointer] = item
	}

	sourceByID := make(map[string]SourceRecord, len(sources.Sources))
	for _, source := range sources.Sources {
		sourceByID[source.SourceID] = source
	}
	conflictByID := make(map[string]Conflict, len(conflicts.Conflicts))
	for _, conflict := range conflicts.Conflicts {
		conflictByID[conflict.ConflictID] = conflict
	}

	claimByID := map[string]Claim{}
	claimIndexByID := map[string]int{}
	pointerOwner := map[string]string{}
	selectorOwner := map[string]string{}
	covered := map[string]struct{}{}
	usedSources := map[string]struct{}{}
	for index, claim := range ledger.Claims {
		base := fmt.Sprintf("/claims/%d", index)
		validateID(claim.ClaimID, base+"/claimId", p)
		if _, exists := claimByID[claim.ClaimID]; exists {
			p.add("DUPLICATE_CLAIM", base+"/claimId", "duplicate claim ID")
		}
		claimByID[claim.ClaimID] = claim
		claimIndexByID[claim.ClaimID] = index
		if !semanticSelectorRE.MatchString(claim.SemanticSelector) {
			p.add("SEMANTIC_SELECTOR", base+"/semanticSelector", "must be a bounded stable semantic selector")
		}
		if first, exists := selectorOwner[claim.SemanticSelector]; exists {
			p.add("DUPLICATE_SELECTOR", base+"/semanticSelector", "selector already belongs to claim %s", first)
		} else {
			selectorOwner[claim.SemanticSelector] = claim.ClaimID
		}
		validateClaimRole(claim.SemanticRole, base+"/semanticRole", p)
		validateSortedUniqueIDs(claim.SourceIDs, base+"/sourceIds", p)
		if len(claim.SourceIDs) == 0 {
			p.add("CLAIM_SOURCES", base+"/sourceIds", "at least one direct source is required")
		}
		for _, sourceID := range claim.SourceIDs {
			if _, ok := sourceByID[sourceID]; !ok {
				p.add("UNKNOWN_SOURCE", base+"/sourceIds", "references unknown source ID %s", sourceID)
			} else {
				usedSources[sourceID] = struct{}{}
			}
		}
		validateSourceLocations(claim, base, sourceByID, p)
		switch claim.Transformation {
		case "verbatim", "normalized", "mechanically-extracted", "reviewer-derived":
		default:
			p.add("TRANSFORMATION", base+"/transformation", "unsupported transformation")
		}
		if claim.Transformation != "verbatim" {
			validateText(claim.Derivation, 1, 4096, true, base+"/derivation", p)
		} else if claim.Derivation != "" {
			p.add("VERBATIM_DERIVATION", base+"/derivation", "verbatim claims must omit derivation")
		}
		if claim.SourcePrecision != "" && !validPrecision(claim.SourcePrecision) {
			p.add("TIME_PRECISION", base+"/sourcePrecision", "unsupported source precision")
		}
		if claim.Approximation != "" {
			switch claim.Approximation {
			case "exact", "source-rounded", "conservative-expanded", "unknown":
			default:
				p.add("APPROXIMATION", base+"/approximation", "unsupported approximation")
			}
		}
		validateSortedUniqueIDs(claim.ConflictIDs, base+"/conflictIds", p)
		for _, conflictID := range claim.ConflictIDs {
			if _, ok := conflictByID[conflictID]; !ok {
				p.add("UNKNOWN_CONFLICT", base+"/conflictIds", "references unknown conflict ID %s", conflictID)
			}
		}
		validateText(claim.AuthorAssessment.Rationale, 1, 4096, true, base+"/authorAssessment/rationale", p)

		if claim.CanonicalPointer == nil {
			validateOmissionClaim(claim, base, omissions, sourceByID, p)
			continue
		}
		validatePresentClaim(claim, base, validated.CanonicalJSON, materialByPointer, pointerOwner, covered, sourceByID, p)
	}

	for _, item := range items {
		if _, ok := covered[item.Pointer]; !ok {
			p.add("UNMAPPED_MATERIAL_FIELD", item.Pointer, "material field %s has no claim row", item.Selector)
		}
	}
	validateClaimConflictClosure(ledger, conflicts, claimByID, claimIndexByID, usedSources, sourceByID, p)
	validatePackSources(validated.Pack, sourceByID, usedSources, p)
	if !equalStrings(packet.ConflictIDs, conflictIDs(conflicts)) {
		p.add("PACKET_CONFLICT_SET", "/packet/conflictIds", "packet conflictIds must exactly equal conflicts.json IDs")
	}
}

func validatePresentClaim(claim Claim, base string, canonicalPack []byte, items map[string]materialItem, pointerOwner map[string]string, covered map[string]struct{}, sources map[string]SourceRecord, p *problems) {
	pointer := *claim.CanonicalPointer
	if err := validateRFC6901(pointer); err != nil {
		p.add("JSON_POINTER", base+"/canonicalPointer", "%v", err)
		return
	}
	if claim.OmittedSlot != "" {
		p.add("PRESENT_WITH_OMISSION", base+"/omittedSlot", "present claims must omit omittedSlot")
	}
	if claim.AuthorAssessment.Decision != "inclusion" {
		p.add("PRESENT_ASSESSMENT", base+"/authorAssessment/decision", "present claims require inclusion")
	}
	if first, exists := pointerOwner[pointer]; exists {
		p.add("DUPLICATE_POINTER", base+"/canonicalPointer", "pointer already belongs to claim %s", first)
	} else {
		pointerOwner[pointer] = claim.ClaimID
	}
	item, material := items[pointer]
	if !material {
		p.add("NON_MATERIAL_POINTER", base+"/canonicalPointer", "pointer is not in the closed material-field inventory")
		return
	}
	covered[pointer] = struct{}{}
	if claim.SemanticSelector != item.Selector {
		p.add("SELECTOR_MISMATCH", base+"/semanticSelector", "does not match the material field selector")
	}
	if claim.SemanticRole != item.Role {
		p.add("ROLE_MISMATCH", base+"/semanticRole", "must be %s for this material field", item.Role)
	}
	resolved, err := resolvePointer(canonicalPack, pointer)
	if err != nil {
		p.add("POINTER_RESOLUTION", base+"/canonicalPointer", "%v", err)
		return
	}
	if !scalarEqual(resolved, item.Value) {
		p.add("INVENTORY_POINTER_DRIFT", base+"/canonicalPointer", "resolved value disagrees with typed material inventory")
	}
	validateClaimValueBinding(claim, resolved, base, p)
	if !containsAll(claim.SourceIDs, item.RequiredSourceIDs) {
		p.add("SOURCE_BINDING", base+"/sourceIds", "claim omits a pack-declared direct source")
	}
	if item.SourcePrecision != "" {
		if claim.SourcePrecision != item.SourcePrecision {
			p.add("PRECISION_MISMATCH", base+"/sourcePrecision", "must equal pack sourcePrecision %s", item.SourcePrecision)
		}
		if claim.Approximation != item.Approximation {
			p.add("APPROXIMATION_MISMATCH", base+"/approximation", "must equal pack approximation %s", item.Approximation)
		}
		if !sourcePrecisionSupports(claim.SourceIDs, claim.SourcePrecision, sources) {
			p.add("FABRICATED_PRECISION", base+"/sourcePrecision", "no direct source supports this temporal precision")
		}
	} else if claim.SourcePrecision != "" || claim.Approximation != "" {
		p.add("NON_TEMPORAL_PRECISION", base, "non-temporal claim must omit precision and approximation")
	}
	if criticalRole(item.Role) && onlySecondarySources(claim.SourceIDs, sources) {
		p.add("SECONDARY_ONLY", base+"/sourceIds", "critical matching claim cannot rely only on secondary leads")
	}
}

func validateOmissionClaim(claim Claim, base string, omissions map[string]omissionItem, sources map[string]SourceRecord, p *problems) {
	if claim.OmittedSlot == "" {
		p.add("OMISSION_SLOT", base+"/omittedSlot", "omission claim requires a closed omittedSlot")
	} else {
		switch claim.OmittedSlot {
		case "known-good-identity", "window-start", "window-end", "immutable-package-digest", "affected-ref", "remediation-guidance", "credential-rotation-trigger", "ioc", "component-subpath":
		default:
			p.add("OMISSION_SLOT", base+"/omittedSlot", "unsupported omitted slot")
		}
	}
	if claim.NormalizedValue != nil || claim.ValueSHA256 != "" {
		p.add("OMISSION_VALUE", base, "omission claims must not carry a value")
	}
	if claim.AuthorAssessment.Decision != "omission" && claim.AuthorAssessment.Decision != "blocked" {
		p.add("OMISSION_ASSESSMENT", base+"/authorAssessment/decision", "omission claim requires omission or blocked")
	}
	item, absent := omissions[claim.SemanticSelector]
	if !absent {
		p.add("OMISSION_NOT_ABSENT", base+"/semanticSelector", "selector does not identify a closed semantic slot that is absent from this pack")
		return
	}
	if claim.OmittedSlot != item.Slot {
		p.add("OMISSION_SLOT_MISMATCH", base+"/omittedSlot", "must equal %s for the selected absent slot", item.Slot)
	}
	if claim.SemanticRole != item.Role {
		p.add("OMISSION_ROLE_MISMATCH", base+"/semanticRole", "must equal %s for the selected absent slot", item.Role)
	}
	if item.SourcePrecision != "" {
		if claim.SourcePrecision != item.SourcePrecision || claim.Approximation != item.Approximation {
			p.add("OMISSION_TEMPORAL_PRECISION", base, "absent window endpoint must retain its window sourcePrecision and approximation")
		}
		if !sourcePrecisionSupports(claim.SourceIDs, claim.SourcePrecision, sources) {
			p.add("FABRICATED_PRECISION", base+"/sourcePrecision", "no direct source supports this temporal precision")
		}
	} else if claim.SourcePrecision != "" || claim.Approximation != "" {
		p.add("NON_TEMPORAL_PRECISION", base, "non-temporal omission must omit precision and approximation")
	}
}

func omissionInventory(pack incident.Pack) map[string]omissionItem {
	result := make(map[string]omissionItem)
	add := func(slot, selector, role, precision, approximation string) {
		result[selector] = omissionItem{Slot: slot, Selector: selector, Role: role, SourcePrecision: precision, Approximation: approximation}
	}
	indicatorsByComponent := make(map[string][]incident.Indicator)
	knownGoodByComponent := make(map[string]int)
	for _, indicator := range pack.Spec.Indicators {
		indicatorsByComponent[indicator.ComponentID] = append(indicatorsByComponent[indicator.ComponentID], indicator)
	}
	for _, known := range pack.Spec.KnownGood {
		knownGoodByComponent[known.ComponentID]++
	}
	for _, component := range pack.Spec.Components {
		prefix := "component:" + component.ID + "/omission:"
		if len(component.Subpaths) == 0 {
			add("component-subpath", prefix+"subpath", "subpath", "", "")
		}
		hasMutableRef, hasDigest := false, false
		for _, indicator := range indicatorsByComponent[component.ID] {
			switch indicator.Kind {
			case "mutable-action-ref", "mutable-workflow-ref":
				hasMutableRef = true
			case "digest":
				hasDigest = true
			}
		}
		if !hasMutableRef {
			add("affected-ref", prefix+"affected-ref", "ref", "", "")
		}
		if knownGoodByComponent[component.ID] == 0 {
			add("known-good-identity", prefix+"known-good-identity", "known-good-sha", "", "")
		}
		if !hasDigest {
			add("immutable-package-digest", prefix+"immutable-package-digest", "package-digest", "", "")
		}
	}
	for _, window := range pack.Spec.Windows {
		if window.Start == "" {
			add("window-start", "window:"+window.ID+"/field:start", "window", window.SourcePrecision, window.Approximation)
		}
		if window.End == "" {
			add("window-end", "window:"+window.ID+"/field:end", "window", window.SourcePrecision, window.Approximation)
		}
	}
	hasIOC := false
	for _, indicator := range pack.Spec.Indicators {
		switch indicator.Kind {
		case "log-literal", "domain", "ip-address", "repository-name", "release-version":
			hasIOC = true
		}
	}
	incidentPrefix := "incident:" + pack.Metadata.ID + "/omission:"
	if !hasIOC {
		add("ioc", incidentPrefix+"ioc", "ioc", "", "")
	}
	if pack.Spec.Remediation == nil || len(pack.Spec.Remediation.Guidance) == 0 {
		add("remediation-guidance", incidentPrefix+"remediation-guidance", "remediation", "", "")
	}
	if pack.Spec.Remediation == nil || len(pack.Spec.Remediation.CredentialRotationTriggers) == 0 {
		add("credential-rotation-trigger", incidentPrefix+"credential-rotation-trigger", "rotation-trigger", "", "")
	}
	return result
}

func validateClaimValueBinding(claim Claim, value any, base string, p *problems) {
	if (claim.NormalizedValue == nil) == (claim.ValueSHA256 == "") {
		p.add("VALUE_BINDING", base, "exactly one of normalizedValue or valueSha256 is required")
		return
	}
	if claim.NormalizedValue != nil {
		want, ok := normalizedScalar(value)
		if !ok {
			p.add("NON_SCALAR_POINTER", base+"/canonicalPointer", "claims may point only to scalar values")
			return
		}
		if *claim.NormalizedValue != want {
			p.add("NORMALIZED_VALUE", base+"/normalizedValue", "does not match the canonical pointed value")
		}
		validateText(*claim.NormalizedValue, 1, 16_384, true, base+"/normalizedValue", p)
		return
	}
	validateSHA256(claim.ValueSHA256, base+"/valueSha256", p)
	canonical, err := evidence.CanonicalJSON(value)
	if err != nil {
		p.add("VALUE_CANONICALIZATION", base+"/valueSha256", "pointed value cannot be canonicalized")
		return
	}
	digest := sha256.Sum256(canonical)
	if claim.ValueSHA256 != hex.EncodeToString(digest[:]) {
		p.add("VALUE_HASH", base+"/valueSha256", "does not match the canonical pointed scalar")
	}
}

func validateSourceLocations(claim Claim, base string, sources map[string]SourceRecord, p *problems) {
	if len(claim.SourceLocations) != len(claim.SourceIDs) {
		p.add("SOURCE_LOCATION_COUNT", base+"/sourceLocations", "requires exactly one location per source ID")
	}
	seen := map[string]struct{}{}
	for i, location := range claim.SourceLocations {
		path := fmt.Sprintf("%s/sourceLocations/%d", base, i)
		validateID(location.SourceID, path+"/sourceId", p)
		if _, ok := sources[location.SourceID]; !ok {
			p.add("UNKNOWN_SOURCE", path+"/sourceId", "references unknown source")
		}
		if _, ok := seen[location.SourceID]; ok {
			p.add("DUPLICATE_SOURCE_LOCATION", path+"/sourceId", "source location repeated")
		}
		seen[location.SourceID] = struct{}{}
		validateText(location.Location, 1, 1000, false, path+"/location", p)
	}
	for _, sourceID := range claim.SourceIDs {
		if _, ok := seen[sourceID]; !ok {
			p.add("MISSING_SOURCE_LOCATION", base+"/sourceLocations", "missing location for source %s", sourceID)
		}
	}
}

func validateClaimConflictClosure(ledger ClaimLedger, conflicts ConflictLedger, claims map[string]Claim, indexes map[string]int, usedSources map[string]struct{}, sources map[string]SourceRecord, p *problems) {
	for conflictIndex, conflict := range conflicts.Conflicts {
		base := fmt.Sprintf("/conflicts/%d", conflictIndex)
		for _, sourceID := range conflict.CompetingSourceIDs {
			if _, ok := sources[sourceID]; !ok {
				p.add("UNKNOWN_CONFLICT_SOURCE", base+"/competingSourceIds", "references unknown source %s", sourceID)
			} else {
				usedSources[sourceID] = struct{}{}
			}
		}
		hasOmission := false
		for _, claimID := range conflict.ClaimIDs {
			claim, ok := claims[claimID]
			if !ok {
				p.add("UNKNOWN_CONFLICT_CLAIM", base+"/claimIds", "references unknown claim %s", claimID)
				continue
			}
			if !containsString(claim.ConflictIDs, conflict.ConflictID) {
				p.add("ASYMMETRIC_CONFLICT", fmt.Sprintf("/claims/%d/conflictIds", indexes[claimID]), "claim omits conflict %s", conflict.ConflictID)
			}
			if claim.CanonicalPointer == nil && (claim.AuthorAssessment.Decision == "omission" || claim.AuthorAssessment.Decision == "blocked") {
				hasOmission = true
			}
			if conflict.Disposition == "excluded" && claim.AuthorAssessment.Decision == "inclusion" {
				p.add("EXCLUDED_CONFLICT_INCLUDED", base+"/disposition", "excluded conflict cannot retain an included claim")
			}
			if conflict.Disposition == "encoded-uncertain" && (claim.SourcePrecision == "" || claim.Approximation == "exact") {
				p.add("UNCERTAINTY_NOT_ENCODED", base+"/disposition", "encoded-uncertain conflict requires visible precision and non-exact approximation")
			}
		}
		if conflict.Disposition == "excluded" && !hasOmission {
			p.add("EXCLUDED_WITHOUT_OMISSION", base+"/disposition", "excluded conflict requires a linked omission or blocked claim")
		}
		if conflict.Disposition == "resolved" {
			selected, ok := claims[conflict.SelectedClaimID]
			if !ok || !containsString(conflict.ClaimIDs, conflict.SelectedClaimID) {
				p.add("RESOLUTION_CLAIM", base+"/selectedClaimId", "selected claim must be one of the conflict claim IDs")
			}
			for _, sourceID := range conflict.SelectedSourceIDs {
				if !containsString(conflict.CompetingSourceIDs, sourceID) {
					p.add("RESOLUTION_SOURCE", base+"/selectedSourceIds", "selected source %s is not a competing source", sourceID)
				}
				if ok && !containsString(selected.SourceIDs, sourceID) {
					p.add("RESOLUTION_SOURCE_BINDING", base+"/selectedSourceIds", "selected source %s does not directly support selected claim", sourceID)
				}
			}
		}
	}
	for sourceID := range sources {
		if _, ok := usedSources[sourceID]; !ok {
			p.add("ORPHAN_SOURCE", "/sources", "source %s supports no claim or conflict", sourceID)
		}
	}
	_ = ledger
}

func validatePackSources(pack incident.Pack, sources map[string]SourceRecord, usedSources map[string]struct{}, p *problems) {
	packIDs := map[string]struct{}{}
	for i, source := range pack.Metadata.Sources {
		packIDs[source.ID] = struct{}{}
		ledger, ok := sources[source.ID]
		if !ok {
			p.add("MISSING_LEDGER_SOURCE", fmt.Sprintf("/pack/metadata/sources/%d", i), "pack source has no sources.json record")
			continue
		}
		if ledger.Locator != source.URL || ledger.Publisher != source.Publisher || ledger.Title != source.Title {
			p.add("SOURCE_LEDGER_DRIFT", fmt.Sprintf("/sources/%s", source.ID), "source ledger identity disagrees with pack metadata")
		}
		if source.SourceSHA256 != "" && ledger.ReviewedSHA256 != source.SourceSHA256 {
			p.add("SOURCE_HASH_DRIFT", fmt.Sprintf("/sources/%s/reviewedSha256", source.ID), "source hash disagrees with pack metadata")
		}
		if source.SourceRevision != "" && ledger.ImmutableRevision != source.SourceRevision {
			p.add("SOURCE_REVISION_DRIFT", fmt.Sprintf("/sources/%s/immutableRevision", source.ID), "source revision disagrees with pack metadata")
		}
		if _, used := usedSources[source.ID]; !used {
			p.add("UNUSED_PACK_SOURCE", fmt.Sprintf("/pack/metadata/sources/%d", i), "pack source is not directly cited by a material claim")
		}
	}
	for sourceID := range sources {
		if _, ok := packIDs[sourceID]; !ok {
			p.add("LEDGER_SOURCE_NOT_IN_PACK", "/sources", "source %s is absent from pack metadata", sourceID)
		}
	}
}

func materialInventory(pack incident.Pack) []materialItem {
	var result []materialItem
	add := func(pointer, selector, role string, value any, sources []string) {
		result = append(result, materialItem{Pointer: pointer, Selector: selector, Role: role, Value: value, RequiredSourceIDs: sortedCopy(sources)})
	}
	// Display and summary fields still require a direct claim source, but they
	// do not implicitly require every source listed in pack metadata.
	add("/metadata/title", "incident:metadata/field:title", "other", pack.Metadata.Title, nil)
	add("/metadata/publishedAt", "incident:metadata/field:published-at", "other", pack.Metadata.PublishedAt, nil)
	add("/metadata/updatedAt", "incident:metadata/field:updated-at", "other", pack.Metadata.UpdatedAt, nil)
	add("/spec/description", "incident:spec/field:description", "other", pack.Spec.Description, nil)
	for i, component := range pack.Spec.Components {
		prefix := fmt.Sprintf("/spec/components/%d", i)
		selector := "component:" + component.ID
		add(prefix+"/type", selector+"/field:type", "component", component.Type, nil)
		add(prefix+"/repository/owner", selector+"/repository:owner", "component", component.Repository.Owner, nil)
		add(prefix+"/repository/name", selector+"/repository:name", "component", component.Repository.Name, nil)
		if component.Repository.ID != nil {
			add(prefix+"/repository/id", selector+"/repository:id", "component", *component.Repository.ID, nil)
		}
		for j, subpath := range component.Subpaths {
			add(fmt.Sprintf("%s/subpaths/%d", prefix, j), selector+"/subpath:"+subpath, "subpath", subpath, nil)
		}
		for j, workflowPath := range component.WorkflowPaths {
			add(fmt.Sprintf("%s/workflowPaths/%d", prefix, j), selector+"/workflow-path:"+workflowPath, "subpath", workflowPath, nil)
		}
	}
	for i, window := range pack.Spec.Windows {
		prefix := fmt.Sprintf("/spec/windows/%d", i)
		selector := "window:" + window.ID
		appendWindowItem := func(field string, value any, temporalEndpoint bool) {
			item := materialItem{Pointer: prefix + "/" + field, Selector: selector + "/field:" + strings.ToLower(field), Role: "window", Value: value, RequiredSourceIDs: sortedCopy(window.SourceRefs)}
			if temporalEndpoint {
				item.SourcePrecision = window.SourcePrecision
				item.Approximation = window.Approximation
			}
			result = append(result, item)
		}
		if window.Start != "" {
			appendWindowItem("start", window.Start, true)
		}
		if window.End != "" {
			appendWindowItem("end", window.End, true)
		}
		appendWindowItem("bounds", window.Bounds, false)
		appendWindowItem("sourcePrecision", window.SourcePrecision, false)
		appendWindowItem("approximation", window.Approximation, false)
		if window.OriginalClaim != "" {
			appendWindowItem("originalClaim", window.OriginalClaim, false)
		}
	}
	for i, indicator := range pack.Spec.Indicators {
		prefix := fmt.Sprintf("/spec/indicators/%d", i)
		selector := "indicator:" + indicator.ID
		role := indicatorRole(indicator.Kind)
		add(prefix+"/componentId", selector+"/field:component", role, indicator.ComponentID, indicator.SourceRefs)
		add(prefix+"/kind", selector+"/field:kind", role, indicator.Kind, indicator.SourceRefs)
		appendIndicatorValue(&result, prefix+"/value", selector, role, indicator.Value, indicator.SourceRefs)
		for j, window := range indicator.WindowRefs {
			add(fmt.Sprintf("%s/windowRefs/%d", prefix, j), selector+"/window:"+window, "window", window, indicator.SourceRefs)
		}
		add(prefix+"/confidence", selector+"/field:confidence", role, indicator.Confidence, indicator.SourceRefs)
	}
	for i, known := range pack.Spec.KnownGood {
		prefix := fmt.Sprintf("/spec/knownGood/%d", i)
		selector := "known-good:" + known.ID
		role := "known-good-sha"
		if known.Kind == "digest" {
			role = "package-digest"
		}
		add(prefix+"/componentId", selector+"/field:component", role, known.ComponentID, known.SourceRefs)
		add(prefix+"/kind", selector+"/field:kind", role, known.Kind, known.SourceRefs)
		appendIndicatorValue(&result, prefix+"/value", selector, role, known.Value, known.SourceRefs)
		add(prefix+"/confidence", selector+"/field:confidence", role, known.Confidence, known.SourceRefs)
	}
	if remediation := pack.Spec.Remediation; remediation != nil {
		for i, guidance := range remediation.Guidance {
			add(fmt.Sprintf("/spec/remediation/guidance/%d", i), fmt.Sprintf("remediation:guidance/%d", i), "remediation", guidance, nil)
		}
		for i, trigger := range remediation.CredentialRotationTriggers {
			prefix := fmt.Sprintf("/spec/remediation/credentialRotationTriggers/%d", i)
			selector := "rotation-trigger:" + trigger.ID
			for j, state := range trigger.WhenStates {
				add(fmt.Sprintf("%s/whenStates/%d", prefix, j), selector+"/state:"+string(state), "rotation-trigger", state, trigger.SourceRefs)
			}
			add(prefix+"/guidance", selector+"/field:guidance", "rotation-trigger", trigger.Guidance, trigger.SourceRefs)
			add(prefix+"/confidence", selector+"/field:confidence", "rotation-trigger", trigger.Confidence, trigger.SourceRefs)
		}
	}
	return result
}

func appendIndicatorValue(result *[]materialItem, prefix, selector, role string, value incident.IndicatorValue, sources []string) {
	add := func(field string, item any) {
		*result = append(*result, materialItem{Pointer: prefix + "/" + field, Selector: selector + "/value:" + strings.ReplaceAll(field, "/", "."), Role: role, Value: item, RequiredSourceIDs: sortedCopy(sources)})
	}
	if value.GitObject != nil {
		add("gitObject/algorithm", value.GitObject.Algorithm)
		add("gitObject/value", value.GitObject.Value)
	}
	for _, fieldValue := range []struct{ field, item string }{
		{"ref", value.Ref}, {"path", value.Path}, {"subject", value.Subject}, {"algorithm", value.Algorithm},
		{"digest", value.Digest}, {"platform", value.Platform}, {"literal", value.Literal}, {"scope", value.Scope},
		{"domain", value.Domain}, {"match", value.Match}, {"address", value.Address}, {"owner", value.Owner},
		{"name", value.Name}, {"version", value.Version},
	} {
		field, item := fieldValue.field, fieldValue.item
		if item != "" {
			add(field, item)
		}
	}
	if value.CaseSensitive != nil {
		add("caseSensitive", *value.CaseSensitive)
	}
}

func indicatorRole(kind string) string {
	switch kind {
	case "action-commit", "reusable-workflow-commit":
		return "compromised-sha"
	case "mutable-action-ref", "mutable-workflow-ref":
		return "ref"
	case "digest":
		return "package-digest"
	case "log-literal":
		return "literal"
	case "domain", "ip-address", "repository-name", "release-version":
		return "ioc"
	default:
		return "other"
	}
}

func validateClaimRole(role, pointer string, p *problems) {
	switch role {
	case "component", "subpath", "ref", "compromised-sha", "package-digest", "known-good-sha", "window", "literal", "ioc", "remediation", "rotation-trigger", "other":
	default:
		p.add("SEMANTIC_ROLE", pointer, "unsupported semantic role")
	}
}

func validateRFC6901(pointer string) error {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("must be a non-root RFC 6901 pointer")
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		for i := 0; i < len(token); i++ {
			if token[i] != '~' {
				continue
			}
			if i+1 >= len(token) || token[i+1] != '0' && token[i+1] != '1' {
				return fmt.Errorf("contains an invalid RFC 6901 escape")
			}
			i++
		}
	}
	return nil
}

func resolvePointer(canonical []byte, pointer string) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var current any
	if err := decoder.Decode(&current); err != nil {
		return nil, err
	}
	for _, encoded := range strings.Split(pointer[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = value[token]
			if !ok {
				return nil, fmt.Errorf("object key is absent")
			}
		case []any:
			if token == "-" || token == "" || len(token) > 1 && token[0] == '0' {
				return nil, fmt.Errorf("array index is not canonical")
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(value) {
				return nil, fmt.Errorf("array index is out of range")
			}
			current = value[index]
		default:
			return nil, fmt.Errorf("pointer descends through a scalar")
		}
	}
	return current, nil
}

func normalizedScalar(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case json.Number:
		return typed.String(), true
	case nil:
		return "null", true
	}
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return "null", true
	}
	switch reflected.Kind() {
	case reflect.String:
		return reflected.String(), true
	case reflect.Bool:
		return strconv.FormatBool(reflected.Bool()), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(reflected.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(reflected.Uint(), 10), true
	default:
		return "", false
	}
}

func scalarEqual(left, right any) bool {
	l, okLeft := normalizedScalar(left)
	r, okRight := normalizedScalar(right)
	if !okRight {
		switch typed := right.(type) {
		case int64:
			r, okRight = strconv.FormatInt(typed, 10), true
		case fmt.Stringer:
			r, okRight = typed.String(), true
		default:
			value := reflect.ValueOf(right)
			if value.IsValid() && value.Kind() == reflect.String {
				r, okRight = value.String(), true
			}
		}
	}
	return okLeft && okRight && l == r
}

func sourcePrecisionSupports(sourceIDs []string, precision string, sources map[string]SourceRecord) bool {
	if precision == "unknown" {
		return true
	}
	want := precisionRank(precision)
	for _, sourceID := range sourceIDs {
		if got := precisionRank(sources[sourceID].StatedPrecision); got != 0 && got <= want {
			return true
		}
	}
	return false
}

func precisionRank(value string) int {
	switch value {
	case "second":
		return 1
	case "minute":
		return 2
	case "hour":
		return 3
	case "day":
		return 4
	case "unknown":
		return 5
	default:
		return 0
	}
}

func criticalRole(role string) bool {
	switch role {
	case "component", "subpath", "ref", "compromised-sha", "package-digest", "known-good-sha", "window", "ioc":
		return true
	default:
		return false
	}
}

func onlySecondarySources(ids []string, sources map[string]SourceRecord) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if sources[id].SourceClass != "secondary-lead" {
			return false
		}
	}
	return true
}

func containsAll(have, required []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, value := range have {
		set[value] = struct{}{}
	}
	for _, value := range required {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func conflictIDs(ledger ConflictLedger) []string {
	result := make([]string, 0, len(ledger.Conflicts))
	for _, conflict := range ledger.Conflicts {
		result = append(result, conflict.ConflictID)
	}
	return sortedCopy(result)
}
