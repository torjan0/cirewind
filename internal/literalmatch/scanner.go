package literalmatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

type logCoverage struct {
	kind     model.CoverageKind
	scope    model.CoverageScope
	id       model.CoverageAssessmentID
	status   model.CoverageStatus
	evidence []model.EvidenceID
}

type derivedEntry struct {
	id    model.EvidenceID
	scope model.CoverageScope
	event model.EventInterval
	rule  string
}

type entryScan struct {
	count int
	stats map[int]matchStat
}

// Scan evaluates all queries in one pass per retained source. Its returned
// coverage facts are derived analysis facts; callers that persist findings
// should append them to the case snapshot, not to the source archive.
func Scan(ctx context.Context, snapshot archive.Snapshot, queries []Query, source RawSource, options Options) (Result, error) {
	var result Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if source == nil {
		return result, errors.New("raw literal source is nil")
	}
	limits := options.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.validate(); err != nil {
		return result, err
	}
	queries = append([]Query(nil), queries...)
	sort.Slice(queries, func(i, j int) bool { return queries[i].IndicatorID < queries[j].IndicatorID })
	if len(queries) > limits.MaxLiterals {
		return result, fmt.Errorf("literal query count %d exceeds limit %d", len(queries), limits.MaxLiterals)
	}
	totalLiteralBytes := 0
	for index, query := range queries {
		if err := query.validate(); err != nil {
			return result, fmt.Errorf("query %d: %w", index, err)
		}
		if index > 0 && queries[index-1].IndicatorID == query.IndicatorID {
			return result, fmt.Errorf("duplicate literal indicator ID %q", query.IndicatorID)
		}
		totalLiteralBytes += len(query.Literal)
	}
	if totalLiteralBytes > limits.MaxLiteralBytes {
		return result, fmt.Errorf("literal query bytes %d exceed limit %d", totalLiteralBytes, limits.MaxLiteralBytes)
	}
	if len(queries) == 0 {
		result.Observations = []Observation{}
		result.Assessments = []Assessment{}
		result.CoverageFacts = []archive.Fact{}
		return result, nil
	}
	patterns := make([][]byte, len(queries))
	for index := range queries {
		patterns[index] = append([]byte(nil), queries[index].Literal...)
	}
	machine := newAutomaton(patterns)
	coverage, byEvidence := collectLogCoverage(snapshot)
	children := collectDerivedEntries(snapshot)

	type rawEnvelope struct {
		envelope evidence.Envelope
	}
	var sources []rawEnvelope
	for _, envelope := range snapshot.Evidence {
		kind := envelope.Evidence.LogicalSource.Kind
		if kind == evidence.SourceWorkflowRunAttemptLog || kind == evidence.SourceJobLog {
			sources = append(sources, rawEnvelope{envelope: envelope})
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].envelope.Evidence.ID < sources[j].envelope.Evidence.ID })

	usedCoverage := make(map[string]bool)
	totalBytes := int64(0)
	for sourceIndex, wrapped := range sources {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		envelope := wrapped.envelope
		kind := envelope.Evidence.LogicalSource.Kind
		applicable := applicableQueries(queries, kind)
		if len(applicable) == 0 {
			continue
		}
		refs := coverageForEvidence(byEvidence, envelope.Evidence.ID, coverageKindForSource(kind), envelope.Evidence.Scope)
		for _, queryIndex := range applicable {
			for _, ref := range refs {
				usedCoverage[coverageUseKey(queryIndex, ref.id)] = true
			}
		}
		if sourceIndex >= limits.MaxSources {
			for _, queryIndex := range applicable {
				if _, err := result.addAssessment(queries[queryIndex], subjectFromScope(envelope.Evidence.Scope), envelope.Evidence.EventTime,
					[]model.EvidenceID{envelope.Evidence.ID}, coverageIDs(refs), StatusGap, GapSourceLimit, 0); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		content := envelope.Evidence.Content
		if !content.Complete {
			for _, queryIndex := range applicable {
				if _, err := result.addAssessment(queries[queryIndex], subjectFromScope(envelope.Evidence.Scope), envelope.Evidence.EventTime,
					[]model.EvidenceID{envelope.Evidence.ID}, coverageIDs(refs), StatusGap, GapRawIncomplete, 0); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if !content.RawRetained {
			for _, queryIndex := range applicable {
				if _, err := result.addAssessment(queries[queryIndex], subjectFromScope(envelope.Evidence.Scope), envelope.Evidence.EventTime,
					[]model.EvidenceID{envelope.Evidence.ID}, coverageIDs(refs), StatusGap, GapRawNotRetained, 0); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if content.ByteLength > uint64(limits.MaxRawSourceBytes) {
			for _, queryIndex := range applicable {
				if _, err := result.addAssessment(queries[queryIndex], subjectFromScope(envelope.Evidence.Scope), envelope.Evidence.EventTime,
					[]model.EvidenceID{envelope.Evidence.ID}, coverageIDs(refs), StatusGap, GapSizeLimit, 0); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if content.ByteLength > uint64(limits.MaxTotalRawBytes-totalBytes) {
			for _, queryIndex := range applicable {
				if _, err := result.addAssessment(queries[queryIndex], subjectFromScope(envelope.Evidence.Scope), envelope.Evidence.EventTime,
					[]model.EvidenceID{envelope.Evidence.ID}, coverageIDs(refs), StatusGap, GapTotalSizeLimit, 0); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		totalBytes += int64(content.ByteLength)
		closed := coverageClosed(refs)
		if kind == evidence.SourceJobLog {
			if err := scanPlain(ctx, &result, source, envelope, queries, applicable, machine, refs, closed, limits); err != nil {
				return Result{}, err
			}
			continue
		}
		if err := scanZIP(ctx, &result, source, envelope, queries, applicable, machine, refs, closed, children, limits, options.TempDir); err != nil {
			return Result{}, err
		}
	}

	// A terminal log coverage unit without a corresponding searchable evidence
	// envelope remains a literal gap. This covers expired/deleted logs that did
	// not produce a raw object and prevents an empty source set from becoming a
	// clean negative.
	for _, ref := range coverage {
		for queryIndex, query := range queries {
			if !coverageApplicable(query.Scope, ref.kind) || usedCoverage[coverageUseKey(queryIndex, ref.id)] {
				continue
			}
			code := GapRawUnavailable
			if ref.status == model.CoverageGap {
				code = GapUnderlyingCoverage
			}
			if _, err := result.addAssessment(query, subjectFromScope(ref.scope), unknownTime(), ref.evidence,
				[]model.CoverageAssessmentID{ref.id}, StatusGap, code, 0); err != nil {
				return Result{}, err
			}
		}
	}
	result.normalize()
	return result, nil
}

func applicableQueries(queries []Query, kind evidence.SourceKind) []int {
	result := make([]int, 0, len(queries))
	for index, query := range queries {
		if kind == evidence.SourceJobLog {
			if query.Scope == ScopeAnyRetained {
				result = append(result, index)
			}
			continue
		}
		result = append(result, index)
	}
	return result
}

func scanPlain(ctx context.Context, result *Result, source RawSource, envelope evidence.Envelope, queries []Query, applicable []int, machine *automaton, refs []logCoverage, closed bool, limits Limits) error {
	matcher := machine.stream(ctx, limits.MaxRawSourceBytes)
	hasher := sha256.New()
	writer := io.MultiWriter(hasher, matcher)
	err := source.CopyRaw(ctx, envelope.Evidence.Content.SourceSHA256, writer)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	gap := GapCode("")
	if err != nil {
		gap = classifyRawError(err)
	} else if matcher.offset != envelope.Evidence.Content.ByteLength || hex.EncodeToString(hasher.Sum(nil)) != envelope.Evidence.Content.SourceSHA256 {
		gap = GapIntegrityFailure
	} else if !closed {
		gap = GapUnderlyingCoverage
	}
	subject := subjectFromScope(envelope.Evidence.Scope)
	evidenceIDs := []model.EvidenceID{envelope.Evidence.ID}
	underlying := coverageIDs(refs)
	for _, queryIndex := range applicable {
		query := queries[queryIndex]
		status := StatusAbsent
		if matcher.stats[queryIndex].found {
			status = StatusMatched
		}
		if gap != "" {
			status = StatusGap
		}
		assessmentID, addErr := result.addAssessment(query, subject, envelope.Evidence.EventTime, evidenceIDs, underlying, status, gap, matcher.offset)
		if addErr != nil {
			return addErr
		}
		stat := matcher.stats[queryIndex]
		if stat.found {
			result.Observations = append(result.Observations, Observation{
				IndicatorID: query.IndicatorID, LiteralSHA256: sha256String(query.Literal), Subject: subject,
				EventTime: envelope.Evidence.EventTime, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs),
				CoverageIDs: model.SortCoverageAssessmentIDs(append(underlying, assessmentID)),
				FirstOffset: stat.first, MatchCount: stat.count,
			})
		}
	}
	return nil
}

func scanZIP(ctx context.Context, result *Result, source RawSource, envelope evidence.Envelope, queries []Query, applicable []int, machine *automaton, refs []logCoverage, closed bool, children map[string][]derivedEntry, limits Limits, tempDir string) error {
	parentSubject := subjectFromScope(envelope.Evidence.Scope)
	parentEvidence := []model.EvidenceID{envelope.Evidence.ID}
	underlying := coverageIDs(refs)

	file, err := os.CreateTemp(tempDir, "cirewind-literal-*.zip")
	if err != nil {
		return addSourceGaps(result, queries, applicable, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, GapRawUnavailable)
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return addSourceGaps(result, queries, applicable, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, GapRawUnavailable)
	}
	hasher := sha256.New()
	bounded := &boundedHashFileWriter{file: file, hash: hasher, limit: limits.MaxRawSourceBytes}
	copyErr := source.CopyRaw(ctx, envelope.Evidence.Content.SourceSHA256, bounded)
	closeErr := file.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if copyErr != nil || closeErr != nil || uint64(bounded.written) != envelope.Evidence.Content.ByteLength || hex.EncodeToString(hasher.Sum(nil)) != envelope.Evidence.Content.SourceSHA256 {
		code := GapIntegrityFailure
		if copyErr != nil {
			code = classifyRawError(copyErr)
		} else if closeErr != nil {
			code = GapRawUnavailable
		}
		return addSourceGaps(result, queries, applicable, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, code)
	}
	opened, err := os.Open(name)
	if err != nil {
		return addSourceGaps(result, queries, applicable, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, GapRawUnavailable)
	}
	defer opened.Close()

	entries := make(map[string]*entryScan)
	anyStats := make(map[int]matchStat)
	archiveResult, archiveErr := logparse.ReadZIP(ctx, opened, bounded.written, limits.Archive, func(parseCtx context.Context, _ logparse.Entry, reader io.Reader) error {
		entryMatcher := machine.stream(parseCtx, limits.Archive.MaxEntryBytes)
		entryHash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(entryHash, entryMatcher), reader); err != nil {
			return err
		}
		key := entryKey(hex.EncodeToString(entryHash.Sum(nil)), entryMatcher.offset)
		entry := entries[key]
		if entry == nil {
			entry = &entryScan{stats: make(map[int]matchStat)}
			entries[key] = entry
		}
		entry.count++
		for index, stat := range entryMatcher.stats {
			if !stat.found {
				continue
			}
			if entry.count == 1 {
				entry.stats[index] = stat
			}
			if queries[index].Scope == ScopeAnyRetained {
				merged := anyStats[index]
				if !merged.found || stat.first < merged.first {
					merged.first = stat.first
				}
				merged.found = true
				merged.count = saturatingAdd(merged.count, stat.count)
				anyStats[index] = merged
			}
		}
		return nil
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	complete := archiveErr == nil && archiveResult.Complete && closed
	archiveGap := GapCode("")
	if archiveErr != nil || !archiveResult.Complete {
		archiveGap = GapUnsafeArchive
	} else if !closed {
		archiveGap = GapUnderlyingCoverage
	}

	// any-retained-log is a whole-source proposition. Exact child association
	// is used for a positive when unique, otherwise the match remains at the
	// attempt scope rather than trusting an archive-controlled filename.
	for _, queryIndex := range applicable {
		query := queries[queryIndex]
		if query.Scope != ScopeAnyRetained {
			continue
		}
		stat := anyStats[queryIndex]
		status := StatusAbsent
		if stat.found {
			status = StatusMatched
		}
		if !complete {
			status = StatusGap
		}
		assessmentID, err := result.addAssessment(query, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, status, archiveGap, uint64(archiveResult.BytesRead))
		if err != nil {
			return err
		}
		if stat.found {
			result.Observations = append(result.Observations, Observation{
				IndicatorID: query.IndicatorID, LiteralSHA256: sha256String(query.Literal), Subject: parentSubject,
				EventTime: envelope.Evidence.EventTime, EvidenceIDs: parentEvidence,
				CoverageIDs: model.SortCoverageAssessmentIDs(append(underlying, assessmentID)), FirstOffset: stat.first, MatchCount: stat.count,
			})
		}
	}

	// setup and step literals are accepted only when the archive entry bytes
	// join uniquely to the collector's exact parent+hash+length child envelope.
	eligible := make(map[int]int)
	for key, entry := range entries {
		childValues := children[string(envelope.Evidence.ID)+"\x00"+key]
		if entry.count != 1 || len(childValues) != 1 {
			continue
		}
		child := childValues[0]
		for _, queryIndex := range applicable {
			query := queries[queryIndex]
			wantRule := ""
			switch query.Scope {
			case ScopeSetup:
				wantRule = "attempt-log-setup-entry"
			case ScopeStep:
				wantRule = "attempt-log-action-step-entry"
			default:
				continue
			}
			if child.rule != wantRule {
				continue
			}
			eligible[queryIndex]++
			stat := entry.stats[queryIndex]
			evidenceIDs := model.SortEvidenceIDs([]model.EvidenceID{envelope.Evidence.ID, child.id})
			// Current compact facts identify these exact bounded entries, but do
			// not inventory every possible setup/shell step entry. Therefore a
			// positive is usable while absence remains an explicit coverage gap.
			assessmentID, err := result.addAssessment(query, subjectFromScope(child.scope), child.event, evidenceIDs, underlying,
				StatusGap, GapUncorrelatedEntry, uint64(archiveResult.BytesRead))
			if err != nil {
				return err
			}
			if stat.found {
				result.Observations = append(result.Observations, Observation{
					IndicatorID: query.IndicatorID, LiteralSHA256: sha256String(query.Literal), Subject: subjectFromScope(child.scope),
					EventTime: child.event, EvidenceIDs: evidenceIDs,
					CoverageIDs: model.SortCoverageAssessmentIDs(append(underlying, assessmentID)), FirstOffset: stat.first, MatchCount: stat.count,
				})
			}
		}
	}
	for _, queryIndex := range applicable {
		query := queries[queryIndex]
		if query.Scope == ScopeRunnerControl {
			if _, err := result.addAssessment(query, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, StatusGap, GapUnsupportedScope, uint64(archiveResult.BytesRead)); err != nil {
				return err
			}
			continue
		}
		if (query.Scope == ScopeSetup || query.Scope == ScopeStep) && eligible[queryIndex] == 0 {
			code := GapUncorrelatedEntry
			if archiveGap != "" {
				code = archiveGap
			}
			if _, err := result.addAssessment(query, parentSubject, envelope.Evidence.EventTime, parentEvidence, underlying, StatusGap, code, uint64(archiveResult.BytesRead)); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectLogCoverage(snapshot archive.Snapshot) ([]logCoverage, map[model.EvidenceID][]logCoverage) {
	var values []logCoverage
	byEvidence := make(map[model.EvidenceID][]logCoverage)
	for _, fact := range snapshot.Facts {
		var unit model.CoverageUnit
		var assessment model.CoverageAssessment
		switch {
		case fact.Coverage != nil:
			unit, assessment = fact.Coverage.Unit, fact.Coverage.Assessment
		case fact.CoverageGap != nil:
			unit, assessment = fact.CoverageGap.Unit, fact.CoverageGap.Assessment
		default:
			continue
		}
		if unit.Kind != model.CoverageAttemptLog && unit.Kind != model.CoverageJobLog {
			continue
		}
		value := logCoverage{kind: unit.Kind, scope: unit.Scope, id: assessment.ID, status: assessment.Status, evidence: model.SortEvidenceIDs(assessment.EvidenceIDs)}
		values = append(values, value)
		for _, evidenceID := range value.evidence {
			byEvidence[evidenceID] = append(byEvidence[evidenceID], value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].id < values[j].id })
	return values, byEvidence
}

func collectDerivedEntries(snapshot archive.Snapshot) map[string][]derivedEntry {
	result := make(map[string][]derivedEntry)
	for _, envelope := range snapshot.Evidence {
		object := envelope.Evidence
		if object.Derivation.Kind != "archive_entry_extraction" || len(object.Derivation.ParentEvidenceIDs) != 1 ||
			(object.Derivation.RuleID != "attempt-log-setup-entry" && object.Derivation.RuleID != "attempt-log-action-step-entry") {
			continue
		}
		key := string(object.Derivation.ParentEvidenceIDs[0]) + "\x00" + entryKey(object.Content.SourceSHA256, object.Content.ByteLength)
		result[key] = append(result[key], derivedEntry{id: object.ID, scope: object.Scope, event: object.EventTime, rule: object.Derivation.RuleID})
	}
	for key := range result {
		sort.Slice(result[key], func(i, j int) bool { return result[key][i].id < result[key][j].id })
	}
	return result
}

func coverageForEvidence(values map[model.EvidenceID][]logCoverage, id model.EvidenceID, kind model.CoverageKind, scope model.CoverageScope) []logCoverage {
	var result []logCoverage
	for _, value := range values[id] {
		if value.kind == kind && coverageScopeEqual(value.scope, scope) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id < result[j].id })
	return result
}

func coverageClosed(refs []logCoverage) bool {
	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		if ref.status != model.CoverageCollected {
			return false
		}
	}
	return true
}

func coverageIDs(refs []logCoverage) []model.CoverageAssessmentID {
	ids := make([]model.CoverageAssessmentID, 0, len(refs))
	for _, ref := range refs {
		ids = append(ids, ref.id)
	}
	return model.SortCoverageAssessmentIDs(ids)
}

func coverageKindForSource(kind evidence.SourceKind) model.CoverageKind {
	if kind == evidence.SourceJobLog {
		return model.CoverageJobLog
	}
	return model.CoverageAttemptLog
}

func coverageApplicable(scope Scope, kind model.CoverageKind) bool {
	if scope == ScopeAnyRetained {
		return kind == model.CoverageAttemptLog || kind == model.CoverageJobLog
	}
	return kind == model.CoverageAttemptLog
}

func coverageUseKey(queryIndex int, id model.CoverageAssessmentID) string {
	return fmt.Sprintf("%d/%s", queryIndex, id)
}

func coverageScopeEqual(left, right model.CoverageScope) bool {
	return pointerEqual(left.RepositoryID, right.RepositoryID) && pointerEqual(left.RunID, right.RunID) &&
		pointerEqual(left.RunAttempt, right.RunAttempt) && pointerEqual(left.JobID, right.JobID) &&
		left.StepKey == right.StepKey
}

func pointerEqual[T comparable](left, right *T) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func subjectFromScope(scope model.CoverageScope) archive.FactSubject {
	subject := archive.FactSubject{}
	if scope.RepositoryID != nil {
		subject.RepositoryID = *scope.RepositoryID
	}
	subject.RunID, subject.RunAttempt, subject.JobID, subject.StepKey = scope.RunID, scope.RunAttempt, scope.JobID, scope.StepKey
	return subject
}

func scopeFromSubject(subject archive.FactSubject) model.CoverageScope {
	repositoryID := subject.RepositoryID
	return model.CoverageScope{RepositoryID: &repositoryID, RunID: subject.RunID, RunAttempt: subject.RunAttempt, JobID: subject.JobID, StepKey: subject.StepKey}
}

func (r *Result) addAssessment(query Query, subject archive.FactSubject, event model.EventInterval, evidenceIDs []model.EvidenceID, underlying []model.CoverageAssessmentID, status Status, gap GapCode, bytesRead uint64) (model.CoverageAssessmentID, error) {
	evidenceIDs = model.SortEvidenceIDs(evidenceIDs)
	logicalHash, err := evidence.CanonicalSHA256(struct {
		Version       string              `json:"version"`
		IndicatorID   string              `json:"indicator_id"`
		LiteralSHA256 string              `json:"literal_sha256"`
		Scope         Scope               `json:"scope"`
		Subject       archive.FactSubject `json:"subject"`
		EvidenceIDs   []model.EvidenceID  `json:"evidence_ids"`
	}{"literal-coverage-v1", query.IndicatorID, sha256String(query.Literal), query.Scope, subject, evidenceIDs})
	if err != nil {
		return "", err
	}
	unit := model.CoverageUnit{
		ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: model.CoverageSearchableLiteral,
		Scope: scopeFromSubject(subject), LogicalKey: "literal-search:" + logicalHash, RequiredForNegative: true,
	}
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		return "", err
	}
	assessment := model.CoverageAssessment{
		ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID,
		Status: model.CoverageCollected, ObservedCount: 1, EvidenceIDs: evidenceIDs,
	}
	if status == StatusGap {
		assessment.Status = model.CoverageGap
		assessment.ObservedCount = 0
		assessment.Gap = &model.CoverageGapDetail{Reason: gapReason(gap), Material: true, SanitizedMessage: gapMessage(gap)}
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return "", err
	}
	factInput := archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: evidenceIDs, Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}}
	if status == StatusGap {
		factInput.Kind, factInput.Coverage, factInput.CoverageGap = archive.FactCoverageGap, nil, &archive.CoverageGapFact{Unit: unit, Assessment: assessment}
	}
	fact, err := archive.NormalizeFact(factInput)
	if err != nil {
		return "", err
	}
	r.CoverageFacts = append(r.CoverageFacts, fact)
	coverage := model.SortCoverageAssessmentIDs(append(append([]model.CoverageAssessmentID(nil), underlying...), assessment.ID))
	r.Assessments = append(r.Assessments, Assessment{
		IndicatorID: query.IndicatorID, Status: status, GapCode: gap, Subject: subject, EventTime: event,
		EvidenceIDs: evidenceIDs, CoverageIDs: coverage, BytesRead: bytesRead,
	})
	return assessment.ID, nil
}

func addSourceGaps(result *Result, queries []Query, applicable []int, subject archive.FactSubject, event model.EventInterval, evidenceIDs []model.EvidenceID, coverage []model.CoverageAssessmentID, code GapCode) error {
	for _, queryIndex := range applicable {
		if _, err := result.addAssessment(queries[queryIndex], subject, event, evidenceIDs, coverage, StatusGap, code, 0); err != nil {
			return err
		}
	}
	return nil
}

func gapReason(code GapCode) model.GapReason {
	switch code {
	case GapIntegrityFailure:
		return model.GapIntegrityFailure
	case GapSizeLimit, GapTotalSizeLimit, GapSourceLimit:
		return model.GapSizeLimit
	case GapUnsafeArchive, GapUnsupportedScope, GapUncorrelatedEntry:
		return model.GapUnsupportedGrammar
	default:
		return model.GapHistoricalContentGone
	}
}

func gapMessage(code GapCode) string {
	switch code {
	case GapRawNotRetained:
		return "raw log bytes were not retained; the recorded hash is not searchable content"
	case GapRawUnavailable:
		return "retained raw log bytes are missing or inaccessible"
	case GapRawIncomplete:
		return "the retained log source is incomplete"
	case GapIntegrityFailure:
		return "retained raw log bytes failed length or SHA-256 verification"
	case GapSizeLimit, GapTotalSizeLimit, GapSourceLimit:
		return "literal matching stopped at a configured source or byte limit"
	case GapUnsafeArchive:
		return "the retained attempt-log archive was unsafe, malformed, or incomplete"
	case GapUnsupportedScope:
		return "runner-control literal attribution requires a typed bounded runner span that is not retained"
	case GapUncorrelatedEntry:
		return "literal absence cannot be closed beyond entries joined by exact parent, hash, and length"
	case GapUnderlyingCoverage:
		return "underlying GitHub log collection coverage is missing or not closed"
	default:
		return "no eligible retained log source was available for literal matching"
	}
}

func classifyRawError(err error) GapCode {
	if errors.Is(err, errByteLimit) {
		return GapSizeLimit
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "sha-256") || strings.Contains(lower, "hash") || strings.Contains(lower, "length") || strings.Contains(lower, "corrupt") {
		return GapIntegrityFailure
	}
	return GapRawUnavailable
}

type boundedHashFileWriter struct {
	file    *os.File
	hash    hash.Hash
	limit   int64
	written int64
}

func (w *boundedHashFileWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > w.limit-w.written {
		return 0, errByteLimit
	}
	n, err := w.file.Write(value)
	if n > 0 {
		_, _ = w.hash.Write(value[:n])
		w.written += int64(n)
	}
	return n, err
}

func entryKey(digest string, length uint64) string { return fmt.Sprintf("%s/%d", digest, length) }

func sha256String(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func saturatingAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func unknownTime() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}

func (r *Result) normalize() {
	for index := range r.Observations {
		r.Observations[index].EvidenceIDs = model.SortEvidenceIDs(r.Observations[index].EvidenceIDs)
		r.Observations[index].CoverageIDs = model.SortCoverageAssessmentIDs(r.Observations[index].CoverageIDs)
	}
	sort.Slice(r.Observations, func(i, j int) bool {
		left, right := r.Observations[i], r.Observations[j]
		if left.IndicatorID != right.IndicatorID {
			return left.IndicatorID < right.IndicatorID
		}
		if key := compareSubject(left.Subject, right.Subject); key != 0 {
			return key < 0
		}
		if left.FirstOffset != right.FirstOffset {
			return left.FirstOffset < right.FirstOffset
		}
		return strings.Join(idsToStrings(left.EvidenceIDs), "\x00") < strings.Join(idsToStrings(right.EvidenceIDs), "\x00")
	})
	sort.Slice(r.Assessments, func(i, j int) bool {
		left, right := r.Assessments[i], r.Assessments[j]
		if left.IndicatorID != right.IndicatorID {
			return left.IndicatorID < right.IndicatorID
		}
		if key := compareSubject(left.Subject, right.Subject); key != 0 {
			return key < 0
		}
		if left.Status != right.Status {
			return left.Status < right.Status
		}
		return strings.Join(idsToStrings(left.EvidenceIDs), "\x00") < strings.Join(idsToStrings(right.EvidenceIDs), "\x00")
	})
	sort.Slice(r.CoverageFacts, func(i, j int) bool { return r.CoverageFacts[i].ID < r.CoverageFacts[j].ID })
	// Identical coverage units can be reached through deduplicated evidence
	// envelopes. Keep one fact so NormalizeSnapshot remains self-contained.
	write := 0
	for _, fact := range r.CoverageFacts {
		if write > 0 && r.CoverageFacts[write-1].ID == fact.ID {
			continue
		}
		r.CoverageFacts[write] = fact
		write++
	}
	r.CoverageFacts = r.CoverageFacts[:write]
}

func compareSubject(left, right archive.FactSubject) int {
	leftKey := subjectKey(left)
	rightKey := subjectKey(right)
	return strings.Compare(leftKey, rightKey)
}

func subjectKey(subject archive.FactSubject) string {
	value := fmt.Sprintf("%020d", subject.RepositoryID)
	if subject.RunID != nil {
		value += fmt.Sprintf("/%020d", *subject.RunID)
	} else {
		value += "/-"
	}
	if subject.RunAttempt != nil {
		value += fmt.Sprintf("/%010d", *subject.RunAttempt)
	} else {
		value += "/-"
	}
	if subject.JobID != nil {
		value += fmt.Sprintf("/%020d", *subject.JobID)
	} else {
		value += "/-"
	}
	return value + "/" + subject.StepKey
}

func idsToStrings(values []model.EvidenceID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}
