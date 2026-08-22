// Package literalmatch performs bounded, exact byte matching against raw log
// objects that an operator explicitly retained. It never interprets incident
// content as a path, expression, regular expression, or network target.
package literalmatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

const RuleVersion = "retained-log-literal-v1alpha1"

// RawSource is the deliberately narrow replay boundary. Implementations must
// copy the exact object identified by its SHA-256 and verify it while copying.
// archive.Archive implements this interface.
type RawSource interface {
	CopyRaw(context.Context, string, io.Writer) error
}

type Scope string

const (
	ScopeRunnerControl Scope = "runner-control"
	ScopeSetup         Scope = "setup"
	ScopeStep          Scope = "step"
	ScopeAnyRetained   Scope = "any-retained-log"
)

func (s Scope) Valid() bool {
	return s == ScopeRunnerControl || s == ScopeSetup || s == ScopeStep || s == ScopeAnyRetained
}

// Query is one already-validated v1alpha1 incident literal. Literal remains
// internal to the matcher and is never copied into an Observation or report.
type Query struct {
	IndicatorID string
	Literal     []byte
	Scope       Scope
}

func (q Query) validate() error {
	if q.IndicatorID == "" || len(q.IndicatorID) > 128 || strings.IndexByte(q.IndicatorID, 0) >= 0 {
		return errors.New("literal query indicator ID is invalid")
	}
	if len(q.Literal) == 0 || len(q.Literal) > 4096 {
		return errors.New("literal query must contain 1-4096 bytes")
	}
	if !q.Scope.Valid() {
		return fmt.Errorf("literal query scope %q is invalid", q.Scope)
	}
	return nil
}

// Limits bound both source custody and matching work. Total raw bytes counts
// each logical retained source examined; it is deliberately independent of
// the archive's larger custody ceiling.
type Limits struct {
	MaxSources        int
	MaxLiterals       int
	MaxLiteralBytes   int
	MaxRawSourceBytes int64
	MaxTotalRawBytes  int64
	Archive           logparse.ArchiveLimits
}

func DefaultLimits() Limits {
	return Limits{
		MaxSources:        100_000,
		MaxLiterals:       256,
		MaxLiteralBytes:   256 << 10,
		MaxRawSourceBytes: 512 << 20,
		MaxTotalRawBytes:  8 << 30,
		Archive:           logparse.DefaultArchiveLimits(),
	}
}

func (l Limits) validate() error {
	if l.MaxSources <= 0 || l.MaxSources > 1_000_000 || l.MaxLiterals <= 0 || l.MaxLiterals > 4096 ||
		l.MaxLiteralBytes <= 0 || l.MaxLiteralBytes > 16<<20 || l.MaxRawSourceBytes <= 0 ||
		l.MaxRawSourceBytes > 2<<30 || l.MaxTotalRawBytes <= 0 || l.MaxTotalRawBytes > 64<<30 {
		return errors.New("literal matching limits must be positive and within compiled ceilings")
	}
	if l.MaxRawSourceBytes > l.MaxTotalRawBytes {
		return errors.New("per-source literal limit exceeds total raw-byte limit")
	}
	return l.Archive.Validate()
}

type Options struct {
	Limits  Limits
	TempDir string
}

type Status string

const (
	StatusMatched Status = "MATCHED"
	StatusAbsent  Status = "ABSENT"
	StatusGap     Status = "GAP"
)

type GapCode string

const (
	GapRawNotRetained      GapCode = "RAW_NOT_RETAINED"
	GapRawUnavailable      GapCode = "RAW_UNAVAILABLE"
	GapRawIncomplete       GapCode = "RAW_INCOMPLETE"
	GapIntegrityFailure    GapCode = "RAW_INTEGRITY_FAILURE"
	GapSizeLimit           GapCode = "LITERAL_SIZE_LIMIT"
	GapTotalSizeLimit      GapCode = "LITERAL_TOTAL_SIZE_LIMIT"
	GapSourceLimit         GapCode = "LITERAL_SOURCE_LIMIT"
	GapUnsafeArchive       GapCode = "UNSAFE_OR_MALFORMED_ARCHIVE"
	GapUnsupportedScope    GapCode = "UNSUPPORTED_LITERAL_SCOPE"
	GapUncorrelatedEntry   GapCode = "UNCORRELATED_LOG_ENTRY"
	GapUnderlyingCoverage  GapCode = "LOG_COVERAGE_NOT_CLOSED"
	GapNoEligibleLogSource GapCode = "NO_ELIGIBLE_LOG_SOURCE"
)

// Observation records only the fact and location needed to reproduce a
// bounded match. It deliberately excludes the literal and surrounding bytes.
type Observation struct {
	IndicatorID   string
	LiteralSHA256 string
	Subject       archive.FactSubject
	EventTime     model.EventInterval
	EvidenceIDs   []model.EvidenceID
	CoverageIDs   []model.CoverageAssessmentID
	FirstOffset   uint64
	MatchCount    uint64
}

// Assessment is one deterministic searchable unit. A GAP can coexist with a
// positive Observation when bytes before a later archive error contained the
// literal; the gap still prevents a negative conclusion.
type Assessment struct {
	IndicatorID string
	Status      Status
	GapCode     GapCode
	Subject     archive.FactSubject
	EventTime   model.EventInterval
	EvidenceIDs []model.EvidenceID
	CoverageIDs []model.CoverageAssessmentID
	BytesRead   uint64
}

type Result struct {
	Observations  []Observation
	Assessments   []Assessment
	CoverageFacts []archive.Fact
}
