package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Instant is a UTC, monotonic-free timestamp with deterministic RFC3339Nano
// serialization.
type Instant struct {
	time.Time
}

func NewInstant(value time.Time) (Instant, error) {
	if value.IsZero() {
		return Instant{}, errors.New("timestamp is zero")
	}
	return Instant{Time: value.UTC().Round(0)}, nil
}

func MustInstant(value time.Time) Instant {
	instant, err := NewInstant(value)
	if err != nil {
		panic(err)
	}
	return instant
}

func (i Instant) Validate() error {
	if i.Time.IsZero() {
		return errors.New("timestamp is zero")
	}
	if i.Location() != time.UTC {
		return errors.New("timestamp must be normalized to UTC")
	}
	return nil
}

func (i Instant) MarshalJSON() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(i.Format(time.RFC3339Nano))
}

func (i *Instant) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("timestamp cannot be null")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode timestamp: %w", err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return fmt.Errorf("parse timestamp: %w", err)
	}
	instant, err := NewInstant(parsed)
	if err != nil {
		return err
	}
	*i = instant
	return nil
}

type IntervalBounds string

const (
	BoundsClosedOpen IntervalBounds = "[)"
	BoundsClosed     IntervalBounds = "[]"
	BoundsOpen       IntervalBounds = "()"
	BoundsOpenClosed IntervalBounds = "(]"
)

func (b IntervalBounds) Valid() bool {
	return b == BoundsClosedOpen || b == BoundsClosed || b == BoundsOpen || b == BoundsOpenClosed
}

func (b *IntervalBounds) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(b), func(value string) bool {
		return IntervalBounds(value).Valid()
	}, "interval bounds")
}

type SourcePrecision string

const (
	PrecisionSecond  SourcePrecision = "second"
	PrecisionMinute  SourcePrecision = "minute"
	PrecisionHour    SourcePrecision = "hour"
	PrecisionDay     SourcePrecision = "day"
	PrecisionUnknown SourcePrecision = "unknown"
)

func (p SourcePrecision) Valid() bool {
	return p == PrecisionSecond || p == PrecisionMinute || p == PrecisionHour || p == PrecisionDay || p == PrecisionUnknown
}

func (p *SourcePrecision) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(p), func(value string) bool {
		return SourcePrecision(value).Valid()
	}, "source precision")
}

type TimeApproximation string

const (
	ApproximationExact                TimeApproximation = "exact"
	ApproximationSourceRounded        TimeApproximation = "source-rounded"
	ApproximationConservativeExpanded TimeApproximation = "conservative-expanded"
	ApproximationUnknown              TimeApproximation = "unknown"
)

func (a TimeApproximation) Valid() bool {
	return a == ApproximationExact || a == ApproximationSourceRounded || a == ApproximationConservativeExpanded || a == ApproximationUnknown
}

func (a *TimeApproximation) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(a), func(value string) bool {
		return TimeApproximation(value).Valid()
	}, "time approximation")
}

type EventTimeBasis string

const (
	TimeBasisAPIField         EventTimeBasis = "api_field"
	TimeBasisLogTimestamp     EventTimeBasis = "log_timestamp"
	TimeBasisDefinitionCommit EventTimeBasis = "definition_commit"
	TimeBasisProxyInterval    EventTimeBasis = "proxy_interval"
	TimeBasisUnknown          EventTimeBasis = "unknown"
)

func (b EventTimeBasis) Valid() bool {
	return b == TimeBasisAPIField || b == TimeBasisLogTimestamp || b == TimeBasisDefinitionCommit || b == TimeBasisProxyInterval || b == TimeBasisUnknown
}

func (b *EventTimeBasis) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(b), func(value string) bool {
		return EventTimeBasis(value).Valid()
	}, "event-time basis")
}

// EventInterval is explicitly separate from collection time. An entirely
// unknown interval is represented by nil endpoints and unknown metadata.
type EventInterval struct {
	Start         *Instant          `json:"start"`
	End           *Instant          `json:"end"`
	Bounds        *IntervalBounds   `json:"bounds"`
	Precision     SourcePrecision   `json:"source_precision"`
	Approximation TimeApproximation `json:"approximation"`
	Basis         EventTimeBasis    `json:"basis"`
}

func (i EventInterval) Validate() error {
	if !i.Precision.Valid() {
		return fmt.Errorf("invalid event-time precision %q", i.Precision)
	}
	if !i.Approximation.Valid() {
		return fmt.Errorf("invalid event-time approximation %q", i.Approximation)
	}
	if !i.Basis.Valid() {
		return fmt.Errorf("invalid event-time basis %q", i.Basis)
	}
	if i.Start == nil && i.End == nil {
		if i.Bounds != nil {
			return errors.New("unknown event time cannot have interval bounds")
		}
		if i.Precision != PrecisionUnknown || i.Approximation != ApproximationUnknown || i.Basis != TimeBasisUnknown {
			return errors.New("missing event time must explicitly use unknown precision, approximation, and basis")
		}
		return nil
	}
	if i.Start == nil && i.End != nil {
		return errors.New("event-time end requires a start")
	}
	if err := i.Start.Validate(); err != nil {
		return fmt.Errorf("event-time start: %w", err)
	}
	if i.End == nil {
		if i.Bounds != nil {
			return errors.New("an event instant cannot have range bounds")
		}
		return nil
	}
	if err := i.End.Validate(); err != nil {
		return fmt.Errorf("event-time end: %w", err)
	}
	if i.Bounds == nil || !i.Bounds.Valid() {
		return errors.New("event-time range requires valid explicit bounds")
	}
	if i.End.Before(i.Start.Time) {
		return errors.New("event-time end precedes start")
	}
	if i.End.Equal(i.Start.Time) && *i.Bounds != BoundsClosed {
		return errors.New("zero-width event interval must use closed bounds")
	}
	return nil
}

type CollectionWindow struct {
	StartedAt Instant `json:"started_at"`
	EndedAt   Instant `json:"ended_at"`
}

func (w CollectionWindow) Validate() error {
	if err := w.StartedAt.Validate(); err != nil {
		return fmt.Errorf("collection start: %w", err)
	}
	if err := w.EndedAt.Validate(); err != nil {
		return fmt.Errorf("collection end: %w", err)
	}
	if w.EndedAt.Before(w.StartedAt.Time) {
		return errors.New("collection end precedes start")
	}
	return nil
}
