package model

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

type SourceSpan struct {
	ByteStart uint64 `json:"byte_start"`
	ByteEnd   uint64 `json:"byte_end"`
	LineStart uint64 `json:"line_start,omitempty"`
	LineEnd   uint64 `json:"line_end,omitempty"`
}

func (s SourceSpan) Validate() error {
	if s.ByteEnd < s.ByteStart {
		return errors.New("source-span byte end precedes start")
	}
	if (s.LineStart == 0) != (s.LineEnd == 0) {
		return errors.New("source-span line bounds must both be present or absent")
	}
	if s.LineStart != 0 && s.LineEnd < s.LineStart {
		return errors.New("source-span line end precedes start")
	}
	return nil
}

// RuntimeActionObservation is a fact, not a destructive lifecycle row. Several
// observations may describe one occurrence, including failures and conflicts.
type RuntimeActionObservation struct {
	ID                RuntimeObservationID   `json:"runtime_observation_id"`
	Kind              RuntimeObservationKind `json:"kind"`
	Execution         JobExecutionIdentity   `json:"execution"`
	Step              *StepIdentity          `json:"step,omitempty"`
	ActionRepository  RepositorySlug         `json:"action_repository"`
	ActionSubpath     string                 `json:"action_subpath,omitempty"`
	DeclaredRef       string                 `json:"declared_ref,omitempty"`
	SourceObjectID    *ActionSourceObjectID  `json:"source_object_id,omitempty"`
	PackageDigest     *PackageDigest         `json:"package_digest,omitempty"`
	ImmutableVersion  string                 `json:"immutable_version,omitempty"`
	EventTime         EventInterval          `json:"event_time"`
	SourceEvidenceIDs []EvidenceID           `json:"source_evidence_ids"`
	SourceSpan        SourceSpan             `json:"source_span"`
	ExtractorName     string                 `json:"extractor_name"`
	ExtractorVersion  string                 `json:"extractor_version"`
	RulesetSHA256     string                 `json:"ruleset_sha256"`
}

func (o RuntimeActionObservation) Validate() error {
	if err := o.ID.Validate(); err != nil {
		return err
	}
	if !o.Kind.Valid() {
		return fmt.Errorf("invalid runtime observation kind %q", o.Kind)
	}
	if err := o.Execution.Validate(); err != nil {
		return err
	}
	if err := o.ActionRepository.Validate(); err != nil {
		return err
	}
	if o.ActionSubpath != "" {
		if len(o.ActionSubpath) > 4096 || !utf8.ValidString(o.ActionSubpath) || hasASCIIControl(o.ActionSubpath) || strings.Contains(o.ActionSubpath, `\`) || strings.HasPrefix(o.ActionSubpath, "/") || path.Clean(o.ActionSubpath) != o.ActionSubpath || strings.HasPrefix(o.ActionSubpath, "../") {
			return errors.New("runtime Action subpath is unsafe")
		}
	}
	if len(o.DeclaredRef) > 1024 || !utf8.ValidString(o.DeclaredRef) || hasASCIIControl(o.DeclaredRef) {
		return errors.New("runtime declared ref is unsafe")
	}
	if len(o.ImmutableVersion) > 256 || !utf8.ValidString(o.ImmutableVersion) || hasASCIIControl(o.ImmutableVersion) {
		return errors.New("immutable package version is unsafe")
	}
	if o.Step != nil {
		if err := o.Step.Validate(); err != nil {
			return err
		}
		if o.Step.Job != o.Execution {
			return errors.New("runtime observation step belongs to a different execution")
		}
	}
	if o.Kind == ObservationLifecycleStarted || o.Kind == ObservationLifecycleCompleted || o.Kind == ObservationConditionSkipped {
		if o.Step == nil {
			return errors.New("step lifecycle observation requires exact step identity")
		}
	}
	switch o.Kind {
	case ObservationResolutionObserved, ObservationDownloadAnnounced, ObservationPreparationComplete, ObservationPreparationFailed:
		if o.SourceObjectID == nil && o.PackageDigest == nil {
			return errors.New("resolution or preparation observation requires an exact source object or typed package digest")
		}
	}
	if o.SourceObjectID != nil {
		if err := o.SourceObjectID.Validate(); err != nil {
			return err
		}
	}
	if o.PackageDigest != nil {
		if err := o.PackageDigest.Validate(); err != nil {
			return err
		}
	}
	if err := o.EventTime.Validate(); err != nil {
		return err
	}
	if len(o.SourceEvidenceIDs) == 0 {
		return errors.New("runtime observation requires source evidence")
	}
	if err := validateSortedUniqueEvidenceIDs(o.SourceEvidenceIDs); err != nil {
		return err
	}
	if err := o.SourceSpan.Validate(); err != nil {
		return err
	}
	if !validMachineName(o.ExtractorName, 128) || !validBoundedIdentityText(o.ExtractorVersion, 128) {
		return errors.New("runtime observation extractor identity is invalid")
	}
	return validateSHA256(o.RulesetSHA256, "runtime ruleset SHA-256")
}
