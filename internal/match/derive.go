// Package match derives conservative finding states from already-normalized
// historical facts. It does not collect evidence or resolve mutable refs.
package match

import (
	"errors"
	"fmt"

	"github.com/torjan0/cirewind/internal/model"
)

const RuleVersion = "finding-state-v1alpha1.1"

// Candidate is one incident indicator evaluated against one historical
// subject. The correlator must only set SameAttemptExactRuntime when the exact
// affected source object or package digest was joined to this run attempt and
// Action occurrence. This deliberately prevents a lifecycle marker for one
// Action from upgrading a different download in the same job.
type Candidate struct {
	SameAttemptExactRuntime bool
	PreparationCompleted    bool
	LifecycleStarted        bool
	LifecycleCompleted      bool
	DownloadAnnouncedOnly   bool
	ExactCalledWorkflow     bool
	HistoricalExactDeclared bool
	HistoricalMutableRef    bool
	RunEventInWindow        bool
	PotentialTransitive     bool
	CurrentReferenceOnly    bool
	KnownGoodExactRuntime   bool
	MaterialContradiction   bool
	RequiredCoverageClosed  bool
	MaterialEvidenceGap     bool
	EvidenceIDs             []model.EvidenceID
	CoverageIDs             []model.CoverageAssessmentID
}

// Decision is a semantic conclusion, not a risk or severity score.
type Decision struct {
	State      model.FindingState
	Provenance model.ProvenanceLevel
	Conclusion string
}

// Derive applies the canonical v0.1 state rules. The order is intentional:
// contradiction cannot be hidden by exact evidence, and known-good exact
// runtime evidence defeats mutable-ref suspicion for that occurrence.
func Derive(c Candidate) (Decision, error) {
	if c.LifecycleCompleted {
		c.LifecycleStarted = true
	}
	if c.MaterialContradiction {
		return Decision{
			State:      model.ContradictoryEvidence,
			Provenance: model.L4Certain,
			Conclusion: "Material runtime, API, or historical-definition evidence disagrees; preserve both accounts and review the evidence chain.",
		}, nil
	}
	if c.KnownGoodExactRuntime && c.SameAttemptExactRuntime {
		if c.MaterialEvidenceGap || !c.RequiredCoverageClosed {
			return evidenceGap(), nil
		}
		return Decision{
			State:      model.NoMatchConfirmed,
			Provenance: model.L4Certain,
			Conclusion: "Exact runtime identity was known-good and the required retained evidence was completely examined for this subject.",
		}, nil
	}
	if c.SameAttemptExactRuntime && c.LifecycleStarted {
		return Decision{
			State:      model.ConfirmedExecuted,
			Provenance: model.L4Certain,
			Conclusion: "The exact affected Action identity was resolved for this run attempt and its corresponding lifecycle demonstrably started.",
		}, nil
	}
	if c.SameAttemptExactRuntime && c.PreparationCompleted {
		return Decision{
			State:      model.ConfirmedDownloaded,
			Provenance: model.L4Certain,
			Conclusion: "The exact affected Action identity completed runner preparation, but execution was not demonstrated.",
		}, nil
	}
	if c.ExactCalledWorkflow {
		return Decision{
			State:      model.ConfirmedCalledWorkflow,
			Provenance: model.L4Certain,
			Conclusion: "GitHub recorded the exact affected reusable-workflow identity for this run attempt; this does not by itself prove every callee step executed.",
		}, nil
	}
	if c.HistoricalExactDeclared {
		return Decision{
			State:      model.DeclaredAtRunSHA,
			Provenance: model.L3Strong,
			Conclusion: "The historical workflow definition at the relevant workflow commit declared the exact affected immutable identity; runtime execution is unconfirmed.",
		}, nil
	}
	if c.HistoricalMutableRef && c.RunEventInWindow && !c.KnownGoodExactRuntime {
		return Decision{
			State:      model.RunInWindowMutableRef,
			Provenance: model.L2Probable,
			Conclusion: "The historical workflow used an affected mutable reference during its source-supported exposure window; exact runtime resolution is unavailable.",
		}, nil
	}
	if c.PotentialTransitive {
		return Decision{
			State:      model.PotentialTransitive,
			Provenance: model.L1Possible,
			Conclusion: "The affected component is historically reachable through a wrapper, composite Action, reusable workflow, or embedded dependency, but exact runtime resolution is unavailable.",
		}, nil
	}
	if c.CurrentReferenceOnly {
		return Decision{
			State:      model.CurrentReferenceOnly,
			Provenance: model.L1Possible,
			Conclusion: "Only present-day repository configuration references the component; this is not evidence of historical execution.",
		}, nil
	}
	if c.MaterialEvidenceGap || c.DownloadAnnouncedOnly || !c.RequiredCoverageClosed {
		return evidenceGap(), nil
	}
	if len(c.EvidenceIDs) == 0 || len(c.CoverageIDs) == 0 {
		return Decision{}, errors.New("NO_MATCH_CONFIRMED requires retained evidence and closed coverage")
	}
	return Decision{
		State:      model.NoMatchConfirmed,
		Provenance: model.L4Certain,
		Conclusion: "All required retained evidence for this subject was examined and no incident indicator matched.",
	}, nil
}

func evidenceGap() Decision {
	return Decision{
		State:      model.UnknownEvidenceGap,
		Provenance: model.L0Unknown,
		Conclusion: "Required evidence is missing, inaccessible, incomplete, or not safely correlated; no compromise or clean-bill conclusion is supported.",
	}
}

// ValidateEvidenceSupport enforces the minimum support contract before a
// Decision is turned into a persisted Finding.
func ValidateEvidenceSupport(c Candidate, d Decision) error {
	if !d.State.Valid() || !d.Provenance.Valid() {
		return errors.New("decision contains a non-canonical state or provenance level")
	}
	if d.State == model.NoMatchConfirmed {
		if !c.RequiredCoverageClosed || c.MaterialEvidenceGap || len(c.EvidenceIDs) == 0 || len(c.CoverageIDs) == 0 {
			return errors.New("NO_MATCH_CONFIRMED lacks closure evidence")
		}
	}
	if d.State == model.UnknownEvidenceGap && !c.MaterialEvidenceGap && !c.DownloadAnnouncedOnly && c.RequiredCoverageClosed {
		return errors.New("UNKNOWN_EVIDENCE_GAP lacks a gap condition")
	}
	if d.State == model.ConfirmedDownloaded && (!c.SameAttemptExactRuntime || !c.PreparationCompleted) {
		return errors.New("CONFIRMED_DOWNLOADED requires same-attempt exact identity and completed preparation")
	}
	if d.State == model.ConfirmedExecuted && (!c.SameAttemptExactRuntime || !c.LifecycleStarted) {
		return errors.New("CONFIRMED_EXECUTED requires same-attempt exact identity and lifecycle start")
	}
	if len(c.EvidenceIDs) == 0 && d.State != model.UnknownEvidenceGap {
		return fmt.Errorf("%s requires at least one evidence object", d.State)
	}
	return nil
}
