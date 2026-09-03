package publiclab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	syntheticIncidentIDPrefix   = "CIR-LAB-PUBLIC-A-B-A-"
	syntheticMarkerBIndicatorID = "public-lab-marker-b"
	packInputSourceID           = "public-lab-pack-input-record"
)

// GenerateSyntheticIncidentPack emits one deterministic declarative pack from
// actual manifest-bound A-to-B-to-A observations recorded before any CIRewind
// case exists. It validates but never follows recordSourceURL and never invents
// a run, finding, case, or time identity.
func GenerateSyntheticIncidentPack(ctx context.Context, sourceRoot, schemaDir string, artifact Artifact, packInput []byte, recordSourceURL string) ([]byte, error) {
	if err := ValidateRecordAgainstArtifact(ctx, sourceRoot, schemaDir, RecordPackInput, packInput, artifact); err != nil {
		return nil, err
	}
	var record labPackInputRecord
	if err := json.Unmarshal(packInput, &record); err != nil {
		return nil, err
	}
	recordRevision, err := immutableRecordRevision(recordSourceURL, record.LabRepository.FullName, record.RecordID)
	if err != nil {
		return nil, err
	}
	protocolSHA, ok := importFileSHA256(artifact.Model, "protocol/README.md")
	if !ok {
		return nil, errors.New("reviewed import manifest omits protocol/README.md")
	}
	precision := coarsestPrecision(
		record.MutableTag.Before.Observation.SourcePrecision,
		record.MutableTag.During.Observation.SourcePrecision,
		record.MutableTag.After.Observation.SourcePrecision,
	)
	mutableConfidence := model.L3Strong
	for _, observation := range []recordObservation{record.MutableTag.Before.Observation, record.MutableTag.During.Observation, record.MutableTag.After.Observation} {
		if observation.SourcePrecision == "unknown" || observation.Approximation == "unknown" {
			mutableConfidence = model.L1Possible
			break
		}
		if observation.Approximation != "exact" {
			mutableConfidence = model.L2Probable
		}
	}
	owner, name, _ := strings.Cut(record.LabRepository.FullName, "/")
	recordHash := sha256.Sum256(packInput)
	collectedAt := record.CreatedAt
	pack := incident.Pack{
		APIVersion: incident.APIVersion,
		Kind:       incident.Kind,
		Metadata: incident.Metadata{
			ID:          syntheticIncidentIDFor(record.LabRepository.FullName, record.FixtureObjects.MarkerB.ObjectID),
			PackVersion: "1.0.0+exercise." + hex.EncodeToString(recordHash[:8]),
			Title:       "Harmless public A-to-B-to-A laboratory",
			PublishedAt: collectedAt,
			UpdatedAt:   collectedAt,
			Labels:      []string{"public-lab", "synthetic"},
			Sources: []incident.Source{
				{
					ID:             "public-lab-protocol",
					Type:           "synthetic-fixture",
					Title:          "Reviewed harmless public laboratory protocol",
					Publisher:      "CIRewind maintainers",
					URL:            record.LabRepository.PublicURL + "/blob/" + record.Protocol.SourceCommit.ObjectID + "/protocol/README.md",
					RetrievedAt:    collectedAt,
					SourceRevision: record.Protocol.SourceCommit.ObjectID,
					SourceSHA256:   protocolSHA,
					Notes:          "Synthetic protocol source; not a real incident advisory.",
				},
				{
					ID:             packInputSourceID,
					Type:           "synthetic-fixture",
					Title:          "Manifest-bound public laboratory pack-input record",
					Publisher:      "CIRewind public laboratory",
					URL:            recordSourceURL,
					RetrievedAt:    collectedAt,
					SourceRevision: recordRevision,
					SourceSHA256:   hex.EncodeToString(recordHash[:]),
					TimePrecision:  precision,
					Notes:          "Contains public synthetic observations only; no raw logs or secret values.",
				},
			},
		},
		Spec: incident.Spec{
			Description: "Harmless synthetic evidence for a controlled mutable v1 tag movement from reviewed marker A to reviewed marker B and back to A.",
			Components: []incident.Component{{
				ID:         "public-lab-marker",
				Type:       "github-action",
				Repository: incident.Repository{Owner: owner, Name: name},
				Subpaths:   []string{"actions/marker"},
			}},
			Windows: []incident.Window{{
				ID:              "observed-b-window",
				Start:           record.MutableTag.Before.Observation.ObservedAt,
				End:             record.MutableTag.After.Observation.ObservedAt,
				Bounds:          "()",
				SourcePrecision: precision,
				Approximation:   "conservative-expanded",
				OriginalClaim:   "v1 was observed at A before the move, at B during the exercise, and at A after restoration; exact ref-update instants lie between those observations.",
				SourceRefs:      []string{packInputSourceID},
				Notes:           "The interval is conservative and does not by itself prove that any job downloaded or executed B.",
			}},
			Indicators: []incident.Indicator{
				{
					ID:          syntheticMarkerBIndicatorID,
					ComponentID: "public-lab-marker",
					Kind:        "action-commit",
					Value:       incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: record.FixtureObjects.MarkerB.ObjectID}},
					WindowRefs:  []string{"observed-b-window"},
					Confidence:  model.L4Certain,
					SourceRefs:  []string{"public-lab-protocol", packInputSourceID},
					Notes:       "Harmless affected synthetic marker B; not malware or a real compromised commit.",
				},
				{
					ID:          "public-lab-mutable-v1",
					ComponentID: "public-lab-marker",
					Kind:        "mutable-action-ref",
					Value:       incident.IndicatorValue{Ref: "v1"},
					WindowRefs:  []string{"observed-b-window"},
					Confidence:  mutableConfidence,
					SourceRefs:  []string{packInputSourceID},
					Notes:       "A window match is not proof that B downloaded or executed.",
				},
			},
			KnownGood: []incident.KnownGood{{
				ID:          "public-lab-marker-a",
				ComponentID: "public-lab-marker",
				Kind:        "action-commit",
				Value:       incident.IndicatorValue{GitObject: &incident.GitObject{Algorithm: "sha1", Value: record.FixtureObjects.MarkerA.ObjectID}},
				Confidence:  model.L4Certain,
				SourceRefs:  []string{"public-lab-protocol", packInputSourceID},
				Notes:       "Known-good means reviewed harmless marker A for this synthetic exercise only.",
			}},
			Remediation: &incident.Remediation{Guidance: []string{
				"Restore the disposable v1 tag to the exact reviewed marker A commit and verify the remote ref before claiming reset success.",
				"Treat each historical run attempt according to exact retained evidence; do not use the current safe tag to clear historical marker B observations.",
			}},
		},
	}
	encoded, err := yaml.Marshal(pack)
	if err != nil {
		return nil, fmt.Errorf("encode synthetic incident pack: %w", err)
	}
	if _, err := incident.Validate(ctx, encoded); err != nil {
		return nil, fmt.Errorf("generated synthetic incident pack is invalid: %w", err)
	}
	return encoded, nil
}

func syntheticIncidentIDFor(repository, markerB string) string {
	identityHash := sha256.Sum256([]byte(repository + "\x00" + markerB))
	return syntheticIncidentIDPrefix + hex.EncodeToString(identityHash[:8])
}

func immutableRecordRevision(value, repository, recordID string) (string, error) {
	if !immutableBlobURL(value, repository, "observations/"+recordID+".json", "") {
		return "", errors.New("pack-input source URL must be an immutable public blob URL for the exact record ID")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", errors.New("pack-input source URL is malformed")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "blob" || !isSHA1(parts[3]) {
		return "", errors.New("pack-input source URL omits an immutable revision")
	}
	return parts[3], nil
}

func importFileSHA256(manifest ObjectManifest, path string) (string, bool) {
	for _, file := range manifest.ImportFiles {
		if file.Path == path {
			return file.SHA256, true
		}
	}
	return "", false
}

func coarsestPrecision(values ...string) string {
	rank := map[string]int{"second": 0, "minute": 1, "hour": 2, "day": 3, "unknown": 4}
	result := "second"
	for _, value := range values {
		if rank[value] > rank[result] {
			result = value
		}
	}
	return result
}
