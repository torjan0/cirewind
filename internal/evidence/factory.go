package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/torjan0/cirewind/internal/model"
)

// EnvelopeInput is the bounded constructor input for a collected source. Raw
// source bytes are hashed and are not retained by this constructor.
type EnvelopeInput struct {
	Kind              SourceKind
	CanonicalSourceID string
	Provider          Provider
	APIVersion        string
	EndpointTemplate  string
	SourceURL         string
	RequestParameters RequestParameters
	RequestAttempt    uint32
	HTTPStatus        *int
	Scope             model.CoverageScope
	EventTime         model.EventInterval
	MediaType         string
	SourceBytes       []byte
	Complete          bool
	Extractor         ExtractorDescriptor
	Redaction         RedactionDescriptor
	Errors            []EvidenceError
	CollectionSession model.CollectionSessionID
	RequestID         model.RequestID
	CollectionTime    model.CollectionWindow
}

// NewEnvelope constructs and validates a hash-verifiable evidence envelope.
// It intentionally has no raw-retention option; callers retaining bytes must
// use a separately reviewed redaction/storage path and NewEvidenceID directly.
func NewEnvelope(input EnvelopeInput) (Envelope, error) {
	if input.SourceBytes == nil {
		return Envelope{}, errors.New("source bytes must be an explicit byte slice")
	}
	if input.RequestParameters == nil {
		input.RequestParameters = RequestParameters{}
	}
	if input.Errors == nil {
		input.Errors = []EvidenceError{}
	}
	if input.RequestAttempt == 0 {
		input.RequestAttempt = 1
	}
	if input.EventTime.Precision == "" {
		input.EventTime = model.EventInterval{
			Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown,
		}
	}
	sourceIdentity := LogicalSourceIdentity{
		Kind: input.Kind, CanonicalID: input.CanonicalSourceID,
		Scope: input.Scope, RequestParameters: input.RequestParameters,
	}
	sourceID, err := NewLogicalSourceID(sourceIdentity)
	if err != nil {
		return Envelope{}, fmt.Errorf("logical source: %w", err)
	}
	sum := sha256.Sum256(input.SourceBytes)
	contentHash := hex.EncodeToString(sum[:])
	retention := RetentionDescriptor{
		MediaType: input.MediaType, ByteLength: uint64(len(input.SourceBytes)), RawRetained: false,
		RedactionStatus: input.Redaction.Status, RedactionPolicyVersion: input.Redaction.PolicyVersion,
	}
	evidenceID, err := NewEvidenceID(sourceID, contentHash, retention)
	if err != nil {
		return Envelope{}, fmt.Errorf("evidence identity: %w", err)
	}
	observationID, err := NewCollectionObservationID(evidenceID, input.CollectionSession, input.RequestID, input.CollectionTime.EndedAt, input.RequestAttempt)
	if err != nil {
		return Envelope{}, fmt.Errorf("collection observation identity: %w", err)
	}
	envelope := Envelope{
		Evidence: EvidenceObject{
			SchemaVersion: EvidenceSchemaVersion,
			ID:            evidenceID,
			LogicalSource: LogicalSource{ID: sourceID, Kind: input.Kind, CanonicalID: input.CanonicalSourceID, RequestParameters: input.RequestParameters},
			Source: SourceDescriptor{
				Provider: input.Provider, APIVersion: input.APIVersion, EndpointTemplate: input.EndpointTemplate,
				SourceURL: input.SourceURL, RequestParameters: input.RequestParameters,
				RequestAttempt: input.RequestAttempt, HTTPStatus: input.HTTPStatus,
			},
			Scope: input.Scope, EventTime: input.EventTime,
			Content: ContentDescriptor{
				MediaType: input.MediaType, ByteLength: uint64(len(input.SourceBytes)), Complete: input.Complete,
				SourceSHA256: contentHash, RawRetained: false,
			},
			Extractor: input.Extractor, Redaction: input.Redaction,
			Derivation: DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: input.Errors,
		},
		Observation: CollectionObservation{
			ID: observationID, EvidenceID: evidenceID, CollectionSessionID: input.CollectionSession,
			RequestID: input.RequestID, RequestAttempt: input.RequestAttempt, CollectionTime: input.CollectionTime,
		},
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}
