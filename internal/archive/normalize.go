package archive

import (
	"errors"
	"fmt"
	"sort"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

// NormalizeBatch canonicalizes user-visible order, validates the closed
// snapshot vocabulary, and computes a resumable content-addressed batch ID.
func NormalizeBatch(input Batch) (Batch, error) {
	return normalizeBatch(input, false)
}

func normalizeRetainedBatch(input Batch) (Batch, error) {
	return normalizeBatch(input, true)
}

func normalizeBatch(input Batch, allowRetainedLegacyBasis bool) (Batch, error) {
	batch := input
	if batch.Collections == nil || batch.Payloads == nil || batch.Evidence == nil || batch.Facts == nil || batch.Capabilities == nil || batch.Checkpoints == nil {
		return Batch{}, errors.New("archive batch arrays must be explicit")
	}
	if len(batch.Payloads) > maxSnapshotPayloads || len(batch.Evidence) > maxSnapshotEvidence || len(batch.Facts) > maxSnapshotFacts {
		return Batch{}, errors.New("archive batch exceeds compact fact count limits")
	}

	collectionIDs := make(map[model.CollectionSessionID]struct{}, len(batch.Collections))
	rawCollections := make(map[model.CollectionSessionID]bool, len(batch.Collections))
	for index := range batch.Collections {
		session := &batch.Collections[index]
		if session.Scope.Repositories != nil {
			repositories := make([]model.RepositoryID, len(session.Scope.Repositories))
			copy(repositories, session.Scope.Repositories)
			session.Scope.Repositories = repositories
		}
		sort.Slice(session.Scope.Repositories, func(i, j int) bool { return session.Scope.Repositories[i] < session.Scope.Repositories[j] })
		if session.Limits == nil {
			return Batch{}, errors.New("collection limits must be explicit")
		}
		limits := make(map[string]uint64, len(session.Limits))
		for key, value := range session.Limits {
			limits[key] = value
		}
		session.Limits = limits
		if err := session.Validate(); err != nil {
			return Batch{}, fmt.Errorf("collection %d: %w", index, err)
		}
		if _, duplicate := collectionIDs[session.ID]; duplicate {
			return Batch{}, fmt.Errorf("duplicate collection session %s", session.ID)
		}
		collectionIDs[session.ID] = struct{}{}
		rawCollections[session.ID] = session.RawRetention
	}
	sort.Slice(batch.Collections, func(i, j int) bool { return batch.Collections[i].ID < batch.Collections[j].ID })

	payloads := make(map[string]Payload, len(batch.Payloads))
	for index := range batch.Payloads {
		payload := &batch.Payloads[index]
		payload.Bytes = append([]byte(nil), payload.Bytes...)
		if err := payload.Validate(); err != nil {
			return Batch{}, fmt.Errorf("payload %d: %w", index, err)
		}
		if _, duplicate := payloads[payload.SHA256]; duplicate {
			return Batch{}, fmt.Errorf("duplicate compact payload %s", payload.SHA256)
		}
		payloads[payload.SHA256] = *payload
	}
	sort.Slice(batch.Payloads, func(i, j int) bool { return batch.Payloads[i].SHA256 < batch.Payloads[j].SHA256 })

	observationIDs := make(map[model.CollectionObservationID]struct{}, len(batch.Evidence))
	for index, envelope := range batch.Evidence {
		if err := envelope.Validate(); err != nil {
			return Batch{}, fmt.Errorf("evidence envelope %d: %w", index, err)
		}
		if _, ok := collectionIDs[envelope.Observation.CollectionSessionID]; !ok {
			return Batch{}, fmt.Errorf("evidence observation %s references unknown collection", envelope.Observation.ID)
		}
		if envelope.Evidence.Content.RawRetained && !rawCollections[envelope.Observation.CollectionSessionID] {
			return Batch{}, fmt.Errorf("evidence %s claims raw retention in a collection that disabled it", envelope.Evidence.ID)
		}
		if retained := envelope.Evidence.Content.RetainedPayloadSHA256; retained != nil && !envelope.Evidence.Content.RawRetained {
			payload, ok := payloads[*retained]
			if !ok {
				return Batch{}, fmt.Errorf("evidence %s references unavailable compact payload", envelope.Evidence.ID)
			}
			if payload.MediaType != envelope.Evidence.Content.MediaType || uint64(len(payload.Bytes)) != envelope.Evidence.Content.ByteLength {
				return Batch{}, fmt.Errorf("evidence %s compact payload descriptor disagrees", envelope.Evidence.ID)
			}
		} else if envelope.Evidence.Content.RawRetained {
			if retained == nil || *retained != envelope.Evidence.Content.SourceSHA256 {
				return Batch{}, fmt.Errorf("evidence %s raw payload must retain the exact source hash", envelope.Evidence.ID)
			}
			expectedPath, err := RawRelativePath(*retained)
			if err != nil || envelope.Evidence.Content.RetainedPath != expectedPath {
				return Batch{}, fmt.Errorf("evidence %s raw payload path is not content-addressed", envelope.Evidence.ID)
			}
			if _, collision := payloads[*retained]; collision {
				return Batch{}, fmt.Errorf("evidence %s raw payload collides with a compact payload", envelope.Evidence.ID)
			}
		}
		if _, duplicate := observationIDs[envelope.Observation.ID]; duplicate {
			return Batch{}, fmt.Errorf("duplicate evidence observation %s", envelope.Observation.ID)
		}
		observationIDs[envelope.Observation.ID] = struct{}{}
	}
	sort.Slice(batch.Evidence, func(i, j int) bool {
		return batch.Evidence[i].Observation.ID < batch.Evidence[j].Observation.ID
	})

	factIDs := make(map[string]struct{}, len(batch.Facts))
	for index := range batch.Facts {
		var fact Fact
		var err error
		if allowRetainedLegacyBasis {
			fact, err = NormalizeRetainedV1Fact(batch.Facts[index])
		} else {
			fact, err = NormalizeFact(batch.Facts[index])
		}
		if err != nil {
			return Batch{}, fmt.Errorf("fact %d: %w", index, err)
		}
		if _, duplicate := factIDs[fact.ID]; duplicate {
			return Batch{}, fmt.Errorf("duplicate archive fact %s", fact.ID)
		}
		batch.Facts[index] = fact
		factIDs[fact.ID] = struct{}{}
	}
	sort.Slice(batch.Facts, func(i, j int) bool { return batch.Facts[i].ID < batch.Facts[j].ID })

	capabilityNames := make(map[string]struct{}, len(batch.Capabilities))
	for index := range batch.Capabilities {
		capability := &batch.Capabilities[index]
		details := make(map[string]string, len(capability.Details))
		for key, value := range capability.Details {
			details[key] = value
		}
		capability.Details = details
		if err := capability.Validate(); err != nil {
			return Batch{}, fmt.Errorf("capability %d: %w", index, err)
		}
		if _, duplicate := capabilityNames[capability.Name]; duplicate {
			return Batch{}, fmt.Errorf("duplicate archive capability %q", capability.Name)
		}
		capabilityNames[capability.Name] = struct{}{}
	}
	sort.Slice(batch.Capabilities, func(i, j int) bool { return batch.Capabilities[i].Name < batch.Capabilities[j].Name })

	checkpointRepos := make(map[model.RepositoryID]struct{}, len(batch.Checkpoints))
	for index := range batch.Checkpoints {
		checkpoint := &batch.Checkpoints[index]
		// Preserve the explicit empty-array distinction required by Checkpoint.
		// append to a nil slice turns a valid empty watch set back into nil.
		if checkpoint.WatchedParents != nil {
			parents := make([]WatchedParent, len(checkpoint.WatchedParents))
			copy(parents, checkpoint.WatchedParents)
			checkpoint.WatchedParents = parents
		}
		sort.Slice(checkpoint.WatchedParents, func(i, j int) bool { return checkpoint.WatchedParents[i].RunID < checkpoint.WatchedParents[j].RunID })
		if err := checkpoint.Validate(); err != nil {
			return Batch{}, fmt.Errorf("checkpoint %d: %w", index, err)
		}
		if _, ok := collectionIDs[checkpoint.LastSuccessfulCollection]; !ok {
			return Batch{}, fmt.Errorf("checkpoint for repository %d references unknown collection", checkpoint.RepositoryID)
		}
		if _, duplicate := checkpointRepos[checkpoint.RepositoryID]; duplicate {
			return Batch{}, fmt.Errorf("duplicate checkpoint for repository %d", checkpoint.RepositoryID)
		}
		checkpointRepos[checkpoint.RepositoryID] = struct{}{}
	}
	sort.Slice(batch.Checkpoints, func(i, j int) bool { return batch.Checkpoints[i].RepositoryID < batch.Checkpoints[j].RepositoryID })

	preimage := batch
	preimage.ID = ""
	hash, err := evidence.CanonicalSHA256(struct {
		Version string `json:"version"`
		Batch   Batch  `json:"batch"`
	}{Version: "archive-batch/v1", Batch: preimage})
	if err != nil {
		return Batch{}, fmt.Errorf("derive archive batch ID: %w", err)
	}
	expected := "batch1:" + hash
	if batch.ID != "" && batch.ID != expected {
		return Batch{}, errors.New("archive batch ID does not match canonical content")
	}
	batch.ID = expected
	return batch, nil
}

// NormalizeSnapshot validates that a snapshot is self-contained for replay.
func NormalizeSnapshot(input Snapshot) (Snapshot, error) {
	return normalizeSnapshot(input, input.retainedLegacyCredentialBasis)
}

func normalizeRetainedSnapshot(input Snapshot) (Snapshot, error) {
	return normalizeSnapshot(input, true)
}

func normalizeSnapshot(input Snapshot, allowRetainedLegacyBasis bool) (Snapshot, error) {
	if err := input.Metadata.Validate(); err != nil {
		return Snapshot{}, err
	}
	batchInput := Batch{
		Collections:  input.Collections,
		Payloads:     input.Payloads,
		Evidence:     input.Evidence,
		Facts:        input.Facts,
		Capabilities: input.Capabilities,
		Checkpoints:  input.Checkpoints,
	}
	var batch Batch
	var err error
	if allowRetainedLegacyBasis {
		batch, err = normalizeRetainedBatch(batchInput)
	} else {
		batch, err = NormalizeBatch(batchInput)
	}
	if err != nil {
		return Snapshot{}, err
	}

	evidenceIDs := make(map[model.EvidenceID]struct{}, len(batch.Evidence))
	repositoryIDs := make(map[model.RepositoryID]struct{})
	for _, envelope := range batch.Evidence {
		evidenceIDs[envelope.Evidence.ID] = struct{}{}
	}
	for _, fact := range batch.Facts {
		if fact.Kind == FactRepository {
			repositoryIDs[fact.Subject.RepositoryID] = struct{}{}
		}
		for _, evidenceID := range fact.EvidenceIDs {
			if _, ok := evidenceIDs[evidenceID]; !ok {
				return Snapshot{}, fmt.Errorf("fact %s references evidence absent from snapshot", fact.ID)
			}
		}
		if fact.Dependency != nil {
			for _, contradicted := range fact.Dependency.ContradictsFactIDs {
				if !containsFactID(batch.Facts, contradicted) {
					return Snapshot{}, fmt.Errorf("dependency fact %s contradicts fact absent from snapshot", fact.ID)
				}
			}
		}
	}
	for _, envelope := range batch.Evidence {
		for _, parentID := range envelope.Evidence.Derivation.ParentEvidenceIDs {
			if _, ok := evidenceIDs[parentID]; !ok {
				return Snapshot{}, fmt.Errorf("evidence %s has parent absent from snapshot", envelope.Evidence.ID)
			}
		}
	}
	for _, checkpoint := range batch.Checkpoints {
		if _, ok := repositoryIDs[checkpoint.RepositoryID]; !ok {
			return Snapshot{}, fmt.Errorf("checkpoint repository %d is absent from snapshot facts", checkpoint.RepositoryID)
		}
	}

	result := Snapshot{
		Metadata:     input.Metadata,
		Collections:  batch.Collections,
		Payloads:     batch.Payloads,
		Evidence:     batch.Evidence,
		Facts:        batch.Facts,
		Capabilities: batch.Capabilities,
		Checkpoints:  batch.Checkpoints,
	}
	result.retainedLegacyCredentialBasis = allowRetainedLegacyBasis && hasLegacyCredentialBasis(batch.Facts)
	return result, nil
}

func hasLegacyCredentialBasis(facts []Fact) bool {
	for _, fact := range facts {
		if fact.Exposure != nil && fact.Exposure.Credential != nil && !fact.Exposure.Credential.Basis.Valid() {
			return true
		}
	}
	return false
}

func (m SnapshotMetadata) Validate() error {
	if m.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported archive snapshot schema %q", m.SchemaVersion)
	}
	if m.StoreSchemaVersion != store.SchemaVersion {
		return fmt.Errorf("unsupported archive store schema %d", m.StoreSchemaVersion)
	}
	if !validPrefixedHash(m.ArchiveID, "arc1:") {
		return errors.New("archive ID is invalid")
	}
	return m.CreatedAt.Validate()
}

func containsFactID(facts []Fact, id string) bool {
	index := sort.Search(len(facts), func(i int) bool { return facts[i].ID >= id })
	return index < len(facts) && facts[index].ID == id
}
