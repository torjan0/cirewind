package publiclab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	tagMoveRecordSchemaVersion = "cirewind.lab-tag-move-record/v1alpha1"
	publicLabProtocolVersion   = "public-a-b-a/v1"
	repositoryDatabaseIDBasis  = "OPERATOR_ASSERTED_PREFLIGHT_REQUIRES_RUN_CROSSCHECK"
	tagMovePrivacyStatement    = "This tag-move record contains only public synthetic Git identities and exact remote-ref observations; it contains no remote URL, command output, authentication material, secret values, local paths, or private user data."
	packInputPrivacyStatement  = "This pack-input record contains only public synthetic Git identities and tag observations; it contains no raw logs, token material, secret values, private repository names, local paths, private user data, findings, or case hashes."
)

type tagMoveRecord struct {
	SchemaVersion        string                `json:"schema_version"`
	RecordID             string                `json:"record_id"`
	LabRepository        labRepositoryBinding  `json:"lab_repository"`
	RepositoryIDBasis    string                `json:"repository_database_id_basis"`
	ProtocolSourceCommit recordGitObject       `json:"protocol_source_commit"`
	FixtureObjects       labFixtureObjects     `json:"fixture_objects"`
	Move                 tagMoveRecordMove     `json:"move"`
	Before               *recordTagObservation `json:"before"`
	After                *recordTagObservation `json:"after"`
	Verified             bool                  `json:"verified"`
	Outcome              string                `json:"outcome"`
	Recovery             tagMoveRecordRecovery `json:"recovery"`
	RecordedAt           string                `json:"recorded_at"`
	PrivacyStatement     string                `json:"privacy_statement"`
	Privacy              publicRecordPrivacy   `json:"privacy"`
}

type packInputDocument struct {
	labPackInputRecord
	PrivacyStatement string              `json:"privacy_statement"`
	Privacy          publicRecordPrivacy `json:"privacy"`
}

type tagMoveRecordMove struct {
	Ref         string           `json:"ref"`
	Direction   TagMoveDirection `json:"direction"`
	ExpectedOld recordGitObject  `json:"expected_old"`
	NewTarget   recordGitObject  `json:"new_target"`
}

type tagMoveRecordRecovery struct {
	Required               bool             `json:"required"`
	Ref                    string           `json:"ref"`
	ObservedTarget         *recordGitObject `json:"observed_target"`
	KnownGoodTarget        recordGitObject  `json:"known_good_target"`
	RestoreExpectedOld     *recordGitObject `json:"restore_expected_old"`
	RestoreTarget          recordGitObject  `json:"restore_target"`
	RestoreAcknowledgement *string          `json:"restore_acknowledgement"`
}

type publicRecordPrivacy struct {
	RawLogsIncluded                bool `json:"rawLogsIncluded"`
	TokensOrCookiesIncluded        bool `json:"tokensOrCookiesIncluded"`
	SecretValuesIncluded           bool `json:"secretValuesIncluded"`
	PrivateRepositoryNamesIncluded bool `json:"privateRepositoryNamesIncluded"`
	LocalPathsIncluded             bool `json:"localPathsIncluded"`
	PrivateUserDataIncluded        bool `json:"privateUserDataIncluded"`
}

// EncodeTagMoveRecord converts a tag-control result into bounded public JSON.
// It records only reviewed object identities and exact ref observations; the
// remote URL, Git output, worktree, and authentication context are omitted.
func EncodeTagMoveRecord(policy TagMovePolicy, result TagMoveResult, moveErr error, recordedAt time.Time) ([]byte, error) {
	if err := validateTagMovePolicy(policy); err != nil {
		return nil, err
	}
	if result.Plan.Repository != policy.Repository || result.Plan.RepositoryDatabaseID != policy.RepositoryDatabaseID || result.Plan.Ref != MutableV1Ref {
		return nil, errors.New("tag-move result is not bound to the reviewed policy")
	}
	record := tagMoveRecord{
		SchemaVersion: tagMoveRecordSchemaVersion,
		LabRepository: labRepositoryBinding{
			DatabaseID: policy.RepositoryDatabaseID,
			FullName:   policy.Repository,
			PublicURL:  "https://github.com/" + policy.Repository,
		},
		RepositoryIDBasis:    repositoryDatabaseIDBasis,
		ProtocolSourceCommit: gitObjectFor(policy.ReviewedMain),
		FixtureObjects: labFixtureObjects{
			MarkerA: gitObjectFor(policy.CommitA),
			MarkerB: gitObjectFor(policy.CommitB),
			TagA:    labAnnotatedTagBinding{Ref: "refs/tags/fixture-a", TagObject: gitObjectFor(policy.FixtureATagObject), PeeledCommit: gitObjectFor(policy.CommitA)},
			TagB:    labAnnotatedTagBinding{Ref: "refs/tags/fixture-b", TagObject: gitObjectFor(policy.FixtureBTagObject), PeeledCommit: gitObjectFor(policy.CommitB)},
		},
		Move: tagMoveRecordMove{
			Ref:         result.Plan.Ref,
			Direction:   result.Plan.Direction,
			ExpectedOld: gitObjectFor(result.Plan.ExpectedOld),
			NewTarget:   gitObjectFor(result.Plan.NewTarget),
		},
		Verified:         result.Verified,
		Outcome:          classifyTagMoveOutcome(result, moveErr),
		RecordedAt:       canonicalObservationTime(recordedAt),
		PrivacyStatement: tagMovePrivacyStatement,
		Recovery: tagMoveRecordRecovery{
			Required:        false,
			Ref:             MutableV1Ref,
			KnownGoodTarget: gitObjectFor(policy.CommitA),
			RestoreTarget:   gitObjectFor(policy.CommitA),
		},
	}
	if result.Before != "" {
		record.Before = tagObservation(result.Before, result.BeforeObservedAt)
	}
	if result.After != "" {
		record.After = tagObservation(result.After, result.AfterObservedAt)
	}
	if result.Recovery != nil && result.Recovery.Required {
		recovery := tagMoveRecordRecovery{
			Required:        true,
			Ref:             MutableV1Ref,
			KnownGoodTarget: gitObjectFor(policy.CommitA),
			RestoreTarget:   gitObjectFor(policy.CommitA),
		}
		if isSHA1(result.Recovery.ObservedTarget) {
			value := gitObjectFor(result.Recovery.ObservedTarget)
			recovery.ObservedTarget = &value
		}
		if result.Recovery.ObservedTarget == policy.CommitB && len(result.Recovery.RestoreArguments) != 0 {
			value := gitObjectFor(policy.CommitB)
			recovery.RestoreExpectedOld = &value
			acknowledgement := RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitB, policy.CommitA)
			recovery.RestoreAcknowledgement = &acknowledgement
		}
		record.Recovery = recovery
	}
	if err := validateTagMoveRecordSemantics(record); err != nil {
		return nil, err
	}
	record.RecordID = tagMoveRecordID(record)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode tag-move record: %w", err)
	}
	return append(encoded, '\n'), nil
}

func tagObservation(target, observedAt string) *recordTagObservation {
	return &recordTagObservation{
		Target: gitObjectFor(target),
		Observation: recordObservation{
			ObservedAt:      observedAt,
			EventSource:     "git-ls-remote",
			SourcePrecision: "second",
			Approximation:   "conservative-expanded",
		},
	}
}

func classifyTagMoveOutcome(result TagMoveResult, err error) string {
	switch {
	case err == nil:
		return "CONFIRMED_APPLIED"
	case errors.Is(err, ErrTagMoveUnconfirmed):
		return "REMOTE_TARGET_REACHED_UNCONFIRMED"
	case errors.Is(err, ErrConcurrentTagMove):
		return "CONCURRENT_CHANGE"
	case errors.Is(err, ErrTagMoveUnknown):
		return "OUTCOME_UNKNOWN"
	case errors.Is(err, ErrRestoreFailed):
		return "RESTORE_FAILED"
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return "INTERRUPTED"
	case errors.Is(err, ErrTagMovePrecondition):
		return "PRECONDITION_FAILED"
	default:
		return "FAILED_UNCHANGED"
	}
}

func tagMoveRecordID(record tagMoveRecord) string {
	copyRecord := record
	copyRecord.RecordID = ""
	encoded, _ := json.Marshal(copyRecord)
	digest := sha256.Sum256(encoded)
	return "tag-move-" + hex.EncodeToString(digest[:16])
}

func validateTagMoveRecordSemantics(record tagMoveRecord) error {
	if record.SchemaVersion != tagMoveRecordSchemaVersion || record.RepositoryIDBasis != repositoryDatabaseIDBasis || record.LabRepository.DatabaseID <= 0 || !validRepositoryName(record.LabRepository.FullName) || record.LabRepository.PublicURL != "https://github.com/"+record.LabRepository.FullName {
		return errors.New("tag-move record repository or schema binding is invalid")
	}
	if record.PrivacyStatement != tagMovePrivacyStatement || record.Privacy != (publicRecordPrivacy{}) {
		return errors.New("tag-move record privacy contract is invalid")
	}
	if record.Move.Ref != MutableV1Ref || record.ProtocolSourceCommit.Algorithm != "sha1" || !isSHA1(record.ProtocolSourceCommit.ObjectID) {
		return errors.New("tag-move record protocol/ref binding is invalid")
	}
	if record.FixtureObjects.TagA.Ref != "refs/tags/fixture-a" || record.FixtureObjects.TagB.Ref != "refs/tags/fixture-b" ||
		record.FixtureObjects.TagA.PeeledCommit != record.FixtureObjects.MarkerA || record.FixtureObjects.TagB.PeeledCommit != record.FixtureObjects.MarkerB ||
		record.FixtureObjects.MarkerA == record.FixtureObjects.MarkerB || record.FixtureObjects.TagA.TagObject == record.FixtureObjects.TagB.TagObject {
		return errors.New("tag-move record fixture-object topology is invalid")
	}
	wantOld, wantNew := record.FixtureObjects.MarkerA, record.FixtureObjects.MarkerB
	if record.Move.Direction == RestoreKnownGood {
		wantOld, wantNew = wantNew, wantOld
	} else if record.Move.Direction != InstallAffectedMarker {
		return errors.New("tag-move record direction is unsupported")
	}
	if record.Move.ExpectedOld != wantOld || record.Move.NewTarget != wantNew {
		return errors.New("tag-move record direction does not bind exact A/B objects")
	}
	recordedAt, err := parseRecordTime(record.RecordedAt)
	if err != nil {
		return err
	}
	var beforeAt, afterAt time.Time
	if record.Before != nil {
		if record.Before.Observation.EventSource != "git-ls-remote" || record.Before.Target != record.Move.ExpectedOld && record.Outcome != "PRECONDITION_FAILED" {
			return errors.New("tag-move before observation does not bind expected-old")
		}
		beforeAt, err = parseRecordTime(record.Before.Observation.ObservedAt)
		if err != nil {
			return err
		}
	}
	if record.After != nil {
		if record.After.Observation.EventSource != "git-ls-remote" {
			return errors.New("tag-move after observation source is invalid")
		}
		afterAt, err = parseRecordTime(record.After.Observation.ObservedAt)
		if err != nil {
			return err
		}
	}
	if !beforeAt.IsZero() && !afterAt.IsZero() && !beforeAt.Before(afterAt) {
		return errors.New("tag-move observation times are not strictly ordered")
	}
	if !afterAt.IsZero() && recordedAt.Before(afterAt) || afterAt.IsZero() && !beforeAt.IsZero() && recordedAt.Before(beforeAt) {
		return errors.New("tag-move record time precedes its remote observation")
	}
	if record.Outcome == "CONFIRMED_APPLIED" {
		if !record.Verified || record.Before == nil || record.After == nil || record.After.Target != record.Move.NewTarget || record.Recovery.Required {
			return errors.New("confirmed tag move lacks exact before/after evidence")
		}
	}
	if record.Verified && (record.After == nil || record.After.Target != record.Move.NewTarget) {
		return errors.New("verified tag move does not have the requested target readback")
	}
	if record.Recovery.Ref != MutableV1Ref || record.Recovery.KnownGoodTarget != record.FixtureObjects.MarkerA || record.Recovery.RestoreTarget != record.FixtureObjects.MarkerA {
		return errors.New("tag-move recovery does not bind the reviewed known-good target")
	}
	if record.Recovery.Required {
		latest := record.After
		if record.Outcome == "PRECONDITION_FAILED" {
			latest = record.Before
		}
		if record.Recovery.ObservedTarget == nil {
			if record.Outcome != "OUTCOME_UNKNOWN" || record.After != nil || record.Before == nil {
				return errors.New("tag-move recovery omits an available exact readback")
			}
		} else if latest == nil || *record.Recovery.ObservedTarget != latest.Target {
			return errors.New("tag-move recovery observed target differs from the latest exact readback")
		}
		if record.Recovery.ObservedTarget != nil && *record.Recovery.ObservedTarget == record.FixtureObjects.MarkerB {
			wantAcknowledgement := RequiredTagMoveAcknowledgement(record.LabRepository.FullName, record.FixtureObjects.MarkerB.ObjectID, record.FixtureObjects.MarkerA.ObjectID)
			if record.Recovery.RestoreExpectedOld == nil || *record.Recovery.RestoreExpectedOld != record.FixtureObjects.MarkerB || record.Recovery.RestoreAcknowledgement == nil || *record.Recovery.RestoreAcknowledgement != wantAcknowledgement {
				return errors.New("tag-move recovery omits the exact B-to-A lease or acknowledgement")
			}
		} else if record.Recovery.RestoreExpectedOld != nil || record.Recovery.RestoreAcknowledgement != nil {
			return errors.New("tag-move recovery invents a restore lease without an exact B readback")
		}
	} else if record.Recovery.ObservedTarget != nil || record.Recovery.RestoreExpectedOld != nil || record.Recovery.RestoreAcknowledgement != nil {
		return errors.New("non-required tag recovery contains an operational restore claim")
	}
	switch record.Outcome {
	case "CONFIRMED_APPLIED":
	case "PRECONDITION_FAILED":
		if record.Verified || record.After != nil {
			return errors.New("precondition-failed tag record contains post-move claims")
		}
		if record.Before != nil && record.Before.Target == record.FixtureObjects.MarkerB && !record.Recovery.Required {
			return errors.New("precondition-failed tag record observed affected B without recovery guidance")
		}
		if record.Recovery.Required && (record.Before == nil || record.Before.Target != record.FixtureObjects.MarkerB) {
			return errors.New("precondition-failed tag record requires recovery without an exact affected-B readback")
		}
	case "FAILED_UNCHANGED":
		if record.Verified || record.Before == nil || record.After == nil || record.After.Target != record.Move.ExpectedOld || record.Recovery.Required {
			return errors.New("failed-unchanged tag record lacks unchanged readback")
		}
	case "REMOTE_TARGET_REACHED_UNCONFIRMED":
		if !record.Verified || record.After == nil || record.After.Target != record.Move.NewTarget {
			return errors.New("unconfirmed same-target outcome lacks exact target readback")
		}
	case "OUTCOME_UNKNOWN":
		if record.Verified || !record.Recovery.Required {
			return errors.New("unknown tag outcome claims verification or omits required reconciliation")
		}
	case "CONCURRENT_CHANGE":
		if record.Verified || record.After == nil || !record.Recovery.Required {
			return errors.New("concurrent-change outcome lacks contradictory readback and recovery")
		}
	case "INTERRUPTED":
		if record.Verified && record.After == nil {
			return errors.New("verified interrupted outcome lacks exact readback")
		}
	case "RESTORE_FAILED":
		if record.Move.Direction != RestoreKnownGood || record.Verified || record.After == nil || record.After.Target != record.FixtureObjects.MarkerB || !record.Recovery.Required {
			return errors.New("restore-failed outcome lacks exact retained-B readback and recovery")
		}
	default:
		return errors.New("tag-move outcome is unsupported")
	}
	if record.RecordID != "" && record.RecordID != tagMoveRecordID(record) {
		return errors.New("tag-move record ID does not bind its canonical content")
	}
	return nil
}

// GeneratePackInputRecord combines the confirmed A-to-B and B-to-A tool
// records into the pre-case incident-pack input. The two exact readback
// intervals, not a guessed exposure timestamp, bound the synthetic window.
func GeneratePackInputRecord(ctx context.Context, sourceRoot, schemaDir string, artifact Artifact, installJSON, restoreJSON []byte, createdAt time.Time) ([]byte, error) {
	if err := verifyArtifactValue(ctx, sourceRoot, artifact); err != nil {
		return nil, fmt.Errorf("verify reviewed public-lab artifact: %w", err)
	}
	install, err := decodeTagMoveRecord(installJSON)
	if err != nil {
		return nil, fmt.Errorf("validate install observation: %w", err)
	}
	restore, err := decodeTagMoveRecord(restoreJSON)
	if err != nil {
		return nil, fmt.Errorf("validate restore observation: %w", err)
	}
	if err := ValidateRecordAgainstArtifact(ctx, sourceRoot, schemaDir, RecordTagMove, installJSON, artifact); err != nil {
		return nil, fmt.Errorf("validate install observation contract: %w", err)
	}
	if err := ValidateRecordAgainstArtifact(ctx, sourceRoot, schemaDir, RecordTagMove, restoreJSON, artifact); err != nil {
		return nil, fmt.Errorf("validate restore observation contract: %w", err)
	}
	if err := bindTagMoveToArtifact(install, artifact); err != nil {
		return nil, fmt.Errorf("bind install observation: %w", err)
	}
	if err := bindTagMoveToArtifact(restore, artifact); err != nil {
		return nil, fmt.Errorf("bind restore observation: %w", err)
	}
	if install.LabRepository != restore.LabRepository || install.FixtureObjects != restore.FixtureObjects || install.ProtocolSourceCommit != restore.ProtocolSourceCommit {
		return nil, errors.New("tag-move records do not describe the same reviewed lab")
	}
	if install.Move.Direction != InstallAffectedMarker || restore.Move.Direction != RestoreKnownGood || install.Outcome != "CONFIRMED_APPLIED" || restore.Outcome != "CONFIRMED_APPLIED" {
		return nil, errors.New("pack input requires confirmed A-to-B and B-to-A moves")
	}
	if install.Before == nil || install.After == nil || restore.Before == nil || restore.After == nil || install.After.Target != restore.Before.Target {
		return nil, errors.New("tag-move records do not contain a closed A-to-B-to-A readback sequence")
	}
	installAfter, err := parseRecordTime(install.After.Observation.ObservedAt)
	if err != nil {
		return nil, err
	}
	restoreBefore, err := parseRecordTime(restore.Before.Observation.ObservedAt)
	if err != nil || !installAfter.Before(restoreBefore) {
		return nil, errors.New("restore precondition was not observed after the installed-B readback")
	}
	restoreAfter, err := parseRecordTime(restore.After.Observation.ObservedAt)
	if err != nil || createdAt.UTC().Before(restoreAfter) {
		return nil, errors.New("pack-input creation time precedes restored-A readback")
	}
	manifestDigest := sha256.Sum256(artifact.Manifest)
	installDigest := sha256.Sum256(installJSON)
	restoreDigest := sha256.Sum256(restoreJSON)
	core := labPackInputRecord{
		SchemaVersion:     "cirewind.lab-pack-input-record/v1alpha1",
		LabRepository:     install.LabRepository,
		RepositoryIDBasis: repositoryDatabaseIDBasis,
		Protocol: labProtocolBinding{
			Version:              publicLabProtocolVersion,
			SourceCommit:         install.ProtocolSourceCommit,
			SourceManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		},
		FixtureObjects: install.FixtureObjects,
		MutableTag: labMutableTag{
			Ref:    MutableV1Ref,
			Before: *install.Before,
			During: *install.After,
			After:  *restore.After,
		},
		DerivationInputs: []struct {
			RecordID string `json:"record_id"`
			SHA256   string `json:"sha256"`
		}{
			{RecordID: install.RecordID, SHA256: hex.EncodeToString(installDigest[:])},
			{RecordID: restore.RecordID, SHA256: hex.EncodeToString(restoreDigest[:])},
		},
		CreatedAt: canonicalObservationTime(createdAt),
	}
	core.RecordID = packInputRecordID(core)
	if err := validatePackInputDerivation(core, installJSON, restoreJSON, artifact); err != nil {
		return nil, fmt.Errorf("validate generated pack-input derivation: %w", err)
	}
	document := packInputDocument{
		labPackInputRecord: core,
		PrivacyStatement:   packInputPrivacyStatement,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode pack-input record: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := ValidateRecordAgainstArtifact(ctx, sourceRoot, schemaDir, RecordPackInput, encoded, artifact); err != nil {
		return nil, fmt.Errorf("validate generated pack-input record: %w", err)
	}
	return encoded, nil
}

func packInputRecordID(record labPackInputRecord) string {
	copyRecord := record
	copyRecord.RecordID = ""
	encoded, _ := json.Marshal(copyRecord)
	digest := sha256.Sum256(encoded)
	return "pack-input-" + hex.EncodeToString(digest[:16])
}

func validatePackInputDerivation(record labPackInputRecord, installJSON, restoreJSON []byte, artifact Artifact) error {
	install, err := decodeTagMoveRecord(installJSON)
	if err != nil {
		return errors.New("install derivation record is invalid")
	}
	restore, err := decodeTagMoveRecord(restoreJSON)
	if err != nil {
		return errors.New("restore derivation record is invalid")
	}
	if err := bindTagMoveToArtifact(install, artifact); err != nil {
		return err
	}
	if err := bindTagMoveToArtifact(restore, artifact); err != nil {
		return err
	}
	if install.RepositoryIDBasis != repositoryDatabaseIDBasis || restore.RepositoryIDBasis != repositoryDatabaseIDBasis ||
		install.LabRepository != restore.LabRepository || install.FixtureObjects != restore.FixtureObjects || install.ProtocolSourceCommit != restore.ProtocolSourceCommit {
		return errors.New("tag-move derivation records do not describe one reviewed lab")
	}
	if install.Move.Direction != InstallAffectedMarker || restore.Move.Direction != RestoreKnownGood ||
		install.Outcome != "CONFIRMED_APPLIED" || restore.Outcome != "CONFIRMED_APPLIED" ||
		install.Before == nil || install.After == nil || restore.Before == nil || restore.After == nil || install.After.Target != restore.Before.Target {
		return errors.New("pack input requires a closed confirmed A-to-B-to-A derivation")
	}
	installAfter, err := parseRecordTime(install.After.Observation.ObservedAt)
	if err != nil {
		return err
	}
	restoreBefore, err := parseRecordTime(restore.Before.Observation.ObservedAt)
	if err != nil || !installAfter.Before(restoreBefore) {
		return errors.New("restore derivation does not follow the installed-B readback")
	}
	restoreAfter, err := parseRecordTime(restore.After.Observation.ObservedAt)
	if err != nil {
		return err
	}
	createdAt, err := parseRecordTime(record.CreatedAt)
	if err != nil || createdAt.Before(restoreAfter) {
		return errors.New("pack-input creation does not follow the restored-A readback")
	}
	manifestDigest := sha256.Sum256(artifact.Manifest)
	wantProtocol := labProtocolBinding{
		Version:              publicLabProtocolVersion,
		SourceCommit:         install.ProtocolSourceCommit,
		SourceManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}
	wantMutable := labMutableTag{Ref: MutableV1Ref, Before: *install.Before, During: *install.After, After: *restore.After}
	if record.LabRepository != install.LabRepository || record.RepositoryIDBasis != repositoryDatabaseIDBasis || record.Protocol != wantProtocol ||
		record.FixtureObjects != install.FixtureObjects || record.MutableTag != wantMutable {
		return errors.New("pack input facts differ from exact tag-move derivation records")
	}
	installDigest := sha256.Sum256(installJSON)
	restoreDigest := sha256.Sum256(restoreJSON)
	if len(record.DerivationInputs) != 2 ||
		record.DerivationInputs[0].RecordID != install.RecordID || record.DerivationInputs[0].SHA256 != hex.EncodeToString(installDigest[:]) ||
		record.DerivationInputs[1].RecordID != restore.RecordID || record.DerivationInputs[1].SHA256 != hex.EncodeToString(restoreDigest[:]) {
		return errors.New("pack input derivation identities do not bind the exact install and restore bytes")
	}
	if record.RecordID == "" || record.RecordID != packInputRecordID(record) {
		return errors.New("pack-input record ID does not bind its canonical content")
	}
	return nil
}

func decodeTagMoveRecord(data []byte) (tagMoveRecord, error) {
	if len(data) == 0 || len(data) > maxRecordBytes {
		return tagMoveRecord{}, errors.New("tag-move record is empty or oversized")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return tagMoveRecord{}, err
	}
	var record tagMoveRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return tagMoveRecord{}, err
	}
	if err := validateTagMoveRecordSemantics(record); err != nil {
		return tagMoveRecord{}, err
	}
	if record.RecordID == "" || record.RecordID != tagMoveRecordID(record) {
		return tagMoveRecord{}, errors.New("tag-move record ID does not bind its content")
	}
	return record, nil
}

// ReadTagMoveRecord reads one bounded regular file, rejects links through the
// shared single-open reader, and verifies its content-bound record identity.
func ReadTagMoveRecord(ctx context.Context, schemaDir, path string) ([]byte, error) {
	data, err := readBoundedRegular(path, maxRecordBytes)
	if err != nil {
		return nil, err
	}
	if err := ValidateRecord(ctx, schemaDir, RecordTagMove, data); err != nil {
		return nil, err
	}
	if _, err := decodeTagMoveRecord(data); err != nil {
		return nil, err
	}
	return data, nil
}

func bindTagMoveToArtifact(record tagMoveRecord, artifact Artifact) error {
	if err := verifyArtifactModel(artifact); err != nil {
		return err
	}
	if record.LabRepository.FullName != artifact.Model.Repository {
		return errors.New("tag-move repository differs from artifact repository")
	}
	commits := make(map[string]string, len(artifact.Model.Commits))
	for _, commit := range artifact.Model.Commits {
		commits[commit.Role] = commit.ObjectID
	}
	tags := manifestTagsByName(artifact.Model)
	if record.ProtocolSourceCommit != gitObjectFor(commits["import"]) ||
		record.FixtureObjects.MarkerA != gitObjectFor(commits["marker-a"]) ||
		record.FixtureObjects.MarkerB != gitObjectFor(commits["marker-b"]) ||
		record.FixtureObjects.TagA.TagObject != gitObjectFor(tags["fixture-a"].ObjectID) ||
		record.FixtureObjects.TagA.PeeledCommit != gitObjectFor(tags["fixture-a"].PeeledCommitID) ||
		record.FixtureObjects.TagB.TagObject != gitObjectFor(tags["fixture-b"].ObjectID) ||
		record.FixtureObjects.TagB.PeeledCommit != gitObjectFor(tags["fixture-b"].PeeledCommitID) {
		return errors.New("tag-move record object identities differ from artifact manifest")
	}
	return nil
}
