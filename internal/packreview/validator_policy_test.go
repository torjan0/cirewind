package packreview

import (
	"context"
	"path/filepath"
	"testing"
)

func TestValidateUnitRejectsUnsupportedIncidentValidatorPolicy(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	packet := repo.unitValue.Pack
	packet.ValidatorVersion = "incident-validator-unsupported"
	mustWrite(t, filepath.Join(repo.candidate, "packet.json"), mustCanonical(t, packet))
	if _, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}

	_, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit)
	assertProblemCode(t, err, "UNSUPPORTED_INCIDENT_VALIDATOR_POLICY")
}

func TestValidateUnitBindsSelectedIncidentValidatorPolicyHash(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	packet := repo.unitValue.Pack
	packet.ValidatorPolicySHA256 = stringOf('b', 64)
	mustWrite(t, filepath.Join(repo.candidate, "packet.json"), mustCanonical(t, packet))
	validation := repo.unitValue.Validation
	validation.ValidatorPolicySHA256 = packet.ValidatorPolicySHA256
	mustWrite(t, filepath.Join(repo.candidate, "validation.json"), mustCanonical(t, validation))
	if _, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}

	_, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit)
	assertProblemCode(t, err, "HASH_BINDING")
}
