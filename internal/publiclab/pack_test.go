package publiclab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

func TestValidateQualifiedRunRecordAgainstArtifact(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	record := qualifiedPublicLabRunRecord(t, artifact)
	data := marshalPublicLabRecord(t, record)
	packInputData := marshalPublicLabRecord(t, qualifiedPublicLabPackInputRecord(t, artifact))
	if err := ValidateRunRecordAgainstPackInput(context.Background(), sourceRoot(t), recordSchemaDir(t), data, packInputData, artifact); err != nil {
		t.Fatalf("qualified record rejected: %v", err)
	}
	if err := ValidateRecordAgainstArtifact(context.Background(), sourceRoot(t), recordSchemaDir(t), RecordRun, data, artifact); err != nil {
		t.Fatalf("qualified scenario oracle rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"repository database ID": func(value map[string]any) {
			value["lab_repository"].(map[string]any)["database_id"] = float64(202)
		},
		"mutable observation time": func(value map[string]any) {
			value["mutable_tag"].(map[string]any)["during"].(map[string]any)["observation"].(map[string]any)["observedAt"] = "2026-01-01T00:01:01Z"
		},
	} {
		t.Run("pack-input cross-binding "+name, func(t *testing.T) {
			value := cloneRecordValue(t, record).(map[string]any)
			mutate(value)
			if err := ValidateRunRecordAgainstPackInput(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, value), packInputData, artifact); err == nil {
				t.Fatal("run record differing from exact pack-input identity was accepted")
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "source manifest binding",
			mutate: func(value map[string]any) {
				value["protocol"].(map[string]any)["source_manifest_sha256"] = strings.Repeat("0", 64)
			},
		},
		{
			name: "marker B binding",
			mutate: func(value map[string]any) {
				value["fixture_objects"].(map[string]any)["marker_b_commit"] = syntheticGitObject("f")
				value["fixture_objects"].(map[string]any)["fixture_b_tag"].(map[string]any)["peeled_commit"] = syntheticGitObject("f")
				value["mutable_tag"].(map[string]any)["during"].(map[string]any)["target_commit"] = syntheticGitObject("f")
			},
		},
		{
			name: "scenario omitted",
			mutate: func(value map[string]any) {
				runs := value["workflow_runs"].([]any)
				value["workflow_runs"] = runs[:len(runs)-1]
			},
		},
		{
			name: "matrix job omitted",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-MATRIX")
				attempt := firstRecordObject(run, "attempts")
				attempt["jobs"] = attempt["jobs"].([]any)[:3]
			},
		},
		{
			name: "missing job log",
			mutate: func(value map[string]any) {
				coverage := value["collection"].(map[string]any)["coverage"].(map[string]any)
				coverage["logs_retrieved"] = 15
				coverage["logs_missing"] = 1
			},
		},
		{
			name: "truncated evidence",
			mutate: func(value map[string]any) {
				value["collection"].(map[string]any)["coverage"].(map[string]any)["truncated_evidence_objects"] = 1
			},
		},
		{
			name: "denied repository",
			mutate: func(value map[string]any) {
				coverage := value["collection"].(map[string]any)["coverage"].(map[string]any)
				coverage["repositories_requested"] = 2
				coverage["repositories_denied"] = 1
			},
		},
		{
			name: "identity coverage undercount",
			mutate: func(value map[string]any) {
				value["collection"].(map[string]any)["coverage"].(map[string]any)["runs_enumerated"] = 6
			},
		},
		{
			name: "identity coverage overcount",
			mutate: func(value map[string]any) {
				value["collection"].(map[string]any)["coverage"].(map[string]any)["attempts_enumerated"] = 11
			},
		},
		{
			name: "definition coverage overcount",
			mutate: func(value map[string]any) {
				value["collection"].(map[string]any)["coverage"].(map[string]any)["action_definitions_retrieved"] = 3
			},
		},
		{
			name: "missing-log collection issue",
			mutate: func(value map[string]any) {
				value["collection"].(map[string]any)["issues"] = []any{map[string]any{
					"code": "logs-expired", "scope": "PUBLIC-DIRECT", "summary": "One required synthetic job log was unavailable.",
				}}
			},
		},
		{
			name: "reusable identity changed",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-REUSABLE")
				job := firstRecordObject(firstRecordObject(run, "attempts"), "jobs")
				firstRecordObject(job, "called_workflow_observations")["called_workflow_commit"] = syntheticGitObject("f")
			},
		},
		{
			name: "marker declared ref changed",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-DIRECT")
				firstRecordObject(job, "action_observations")["declared_ref"] = value["fixture_objects"].(map[string]any)["marker_b_commit"].(map[string]any)["objectId"]
			},
		},
		{
			name: "wrapper declared ref changed",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
				job["action_observations"].([]any)[1].(map[string]any)["declared_ref"] = "v1"
			},
		},
		{
			name: "extra third-party Action observation",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-DIRECT")
				job["action_observations"] = append(job["action_observations"].([]any), map[string]any{
					"action_repository": "synthetic-third-party/marker", "action_path": "actions/marker/action.yml", "declared_ref": strings.Repeat("e", 40),
					"source_commit": syntheticGitObject("e"), "lifecycle": "LIFECYCLE_STARTED", "step_identity": "step:third-party",
					"evidence_ids": []any{testVersionedID("ev1", 994)},
				})
			},
		},
		{
			name: "extra contradictory marker-A observation",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-DIRECT")
				job["action_observations"] = append(job["action_observations"].([]any), map[string]any{
					"action_repository": RepositoryName, "action_path": "actions/marker/action.yml", "declared_ref": "v1",
					"source_commit": value["fixture_objects"].(map[string]any)["marker_a_commit"], "lifecycle": "LIFECYCLE_STARTED", "step_identity": "step:marker",
					"evidence_ids": []any{testVersionedID("ev1", 995)},
				})
			},
		},
		{
			name: "unexpected called workflow",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-DIRECT")
				job["called_workflow_observations"] = []any{map[string]any{
					"repository": RepositoryName, "workflow_path": ".github/workflows/reusable.yml",
					"called_workflow_commit": syntheticGitObject("e"), "evidence_ids": []any{testVersionedID("ev1", 996)},
				}}
			},
		},
		{
			name: "finding ID reused across jobs",
			mutate: func(value map[string]any) {
				first := firstQualifiedFinding(value, "PUBLIC-COMPOSITE")
				firstQualifiedFinding(value, "PUBLIC-DIRECT")["finding_id"] = first["finding_id"]
			},
		},
		{
			name: "finding revision reused across jobs",
			mutate: func(value map[string]any) {
				first := firstQualifiedFinding(value, "PUBLIC-COMPOSITE")
				firstQualifiedFinding(value, "PUBLIC-DIRECT")["finding_revision_id"] = first["finding_revision_id"]
			},
		},
		{
			name: "exact finding provenance weakened",
			mutate: func(value map[string]any) {
				firstQualifiedFinding(value, "PUBLIC-DIRECT")["provenance"] = "L3_STRONG"
			},
		},
		{
			name: "finding cites evidence outside its job",
			mutate: func(value map[string]any) {
				firstQualifiedFinding(value, "PUBLIC-DIRECT")["evidence_ids"] = []any{testVersionedID("ev1", 999)}
			},
		},
		{
			name: "dependency edge cites evidence outside its job",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
				firstRecordObject(job, "dependency_chain")["evidence_ids"] = []any{testVersionedID("ev1", 999)}
			},
		},
		{
			name: "wrapper and marker edge evidence swapped",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
				links := job["dependency_chain"].([]any)
				first := links[0].(map[string]any)["evidence_ids"]
				second := links[1].(map[string]any)["evidence_ids"]
				links[0].(map[string]any)["evidence_ids"] = second
				links[1].(map[string]any)["evidence_ids"] = first
			},
		},
		{
			name: "edge cites unrelated same-job observation",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
				links := job["dependency_chain"].([]any)
				links[0].(map[string]any)["evidence_ids"] = links[1].(map[string]any)["evidence_ids"]
			},
		},
		{
			name: "same-repository Action path differs from edge",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-DIRECT")
				firstRecordObject(job, "action_observations")["action_path"] = "actions/other/action.yml"
			},
		},
		{
			name: "called-workflow edge cites Action observation",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-REUSABLE")
				links := job["dependency_chain"].([]any)
				links[0].(map[string]any)["evidence_ids"] = links[1].(map[string]any)["evidence_ids"]
			},
		},
		{
			name: "composite transitive link omitted",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
				job["dependency_chain"] = job["dependency_chain"].([]any)[:1]
			},
		},
		{
			name: "reusable transitive chain omitted",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-REUSABLE")
				job["dependency_chain"] = job["dependency_chain"].([]any)[:2]
			},
		},
		{
			name: "skipped job hides uncited B lifecycle start",
			mutate: func(value map[string]any) {
				job := firstQualifiedJob(value, "PUBLIC-SKIPPED")
				appendUncitedQualifiedStart(job, value["fixture_objects"].(map[string]any)["marker_b_commit"], testVersionedID("ev1", 997))
			},
		},
		{
			name: "restored-A rerun hides extra B lifecycle start",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-FULL")
				job := firstRecordObject(run["attempts"].([]any)[1].(map[string]any), "jobs")
				appendUncitedQualifiedStart(job, value["fixture_objects"].(map[string]any)["marker_b_commit"], testVersionedID("ev1", 998))
			},
		},
		{
			name: "run attempts skip a number",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-FULL")
				run["attempts"].([]any)[1].(map[string]any)["run_attempt"] = 3
			},
		},
		{
			name: "job ID reused across attempts",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-FULL")
				first := firstRecordObject(run["attempts"].([]any)[0].(map[string]any), "jobs")
				firstRecordObject(run["attempts"].([]any)[1].(map[string]any), "jobs")["job_id"] = first["job_id"]
			},
		},
		{
			name: "full rerun omits a job",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-FULL")
				attempt := run["attempts"].([]any)[1].(map[string]any)
				attempt["jobs"] = attempt["jobs"].([]any)[:1]
			},
		},
		{
			name: "full rerun lineage duplicates original",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-FULL")
				jobs := run["attempts"].([]any)[1].(map[string]any)["jobs"].([]any)
				jobs[1].(map[string]any)["rerun_of_job_id"] = jobs[0].(map[string]any)["rerun_of_job_id"]
			},
		},
		{
			name: "failed-jobs rerun includes successful job",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-JOB")
				jobs := run["attempts"].([]any)[0].(map[string]any)["jobs"].([]any)
				jobs[1].(map[string]any)["conclusion"] = "success"
			},
		},
		{
			name: "single-job request selects another attempt",
			mutate: func(value map[string]any) {
				run := qualifiedScenario(value, "PUBLIC-RERUN-JOB")
				original := firstRecordObject(run["attempts"].([]any)[0].(map[string]any), "jobs")
				value["rerun_requests"].([]any)[2].(map[string]any)["job_id"] = original["job_id"]
			},
		},
		{
			name: "rerun requested before restored A",
			mutate: func(value map[string]any) {
				request := value["rerun_requests"].([]any)[0].(map[string]any)
				request["operator_action_time"] = syntheticObservation("2026-01-01T00:07:59Z", "github-web-ui")
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := cloneRecordValue(t, record).(map[string]any)
			test.mutate(value)
			if err := ValidateRecordAgainstArtifact(context.Background(), sourceRoot(t), recordSchemaDir(t), RecordRun, marshalPublicLabRecord(t, value), artifact); err == nil {
				t.Fatal("mutated binding or qualified scenario set was accepted")
			}
		})
	}

	tampered := artifact
	tampered.Bundle = append([]byte(nil), artifact.Bundle...)
	tampered.Bundle[len(tampered.Bundle)/2] ^= 1
	if err := ValidateRunRecordAgainstPackInput(context.Background(), sourceRoot(t), recordSchemaDir(t), data, packInputData, tampered); err == nil {
		t.Fatal("record verified against a tampered artifact")
	}
}

func TestArtifactBoundValidationRejectsExternalSchemaDirectory(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	for _, name := range append(append([]string(nil), recordSchemaFiles...), "expected-findings.seed.json") {
		data, err := os.ReadFile(filepath.Join(recordSchemaDir(t), name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "run-record.schema.json" {
			data = bytes.Replace(data, []byte(`"actor",`), nil, 1)
		}
		if err := os.WriteFile(filepath.Join(external, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	record := qualifiedPublicLabRunRecord(t, artifact)
	data := marshalPublicLabRecord(t, record)
	err = ValidateRecordAgainstArtifact(context.Background(), sourceRoot(t), external, RecordRun, data, artifact)
	if err == nil || !strings.Contains(err.Error(), "not the reviewed artifact-bound protocol directory") {
		t.Fatalf("external schema directory error=%v", err)
	}
}

func TestArtifactBoundValidationRejectsForgedInMemoryManifestModel(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	record := qualifiedPublicLabRunRecord(t, artifact)
	data := marshalPublicLabRecord(t, record)
	artifact.Model.Repository = "example/forged-lab"
	err = ValidateRecordAgainstArtifact(context.Background(), sourceRoot(t), recordSchemaDir(t), RecordRun, data, artifact)
	if err == nil || !strings.Contains(err.Error(), "in-memory artifact model differs") {
		t.Fatalf("forged in-memory manifest model error=%v", err)
	}
}

func firstQualifiedJob(value map[string]any, scenario string) map[string]any {
	return firstRecordObject(firstRecordObject(qualifiedScenario(value, scenario), "attempts"), "jobs")
}

func firstQualifiedFinding(value map[string]any, scenario string) map[string]any {
	return firstRecordObject(firstQualifiedJob(value, scenario), "findings")
}

func appendUncitedQualifiedStart(job map[string]any, source any, evidenceID string) {
	job["action_observations"] = append(job["action_observations"].([]any), map[string]any{
		"action_repository": RepositoryName,
		"action_path":       "actions/marker/action.yml",
		"declared_ref":      "v1",
		"source_commit":     source,
		"lifecycle":         "LIFECYCLE_STARTED",
		"step_identity":     "step:uncited",
		"evidence_ids":      []any{evidenceID},
	})
}

func TestGenerateSyntheticIncidentPackIsDeterministicAndConservative(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	record := qualifiedPublicLabPackInputRecord(t, artifact)
	data := marshalPublicLabRecord(t, record)
	revision := strings.Repeat("d", 40) // Later immutable observations-branch commit; main remains import I.
	recordURL := "https://github.com/torjan0/cirewind-lab/blob/" + revision + "/observations/" + record["record_id"].(string) + ".json"

	first, err := GenerateSyntheticIncidentPack(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, data, recordURL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateSyntheticIncidentPack(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, data, recordURL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical manifest-bound observations produced different incident-pack bytes")
	}
	validated, err := incident.Validate(context.Background(), first)
	if err != nil {
		t.Fatalf("generated pack did not pass the production validator: %v", err)
	}
	pack := validated.Pack
	if pack.Metadata.ID != syntheticIncidentIDFor(artifact.Model.Repository, artifact.Model.Commits[2].ObjectID) || len(pack.Spec.Windows) != 1 || len(pack.Spec.Indicators) != 2 || len(pack.Spec.KnownGood) != 1 {
		t.Fatalf("generated pack shape=%#v", pack)
	}
	if !strings.HasPrefix(pack.Metadata.PackVersion, "1.0.0+exercise.") {
		t.Fatalf("pack version does not distinguish observation bytes: %q", pack.Metadata.PackVersion)
	}
	window := pack.Spec.Windows[0]
	if window.Start != "2026-01-01T00:00:00Z" || window.End != "2026-01-01T00:08:00Z" || window.Bounds != "()" || window.SourcePrecision != "second" || window.Approximation != "conservative-expanded" {
		t.Fatalf("window=%#v", window)
	}
	if !strings.Contains(window.Notes, "does not by itself prove") {
		t.Fatalf("window omitted non-causal limitation: %q", window.Notes)
	}

	indicators := make(map[string]incident.Indicator, len(pack.Spec.Indicators))
	for _, indicator := range pack.Spec.Indicators {
		indicators[indicator.ID] = indicator
	}
	exactB := indicators["public-lab-marker-b"]
	if exactB.Confidence != model.L4Certain || exactB.Value.GitObject == nil || exactB.Value.GitObject.Algorithm != "sha1" || exactB.Value.GitObject.Value != artifact.Model.Commits[2].ObjectID {
		t.Fatalf("exact marker B indicator=%#v", exactB)
	}
	mutable := indicators["public-lab-mutable-v1"]
	if mutable.Confidence != model.L3Strong || mutable.Value.Ref != "v1" || len(mutable.WindowRefs) != 1 || mutable.WindowRefs[0] != window.ID {
		t.Fatalf("mutable v1 indicator=%#v", mutable)
	}
	knownA := pack.Spec.KnownGood[0]
	if knownA.Confidence != model.L4Certain || knownA.Value.GitObject == nil || knownA.Value.GitObject.Value != artifact.Model.Commits[1].ObjectID {
		t.Fatalf("known-good marker A=%#v", knownA)
	}
	var packInputSource incident.Source
	for _, source := range pack.Metadata.Sources {
		if source.ID == packInputSourceID {
			packInputSource = source
		}
	}
	if packInputSource.URL != recordURL || packInputSource.SourceRevision != revision {
		t.Fatalf("pack-input source was not bound to immutable URL: %#v", packInputSource)
	}
	changedRecord := cloneRecordValue(t, record).(map[string]any)
	changedRecord["created_at"] = "2026-01-01T00:10:00Z"
	changedRecord["record_id"] = contentBoundPackInputID(t, changedRecord)
	changedRevision := strings.Repeat("e", 40)
	changedURL := "https://github.com/torjan0/cirewind-lab/blob/" + changedRevision + "/observations/" + changedRecord["record_id"].(string) + ".json"
	changedBytes, err := GenerateSyntheticIncidentPack(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, marshalPublicLabRecord(t, changedRecord), changedURL)
	if err != nil {
		t.Fatal(err)
	}
	changedPack, err := incident.Validate(context.Background(), changedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if changedPack.Pack.Metadata.ID != pack.Metadata.ID || changedPack.Pack.Metadata.PackVersion == pack.Metadata.PackVersion {
		t.Fatalf("materially different exercise bytes did not receive a distinct pack version: %q vs %q", pack.Metadata.PackVersion, changedPack.Pack.Metadata.PackVersion)
	}
}

func TestGenerateSyntheticIncidentPackRejectsUnsafeRecordURLsAndCancellation(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	record := qualifiedPublicLabPackInputRecord(t, artifact)
	data := marshalPublicLabRecord(t, record)
	revision := strings.Repeat("d", 40)
	recordID := record["record_id"].(string)
	valid := "https://github.com/torjan0/cirewind-lab/blob/" + revision + "/observations/" + recordID + ".json"
	for name, value := range map[string]string{
		"mutable branch": "https://github.com/torjan0/cirewind-lab/blob/main/observations/" + recordID + ".json",
		"wrong record":   "https://github.com/torjan0/cirewind-lab/blob/" + revision + "/observations/another-record.json",
		"query":          valid + "?download=1",
		"fragment":       valid + "#record",
		"userinfo":       "https://user@github.com/torjan0/cirewind-lab/blob/" + revision + "/observations/qualified-public-lab.json",
		"other host":     "https://example.invalid/torjan0/cirewind-lab/blob/" + revision + "/observations/qualified-public-lab.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := GenerateSyntheticIncidentPack(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, data, value); err == nil {
				t.Fatalf("unsafe record URL accepted: %q", value)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GenerateSyntheticIncidentPack(ctx, sourceRoot(t), recordSchemaDir(t), artifact, data, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v, want context.Canceled", err)
	}
}

func contentBoundPackInputID(t *testing.T, value map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var record labPackInputRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	return packInputRecordID(record)
}

func qualifiedPublicLabPackInputRecord(t *testing.T, artifact Artifact) map[string]any {
	t.Helper()
	run := qualifiedPublicLabRunRecord(t, artifact)
	value := map[string]any{
		"schema_version":               "cirewind.lab-pack-input-record/v1alpha1",
		"record_id":                    "pack-input-placeholder",
		"lab_repository":               cloneRecordValue(t, run["lab_repository"]),
		"repository_database_id_basis": "OPERATOR_ASSERTED_PREFLIGHT_REQUIRES_RUN_CROSSCHECK",
		"protocol":                     cloneRecordValue(t, run["protocol"]),
		"fixture_objects":              cloneRecordValue(t, run["fixture_objects"]),
		"mutable_tag":                  cloneRecordValue(t, run["mutable_tag"]),
		"derivation_inputs": []any{
			map[string]any{"record_id": "tag-move-install", "sha256": strings.Repeat("b", 64)},
			map[string]any{"record_id": "tag-move-restore", "sha256": strings.Repeat("c", 64)},
		},
		"created_at":        "2026-01-01T00:09:00Z",
		"privacy_statement": "This pack-input record contains only public synthetic Git identities and tag observations; it contains no raw logs, token material, secret values, private repository names, local paths, private user data, findings, or case hashes.",
		"privacy":           cloneRecordValue(t, run["privacy"]),
	}
	value["record_id"] = contentBoundPackInputID(t, value)
	return value
}

func qualifiedPublicLabRunRecord(t *testing.T, artifact Artifact) map[string]any {
	t.Helper()
	value := validPublicLabRunRecord()
	manifest := artifact.Model
	tags := manifestTagsByName(manifest)
	importCommit := manifest.Commits[5].ObjectID
	markerA := manifest.Commits[1].ObjectID
	markerB := manifest.Commits[2].ObjectID
	value["record_id"] = "qualified-public-lab"
	value["protocol"] = map[string]any{
		"version":                "public-a-b-a/v1",
		"source_commit":          testGitObject(importCommit),
		"source_manifest_sha256": manifestSHA256(artifact.Manifest),
	}
	value["fixture_objects"] = map[string]any{
		"marker_a_commit": testGitObject(markerA),
		"marker_b_commit": testGitObject(markerB),
		"fixture_a_tag": map[string]any{
			"ref":           "refs/tags/fixture-a",
			"tag_object":    testGitObject(tags["fixture-a"].ObjectID),
			"peeled_commit": testGitObject(markerA),
		},
		"fixture_b_tag": map[string]any{
			"ref":           "refs/tags/fixture-b",
			"tag_object":    testGitObject(tags["fixture-b"].ObjectID),
			"peeled_commit": testGitObject(markerB),
		},
	}
	value["mutable_tag"] = map[string]any{
		"ref":    "refs/tags/v1",
		"before": qualifiedTagObservation(markerA, "2026-01-01T00:00:00Z"),
		"during": qualifiedTagObservation(markerB, "2026-01-01T00:01:00Z"),
		"after":  qualifiedTagObservation(markerA, "2026-01-01T00:08:00Z"),
	}

	nextEvidence := 1
	nextFinding := 1
	nextJob := int64(3000)
	newJob := func(source, lifecycle, state, label string) map[string]any {
		nextJob++
		evidence := testVersionedID("ev1", nextEvidence)
		nextEvidence++
		coverage := testVersionedID("cova1", nextEvidence)
		nextEvidence++
		findingID := testVersionedID("find1", nextFinding)
		nextFinding++
		revisionID := testVersionedID("frev1", nextFinding)
		nextFinding++
		provenance := "L4_CERTAIN"
		conclusion := "Exact harmless synthetic marker B began its lifecycle in this job attempt."
		if state == "CONFIRMED_DOWNLOADED" {
			conclusion = "Exact harmless synthetic marker B completed preparation, but no lifecycle start was observed."
		}
		if state == "NO_MATCH_CONFIRMED" {
			conclusion = "Exact reviewed marker A began after v1 restoration; complete retained evidence contains no marker B observation for this job attempt."
		}
		return map[string]any{
			"job_id":       nextJob,
			"display_name": label,
			"conclusion":   "success",
			"action_observations": []any{map[string]any{
				"action_repository": RepositoryName,
				"action_path":       "actions/marker/action.yml",
				"declared_ref":      "v1",
				"source_commit":     testGitObject(source),
				"lifecycle":         lifecycle,
				"step_identity":     "step:marker",
				"evidence_ids":      []any{evidence},
			}},
			"called_workflow_observations": []any{},
			"dependency_chain":             []any{},
			"findings": []any{map[string]any{
				"finding_id":              findingID,
				"finding_revision_id":     revisionID,
				"indicator_id":            "public-lab-marker-b",
				"step_identity":           "step:marker",
				"state":                   state,
				"provenance":              provenance,
				"conclusion":              conclusion,
				"evidence_ids":            []any{evidence},
				"coverage_assessment_ids": []any{coverage},
				"evidence_gap_codes":      []any{},
			}},
		}
	}
	bJob := func(label string) map[string]any {
		return newJob(markerB, "LIFECYCLE_STARTED", "CONFIRMED_EXECUTED", label)
	}
	aJob := func(label string) map[string]any {
		return newJob(markerA, "LIFECYCLE_STARTED", "NO_MATCH_CONFIRMED", label)
	}
	skippedJob := newJob(markerB, "PREPARATION_COMPLETED", "CONFIRMED_DOWNLOADED", "Skipped marker")
	skippedJob["conclusion"] = "skipped"
	conditionEvidence := testVersionedID("ev1", nextEvidence)
	nextEvidence++
	skippedJob["action_observations"] = append(skippedJob["action_observations"].([]any), map[string]any{
		"action_repository": RepositoryName,
		"action_path":       "actions/marker/action.yml",
		"declared_ref":      "v1",
		"source_commit":     testGitObject(markerB),
		"lifecycle":         "CONDITION_SKIPPED",
		"step_identity":     "step:marker",
		"evidence_ids":      []any{conditionEvidence},
	})

	fullOriginalSuccess := bJob("Full rerun original success marker")
	fullOriginalFailure := bJob("Full rerun original failure marker")
	fullOriginalFailure["conclusion"] = "failure"
	fullRestoredSuccess := aJob("Full rerun restored success marker")
	fullRestoredSuccess["rerun_of_job_id"] = fullOriginalSuccess["job_id"]
	fullRestoredFailure := aJob("Full rerun restored failure marker")
	fullRestoredFailure["rerun_of_job_id"] = fullOriginalFailure["job_id"]

	jobOriginalSuccess := bJob("Job rerun original success marker")
	jobOriginalFailure := bJob("Job rerun original failure marker")
	jobOriginalFailure["conclusion"] = "failure"
	failedJobRestored := aJob("Failed-job rerun restored marker")
	failedJobRestored["rerun_of_job_id"] = jobOriginalFailure["job_id"]
	singleJobRestored := aJob("Single-job rerun restored marker")
	singleJobRestored["rerun_of_job_id"] = failedJobRestored["job_id"]

	runs := []any{
		qualifiedWorkflowRun(importCommit, "PUBLIC-COMPOSITE", ".github/workflows/composite.yml", 1001, "2026-01-01T00:02:00Z", []any{qualifiedAttempt(1, bJob("Composite marker"))}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-DIRECT", ".github/workflows/direct.yml", 1002, "2026-01-01T00:02:10Z", []any{qualifiedAttempt(1, bJob("Direct marker"))}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-MATRIX", ".github/workflows/matrix.yml", 1003, "2026-01-01T00:02:20Z", []any{qualifiedAttempt(1,
			bJob("Matrix alpha one"), bJob("Matrix alpha two"), bJob("Matrix beta one"), bJob("Matrix beta two"),
		)}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-RERUN-FULL", ".github/workflows/rerun.yml", 1004, "2026-01-01T00:03:00Z", []any{
			qualifiedAttempt(1, fullOriginalSuccess, fullOriginalFailure),
			qualifiedAttempt(2, fullRestoredSuccess, fullRestoredFailure),
		}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-RERUN-JOB", ".github/workflows/rerun.yml", 1005, "2026-01-01T00:03:10Z", []any{
			qualifiedAttempt(1, jobOriginalSuccess, jobOriginalFailure),
			qualifiedAttempt(2, failedJobRestored),
			qualifiedAttempt(3, singleJobRestored),
		}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-REUSABLE", ".github/workflows/reusable-caller.yml", 1006, "2026-01-01T00:04:00Z", []any{qualifiedAttempt(1, bJob("Reusable marker"))}),
		qualifiedWorkflowRun(importCommit, "PUBLIC-SKIPPED", ".github/workflows/skipped.yml", 1007, "2026-01-01T00:04:10Z", []any{qualifiedAttempt(1, skippedJob)}),
	}
	reusableJob := firstRecordObject(firstRecordObject(runs[5].(map[string]any), "attempts"), "jobs")
	reusableEvidence := testVersionedID("ev1", nextEvidence)
	nextEvidence++
	reusableJob["called_workflow_observations"] = []any{map[string]any{
		"repository":             RepositoryName,
		"workflow_path":          ".github/workflows/reusable.yml",
		"called_workflow_commit": testGitObject(manifest.Commits[4].ObjectID),
		"evidence_ids":           []any{reusableEvidence},
	}}

	compositeJob := firstRecordObject(firstRecordObject(runs[0].(map[string]any), "attempts"), "jobs")
	compositeWrapperEvidence := appendQualifiedActionObservation(compositeJob, RepositoryName, manifest.Commits[3].ObjectID, "step:wrapper", &nextEvidence)
	reusableWrapperEvidence := appendQualifiedActionObservation(reusableJob, RepositoryName, manifest.Commits[3].ObjectID, "step:wrapper", &nextEvidence)
	markerEvidence := func(job map[string]any) any {
		return firstRecordObject(job, "action_observations")["evidence_ids"].([]any)[0]
	}
	setQualifiedDependencyChain(compositeJob, []any{
		qualifiedDependencyLink("WORKFLOW_DECLARED_ACTION",
			qualifiedDependencyEndpoint("WORKFLOW_DEFINITION", RepositoryName, ".github/workflows/composite.yml", importCommit),
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/wrapper/action.yml", manifest.Commits[3].ObjectID), compositeWrapperEvidence),
		qualifiedDependencyLink("ACTION_CONTAINS_ACTION",
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/wrapper/action.yml", manifest.Commits[3].ObjectID),
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/marker/action.yml", markerB), markerEvidence(compositeJob)),
	})
	setQualifiedDependencyChain(reusableJob, []any{
		qualifiedDependencyLink("WORKFLOW_CALLED_WORKFLOW",
			qualifiedDependencyEndpoint("WORKFLOW_DEFINITION", RepositoryName, ".github/workflows/reusable-caller.yml", importCommit),
			qualifiedDependencyEndpoint("REUSABLE_WORKFLOW_DEFINITION", RepositoryName, ".github/workflows/reusable.yml", manifest.Commits[4].ObjectID), reusableEvidence),
		qualifiedDependencyLink("WORKFLOW_DECLARED_ACTION",
			qualifiedDependencyEndpoint("REUSABLE_WORKFLOW_DEFINITION", RepositoryName, ".github/workflows/reusable.yml", manifest.Commits[4].ObjectID),
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/wrapper/action.yml", manifest.Commits[3].ObjectID), reusableWrapperEvidence),
		qualifiedDependencyLink("ACTION_CONTAINS_ACTION",
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/wrapper/action.yml", manifest.Commits[3].ObjectID),
			qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/marker/action.yml", markerB), markerEvidence(reusableJob)),
	})
	for runIndex, rawRun := range runs {
		if runIndex == 0 || runIndex == 5 {
			continue
		}
		run := rawRun.(map[string]any)
		for attemptIndex, rawAttempt := range run["attempts"].([]any) {
			source := markerB
			if (runIndex == 3 || runIndex == 4) && attemptIndex > 0 {
				source = markerA
			}
			for _, rawJob := range rawAttempt.(map[string]any)["jobs"].([]any) {
				job := rawJob.(map[string]any)
				setQualifiedDependencyChain(job, []any{qualifiedDependencyLink("WORKFLOW_DECLARED_ACTION",
					qualifiedDependencyEndpoint("WORKFLOW_DEFINITION", RepositoryName, run["workflow_path"].(string), importCommit),
					qualifiedDependencyEndpoint("ACTION_DEFINITION", RepositoryName, "actions/marker/action.yml", source), markerEvidence(job))})
			}
		}
	}
	value["workflow_runs"] = runs
	singleJobID := failedJobRestored["job_id"]
	value["rerun_requests"] = []any{
		qualifiedRerunRequest(1004, "full-workflow", nil, "2026-01-01T00:08:10Z"),
		qualifiedRerunRequest(1005, "failed-jobs", nil, "2026-01-01T00:08:20Z"),
		qualifiedRerunRequest(1005, "single-job", singleJobID, "2026-01-01T00:08:30Z"),
	}
	collection := value["collection"].(map[string]any)
	collection["window_start"] = "2026-01-01T00:00:00Z"
	collection["window_end"] = "2026-01-01T00:09:00Z"
	collection["collected_at"] = "2026-01-01T00:10:00Z"
	coverage := collection["coverage"].(map[string]any)
	coverage["runs_enumerated"] = 7
	coverage["attempts_enumerated"] = 10
	coverage["jobs_enumerated"] = 16
	coverage["logs_retrieved"] = 16
	coverage["workflow_definitions_retrieved"] = 7
	coverage["action_definitions_retrieved"] = 2
	return value
}

func appendQualifiedActionObservation(job map[string]any, repository, source, step string, nextEvidence *int) any {
	evidenceID := testVersionedID("ev1", *nextEvidence)
	*nextEvidence = *nextEvidence + 1
	job["action_observations"] = append(job["action_observations"].([]any), map[string]any{
		"action_repository": repository,
		"action_path":       "actions/wrapper/action.yml",
		"declared_ref":      source,
		"source_commit":     testGitObject(source),
		"lifecycle":         "LIFECYCLE_STARTED",
		"step_identity":     step,
		"evidence_ids":      []any{evidenceID},
	})
	return evidenceID
}

func setQualifiedDependencyChain(job map[string]any, links []any) {
	job["dependency_chain"] = links
}

func qualifiedDependencyEndpoint(kind, repository, path, commit string) map[string]any {
	return map[string]any{
		"kind":       kind,
		"repository": repository,
		"path":       path,
		"commit":     testGitObject(commit),
	}
}

func qualifiedDependencyLink(relationship string, from, to map[string]any, evidenceID any) map[string]any {
	return map[string]any{
		"relationship": relationship,
		"from":         from,
		"to":           to,
		"evidence_ids": []any{evidenceID},
	}
}

func qualifiedWorkflowRun(importCommit, scenario, workflowPath string, runID int64, eventTime string, attempts []any) map[string]any {
	return map[string]any{
		"scenario_id":                scenario,
		"workflow_path":              workflowPath,
		"workflow_definition_commit": testGitObject(importCommit),
		"event_type":                 "workflow_dispatch",
		"actor":                      "synthetic-reproducer",
		"triggering_actor":           "synthetic-reproducer",
		"event_time":                 syntheticObservation(eventTime, "github-actions-event"),
		"run_id":                     runID,
		"run_url":                    fmt.Sprintf("https://github.com/%s/actions/runs/%d", RepositoryName, runID),
		"attempts":                   attempts,
	}
}

func qualifiedAttempt(number int64, jobs ...map[string]any) map[string]any {
	values := make([]any, len(jobs))
	for index := range jobs {
		values[index] = jobs[index]
	}
	return map[string]any{"run_attempt": number, "jobs": values}
}

func qualifiedRerunRequest(runID int64, kind string, jobID any, at string) map[string]any {
	value := map[string]any{
		"original_run_id":      runID,
		"kind":                 kind,
		"requested_by":         "synthetic-reproducer",
		"operator_action_time": syntheticObservation(at, "github-web-ui"),
	}
	if jobID != nil {
		value["job_id"] = jobID
	}
	return value
}

func qualifiedTagObservation(objectID, at string) map[string]any {
	return map[string]any{
		"target_commit": testGitObject(objectID),
		"observation":   syntheticObservation(at, "git-ls-remote"),
	}
}

func testGitObject(objectID string) map[string]any {
	return map[string]any{"algorithm": "sha1", "objectId": objectID}
}

func testVersionedID(prefix string, value int) string {
	return fmt.Sprintf("%s:%064x", prefix, value)
}

func marshalPublicLabRecord(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func qualifiedScenario(value map[string]any, scenario string) map[string]any {
	for _, item := range value["workflow_runs"].([]any) {
		run := item.(map[string]any)
		if run["scenario_id"] == scenario {
			return run
		}
	}
	panic("qualified scenario fixture is missing " + scenario)
}
