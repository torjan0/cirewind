package publiclab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func TestValidateRecordAppliesCrossFieldSemantics(t *testing.T) {
	t.Parallel()
	schemaDir := recordSchemaDir(t)
	tests := []struct {
		name   string
		kind   RecordKind
		value  func() map[string]any
		mutate func(map[string]any)
		ok     bool
	}{
		{name: "valid run", kind: RecordRun, value: validPublicLabRunRecord, ok: true},
		{name: "valid pack input", kind: RecordPackInput, value: validPublicLabPackInputRecord, ok: true},
		{name: "valid tag move", kind: RecordTagMove, value: func() map[string]any { return validPublicLabTagMoveRecord(t) }, ok: true},
		{name: "valid reproduction", kind: RecordReproduction, value: validPublicLabReproductionRecord, ok: true},
		{name: "valid empty index", kind: RecordReproductionsIdx, value: func() map[string]any {
			var value map[string]any
			readPublicLabJSON(t, recordSchemaDir(t)+"/reproductions-index.template.json", &value)
			return value
		}, ok: true},
		{
			name: "pack input derivation identities collide", kind: RecordPackInput, value: validPublicLabPackInputRecord,
			mutate: func(value map[string]any) {
				inputs := value["derivation_inputs"].([]any)
				inputs[1].(map[string]any)["record_id"] = inputs[0].(map[string]any)["record_id"]
			},
		},
		{
			name: "fixture peel mismatch", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				value["fixture_objects"].(map[string]any)["fixture_a_tag"].(map[string]any)["peeled_commit"] = syntheticGitObject("f")
			},
		},
		{
			name: "not A B A", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				value["mutable_tag"].(map[string]any)["after"].(map[string]any)["target_commit"] = syntheticGitObject("3")
			},
		},
		{
			name: "tag time reversal", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				value["mutable_tag"].(map[string]any)["after"].(map[string]any)["observation"].(map[string]any)["observedAt"] = "2026-01-01T00:00:30Z"
			},
		},
		{
			name: "run URL identity mismatch", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts")
				value["workflow_runs"].([]any)[0].(map[string]any)["run_url"] = "https://github.com/torjan0/cirewind-lab/actions/runs/9999"
			},
		},
		{
			name: "download cannot support executed", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
				firstRecordObject(job, "action_observations")["lifecycle"] = "PREPARATION_COMPLETED"
			},
		},
		{
			name: "downloaded finding cannot ignore separately evidenced start", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
				observation := firstRecordObject(job, "action_observations")
				observation["lifecycle"] = "PREPARATION_COMPLETED"
				started := cloneRecordValue(t, observation).(map[string]any)
				started["lifecycle"] = "LIFECYCLE_STARTED"
				started["evidence_ids"] = []any{"ev1:" + strings.Repeat("a", 64)}
				job["action_observations"] = append(job["action_observations"].([]any), started)
				firstRecordObject(job, "findings")["state"] = "CONFIRMED_DOWNLOADED"
			},
		},
		{
			name: "no match cannot coexist with exact B completed preparation", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
				firstRecordObject(job, "action_observations")["lifecycle"] = "PREPARATION_COMPLETED"
				firstRecordObject(job, "findings")["state"] = "NO_MATCH_CONFIRMED"
			},
		},
		{
			name: "duplicate run", kind: RecordRun, value: validPublicLabRunRecord,
			mutate: func(value map[string]any) {
				runs := value["workflow_runs"].([]any)
				value["workflow_runs"] = append(runs, cloneRecordValue(t, runs[0]))
				value["collection"].(map[string]any)["coverage"].(map[string]any)["runs_enumerated"] = 2
			},
		},
		{
			name: "reproduction run-record URL mutable", kind: RecordReproduction, value: validPublicLabReproductionRecord,
			mutate: func(value map[string]any) {
				value["run_record"].(map[string]any)["public_url"] = "https://github.com/torjan0/cirewind-lab/blob/main/reproductions/synthetic-record-1.json"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := test.value()
			if test.mutate != nil {
				test.mutate(value)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateRecord(context.Background(), schemaDir, test.kind, data)
			if test.ok && err != nil {
				t.Fatalf("valid record rejected: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("semantically invalid record accepted")
			}
		})
	}
}

func TestReproductionCrossBindsExactRunRecordBytesAndPublicTuples(t *testing.T) {
	t.Parallel()
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	runValue := qualifiedPublicLabRunRecord(t, artifact)
	runJSON := marshalPublicLabRecord(t, runValue)
	packInputJSON := marshalPublicLabRecord(t, qualifiedPublicLabPackInputRecord(t, artifact))
	reproduction := validPublicLabReproductionRecord()
	reproduction["lab_binding"] = map[string]any{
		"repository":              runValue["lab_repository"].(map[string]any)["full_name"],
		"repository_database_id":  runValue["lab_repository"].(map[string]any)["database_id"],
		"public_url":              runValue["lab_repository"].(map[string]any)["public_url"],
		"source_commit":           runValue["protocol"].(map[string]any)["source_commit"],
		"source_manifest_sha256":  runValue["protocol"].(map[string]any)["source_manifest_sha256"],
		"marker_a_commit":         runValue["fixture_objects"].(map[string]any)["marker_a_commit"],
		"marker_b_commit":         runValue["fixture_objects"].(map[string]any)["marker_b_commit"],
		"fixture_a_tag_object":    runValue["fixture_objects"].(map[string]any)["fixture_a_tag"].(map[string]any)["tag_object"],
		"fixture_a_peeled_commit": runValue["fixture_objects"].(map[string]any)["fixture_a_tag"].(map[string]any)["peeled_commit"],
		"fixture_b_tag_object":    runValue["fixture_objects"].(map[string]any)["fixture_b_tag"].(map[string]any)["tag_object"],
		"fixture_b_peeled_commit": runValue["fixture_objects"].(map[string]any)["fixture_b_tag"].(map[string]any)["peeled_commit"],
		"v1_before":               runValue["mutable_tag"].(map[string]any)["before"],
		"v1_during":               runValue["mutable_tag"].(map[string]any)["during"],
		"v1_after":                runValue["mutable_tag"].(map[string]any)["after"],
	}
	digest := sha256.Sum256(runJSON)
	reproduction["run_record"] = map[string]any{
		"record_id":   runValue["record_id"],
		"public_url":  "https://github.com/" + RepositoryName + "/blob/" + strings.Repeat("d", 40) + "/reproductions/" + runValue["record_id"].(string) + ".json",
		"sha256":      hex.EncodeToString(digest[:]),
		"byte_length": len(runJSON),
	}
	publicRuns := make([]any, 0, len(runValue["workflow_runs"].([]any)))
	for _, rawRun := range runValue["workflow_runs"].([]any) {
		run := rawRun.(map[string]any)
		attempts := make([]any, 0, len(run["attempts"].([]any)))
		for _, rawAttempt := range run["attempts"].([]any) {
			attempt := rawAttempt.(map[string]any)
			jobIDs := make([]any, 0, len(attempt["jobs"].([]any)))
			for _, rawJob := range attempt["jobs"].([]any) {
				jobIDs = append(jobIDs, rawJob.(map[string]any)["job_id"])
			}
			attempts = append(attempts, map[string]any{"run_attempt": attempt["run_attempt"], "job_ids": jobIDs})
		}
		publicRuns = append(publicRuns, map[string]any{
			"scenario_id": run["scenario_id"],
			"run_id":      run["run_id"],
			"run_url":     run["run_url"],
			"attempts":    attempts,
		})
	}
	reproduction["public_runs"] = publicRuns
	reproduction["submitted_at"] = "2026-01-01T00:10:00Z"
	var typedRun labRunRecord
	if err := json.Unmarshal(runJSON, &typedRun); err != nil {
		t.Fatal(err)
	}
	collector := runValue["collector"].(map[string]any)
	qualifiedBinary := reproduction["qualified_binary"].(map[string]any)
	qualifiedBinary["version"] = collector["version"]
	qualifiedBinary["source_revision"] = collector["source_revision"]
	qualifiedBinary["binary_sha256"] = collector["binary_sha256"]
	qualifiedBinary["acquisition"].(map[string]any)["source_commit"] = collector["source_revision"]
	reproduction["case_archive"].(map[string]any)["case_manifest_sha256"] = runValue["collection"].(map[string]any)["case_manifest_sha256"]
	counts := deriveFindingCounts(typedRun)
	if counts[string(model.ConfirmedExecuted)] != 11 || counts[string(model.ConfirmedDownloaded)] != 1 || counts[string(model.NoMatchConfirmed)] != 4 {
		t.Fatalf("qualified finding counts=%v", counts)
	}
	for _, state := range model.FindingStates() {
		if state != model.ConfirmedExecuted && state != model.ConfirmedDownloaded && state != model.NoMatchConfirmed && counts[string(state)] != 0 {
			t.Fatalf("qualified finding count %s=%d", state, counts[string(state)])
		}
	}
	checks := deriveScenarioChecks(typedRun)
	if !checks.allSatisfied() {
		t.Fatalf("qualified scenario checks=%+v", checks)
	}
	reproduction["finding_counts"] = counts
	reproduction["scenario_checks"] = checks
	seed, err := readBoundedRegular(recordSchemaDir(t)+"/expected-findings.seed.json", maxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	seedDigest := sha256.Sum256(seed)
	reproduction["oracle_comparison"].(map[string]any)["oracle_sha256"] = hex.EncodeToString(seedDigest[:])
	reproductionJSON := marshalPublicLabRecord(t, reproduction)
	if err := ValidateRecordAgainstArtifact(context.Background(), sourceRoot(t), recordSchemaDir(t), RecordReproduction, reproductionJSON, artifact); err != nil {
		t.Fatalf("manifest-bound reproduction rejected: %v", err)
	}
	if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), reproductionJSON, runJSON, packInputJSON, artifact); err != nil {
		t.Fatalf("exact reproduction/run binding rejected: %v", err)
	}

	for name, mutateRun := range map[string]func(map[string]any){
		"composite transitive edge removed": func(value map[string]any) {
			job := firstQualifiedJob(value, "PUBLIC-COMPOSITE")
			chain := job["dependency_chain"].([]any)
			job["dependency_chain"] = []any{cloneRecordValue(t, chain[len(chain)-1])}
		},
		"reusable caller edges removed": func(value map[string]any) {
			job := firstQualifiedJob(value, "PUBLIC-REUSABLE")
			chain := job["dependency_chain"].([]any)
			job["dependency_chain"] = []any{cloneRecordValue(t, chain[len(chain)-1])}
		},
		"extra contradictory finding": func(value map[string]any) {
			job := firstQualifiedJob(value, "PUBLIC-DIRECT")
			finding := cloneRecordValue(t, firstRecordObject(job, "findings")).(map[string]any)
			finding["finding_id"] = "find1:" + strings.Repeat("9", 64)
			finding["finding_revision_id"] = "frev1:" + strings.Repeat("8", 64)
			finding["state"] = string(model.ContradictoryEvidence)
			finding["provenance"] = string(model.L2Probable)
			finding["conclusion"] = "Synthetic static and runtime evidence materially disagreed; neither source was silently preferred."
			job["findings"] = append(job["findings"].([]any), finding)
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutatedRun := cloneRecordValue(t, runValue).(map[string]any)
			mutateRun(mutatedRun)
			mutatedRunJSON := marshalPublicLabRecord(t, mutatedRun)
			var typedMutatedRun labRunRecord
			if err := json.Unmarshal(mutatedRunJSON, &typedMutatedRun); err != nil {
				t.Fatal(err)
			}
			mutatedChecks := deriveScenarioChecks(typedMutatedRun)
			if !mutatedChecks.allSatisfied() {
				t.Fatalf("mutation unexpectedly changed coarse scenario checks: %+v", mutatedChecks)
			}
			deviations := qualificationOracleDeviations(typedMutatedRun, mutatedChecks, artifact.Model)
			if !containsString(deviations, "qualified scenario set differs from reviewed artifact") {
				t.Fatalf("exact scenario deviation was not derived: %v", deviations)
			}
			mutatedReproduction := cloneRecordValue(t, reproduction).(map[string]any)
			mutatedDigest := sha256.Sum256(mutatedRunJSON)
			mutatedReproduction["run_record"].(map[string]any)["sha256"] = hex.EncodeToString(mutatedDigest[:])
			mutatedReproduction["run_record"].(map[string]any)["byte_length"] = len(mutatedRunJSON)
			mutatedReproduction["finding_counts"] = deriveFindingCounts(typedMutatedRun)
			mutatedReproduction["scenario_checks"] = mutatedChecks
			mutatedReproduction["claimed_result"] = "does-not-match-qualified-oracle"
			mutatedReproduction["oracle_comparison"].(map[string]any)["result"] = "mismatch"
			mutatedReproduction["oracle_comparison"].(map[string]any)["deviations"] = deviations
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, mutatedReproduction), mutatedRunJSON, packInputJSON, artifact); err != nil {
				t.Fatalf("exactly derived mismatch record rejected: %v", err)
			}
			mutatedReproduction["claimed_result"] = "matches-qualified-oracle"
			mutatedReproduction["oracle_comparison"].(map[string]any)["result"] = "match"
			mutatedReproduction["oracle_comparison"].(map[string]any)["deviations"] = []any{}
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, mutatedReproduction), mutatedRunJSON, packInputJSON, artifact); err == nil {
				t.Fatal("coarse counts/checks qualified a run with the wrong exact scenario shape")
			}
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"run hash":      func(value map[string]any) { value["run_record"].(map[string]any)["sha256"] = strings.Repeat("0", 64) },
		"repository ID": func(value map[string]any) { value["lab_binding"].(map[string]any)["repository_database_id"] = 999 },
		"finding counts": func(value map[string]any) {
			value["finding_counts"].(map[string]any)["CONFIRMED_EXECUTED"] = float64(10)
		},
		"scenario check": func(value map[string]any) {
			value["claimed_result"] = "does-not-match-qualified-oracle"
			value["scenario_checks"].(map[string]any)["direct_b_executed"] = false
			value["oracle_comparison"].(map[string]any)["result"] = "mismatch"
			value["oracle_comparison"].(map[string]any)["deviations"] = []any{"synthetic mismatch"}
		},
		"oracle hash": func(value map[string]any) {
			value["oracle_comparison"].(map[string]any)["oracle_sha256"] = strings.Repeat("0", 64)
		},
		"case manifest": func(value map[string]any) {
			value["case_archive"].(map[string]any)["case_manifest_sha256"] = strings.Repeat("0", 64)
		},
		"binary version": func(value map[string]any) { value["qualified_binary"].(map[string]any)["version"] = "0.2.0+different" },
		"binary revision": func(value map[string]any) {
			value["qualified_binary"].(map[string]any)["source_revision"] = syntheticGitObject("f")
			value["qualified_binary"].(map[string]any)["acquisition"].(map[string]any)["source_commit"] = syntheticGitObject("f")
		},
		"binary acquisition revision": func(value map[string]any) {
			value["qualified_binary"].(map[string]any)["acquisition"].(map[string]any)["source_commit"] = syntheticGitObject("f")
		},
		"binary hash": func(value map[string]any) {
			value["qualified_binary"].(map[string]any)["binary_sha256"] = strings.Repeat("0", 64)
		},
		"collection time": func(value map[string]any) { value["submitted_at"] = "2026-01-01T00:09:59Z" },
		"job tuple": func(value map[string]any) {
			firstRecordObject(firstRecordObject(value, "public_runs"), "attempts")["job_ids"].([]any)[0] = float64(999999)
		},
		"extra coverage issue": func(value map[string]any) {
			value["coverage_issues"] = []any{map[string]any{
				"code": "invented-gap", "scope": "PUBLIC-DIRECT", "summary": "Synthetic issue not present in the bound run record.",
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := cloneRecordValue(t, reproduction).(map[string]any)
			mutate(value)
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, value), runJSON, packInputJSON, artifact); err == nil {
				t.Fatal("mismatched reproduction/run binding was accepted")
			}
		})
	}

	for name, acquisition := range map[string]map[string]any{
		"CI artifact": {
			"kind": "immutable-ci-artifact", "workflow_run_url": "https://github.com/torjan0/cirewind/actions/runs/12345",
			"workflow_run_id": 12345, "workflow_run_attempt": 1, "artifact_id": 67890,
			"artifact_sha256": collector["binary_sha256"], "source_commit": collector["source_revision"],
			"accessed_at": "2026-01-01T00:09:00Z", "provenance_verified": true,
		},
		"release asset": {
			"kind": "published-release-recheck", "release_url": "https://github.com/torjan0/cirewind/releases/tag/v0.2.0",
			"asset_sha256": collector["binary_sha256"], "source_commit": collector["source_revision"],
			"accessed_at": "2026-01-01T00:09:00Z", "provenance_verified": true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			variant := cloneRecordValue(t, reproduction).(map[string]any)
			variant["qualified_binary"].(map[string]any)["acquisition"] = acquisition
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, variant), runJSON, packInputJSON, artifact); err != nil {
				t.Fatalf("valid %s acquisition rejected: %v", name, err)
			}
			tampered := cloneRecordValue(t, variant).(map[string]any)
			field := "artifact_sha256"
			if name == "release asset" {
				field = "asset_sha256"
			}
			tampered["qualified_binary"].(map[string]any)["acquisition"].(map[string]any)[field] = strings.Repeat("0", 64)
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, tampered), runJSON, packInputJSON, artifact); err == nil {
				t.Fatalf("%s acquisition hash differed from the collector binary but was accepted", name)
			}
			wrongSource := cloneRecordValue(t, variant).(map[string]any)
			wrongSource["qualified_binary"].(map[string]any)["acquisition"].(map[string]any)["source_commit"] = syntheticGitObject("f")
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, wrongSource), runJSON, packInputJSON, artifact); err == nil {
				t.Fatalf("%s acquisition accepted a different source revision", name)
			}
			wrongURL := cloneRecordValue(t, variant).(map[string]any)
			urlField := "workflow_run_url"
			if name == "release asset" {
				urlField = "release_url"
			}
			wrongURL["qualified_binary"].(map[string]any)["acquisition"].(map[string]any)[urlField] = "https://github.com/other/project/actions/runs/12345"
			if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, wrongURL), runJSON, packInputJSON, artifact); err == nil {
				t.Fatalf("%s acquisition accepted a different project URL", name)
			}
		})
	}

	issue := map[string]any{
		"code":    "synthetic-collection-gap",
		"scope":   "PUBLIC-DIRECT",
		"summary": "Synthetic collection issue retained for cross-binding regression coverage.",
	}
	runWithIssue := cloneRecordValue(t, runValue).(map[string]any)
	runWithIssue["collection"].(map[string]any)["issues"] = []any{issue}
	issueCoverage := runWithIssue["collection"].(map[string]any)["coverage"].(map[string]any)
	issueCoverage["logs_retrieved"] = 15
	issueCoverage["logs_missing"] = 1
	runWithIssueJSON := marshalPublicLabRecord(t, runWithIssue)
	issueReproduction := cloneRecordValue(t, reproduction).(map[string]any)
	issueDigest := sha256.Sum256(runWithIssueJSON)
	issueReproduction["run_record"].(map[string]any)["sha256"] = hex.EncodeToString(issueDigest[:])
	issueReproduction["run_record"].(map[string]any)["byte_length"] = len(runWithIssueJSON)
	if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, issueReproduction), runWithIssueJSON, packInputJSON, artifact); err == nil {
		t.Fatal("reproduction omitted a retained run-record collection issue")
	}
	issueReproduction["coverage_issues"] = []any{issue}
	var typedIssueRun labRunRecord
	if err := json.Unmarshal(runWithIssueJSON, &typedIssueRun); err != nil {
		t.Fatal(err)
	}
	issueReproduction["claimed_result"] = "does-not-match-qualified-oracle"
	issueReproduction["oracle_comparison"].(map[string]any)["result"] = "mismatch"
	issueReproduction["oracle_comparison"].(map[string]any)["deviations"] = []any{"arbitrary mismatch description"}
	if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, issueReproduction), runWithIssueJSON, packInputJSON, artifact); err == nil {
		t.Fatal("reproduction supplied arbitrary rather than deterministic oracle deviations")
	}
	deviations := qualificationOracleDeviations(typedIssueRun, deriveScenarioChecks(typedIssueRun), artifact.Model)
	if len(deviations) < 2 {
		t.Fatalf("mismatch deviations=%v, want multiple independently derived entries", deviations)
	}
	reversed := append([]string(nil), deviations...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	issueReproduction["oracle_comparison"].(map[string]any)["deviations"] = reversed
	if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, issueReproduction), runWithIssueJSON, packInputJSON, artifact); err == nil {
		t.Fatal("reproduction supplied correct oracle deviations in nondeterministic order")
	}
	issueReproduction["oracle_comparison"].(map[string]any)["deviations"] = deviations
	if err := ValidateReproductionAgainstRunRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), marshalPublicLabRecord(t, issueReproduction), runWithIssueJSON, packInputJSON, artifact); err != nil {
		t.Fatalf("reproduction retaining exact collection issue rejected: %v", err)
	}
}

func TestValidateRecordRejectsDuplicateKeysTrailingDataAndCancellation(t *testing.T) {
	t.Parallel()
	schemaDir := recordSchemaDir(t)
	for name, data := range map[string][]byte{
		"duplicate": []byte(`{"schema_version":"cirewind.lab-run-record/v1alpha1","schema_version":"cirewind.lab-run-record/v1alpha1"}`),
		"trailing":  []byte(`{} {}`),
		"nul":       append([]byte(`{}`), 0),
	} {
		if err := ValidateRecord(context.Background(), schemaDir, RecordRun, data); err == nil {
			t.Fatalf("%s record accepted", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateRecord(ctx, schemaDir, RecordRun, []byte(`{}`)); err != context.Canceled {
		t.Fatalf("cancellation error=%v", err)
	}
	if err := ValidateRecord(context.Background(), schemaDir, RecordKind("not-reviewed"), []byte(`{}`)); err == nil {
		t.Fatal("unknown record kind accepted")
	}
}

func TestValidateRecordNeverEchoesHostileObjectNames(t *testing.T) {
	t.Parallel()
	hostile := strings.Join([]string{"Authorization", "Bearer", "SYNTHETIC_PRIVATE_MATERIAL"}, ": ")
	inputs := [][]byte{
		[]byte(`{"schema_version":"cirewind.lab-run-record/v1alpha1","` + hostile + `":true}`),
		[]byte(`{"` + hostile + `":1,"` + hostile + `":2}`),
	}
	for _, data := range inputs {
		err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordRun, data)
		if err == nil {
			t.Fatal("hostile object name was accepted")
		}
		if strings.Contains(err.Error(), hostile) || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MATERIAL") {
			t.Fatalf("validation error echoed hostile object name: %q", err)
		}
	}
}

func TestValidateRecordRejectsCredentialAndLocalPathMaterial(t *testing.T) {
	t.Parallel()
	for name, hostile := range map[string]string{
		"private key":    "-----BEGIN PRIVATE KEY-----",
		"github token":   "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"authorization":  "Authorization: Bearer SYNTHETIC_BUT_FORBIDDEN_MATERIAL",
		"cookie":         "Cookie: session=SYNTHETIC_BUT_FORBIDDEN",
		"unix path":      "/home/private-user/cases/case.db",
		"windows path":   `C:\Users\private-user\case.db`,
		"temporary path": "/tmp/private-user/case.db",
		"macOS path":     "/private/var/folders/aa/private-case",
		"UNC path":       `\\private-host\private-share\case.db`,
		"slack token":    strings.Join([]string{"xoxb", "1234567890", "SYNTHETICBUTREJECTED"}, "-"),
		"google key":     "AIza012345678abcdefghijklmnopqrstuvwxyz",
		"stripe key":     strings.Join([]string{"sk", "live", "SYNTHETICKEYMATERIAL1234567890"}, "_"),
		"JWT-like":       "eyJabcdefghijk.eyJlmnopqrst.abcdefghijklmnop",
		"signed URL":     "https://downloads.invalid/case?X-Goog-Signature=SYNTHETIC1234567890ABCDEF",
	} {
		t.Run(name, func(t *testing.T) {
			value := validPublicLabRunRecord()
			job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
			firstRecordObject(job, "findings")["conclusion"] = hostile
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordRun, data); err == nil {
				t.Fatal("credential-like or private-path material was accepted")
			}
		})
	}
}

func TestRunRecordRequiresEvidenceForNonGapFinding(t *testing.T) {
	t.Parallel()
	value := validPublicLabRunRecord()
	job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
	finding := firstRecordObject(job, "findings")
	finding["evidence_ids"] = []any{}
	finding["evidence_gap_codes"] = []any{"missing-runtime-evidence"}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordRun, data); err == nil {
		t.Fatal("non-gap finding without evidence IDs was accepted")
	}
}

func TestRunRecordRejectsNoncanonicalOrOverclaimingFindingConclusions(t *testing.T) {
	t.Parallel()
	for name, conclusion := range map[string]string{
		"exfiltration": "Synthetic marker B exfiltrated repository secrets.",
		"causation":    "Synthetic marker B caused a later deployment.",
		"cloud role":   "Synthetic marker B assumed the production cloud role.",
	} {
		t.Run(name, func(t *testing.T) {
			value := validPublicLabRunRecord()
			job := firstRecordObject(firstRecordObject(firstRecordObject(value, "workflow_runs"), "attempts"), "jobs")
			firstRecordObject(job, "findings")["conclusion"] = conclusion
			if err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordRun, marshalPublicLabRecord(t, value)); err == nil {
				t.Fatal("noncanonical overclaiming finding conclusion was accepted")
			}
		})
	}
}

func TestReproductionRecordHardensPublicIdentityTopology(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "repository database identity omitted",
			mutate: func(value map[string]any) {
				delete(value["lab_binding"].(map[string]any), "repository_database_id")
			},
		},
		{
			name: "repository database identity is not positive",
			mutate: func(value map[string]any) {
				value["lab_binding"].(map[string]any)["repository_database_id"] = 0
			},
		},
		{
			name: "matching claim omits a scenario",
			mutate: func(value map[string]any) {
				runs := value["public_runs"].([]any)
				value["public_runs"] = runs[:len(runs)-1]
			},
		},
		{
			name: "attempt numbering does not start at one",
			mutate: func(value map[string]any) {
				firstRecordObject(firstRecordObject(value, "public_runs"), "attempts")["run_attempt"] = 2
			},
		},
		{
			name: "job ID is reused across runs",
			mutate: func(value map[string]any) {
				runs := value["public_runs"].([]any)
				first := firstRecordObject(runs[0].(map[string]any), "attempts")["job_ids"].([]any)[0]
				firstRecordObject(runs[1].(map[string]any), "attempts")["job_ids"] = []any{first}
			},
		},
		{
			name: "matching full rerun has wrong cardinality",
			mutate: func(value map[string]any) {
				run := reproductionScenario(value, "PUBLIC-RERUN-FULL")
				attempt := run["attempts"].([]any)[1].(map[string]any)
				attempt["job_ids"] = attempt["job_ids"].([]any)[:1]
			},
		},
		{
			name: "submission precedes restored A",
			mutate: func(value map[string]any) {
				value["submitted_at"] = "2026-01-01T00:01:59Z"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPublicLabReproductionRecord()
			test.mutate(value)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordReproduction, data); err == nil {
				t.Fatal("invalid reproduction identity topology was accepted")
			}
		})
	}
}

func TestReproductionAllowsScenarioSortedRunsWithNonmonotonicGitHubIDs(t *testing.T) {
	t.Parallel()
	value := validPublicLabReproductionRecord()
	runs := value["public_runs"].([]any)
	for index, raw := range runs {
		run := raw.(map[string]any)
		runID := int64(9000 - index*137)
		run["run_id"] = runID
		run["run_url"] = "https://github.com/torjan0/cirewind-lab/actions/runs/" + fmt.Sprint(runID)
	}
	if err := ValidateRecord(context.Background(), recordSchemaDir(t), RecordReproduction, marshalPublicLabRecord(t, value)); err != nil {
		t.Fatalf("scenario-sorted real-world run IDs were rejected: %v", err)
	}
}

func reproductionScenario(value map[string]any, scenario string) map[string]any {
	for _, raw := range value["public_runs"].([]any) {
		run := raw.(map[string]any)
		if run["scenario_id"] == scenario {
			return run
		}
	}
	panic("missing reproduction scenario " + scenario)
}

func TestRuntimeObservationSchemaUsesCanonicalIdentifiers(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validPublicLabRunRecord())
	if err != nil {
		t.Fatal(err)
	}
	for _, synonym := range []string{"lifecycle_started", "preparation_completed", "download_announced"} {
		if strings.Contains(string(raw), synonym) {
			t.Fatalf("record fixture contains lowercase lifecycle synonym %q", synonym)
		}
	}
}

func recordSchemaDir(t *testing.T) string {
	t.Helper()
	return recordSourceRoot(t) + "/import/protocol"
}

func firstRecordObject(value map[string]any, key string) map[string]any {
	return value[key].([]any)[0].(map[string]any)
}

func cloneRecordValue(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy any
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
