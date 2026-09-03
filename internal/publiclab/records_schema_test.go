package publiclab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/torjan0/cirewind/internal/model"
)

const publicLabRecordSchemaBase = "https://schemas.invalid/cirewind/public-lab/"

var publicLabRecordSchemaFiles = []string{
	"record-common.schema.json",
	"run-record.schema.json",
	"tag-move-record.schema.json",
	"pack-input-record.schema.json",
	"reproduction-record.schema.json",
	"expected-findings-seed.schema.json",
	"reproductions-index.schema.json",
}

func TestPublicLabRecordSchemasCompileAndAcceptPositiveFixtures(t *testing.T) {
	t.Parallel()
	schemas := compilePublicLabRecordSchemas(t)
	fixtures := validPublicLabRecordFixtures(t)
	for name, instance := range fixtures {
		name, instance := name, instance
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := schemas[name].Validate(instance); err != nil {
				t.Fatalf("valid fixture violates %s: %v", name, err)
			}
		})
	}
}

func TestPublicLabRecordSchemasRejectNullUnknownAndUnsafeValues(t *testing.T) {
	t.Parallel()
	schemas := compilePublicLabRecordSchemas(t)
	fixtures := validPublicLabRecordFixtures(t)

	for name, instance := range fixtures {
		if name == "record-common.schema.json" {
			continue
		}
		name, instance := name, instance
		t.Run(name+"/unknown-top-level", func(t *testing.T) {
			value := clonePublicLabRecord(t, instance)
			value["self_approved"] = true
			if err := schemas[name].Validate(value); err == nil {
				t.Fatal("schema accepted an unknown top-level property")
			}
		})

		required := requiredPublicLabFields(t, name)
		for _, field := range required {
			field := field
			t.Run(name+"/null-"+field, func(t *testing.T) {
				value := clonePublicLabRecord(t, instance)
				value[field] = nil
				if err := schemas[name].Validate(value); err == nil {
					t.Fatalf("schema accepted null for required field %q", field)
				}
			})
		}
	}

	tests := []struct {
		name   string
		schema string
		mutate func(map[string]any)
	}{
		{
			name:   "run identity cannot omit job_id",
			schema: "run-record.schema.json",
			mutate: func(value map[string]any) {
				job := firstPublicLabObject(firstPublicLabObject(firstPublicLabObject(value, "workflow_runs"), "attempts"), "jobs")
				delete(job, "job_id")
			},
		},
		{
			name:   "run record rejects abbreviated git identity",
			schema: "run-record.schema.json",
			mutate: func(value map[string]any) {
				value["fixture_objects"].(map[string]any)["marker_b_commit"].(map[string]any)["objectId"] = "deadbeef"
			},
		},
		{
			name:   "run record rejects raw-log privacy claim",
			schema: "run-record.schema.json",
			mutate: func(value map[string]any) {
				value["privacy"].(map[string]any)["rawLogsIncluded"] = true
			},
		},
		{
			name:   "run record rejects unsafe Action path",
			schema: "run-record.schema.json",
			mutate: func(value map[string]any) {
				job := firstPublicLabObject(firstPublicLabObject(firstPublicLabObject(value, "workflow_runs"), "attempts"), "jobs")
				firstPublicLabObject(job, "action_observations")["action_path"] = "../actions/marker/action.yml"
			},
		},
		{
			name:   "matching reproduction cannot fail skipped invariant",
			schema: "reproduction-record.schema.json",
			mutate: func(value map[string]any) {
				value["scenario_checks"].(map[string]any)["skipped_b_not_executed"] = false
			},
		},
		{
			name:   "reproducer cannot claim independence from authored implementation",
			schema: "reproduction-record.schema.json",
			mutate: func(value map[string]any) {
				value["reproducer"].(map[string]any)["authored_cirewind_implementation"] = true
			},
		},
		{
			name:   "signed case URL is forbidden",
			schema: "reproduction-record.schema.json",
			mutate: func(value map[string]any) {
				value["case_archive"].(map[string]any)["public_anonymous_url"] = "https://downloads.example.invalid/case.zip?token=not-a-real-token"
			},
		},
		{
			name:   "raw directory cannot enter fixed case contract",
			schema: "reproduction-record.schema.json",
			mutate: func(value map[string]any) {
				value["case_archive"].(map[string]any)["raw_directory_present"] = true
			},
		},
		{
			name:   "matching claim cannot contain deviations",
			schema: "reproduction-record.schema.json",
			mutate: func(value map[string]any) {
				value["oracle_comparison"].(map[string]any)["deviations"] = []any{"synthetic mismatch"}
			},
		},
		{
			name:   "awaiting index cannot self-list acceptance",
			schema: "reproductions-index.schema.json",
			mutate: func(value map[string]any) {
				value["records"] = []any{map[string]any{}}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := clonePublicLabRecord(t, fixtures[test.schema])
			test.mutate(value)
			if err := schemas[test.schema].Validate(value); err == nil {
				t.Fatal("hostile or semantically unsafe fixture was accepted")
			}
		})
	}
}

func TestPublicLabRecordPositiveContainersRejectNullAndNestedUnknownFields(t *testing.T) {
	t.Parallel()
	schemas := compilePublicLabRecordSchemas(t)
	fixtures := validPublicLabRecordFixtures(t)
	for name, instance := range fixtures {
		name, instance := name, instance
		t.Run(name, func(t *testing.T) {
			for _, path := range publicLabContainerPaths(instance, nil) {
				path := path
				t.Run("null/"+publicLabPathName(path), func(t *testing.T) {
					value := clonePublicLabRecord(t, instance)
					if len(path) == 0 {
						if err := schemas[name].Validate(nil); err == nil {
							t.Fatal("schema accepted null root")
						}
						return
					}
					publicLabSetPath(t, value, path, nil)
					if err := schemas[name].Validate(value); err == nil {
						t.Fatalf("schema accepted null container at %s", publicLabPathName(path))
					}
				})
			}
			for _, path := range publicLabObjectPaths(instance, nil) {
				path := path
				t.Run("unknown/"+publicLabPathName(path), func(t *testing.T) {
					value := clonePublicLabRecord(t, instance)
					object := publicLabObjectAtPath(t, value, path)
					object["unexpected_private_material"] = true
					if err := schemas[name].Validate(value); err == nil {
						t.Fatalf("schema accepted unknown property at %s", publicLabPathName(path))
					}
				})
			}
		})
	}
}

func TestPublicLabRecordCanonicalEnumsMatchDomainModel(t *testing.T) {
	t.Parallel()
	path := filepath.Join(recordSourceRoot(t), "import", "protocol", "record-common.schema.json")
	var document map[string]any
	readPublicLabJSON(t, path, &document)
	definitions := document["$defs"].(map[string]any)

	states := stringEnum(t, definitions["findingState"].(map[string]any)["enum"])
	wantStates := make([]string, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		wantStates = append(wantStates, string(state))
	}
	if !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("public lab finding states drifted\n got: %v\nwant: %v", states, wantStates)
	}

	levels := stringEnum(t, definitions["provenanceLevel"].(map[string]any)["enum"])
	wantLevels := make([]string, 0, len(model.ProvenanceLevels()))
	for _, level := range model.ProvenanceLevels() {
		wantLevels = append(wantLevels, string(level))
	}
	if !reflect.DeepEqual(levels, wantLevels) {
		t.Fatalf("public lab provenance levels drifted\n got: %v\nwant: %v", levels, wantLevels)
	}

	runPath := filepath.Join(recordSourceRoot(t), "import", "protocol", "run-record.schema.json")
	var runDocument map[string]any
	readPublicLabJSON(t, runPath, &runDocument)
	runDefinitions := runDocument["$defs"].(map[string]any)
	actionProperties := runDefinitions["actionObservation"].(map[string]any)["properties"].(map[string]any)
	lifecycles := stringEnum(t, actionProperties["lifecycle"].(map[string]any)["enum"])
	wantLifecycles := make([]string, 0, len(model.RuntimeObservationKinds()))
	for _, kind := range model.RuntimeObservationKinds() {
		wantLifecycles = append(wantLifecycles, string(kind))
	}
	if !reflect.DeepEqual(lifecycles, wantLifecycles) {
		t.Fatalf("public lab runtime observation kinds drifted\n got: %v\nwant: %v", lifecycles, wantLifecycles)
	}
}

func TestExpectedFindingsSeedContainsNoInventedLiveIdentityOrTime(t *testing.T) {
	t.Parallel()
	path := filepath.Join(recordSourceRoot(t), "import", "protocol", "expected-findings.seed.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"run_id"`, `"run_attempt"`, `"job_id"`, `"observed_at"`, `"event_time"`, `"submitted_at"`, `"evidence_ids"`} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("seed contains forbidden live-binding field %s", forbidden)
		}
	}
	if regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`).Match(data) {
		t.Fatal("seed contains a timestamp that could be mistaken for a live observation")
	}
	for _, placeholder := range []string{"deadbeef", "0000000000000000000000000000000000000000", "example-run"} {
		if bytes.Contains(bytes.ToLower(data), []byte(placeholder)) {
			t.Fatalf("seed contains fabricated identity placeholder %q", placeholder)
		}
	}
}

func TestPublicLabTemplatesCannotMasqueradeAsCompletedRecords(t *testing.T) {
	t.Parallel()
	schemas := compilePublicLabRecordSchemas(t)
	root := filepath.Join(recordSourceRoot(t), "import", "protocol")
	for schemaName, templateName := range map[string]string{
		"pack-input-record.schema.json":   "pack-input-record.template.json",
		"run-record.schema.json":          "run-record.template.json",
		"tag-move-record.schema.json":     "tag-move-record.template.json",
		"reproduction-record.schema.json": "reproduction-record.template.json",
	} {
		raw, err := os.ReadFile(filepath.Join(root, templateName))
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`[0-9a-f]{40}|[0-9a-f]{64}|\d{4}-\d{2}-\d{2}T`).Match(raw) {
			t.Fatalf("%s contains an identity or time that could be mistaken for a live observation", templateName)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("parse %s: %v", templateName, err)
		}
		if err := schemas[schemaName].Validate(value); err == nil {
			t.Fatalf("intentionally incomplete %s passed the completed-record schema", templateName)
		}
	}
}

func TestStableReproductionsIndexMatchesValidatedEmptyTemplate(t *testing.T) {
	t.Parallel()
	root := filepath.Join(recordSourceRoot(t), "import")
	stable, err := os.ReadFile(filepath.Join(root, "reproductions", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile(filepath.Join(root, "protocol", "reproductions-index.template.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stable, template) {
		t.Fatal("stable reproductions/index.json differs from the reviewed empty template")
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(stable))
	if err != nil {
		t.Fatal(err)
	}
	if err := compilePublicLabRecordSchemas(t)["reproductions-index.schema.json"].Validate(instance); err != nil {
		t.Fatalf("stable empty index violates its schema: %v", err)
	}
}

func TestReproductionIssueFormCarriesPrivacyAndIdentityContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(recordSourceRoot(t), "import", ".github", "ISSUE_TEMPLATE", "reproduction.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse reproduction issue form: %v", err)
	}
	for _, required := range []string{
		"run_id + run_attempt + job_id",
		"Do not paste or upload tokens",
		"raw logs",
		"secret values",
		"private repository names",
		"exact local paths",
		"CONFIRMED_EXECUTED",
		"UNKNOWN_EVIDENCE_GAP",
	} {
		if !bytes.Contains(data, []byte(required)) {
			t.Fatalf("reproduction issue form omits %q", required)
		}
	}
}

func compilePublicLabRecordSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	root := filepath.Join(recordSourceRoot(t), "import", "protocol")
	for _, name := range publicLabRecordSchemaFiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if err := compiler.AddResource(publicLabRecordSchemaBase+name, document); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	result := make(map[string]*jsonschema.Schema, len(publicLabRecordSchemaFiles))
	for _, name := range publicLabRecordSchemaFiles {
		schema, err := compiler.Compile(publicLabRecordSchemaBase + name)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		result[name] = schema
	}
	return result
}

func validPublicLabRecordFixtures(t *testing.T) map[string]map[string]any {
	t.Helper()
	result := map[string]map[string]any{
		"record-common.schema.json":       {},
		"pack-input-record.schema.json":   validPublicLabPackInputRecord(),
		"run-record.schema.json":          validPublicLabRunRecord(),
		"tag-move-record.schema.json":     validPublicLabTagMoveRecord(t),
		"reproduction-record.schema.json": validPublicLabReproductionRecord(),
	}
	for name, file := range map[string]string{
		"expected-findings-seed.schema.json": "expected-findings.seed.json",
		"reproductions-index.schema.json":    "reproductions-index.template.json",
	} {
		var value map[string]any
		readPublicLabJSON(t, filepath.Join(recordSourceRoot(t), "import", "protocol", file), &value)
		result[name] = value
	}
	return result
}

func validPublicLabTagMoveRecord(t *testing.T) map[string]any {
	t.Helper()
	policy := TagMovePolicy{
		Repository:           RepositoryName,
		RepositoryDatabaseID: 101,
		RemoteURL:            "https://github.com/" + RepositoryName + ".git",
		ReviewedMain:         strings.Repeat("1", 40),
		CommitA:              strings.Repeat("2", 40),
		CommitB:              strings.Repeat("3", 40),
		FixtureATagObject:    strings.Repeat("4", 40),
		FixtureBTagObject:    strings.Repeat("5", 40),
	}
	result := TagMoveResult{
		Plan: TagMovePlan{
			Repository:           policy.Repository,
			RepositoryDatabaseID: policy.RepositoryDatabaseID,
			Ref:                  MutableV1Ref,
			ExpectedOld:          policy.CommitA,
			NewTarget:            policy.CommitB,
			Direction:            InstallAffectedMarker,
		},
		Before:           policy.CommitA,
		BeforeObservedAt: "2026-01-01T00:00:00Z",
		After:            policy.CommitB,
		AfterObservedAt:  "2026-01-01T00:01:00Z",
		Verified:         true,
	}
	data, err := EncodeTagMoveRecord(policy, result, nil, time.Date(2026, 1, 1, 0, 1, 1, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func validPublicLabPackInputRecord() map[string]any {
	run := validPublicLabRunRecord()
	value := map[string]any{
		"schema_version":               "cirewind.lab-pack-input-record/v1alpha1",
		"record_id":                    "pack-input-placeholder",
		"lab_repository":               run["lab_repository"],
		"repository_database_id_basis": "OPERATOR_ASSERTED_PREFLIGHT_REQUIRES_RUN_CROSSCHECK",
		"protocol":                     run["protocol"],
		"fixture_objects":              run["fixture_objects"],
		"mutable_tag":                  run["mutable_tag"],
		"derivation_inputs": []any{
			map[string]any{"record_id": "tag-move-install", "sha256": strings.Repeat("b", 64)},
			map[string]any{"record_id": "tag-move-restore", "sha256": strings.Repeat("c", 64)},
		},
		"created_at":        "2026-01-01T00:03:30Z",
		"privacy_statement": "This pack-input record contains only public synthetic Git identities and tag observations; it contains no raw logs, token material, secret values, private repository names, local paths, private user data, findings, or case hashes.",
		"privacy":           run["privacy"],
	}
	encoded, _ := json.Marshal(value)
	var record labPackInputRecord
	_ = json.Unmarshal(encoded, &record)
	value["record_id"] = packInputRecordID(record)
	return value
}

func validPublicLabRunRecord() map[string]any {
	return map[string]any{
		"schema_version": "cirewind.lab-run-record/v1alpha1",
		"record_id":      "synthetic-record-1",
		"lab_repository": map[string]any{
			"database_id": 101,
			"full_name":   "torjan0/cirewind-lab",
			"public_url":  "https://github.com/torjan0/cirewind-lab",
		},
		"protocol": map[string]any{
			"version":                "public-a-b-a/v1",
			"source_commit":          syntheticGitObject("1"),
			"source_manifest_sha256": strings.Repeat("a", 64),
		},
		"fixture_objects": map[string]any{
			"marker_a_commit": syntheticGitObject("2"),
			"marker_b_commit": syntheticGitObject("3"),
			"fixture_a_tag": map[string]any{
				"ref":           "refs/tags/fixture-a",
				"tag_object":    syntheticGitObject("4"),
				"peeled_commit": syntheticGitObject("2"),
			},
			"fixture_b_tag": map[string]any{
				"ref":           "refs/tags/fixture-b",
				"tag_object":    syntheticGitObject("5"),
				"peeled_commit": syntheticGitObject("3"),
			},
		},
		"mutable_tag": map[string]any{
			"ref":    "refs/tags/v1",
			"before": syntheticTagObservation("2", "2026-01-01T00:00:00Z"),
			"during": syntheticTagObservation("3", "2026-01-01T00:01:00Z"),
			"after":  syntheticTagObservation("2", "2026-01-01T00:02:00Z"),
		},
		"workflow_runs": []any{
			map[string]any{
				"scenario_id":                "PUBLIC-DIRECT",
				"workflow_path":              ".github/workflows/direct.yml",
				"workflow_definition_commit": syntheticGitObject("1"),
				"event_type":                 "workflow_dispatch",
				"actor":                      "synthetic-reproducer",
				"triggering_actor":           "synthetic-reproducer",
				"event_time":                 syntheticObservation("2026-01-01T00:01:10Z", "github-actions-event"),
				"run_id":                     1001,
				"run_url":                    "https://github.com/torjan0/cirewind-lab/actions/runs/1001",
				"attempts": []any{
					map[string]any{
						"run_attempt": 1,
						"jobs": []any{
							map[string]any{
								"job_id":       3001,
								"display_name": "Direct synthetic marker",
								"conclusion":   "success",
								"action_observations": []any{
									map[string]any{
										"action_repository": "torjan0/cirewind-lab",
										"action_path":       "actions/marker/action.yml",
										"declared_ref":      "v1",
										"source_commit":     syntheticGitObject("3"),
										"lifecycle":         "LIFECYCLE_STARTED",
										"step_identity":     "step:marker",
										"evidence_ids":      []any{"ev1:" + strings.Repeat("6", 64)},
									},
								},
								"dependency_chain": []any{
									map[string]any{
										"relationship": "WORKFLOW_DECLARED_ACTION",
										"from": map[string]any{
											"kind":       "WORKFLOW_DEFINITION",
											"repository": "torjan0/cirewind-lab",
											"path":       ".github/workflows/direct.yml",
											"commit":     syntheticGitObject("1"),
										},
										"to": map[string]any{
											"kind":       "ACTION_DEFINITION",
											"repository": "torjan0/cirewind-lab",
											"path":       "actions/marker/action.yml",
											"commit":     syntheticGitObject("3"),
										},
										"evidence_ids": []any{"ev1:" + strings.Repeat("6", 64)},
									},
								},
								"called_workflow_observations": []any{},
								"findings": []any{
									map[string]any{
										"finding_id":              "find1:" + strings.Repeat("7", 64),
										"finding_revision_id":     "frev1:" + strings.Repeat("8", 64),
										"indicator_id":            "public-lab-marker-b",
										"step_identity":           "step:marker",
										"state":                   "CONFIRMED_EXECUTED",
										"provenance":              "L4_CERTAIN",
										"conclusion":              "Exact harmless synthetic marker B began its lifecycle in this job attempt.",
										"evidence_ids":            []any{"ev1:" + strings.Repeat("6", 64)},
										"coverage_assessment_ids": []any{"cova1:" + strings.Repeat("9", 64)},
										"evidence_gap_codes":      []any{},
									},
								},
							},
						},
					},
				},
			},
		},
		"rerun_requests": []any{},
		"collector": map[string]any{
			"version":         "0.2.0",
			"source_revision": syntheticGitObject("a"),
			"binary_sha256":   strings.Repeat("b", 64),
		},
		"collection": map[string]any{
			"window_start":           "2026-01-01T00:00:00Z",
			"window_end":             "2026-01-01T00:03:00Z",
			"collected_at":           "2026-01-01T00:04:00Z",
			"case_manifest_sha256":   strings.Repeat("c", 64),
			"case_manifest_verified": true,
			"coverage": map[string]any{
				"repositories_requested":         1,
				"repositories_accessible":        1,
				"repositories_denied":            0,
				"runs_enumerated":                1,
				"attempts_enumerated":            1,
				"jobs_enumerated":                1,
				"logs_retrieved":                 1,
				"logs_missing":                   0,
				"workflow_definitions_retrieved": 1,
				"action_definitions_retrieved":   1,
				"optional_capabilities_denied":   0,
				"truncated_evidence_objects":     0,
			},
			"parser_versions": []any{map[string]any{"component": "github-log", "version": "v1"}},
			"api_versions":    []any{map[string]any{"component": "github-rest", "version": "2026-03-10"}},
			"issues":          []any{},
		},
		"privacy_statement": "This public record contains no raw logs, token material, secret values, private repository names, local paths, or private user data.",
		"privacy":           syntheticPrivacyAttestation(),
	}
}

func validPublicLabReproductionRecord() map[string]any {
	files := []any{
		"affected-runs.csv", "case.db", "collection-metadata.json", "evidence.jsonl", "findings.json",
		"graph.json", "graph.svg", "manifest.sha256", "report.html", "summary.md",
	}
	checks := map[string]any{
		"direct_b_executed":                      true,
		"composite_b_executed":                   true,
		"reusable_b_executed":                    true,
		"skipped_b_not_executed":                 true,
		"matrix_jobs_kept_distinct":              true,
		"rerun_attempts_kept_distinct":           true,
		"present_tag_did_not_rewrite_history":    true,
		"called_workflow_identity_kept_separate": true,
	}
	counts := map[string]any{}
	for _, state := range model.FindingStates() {
		counts[string(state)] = 0
	}
	counts["CONFIRMED_EXECUTED"] = 1

	return map[string]any{
		"schema_version":  "cirewind.lab-reproduction/v1alpha1",
		"reproduction_id": "synthetic-reproduction-1",
		"claimed_result":  "matches-qualified-oracle",
		"reproducer": map[string]any{
			"github_login":                             "synthetic-reproducer",
			"github_database_id":                       501,
			"conflict_disclosure":                      "No conflict in this synthetic schema fixture.",
			"authored_cirewind_implementation":         false,
			"authored_lab_source":                      false,
			"authored_expected_oracle":                 false,
			"authored_this_record_before_reproduction": false,
		},
		"lab_binding": map[string]any{
			"repository":              "torjan0/cirewind-lab",
			"repository_database_id":  101,
			"public_url":              "https://github.com/torjan0/cirewind-lab",
			"source_commit":           syntheticGitObject("1"),
			"source_manifest_sha256":  strings.Repeat("a", 64),
			"marker_a_commit":         syntheticGitObject("2"),
			"marker_b_commit":         syntheticGitObject("3"),
			"fixture_a_tag_object":    syntheticGitObject("4"),
			"fixture_a_peeled_commit": syntheticGitObject("2"),
			"fixture_b_tag_object":    syntheticGitObject("5"),
			"fixture_b_peeled_commit": syntheticGitObject("3"),
			"v1_before":               syntheticTagObservation("2", "2026-01-01T00:00:00Z"),
			"v1_during":               syntheticTagObservation("3", "2026-01-01T00:01:00Z"),
			"v1_after":                syntheticTagObservation("2", "2026-01-01T00:02:00Z"),
		},
		"qualified_binary": map[string]any{
			"version":         "0.2.0",
			"source_revision": syntheticGitObject("a"),
			"binary_sha256":   strings.Repeat("b", 64),
			"acquisition": map[string]any{
				"kind":                    "independent-reproducible-source-build",
				"source_url":              "https://github.com/torjan0/cirewind/tree/" + strings.Repeat("a", 40),
				"source_commit":           syntheticGitObject("a"),
				"go_version":              "go1.25.1",
				"build_recipe_id":         "release-build-v1",
				"byte_matched_project_rc": true,
			},
		},
		"run_record": map[string]any{
			"record_id":   "synthetic-record-1",
			"public_url":  "https://github.com/torjan0/cirewind-lab/blob/" + strings.Repeat("1", 40) + "/reproductions/synthetic-record-1.json",
			"sha256":      strings.Repeat("d", 64),
			"byte_length": 4096,
		},
		"public_runs": syntheticReproductionRuns(),
		"sanitized_command_shapes": []any{
			"cirewind investigate --repo PUBLIC_LAB_REPOSITORY --incident SYNTHETIC_INCIDENT_PACK --from WINDOW_START --to WINDOW_END --out CASE_DIRECTORY",
			"cirewind verify --case CASE_DIRECTORY",
		},
		"case_archive": map[string]any{
			"public_anonymous_url":         "https://downloads.example.invalid/cirewind-lab-case.zip",
			"archive_sha256":               strings.Repeat("e", 64),
			"archive_byte_length":          65536,
			"case_manifest_sha256":         strings.Repeat("c", 64),
			"anonymous_download_verified":  true,
			"manifest_verification_result": "verified",
			"raw_directory_present":        false,
			"files":                        files,
		},
		"finding_counts":  counts,
		"scenario_checks": checks,
		"oracle_comparison": map[string]any{
			"oracle_sha256": strings.Repeat("f", 64),
			"result":        "match",
			"deviations":    []any{},
		},
		"outputs": map[string]any{
			"report_url":    "https://downloads.example.invalid/report.html",
			"graph_svg_url": "https://downloads.example.invalid/graph.svg",
		},
		"platform_versions": []any{
			map[string]any{"component": "operating-system", "version": "Synthetic Linux"},
		},
		"coverage_issues": []any{},
		"submitted_at":    "2026-01-01T00:05:00Z",
		"safety": map[string]any{
			"used_only_public_lab_repository": true,
			"used_no_real_secrets":            true,
			"used_no_production_resources":    true,
			"used_no_exfiltration_behavior":   true,
			"case_is_raw_log_disabled":        true,
			"permission_to_link_publicly":     true,
		},
		"privacy_statement": "Do not include tokens, cookies, signed URLs, authentication headers, raw logs, secret values, private repository names, exact local paths, or private user data.",
		"privacy":           syntheticPrivacyAttestation(),
	}
}

func syntheticReproductionRuns() []any {
	type scenarioTopology struct {
		name        string
		cardinality []int
	}
	scenarios := []scenarioTopology{
		{name: "PUBLIC-COMPOSITE", cardinality: []int{1}},
		{name: "PUBLIC-DIRECT", cardinality: []int{1}},
		{name: "PUBLIC-MATRIX", cardinality: []int{4}},
		{name: "PUBLIC-RERUN-FULL", cardinality: []int{2, 2}},
		{name: "PUBLIC-RERUN-JOB", cardinality: []int{2, 1, 1}},
		{name: "PUBLIC-REUSABLE", cardinality: []int{1}},
		{name: "PUBLIC-SKIPPED", cardinality: []int{1}},
	}
	nextJobID := int64(3000)
	result := make([]any, 0, len(scenarios))
	for index, scenario := range scenarios {
		runID := int64(1001 + index)
		attempts := make([]any, 0, len(scenario.cardinality))
		for attemptIndex, count := range scenario.cardinality {
			jobIDs := make([]any, 0, count)
			for range count {
				nextJobID++
				jobIDs = append(jobIDs, nextJobID)
			}
			attempts = append(attempts, map[string]any{"run_attempt": attemptIndex + 1, "job_ids": jobIDs})
		}
		result = append(result, map[string]any{
			"scenario_id": scenario.name,
			"run_id":      runID,
			"run_url":     fmt.Sprintf("https://github.com/torjan0/cirewind-lab/actions/runs/%d", runID),
			"attempts":    attempts,
		})
	}
	return result
}

func syntheticGitObject(digit string) map[string]any {
	return map[string]any{"algorithm": "sha1", "objectId": strings.Repeat(digit, 40)}
}

func syntheticObservation(at, source string) map[string]any {
	return map[string]any{
		"observedAt":      at,
		"eventSource":     source,
		"sourcePrecision": "second",
		"approximation":   "exact",
	}
}

func syntheticTagObservation(digit, at string) map[string]any {
	return map[string]any{
		"target_commit": syntheticGitObject(digit),
		"observation":   syntheticObservation(at, "git-ls-remote"),
	}
}

func syntheticPrivacyAttestation() map[string]any {
	return map[string]any{
		"rawLogsIncluded":                false,
		"tokensOrCookiesIncluded":        false,
		"secretValuesIncluded":           false,
		"privateRepositoryNamesIncluded": false,
		"localPathsIncluded":             false,
		"privateUserDataIncluded":        false,
	}
}

func requiredPublicLabFields(t *testing.T, schemaName string) []string {
	t.Helper()
	path := filepath.Join(recordSourceRoot(t), "import", "protocol", schemaName)
	var document map[string]any
	readPublicLabJSON(t, path, &document)
	values, ok := document["required"].([]any)
	if !ok {
		t.Fatalf("%s has no top-level required array", schemaName)
	}
	return stringEnum(t, values)
}

func readPublicLabJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func clonePublicLabRecord(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func firstPublicLabObject(value map[string]any, field string) map[string]any {
	return value[field].([]any)[0].(map[string]any)
}

func stringEnum(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("enum has type %T", value)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("enum item has type %T", item)
		}
		result = append(result, text)
	}
	return result
}

func publicLabContainerPaths(value any, prefix []any) [][]any {
	result := [][]any{append([]any(nil), prefix...)}
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range sortedPublicLabKeys(typed) {
			child := typed[key]
			switch child.(type) {
			case map[string]any, []any:
				result = append(result, publicLabContainerPaths(child, appendPath(prefix, key))...)
			}
		}
	case []any:
		for index, child := range typed {
			switch child.(type) {
			case map[string]any, []any:
				result = append(result, publicLabContainerPaths(child, appendPath(prefix, index))...)
			}
		}
	}
	return result
}

func publicLabObjectPaths(value any, prefix []any) [][]any {
	result := make([][]any, 0)
	switch typed := value.(type) {
	case map[string]any:
		result = append(result, append([]any(nil), prefix...))
		for _, key := range sortedPublicLabKeys(typed) {
			child := typed[key]
			result = append(result, publicLabObjectPaths(child, appendPath(prefix, key))...)
		}
	case []any:
		for index, child := range typed {
			result = append(result, publicLabObjectPaths(child, appendPath(prefix, index))...)
		}
	}
	return result
}

func appendPath(path []any, element any) []any {
	result := make([]any, len(path), len(path)+1)
	copy(result, path)
	return append(result, element)
}

func publicLabSetPath(t *testing.T, root map[string]any, path []any, replacement any) {
	t.Helper()
	var current any = root
	for _, element := range path[:len(path)-1] {
		switch index := element.(type) {
		case string:
			current = current.(map[string]any)[index]
		case int:
			current = current.([]any)[index]
		default:
			t.Fatalf("unsupported path element %T", element)
		}
	}
	switch last := path[len(path)-1].(type) {
	case string:
		current.(map[string]any)[last] = replacement
	case int:
		current.([]any)[last] = replacement
	default:
		t.Fatalf("unsupported final path element %T", last)
	}
}

func publicLabObjectAtPath(t *testing.T, root map[string]any, path []any) map[string]any {
	t.Helper()
	var current any = root
	for _, element := range path {
		switch index := element.(type) {
		case string:
			current = current.(map[string]any)[index]
		case int:
			current = current.([]any)[index]
		default:
			t.Fatalf("unsupported path element %T", element)
		}
	}
	object, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("path %s has type %T", publicLabPathName(path), current)
	}
	return object
}

func publicLabPathName(path []any) string {
	if len(path) == 0 {
		return "root"
	}
	parts := make([]string, 0, len(path))
	for _, element := range path {
		parts = append(parts, strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(toPublicLabPathPart(element)), "/", "-"), " ", "-")))
	}
	return strings.Join(parts, "/")
}

func toPublicLabPathPart(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int:
		return "item-" + strconv.Itoa(typed)
	default:
		return "unknown"
	}
}

func sortedPublicLabKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func recordSourceRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "lab", "public", "source")
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatalf("public lab source root: %v", err)
	}
	return root
}
