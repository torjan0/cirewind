package packreview_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/torjan0/cirewind/internal/model"
)

const reviewSchemaBase = "https://schemas.invalid/cirewind/review/"

var reviewSchemaFiles = []string{
	"review-common-v1alpha1.json",
	"review-policy-v1alpha1.json",
	"review-packet-v1alpha1.json",
	"review-sources-v1alpha1.json",
	"review-claims-v1alpha1.json",
	"review-conflicts-v1alpha1.json",
	"review-expected-findings-v1alpha1.json",
	"review-fixture-index-v1alpha1.json",
	"review-validation-v1alpha1.json",
	"review-assertion-v1alpha1.json",
	"review-approval-v1alpha1.json",
	"platform-approval-snapshot-v1alpha1.json",
	"review-promotion-v1alpha1.json",
	"review-registry-v1alpha1.json",
}

func TestReviewSchemasUseRelativeLocalReferencesAndCompile(t *testing.T) {
	t.Parallel()
	compileReviewSchemas(t)
}

func TestReviewSchemasRejectUnknownFields(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()

	for name, instance := range instances {
		name, instance := name, instance
		t.Run(name+"/top-level", func(t *testing.T) {
			value := cloneObject(t, instance)
			value["unexpected"] = true
			if err := schemas[name].Validate(value); err == nil {
				t.Fatal("schema accepted an unknown top-level field")
			}
		})
	}

	nested := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"review-packet-v1alpha1.json", func(value map[string]any) {
			value["preparation"].(map[string]any)["selfApproved"] = true
		}},
		{"review-policy-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "profiles")["roleCreatesEligibility"] = true
		}},
		{"review-sources-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "sources")["fetchAutomatically"] = true
		}},
		{"review-claims-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "claims")["trusted"] = true
		}},
		{"review-conflicts-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "conflicts")["silentlyResolved"] = true
		}},
		{"review-expected-findings-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "findings")["assumedExecuted"] = true
		}},
		{"review-expected-findings-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "forbidden")["waived"] = true
		}},
		{"review-fixture-index-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "scenarios")["fetchSnapshot"] = true
		}},
		{"review-approval-v1alpha1.json", func(value map[string]any) {
			value["bindings"].(map[string]any)["selfCertified"] = true
		}},
		{"platform-approval-snapshot-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "approvals")["provesHumanIdentity"] = true
		}},
		{"review-registry-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "records")["containingCommit"] = strings.Repeat("f", 40)
		}},
	}
	for _, test := range nested {
		test := test
		t.Run(test.name+"/nested", func(t *testing.T) {
			value := cloneObject(t, instances[test.name])
			test.mutate(value)
			if err := schemas[test.name].Validate(value); err == nil {
				t.Fatal("schema accepted an unknown nested field")
			}
		})
	}
}

func TestReviewSchemasRejectUnsafeIdentityBindingsAndPaths(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"uppercase hash", func(value map[string]any) {
			value["originalPackSha256"] = strings.Repeat("A", 64)
		}},
		{"abbreviated candidate commit", func(value map[string]any) {
			value["candidateCommit"] = "deadbeef"
		}},
		{"source path traversal", func(value map[string]any) {
			source := firstObject(value, "sources")
			delete(source, "notRedistributedReason")
			source["archivePath"] = "../outside"
		}},
		{"Windows reserved source path", func(value map[string]any) {
			source := firstObject(value, "sources")
			delete(source, "notRedistributedReason")
			source["archivePath"] = "source-objects/NUL.txt"
		}},
		{"Windows reserved incident ID", func(value map[string]any) {
			value["incidentId"] = "CON"
		}},
		{"Windows reserved stable ID", func(value map[string]any) {
			firstObject(value, "sources")["sourceId"] = "NUL.synthetic.txt"
		}},
		{"trailing-dot stable ID", func(value map[string]any) {
			firstObject(value, "conflicts")["conflictId"] = "conflict."
		}},
		{"non-Go-compatible source path", func(value map[string]any) {
			source := firstObject(value, "sources")
			delete(source, "notRedistributedReason")
			source["archivePath"] = "source-objects/object+one.txt"
		}},
		{"uppercase human login", func(value map[string]any) {
			value["preparation"].(map[string]any)["preparer"].(map[string]any)["login"] = "Schema-Preparer"
		}},
		{"candidate path as reviewed destination", func(value map[string]any) {
			value["reviewedPath"] = "incidents/candidates/synthetic-schema-only/1.0.0.yaml"
		}},
	}
	cases := []struct {
		schema string
		index  int
	}{
		{"review-packet-v1alpha1.json", 0},
		{"review-approval-v1alpha1.json", 1},
		{"review-sources-v1alpha1.json", 2},
		{"review-sources-v1alpha1.json", 3},
		{"review-packet-v1alpha1.json", 4},
		{"review-sources-v1alpha1.json", 5},
		{"review-conflicts-v1alpha1.json", 6},
		{"review-sources-v1alpha1.json", 7},
		{"review-packet-v1alpha1.json", 8},
		{"review-promotion-v1alpha1.json", 9},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(tests[testCase.index].name, func(t *testing.T) {
			value := cloneObject(t, instances[testCase.schema])
			tests[testCase.index].mutate(value)
			if err := schemas[testCase.schema].Validate(value); err == nil {
				t.Fatal("schema accepted an unsafe identity binding or path")
			}
		})
	}
}

func TestReviewedPathSchemaAcceptsCanonicalSemVerBuildMetadata(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-promotion-v1alpha1.json"]
	value := cloneObject(t, validReviewSchemaInstances()["review-promotion-v1alpha1.json"])
	value["packVersion"] = "1.0.0+synthetic.1"
	value["reviewedPath"] = "incidents/reviewed/synthetic-schema-only/1.0.0+synthetic.1.yaml"
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected safe identifier-derived reviewed path: %v", err)
	}
}

func TestPlatformSnapshotSchemaRepresentsBotsWithoutTreatingThemAsHumans(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	value := cloneObject(t, validReviewSchemaInstances()["platform-approval-snapshot-v1alpha1.json"])
	approval := firstObject(value, "approvals")
	approval["accountType"] = "Bot"
	approval["reviewer"].(map[string]any)["login"] = "schema-automation[bot]"
	if err := schemas["platform-approval-snapshot-v1alpha1.json"].Validate(value); err != nil {
		t.Fatalf("schema rejected normalized non-human platform metadata: %v", err)
	}
	approval["accountType"] = "User"
	if err := schemas["platform-approval-snapshot-v1alpha1.json"].Validate(value); err == nil {
		t.Fatal("schema treated a canonical bot login as a human account")
	}
}

func TestReviewSchemasMatchSafeTextLineAndAnglePolicy(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()

	multiline := cloneObject(t, instances["review-conflicts-v1alpha1.json"])
	firstObject(multiline, "conflicts")["description"] = "Synthetic\nmultiline rationale."
	if err := schemas["review-conflicts-v1alpha1.json"].Validate(multiline); err != nil {
		t.Fatalf("schema rejected LF in a multiline safe-text field: %v", err)
	}

	for _, test := range []struct {
		name   string
		schema string
		mutate func(map[string]any)
	}{
		{"packet newline", "review-packet-v1alpha1.json", func(value map[string]any) { value["validatorVersion"] = "one\ntwo" }},
		{"packet Unicode line separator", "review-packet-v1alpha1.json", func(value map[string]any) { value["validatorVersion"] = "one\u2028two" }},
		{"source title newline", "review-sources-v1alpha1.json", func(value map[string]any) { firstObject(value, "sources")["title"] = "one\ntwo" }},
		{"command argument newline", "review-approval-v1alpha1.json", func(value map[string]any) {
			firstObject(value, "commands")["arguments"] = []any{"one\ntwo"}
		}},
		{"step identity newline", "review-expected-findings-v1alpha1.json", func(value map[string]any) { firstObject(value, "findings")["stepIdentity"] = "one\ntwo" }},
		{"multiline tab", "review-conflicts-v1alpha1.json", func(value map[string]any) { firstObject(value, "conflicts")["description"] = "one\ttwo" }},
		{"left angle", "review-conflicts-v1alpha1.json", func(value map[string]any) { firstObject(value, "conflicts")["description"] = "one < two" }},
		{"right angle", "review-approval-v1alpha1.json", func(value map[string]any) { value["rationale"] = "one > two" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, instances[test.schema])
			test.mutate(value)
			if err := schemas[test.schema].Validate(value); err == nil {
				t.Fatal("schema accepted text outside the safe-text contract")
			}
		})
	}
}

func TestReviewSchemasEnforceSemVerLengthBoundary(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()
	valid := "1.0.0+" + strings.Repeat("a", 122)
	invalid := valid + "a"
	if len(valid) != 128 || len(invalid) != 129 {
		t.Fatal("test SemVer boundary construction is incorrect")
	}

	for _, test := range []struct {
		name   string
		schema string
		set    func(map[string]any, string)
	}{
		{"packet", "review-packet-v1alpha1.json", func(value map[string]any, version string) { value["packVersion"] = version }},
		{"validation", "review-validation-v1alpha1.json", func(value map[string]any, version string) { value["packVersion"] = version }},
		{"approval", "review-approval-v1alpha1.json", func(value map[string]any, version string) { value["packVersion"] = version }},
		{"promotion", "review-promotion-v1alpha1.json", func(value map[string]any, version string) {
			value["packVersion"] = version
			value["reviewedPath"] = "incidents/reviewed/synthetic-schema-only/" + version + ".yaml"
		}},
		{"registry", "review-registry-v1alpha1.json", func(value map[string]any, version string) { firstObject(value, "records")["packVersion"] = version }},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted := cloneObject(t, instances[test.schema])
			test.set(accepted, valid)
			if err := schemas[test.schema].Validate(accepted); err != nil {
				t.Fatalf("schema rejected 128-character SemVer: %v", err)
			}
			rejected := cloneObject(t, instances[test.schema])
			test.set(rejected, invalid)
			if err := schemas[test.schema].Validate(rejected); err == nil {
				t.Fatal("schema accepted 129-character SemVer")
			}
		})
	}
}

func TestReviewSchemasEnforceNumericIdentityBoundaries(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()

	t.Run("database ID", func(t *testing.T) {
		for _, value := range []int64{1, 9007199254740991} {
			instance := cloneObject(t, instances["review-packet-v1alpha1.json"])
			instance["preparation"].(map[string]any)["preparer"].(map[string]any)["databaseId"] = value
			if err := schemas["review-packet-v1alpha1.json"].Validate(instance); err != nil {
				t.Fatalf("accepted database ID %d rejected: %v", value, err)
			}
		}
		instance := cloneObject(t, instances["review-packet-v1alpha1.json"])
		instance["preparation"].(map[string]any)["preparer"].(map[string]any)["databaseId"] = int64(9007199254740992)
		if err := schemas["review-packet-v1alpha1.json"].Validate(instance); err == nil {
			t.Fatal("schema accepted a non-JSON-safe database ID")
		}
	})

	t.Run("pull request number", func(t *testing.T) {
		for _, value := range []int64{1, 2147483647} {
			instance := cloneObject(t, instances["review-approval-v1alpha1.json"])
			reference := instance["platformReview"].(map[string]any)
			reference["pullRequestNumber"] = value
			reference["reviewUrl"] = "https://github.com/example/project/pull/" + fmt.Sprint(value) + "#pullrequestreview-41"
			if err := schemas["review-approval-v1alpha1.json"].Validate(instance); err != nil {
				t.Fatalf("accepted pull request number %d rejected: %v", value, err)
			}
		}
		instance := cloneObject(t, instances["review-approval-v1alpha1.json"])
		instance["platformReview"].(map[string]any)["pullRequestNumber"] = int64(2147483648)
		if err := schemas["review-approval-v1alpha1.json"].Validate(instance); err == nil {
			t.Fatal("schema accepted pull request number above the bound")
		}
	})

	t.Run("workflow run ID and attempt", func(t *testing.T) {
		for _, runID := range []int64{1, 9007199254740991} {
			instance := cloneObject(t, instances["platform-approval-snapshot-v1alpha1.json"])
			instance["workflowRunId"] = runID
			instance["workflowRunUrl"] = "https://github.com/example/project/actions/runs/" + fmt.Sprint(runID)
			if err := schemas["platform-approval-snapshot-v1alpha1.json"].Validate(instance); err != nil {
				t.Fatalf("accepted workflow run ID %d rejected: %v", runID, err)
			}
		}
		for _, attempt := range []int64{1, 10000} {
			instance := cloneObject(t, instances["platform-approval-snapshot-v1alpha1.json"])
			instance["workflowRunAttempt"] = attempt
			if err := schemas["platform-approval-snapshot-v1alpha1.json"].Validate(instance); err != nil {
				t.Fatalf("accepted workflow attempt %d rejected: %v", attempt, err)
			}
		}
		for field, invalid := range map[string]int64{"workflowRunId": 9007199254740992, "workflowRunAttempt": 10001} {
			instance := cloneObject(t, instances["platform-approval-snapshot-v1alpha1.json"])
			instance[field] = invalid
			if err := schemas["platform-approval-snapshot-v1alpha1.json"].Validate(instance); err == nil {
				t.Fatalf("schema accepted %s above its bound", field)
			}
		}
	})
}

func TestPlatformSnapshotSchemaCorrelatesAccountAndDismissalState(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["platform-approval-snapshot-v1alpha1.json"]
	base := validReviewSchemaInstances()["platform-approval-snapshot-v1alpha1.json"]
	for _, test := range []struct {
		name      string
		login     string
		account   string
		state     string
		dismissed bool
		valid     bool
	}{
		{"human", "schema-reviewer", "User", "APPROVED", false, true},
		{"bot metadata", "schema-automation[bot]", "Bot", "COMMENTED", false, true},
		{"dismissed", "schema-reviewer", "User", "DISMISSED", true, true},
		{"bot missing suffix", "schema-automation", "Bot", "COMMENTED", false, false},
		{"non-bot with suffix", "schema-automation[bot]", "Organization", "COMMENTED", false, false},
		{"dismissed state false", "schema-reviewer", "User", "DISMISSED", false, false},
		{"approved dismissed true", "schema-reviewer", "User", "APPROVED", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance := cloneObject(t, base)
			approval := firstObject(instance, "approvals")
			approval["reviewer"].(map[string]any)["login"] = test.login
			approval["accountType"] = test.account
			approval["state"] = test.state
			approval["dismissed"] = test.dismissed
			err := schema.Validate(instance)
			if test.valid && err != nil {
				t.Fatalf("schema rejected valid platform relation: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("schema accepted inconsistent platform relation")
			}
		})
	}
}

func TestReviewSchemasExcludeSelfReferentialAuthorityFields(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	instances := validReviewSchemaInstances()
	tests := []struct {
		name  string
		field string
		value any
	}{
		{"review-packet-v1alpha1.json", "status", "reviewed"},
		{"review-packet-v1alpha1.json", "candidateCommit", strings.Repeat("b", 40)},
		{"review-approval-v1alpha1.json", "certifiesIndependence", true},
		{"platform-approval-snapshot-v1alpha1.json", "selfCertifying", true},
		{"review-promotion-v1alpha1.json", "promotionContentCommit", strings.Repeat("c", 40)},
		{"review-promotion-v1alpha1.json", "reviewRecordManifestSha256", strings.Repeat("d", 64)},
		{"review-registry-v1alpha1.json", "containingCommit", strings.Repeat("e", 40)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name+"/"+test.field, func(t *testing.T) {
			value := cloneObject(t, instances[test.name])
			value[test.field] = test.value
			if err := schemas[test.name].Validate(value); err == nil {
				t.Fatalf("schema accepted forbidden authority field %q", test.field)
			}
		})
	}
}

func TestReviewPolicySchemaFixesAcceptedProfileFloors(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-policy-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-policy-v1alpha1.json"]
	for _, test := range []struct {
		name   string
		mutate func([]any)
	}{
		{"one maintainer", func(profiles []any) {
			profiles[0].(map[string]any)["minimumMaintainers"] = float64(1)
		}},
		{"one Trivy outside reviewer", func(profiles []any) {
			profiles[1].(map[string]any)["minimumOutsideReviewers"] = float64(1)
		}},
		{"Trivy outside scope omitted", func(profiles []any) {
			profiles[1].(map[string]any)["requiredOutsideScopes"] = []any{"component-namespace", "ioc-extraction"}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, base)
			test.mutate(value["profiles"].([]any))
			if err := schema.Validate(value); err == nil {
				t.Fatal("schema accepted a weakened review-policy floor")
			}
		})
	}
}

func TestConflictSchemaBindsResolvedSelectionOnly(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-conflicts-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-conflicts-v1alpha1.json"]

	resolved := cloneObject(t, base)
	conflict := firstObject(resolved, "conflicts")
	conflict["disposition"] = "resolved"
	conflict["selectedClaimId"] = "claim.title"
	conflict["selectedSourceIds"] = []any{"source.one"}
	if err := schema.Validate(resolved); err != nil {
		t.Fatalf("schema rejected a resolved conflict with an explicit selection: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"resolved missing selected claim", func(value map[string]any) {
			row := firstObject(value, "conflicts")
			row["disposition"] = "resolved"
			row["selectedSourceIds"] = []any{"source.one"}
		}},
		{"resolved empty selected sources", func(value map[string]any) {
			row := firstObject(value, "conflicts")
			row["disposition"] = "resolved"
			row["selectedClaimId"] = "claim.title"
			row["selectedSourceIds"] = []any{}
		}},
		{"unresolved carries a selection", func(value map[string]any) {
			row := firstObject(value, "conflicts")
			row["selectedClaimId"] = "claim.title"
			row["selectedSourceIds"] = []any{"source.one"}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, base)
			test.mutate(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("schema accepted a conflict with an incomplete or inapplicable selection")
			}
		})
	}
}

func TestExpectedFindingsSchemaUsesCanonicalFindingVocabulary(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../schema/review-common-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	defs := document["$defs"].(map[string]any)
	states := stringEnum(t, defs["findingState"])
	wantStates := make([]string, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		wantStates = append(wantStates, string(state))
	}
	if !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("finding states = %v, want canonical model %v", states, wantStates)
	}
	provenance := stringEnum(t, defs["provenanceLevel"])
	wantProvenance := make([]string, 0, len(model.ProvenanceLevels()))
	for _, level := range model.ProvenanceLevels() {
		wantProvenance = append(wantProvenance, string(level))
	}
	if !reflect.DeepEqual(provenance, wantProvenance) {
		t.Fatalf("provenance levels = %v, want canonical model %v", provenance, wantProvenance)
	}
}

func TestExpectedFindingsSchemaRejectsMalformedOracleRows(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-expected-findings-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-expected-findings-v1alpha1.json"]

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"empty expected rows", func(value map[string]any) { value["findings"] = []any{} }},
		{"empty forbidden rows", func(value map[string]any) { value["forbidden"] = []any{} }},
		{"nonpositive run ID", func(value map[string]any) { firstObject(value, "findings")["runId"] = int64(0) }},
		{"traversing workflow path", func(value map[string]any) {
			firstObject(value, "findings")["workflow"] = ".github/workflows/../synthetic.yml"
		}},
		{"noncanonical state", func(value map[string]any) { firstObject(value, "findings")["state"] = "EXECUTED" }},
		{"noncanonical provenance", func(value map[string]any) { firstObject(value, "findings")["provenance"] = "CERTAIN" }},
		{"missing evidence and gap", func(value map[string]any) {
			row := firstObject(value, "findings")
			row["evidenceIds"] = []any{}
			row["evidenceGapCodes"] = []any{}
		}},
		{"missing coverage array", func(value map[string]any) { delete(firstObject(value, "findings"), "coverageAssessmentIds") }},
		{"duplicate evidence", func(value map[string]any) {
			id := "ev1:" + strings.Repeat("e", 64)
			firstObject(value, "findings")["evidenceIds"] = []any{id, id}
		}},
		{"unsafe evidence-gap code", func(value map[string]any) {
			firstObject(value, "findings")["evidenceGapCodes"] = []any{"NUL"}
		}},
		{"unsafe forbidden rationale", func(value map[string]any) {
			firstObject(value, "forbidden")["rationale"] = "synthetic <script>"
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, base)
			test.mutate(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("schema accepted malformed expected-findings oracle")
			}
		})
	}
}

func TestExpectedFindingsSchemaSupportsRepositoryScopeAndRejectsBrokenHierarchy(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-expected-findings-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-expected-findings-v1alpha1.json"]

	repositoryScope := cloneObject(t, base)
	finding := firstObject(repositoryScope, "findings")
	delete(finding, "runId")
	delete(finding, "runAttempt")
	delete(finding, "jobId")
	delete(finding, "stepIdentity")
	delete(finding, "workflow")
	finding["state"] = "CURRENT_REFERENCE_ONLY"
	finding["provenance"] = "L1_POSSIBLE"
	finding["evidenceIds"] = []any{}
	if err := schema.Validate(repositoryScope); err != nil {
		t.Fatalf("schema rejected a repository-scope expected finding: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"run attempt without run", func(row map[string]any) {
			delete(row, "runId")
			delete(row, "jobId")
			delete(row, "stepIdentity")
		}},
		{"job without run attempt", func(row map[string]any) {
			delete(row, "runAttempt")
			delete(row, "stepIdentity")
		}},
		{"step without job", func(row map[string]any) {
			delete(row, "jobId")
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, base)
			test.mutate(firstObject(value, "findings"))
			if err := schema.Validate(value); err == nil {
				t.Fatal("schema accepted a broken expected-finding execution hierarchy")
			}
		})
	}
}

func TestExpectedFindingsSchemaMatchesConservativeWorkflowSyntax(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-expected-findings-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-expected-findings-v1alpha1.json"]
	for _, workflow := range []string{
		".github/workflows/a.yml",
		".github/workflows/dir/build+test_1-2.yaml",
	} {
		instance := cloneObject(t, base)
		firstObject(instance, "findings")["workflow"] = workflow
		if err := schema.Validate(instance); err != nil {
			t.Errorf("schema rejected valid workflow %q: %v", workflow, err)
		}
	}
	for _, workflow := range []string{
		".github/workflows/.hidden.yml",
		".github/workflows/café.yml",
		".github/workflows/a b.yml",
		".github/workflows/../outside.yml",
		".github/workflows/a\\b.yml",
		".github/workflows/" + strings.Repeat("a", 4096) + ".yml",
	} {
		instance := cloneObject(t, base)
		firstObject(instance, "findings")["workflow"] = workflow
		if err := schema.Validate(instance); err == nil {
			t.Errorf("schema accepted non-conservative workflow %q", workflow)
		}
	}
}

func TestConflictSchemaRequiresAffectedClaim(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-conflicts-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-conflicts-v1alpha1.json"]
	if err := schema.Validate(base); err != nil {
		t.Fatalf("schema rejected one-claim conflict: %v", err)
	}
	instance := cloneObject(t, base)
	firstObject(instance, "conflicts")["claimIds"] = []any{}
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted conflict without an affected claim")
	}
}

func TestReviewApprovalSchemaCapsCheckedSourceObjects(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-approval-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-approval-v1alpha1.json"]
	objects := func(count int) []any {
		result := make([]any, count)
		for index := range result {
			result[index] = map[string]any{"sourceId": fmt.Sprintf("source-%04d", index), "sha256": strings.Repeat("a", 64)}
		}
		return result
	}
	instance := cloneObject(t, base)
	instance["sourceObjectsChecked"] = objects(2000)
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema rejected 2000 source objects: %v", err)
	}
	instance["sourceObjectsChecked"] = objects(2001)
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted 2001 source objects")
	}
}

func TestPromotionAndRegistrySchemasEnforceApprovalBoundaries(t *testing.T) {
	t.Parallel()
	schemas := compileReviewSchemas(t)
	promotionBase := validReviewSchemaInstances()["review-promotion-v1alpha1.json"]
	approvalIDs := func(count int) []any {
		result := make([]any, count)
		for index := range result {
			result[index] = fmt.Sprintf("approval-%03d", index)
		}
		return result
	}

	for _, test := range []struct {
		name      string
		profile   string
		count     int
		wantValid bool
	}{
		{"standard two", "standard-v0.2", 2, false},
		{"standard three", "standard-v0.2", 3, true},
		{"Trivy three", "trivy-v0.2", 3, false},
		{"Trivy four", "trivy-v0.2", 4, true},
		{"one hundred", "standard-v0.2", 100, true},
		{"one hundred one", "standard-v0.2", 101, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			promotion := cloneObject(t, promotionBase)
			promotion["reviewPolicyProfile"] = test.profile
			promotion["approvalIds"] = approvalIDs(test.count)
			promotionErr := schemas["review-promotion-v1alpha1.json"].Validate(promotion)
			registry := map[string]any{
				"schemaVersion": "cirewind.review-registry/v1alpha1",
				"records":       []any{reviewedRegistrySchemaRecord(test.profile, approvalIDs(test.count))},
			}
			registryErr := schemas["review-registry-v1alpha1.json"].Validate(registry)
			if test.wantValid {
				if promotionErr != nil {
					t.Fatalf("promotion schema rejected valid boundary: %v", promotionErr)
				}
				if registryErr != nil {
					t.Fatalf("registry schema rejected valid boundary: %v", registryErr)
				}
				return
			}
			if promotionErr == nil {
				t.Fatal("promotion schema accepted invalid approval count")
			}
			if registryErr == nil {
				t.Fatal("registry schema accepted invalid approval count")
			}
		})
	}

	withdrawn := reviewedRegistrySchemaRecord("standard-v0.2", []any{})
	withdrawn["status"] = "withdrawn"
	delete(withdrawn, "promotionContentCommit")
	delete(withdrawn, "reviewedPath")
	delete(withdrawn, "reviewRecordManifestSha256")
	withdrawn["withdrawalReason"] = "Synthetic pre-promotion withdrawal."
	registry := map[string]any{"schemaVersion": "cirewind.review-registry/v1alpha1", "records": []any{withdrawn}}
	if err := schemas["review-registry-v1alpha1.json"].Validate(registry); err != nil {
		t.Fatalf("schema rejected pre-promotion withdrawal without approvals: %v", err)
	}
	withdrawn["approvalIds"] = []any{"approval-001"}
	if err := schemas["review-registry-v1alpha1.json"].Validate(registry); err == nil {
		t.Fatal("schema accepted pre-promotion withdrawal with an approval identity")
	}
	for _, field := range []string{"reviewedPath", "reviewRecordManifestSha256", "supersedesPackVersion", "supersededByPackVersion"} {
		withdrawn = reviewedRegistrySchemaRecord("standard-v0.2", []any{})
		withdrawn["status"] = "withdrawn"
		delete(withdrawn, "promotionContentCommit")
		delete(withdrawn, "reviewedPath")
		delete(withdrawn, "reviewRecordManifestSha256")
		withdrawn["withdrawalReason"] = "Synthetic pre-promotion withdrawal."
		switch field {
		case "reviewedPath":
			withdrawn[field] = "incidents/reviewed/CIR-SYNTHETIC/1.0.0.yaml"
		case "reviewRecordManifestSha256":
			withdrawn[field] = strings.Repeat("a", 64)
		default:
			withdrawn[field] = "0.9.0"
		}
		registry = map[string]any{"schemaVersion": "cirewind.review-registry/v1alpha1", "records": []any{withdrawn}}
		if err := schemas["review-registry-v1alpha1.json"].Validate(registry); err == nil {
			t.Fatalf("schema accepted pre-promotion withdrawal field %s", field)
		}
	}
}

func TestReviewFixtureIndexSchemaConstrainsLocalScenarioSnapshots(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-fixture-index-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-fixture-index-v1alpha1.json"]

	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"empty index", func(value map[string]any) { value["scenarios"] = []any{} }},
		{"path traversal", func(value map[string]any) {
			firstObject(value, "scenarios")["snapshotPath"] = "scenarios/../archive-snapshot.json"
		}},
		{"wrong snapshot filename", func(value map[string]any) {
			firstObject(value, "scenarios")["snapshotPath"] = "scenarios/scenario.synthetic-gap/snapshot.json"
		}},
		{"reserved scenario directory", func(value map[string]any) {
			firstObject(value, "scenarios")["snapshotPath"] = "scenarios/CON.synthetic/archive-snapshot.json"
		}},
		{"noncanonical analysis time", func(value map[string]any) {
			firstObject(value, "scenarios")["analysisTime"] = "2026-08-30T12:00:00.000Z"
		}},
		{"duplicate row", func(value map[string]any) {
			row := firstObject(value, "scenarios")
			value["scenarios"] = []any{row, row}
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			value := cloneObject(t, base)
			test.mutate(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("schema accepted an invalid review fixture index")
			}
		})
	}
}

func TestCandidateValidationSchemaOnlyAcceptsPassingBoundResult(t *testing.T) {
	t.Parallel()
	schema := compileReviewSchemas(t)["review-validation-v1alpha1.json"]
	base := validReviewSchemaInstances()["review-validation-v1alpha1.json"]

	value := cloneObject(t, base)
	value["result"] = "fail"
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted a non-passing candidate validation result")
	}

	value = cloneObject(t, base)
	delete(value, "expectedFindingsSha256")
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted a validation result without its oracle binding")
	}
}

func compileReviewSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})

	for _, name := range reviewSchemaFiles {
		data, err := os.ReadFile("../../schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var header map[string]any
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatalf("decode schema %s: %v", name, err)
		}
		if got := header["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("schema %s draft = %v", name, got)
		}
		if got := header["$id"]; got != name {
			t.Fatalf("schema %s $id = %v, want relative filename", name, got)
		}
		assertRelativeRefs(t, name, header)
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode schema resource %s: %v", name, err)
		}
		if err := compiler.AddResource(reviewSchemaBase+name, document); err != nil {
			t.Fatalf("add schema resource %s: %v", name, err)
		}
	}

	compiled := make(map[string]*jsonschema.Schema, len(reviewSchemaFiles)-1)
	for _, name := range reviewSchemaFiles {
		schema, err := compiler.Compile(reviewSchemaBase + name)
		if err != nil {
			t.Fatalf("compile schema %s: %v", name, err)
		}
		if name != "review-common-v1alpha1.json" {
			compiled[name] = schema
		}
	}
	for name, instance := range validReviewSchemaInstances() {
		if err := compiled[name].Validate(instance); err != nil {
			t.Fatalf("valid %s fixture rejected: %v", name, err)
		}
	}
	return compiled
}

func assertRelativeRefs(t *testing.T, name string, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "$ref" {
				ref, ok := child.(string)
				if !ok || strings.Contains(ref, "://") || strings.HasPrefix(ref, "/") {
					t.Fatalf("schema %s contains non-local $ref %v", name, child)
				}
			}
			assertRelativeRefs(t, name, child)
		}
	case []any:
		for _, child := range typed {
			assertRelativeRefs(t, name, child)
		}
	}
}

func validReviewSchemaInstances() map[string]map[string]any {
	hash := strings.Repeat("a", 64)
	candidateCommit := strings.Repeat("b", 40)
	identity := func(login string, id int64) map[string]any {
		return map[string]any{"login": login, "databaseId": id}
	}
	bindings := map[string]any{
		"candidateManifestSha256": hash,
		"originalPackSha256":      hash,
		"canonicalPackSha256":     hash,
		"claimsSha256":            hash,
		"sourcesSha256":           hash,
		"conflictsSha256":         hash,
		"fixtureManifestSha256":   hash,
		"validatorPolicySha256":   hash,
		"reviewPolicySha256":      hash,
	}

	return map[string]map[string]any{
		"review-policy-v1alpha1.json": {
			"schemaVersion":      "cirewind.review-policy/v1alpha1",
			"policyVersion":      "synthetic-v0.2",
			"officialRepository": "example/project",
			"eligibleMaintainers": []any{
				identity("schema-maintainer", 10),
				identity("schema-maintainer-two", 11),
			},
			"profiles": []any{
				map[string]any{
					"profileId":                 "standard-v0.2",
					"minimumMaintainers":        int64(2),
					"minimumOutsideReviewers":   int64(1),
					"requiredAnyApprovalScopes": []any{"hostile-input-privacy", "identity"},
					"requiredOutsideScopes":     []any{},
				},
				map[string]any{
					"profileId":                 "trivy-v0.2",
					"minimumMaintainers":        int64(2),
					"minimumOutsideReviewers":   int64(2),
					"requiredAnyApprovalScopes": []any{"hostile-input-privacy", "identity"},
					"requiredOutsideScopes":     []any{"component-namespace", "ioc-extraction", "time"},
				},
			},
		},
		"review-packet-v1alpha1.json": {
			"schemaVersion":          "cirewind.review-packet/v1alpha1",
			"incidentId":             "synthetic-schema-only",
			"packVersion":            "1.0.0",
			"reviewUnitPackPath":     "pack.yaml",
			"originalPackSha256":     hash,
			"canonicalPackSha256":    hash,
			"packSchemaVersion":      "cirewind.dev/v1alpha1",
			"validatorVersion":       "schema-test-v1",
			"validatorPolicySha256":  hash,
			"claimsSha256":           hash,
			"sourcesSha256":          hash,
			"conflictsSha256":        hash,
			"expectedFindingsSha256": hash,
			"fixtureManifestSha256":  hash,
			"conflictIds":            []any{},
			"reviewPolicyProfile":    "standard-v0.2",
			"reviewPolicySha256":     hash,
			"preparation": map[string]any{
				"preparer":           identity("schema-preparer", 1),
				"authors":            []any{identity("schema-preparer", 1)},
				"sourceTranscribers": []any{identity("schema-transcriber", 2)},
			},
		},
		"review-sources-v1alpha1.json": {
			"schemaVersion": "cirewind.review-sources/v1alpha1",
			"sources": []any{map[string]any{
				"sourceId":                 "source.primary",
				"sourceClass":              "maintainer-advisory",
				"publisher":                "Synthetic Maintainer",
				"title":                    "Synthetic incident advisory",
				"locator":                  "https://example.invalid/advisory",
				"statedPrecision":          "day",
				"retrievedAt":              "2026-08-30T12:00:00Z",
				"mediaType":                "text/plain",
				"reviewedByteLength":       int64(100),
				"reviewedSha256":           hash,
				"notRedistributedReason":   "Synthetic schema fixture; bytes are unnecessary.",
				"redistributionAssessment": "metadata-only",
				"conflictIds":              []any{},
			}},
		},
		"review-claims-v1alpha1.json": {
			"schemaVersion": "cirewind.review-claims/v1alpha1",
			"claims": []any{map[string]any{
				"claimId":          "claim.title",
				"canonicalPointer": "/metadata/title",
				"semanticSelector": "incident:metadata/field:title",
				"normalizedValue":  "Synthetic incident",
				"semanticRole":     "other",
				"sourceIds":        []any{"source.primary"},
				"sourceLocations": []any{map[string]any{
					"sourceId": "source.primary",
					"location": "section:summary",
				}},
				"transformation": "verbatim",
				"conflictIds":    []any{},
				"authorAssessment": map[string]any{
					"decision":  "inclusion",
					"rationale": "Synthetic schema coverage value.",
				},
			}},
		},
		"review-conflicts-v1alpha1.json": {
			"schemaVersion": "cirewind.review-conflicts/v1alpha1",
			"conflicts": []any{map[string]any{
				"conflictId":         "conflict.synthetic",
				"claimIds":           []any{"claim.title"},
				"competingSourceIds": []any{"source.one", "source.two"},
				"description":        "Synthetic sources disagree for schema coverage.",
				"materiality":        "context-only",
				"disposition":        "excluded",
				"rationale":          "The synthetic disputed value is omitted.",
			}},
		},
		"review-validation-v1alpha1.json": {
			"schemaVersion":          "cirewind.review-validation/v1alpha1",
			"incidentId":             "synthetic-schema-only",
			"packVersion":            "1.0.0",
			"originalPackSha256":     hash,
			"canonicalPackSha256":    hash,
			"validatorVersion":       "schema-test-v1",
			"validatorPolicySha256":  hash,
			"expectedFindingsSha256": hash,
			"fixtureManifestSha256":  hash,
			"result":                 "pass",
		},
		"review-expected-findings-v1alpha1.json": {
			"schemaVersion": "cirewind.review-expected-findings/v1alpha1",
			"findings": []any{map[string]any{
				"scenarioId":   "scenario.synthetic-gap",
				"indicatorId":  "indicator.synthetic",
				"repository":   "example/project",
				"workflow":     ".github/workflows/synthetic.yml",
				"runId":        int64(1),
				"runAttempt":   int64(1),
				"jobId":        int64(1),
				"stepIdentity": "synthetic-step-1",
				"state":        "UNKNOWN_EVIDENCE_GAP",
				"provenance":   "L0_UNKNOWN",
				"evidenceIds":  []any{"ev1:" + strings.Repeat("e", 64)},
				"coverageAssessmentIds": []any{
					"cova1:" + strings.Repeat("c", 64),
				},
				"evidenceGapCodes": []any{"SYNTHETIC_LOG_GAP"},
			}},
			"forbidden": []any{map[string]any{
				"scenarioId": "scenario.synthetic-gap",
				"state":      "CONFIRMED_EXECUTED",
				"rationale":  "Missing synthetic evidence must not become confirmed execution.",
			}},
		},
		"review-fixture-index-v1alpha1.json": {
			"schemaVersion": "cirewind.review-fixture-index/v1alpha1",
			"scenarios": []any{map[string]any{
				"scenarioId":   "scenario.synthetic-gap",
				"snapshotPath": "scenarios/scenario.synthetic-gap/archive-snapshot.json",
				"analysisTime": "2026-08-30T12:00:00Z",
			}},
		},
		"review-approval-v1alpha1.json": {
			"schemaVersion":      "cirewind.review-approval/v1alpha1",
			"reviewId":           "review.synthetic",
			"reviewer":           identity("schema-reviewer", 3),
			"declaredRole":       "maintainer",
			"independent":        false,
			"conflictDisclosure": "Synthetic schema fixture; no review is asserted.",
			"incidentId":         "synthetic-schema-only",
			"packVersion":        "1.0.0",
			"candidateCommit":    candidateCommit,
			"bindings":           bindings,
			"platformReview": map[string]any{
				"repository":        "example/project",
				"pullRequestNumber": int64(7),
				"reviewUrl":         "https://github.com/example/project/pull/7#pullrequestreview-41",
				"reviewDatabaseId":  int64(41),
				"assertionSha256":   hash,
				"bodySha256":        hash,
			},
			"scopes": []any{"identity"},
			"commands": []any{map[string]any{
				"tool": "cirewind", "version": "schema-test-v1", "arguments": []any{"pack", "validate"},
			}},
			"sourceObjectsChecked": []any{map[string]any{"sourceId": "source.primary", "sha256": hash}},
			"decision":             "abstain",
			"reviewedAt":           "2026-08-30T12:01:00Z",
			"rationale":            "Synthetic schema fixture; this is not an approval.",
			"knownLimitations":     []any{"No factual review is represented."},
		},
		"review-assertion-v1alpha1.json": {
			"schemaVersion":      "cirewind.review-assertion/v1alpha1",
			"reviewId":           "review.synthetic",
			"reviewer":           identity("schema-reviewer", 3),
			"declaredRole":       "maintainer",
			"independent":        false,
			"conflictDisclosure": "Synthetic schema fixture; no review is asserted.",
			"incidentId":         "synthetic-schema-only",
			"packVersion":        "1.0.0",
			"candidateCommit":    candidateCommit,
			"bindings":           bindings,
			"repository":         "example/project",
			"pullRequestNumber":  int64(7),
			"scopes":             []any{"identity"},
			"commands": []any{map[string]any{
				"tool": "cirewind", "version": "schema-test-v1", "arguments": []any{"pack", "validate"},
			}},
			"sourceObjectsChecked": []any{map[string]any{"sourceId": "source.primary", "sha256": hash}},
			"decision":             "abstain",
			"rationale":            "Synthetic schema fixture; this is not an approval.",
			"knownLimitations":     []any{"No factual review is represented."},
		},
		"platform-approval-snapshot-v1alpha1.json": {
			"schemaVersion":        "cirewind.platform-approval-snapshot/v1alpha1",
			"repository":           "example/project",
			"pullRequestNumber":    int64(7),
			"candidateCommit":      candidateCommit,
			"observedAt":           "2026-08-30T12:02:00Z",
			"observationSource":    "github-rest-api",
			"workflowSourceCommit": candidateCommit,
			"workflowRunUrl":       "https://github.com/example/project/actions/runs/9",
			"workflowRunId":        int64(9),
			"workflowRunAttempt":   int64(1),
			"responseSha256":       hash,
			"approvals": []any{map[string]any{
				"reviewDatabaseId": int64(41),
				"reviewUrl":        "https://github.com/example/project/pull/7#pullrequestreview-41",
				"reviewer":         identity("schema-reviewer", 3),
				"accountType":      "User",
				"state":            "COMMENTED",
				"commitId":         candidateCommit,
				"submittedAt":      "2026-08-30T12:01:00Z",
				"bodySha256":       hash,
				"dismissed":        false,
			}},
		},
		"review-promotion-v1alpha1.json": {
			"schemaVersion":           "cirewind.review-promotion/v1alpha1",
			"incidentId":              "synthetic-schema-only",
			"packVersion":             "1.0.0",
			"status":                  "reviewed",
			"candidateCommit":         candidateCommit,
			"candidateManifestSha256": hash,
			"originalPackSha256":      hash,
			"canonicalPackSha256":     hash,
			"reviewedPath":            "incidents/reviewed/synthetic-schema-only/1.0.0.yaml",
			"approvalIds":             []any{"review.synthetic-one", "review.synthetic-three", "review.synthetic-two"},
			"platformSnapshotSha256":  hash,
			"reviewPolicyProfile":     "standard-v0.2",
			"reviewPolicySha256":      hash,
			"promotedAt":              "2026-08-30T12:03:00Z",
		},
		"review-registry-v1alpha1.json": {
			"schemaVersion": "cirewind.review-registry/v1alpha1",
			"records": []any{map[string]any{
				"recordId":    "record.synthetic-research",
				"incidentId":  "synthetic-schema-only",
				"packVersion": "1.0.0",
				"status":      "research",
				"approvalIds": []any{},
				"recordedAt":  "2026-08-30T12:00:00Z",
			}},
		},
	}
}

func cloneObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func firstObject(value map[string]any, field string) map[string]any {
	return value[field].([]any)[0].(map[string]any)
}

func reviewedRegistrySchemaRecord(profile string, approvalIDs []any) map[string]any {
	hash := strings.Repeat("a", 64)
	return map[string]any{
		"recordId":                   "record-synthetic-reviewed",
		"incidentId":                 "synthetic-schema-only",
		"packVersion":                "1.0.0",
		"status":                     "reviewed",
		"previousRecordId":           "record-synthetic-prior",
		"candidateCommit":            strings.Repeat("b", 40),
		"promotionContentCommit":     strings.Repeat("c", 40),
		"reviewedPath":               "incidents/reviewed/synthetic-schema-only/1.0.0.yaml",
		"originalPackSha256":         hash,
		"canonicalPackSha256":        hash,
		"candidateManifestSha256":    hash,
		"reviewRecordManifestSha256": hash,
		"approvalIds":                approvalIDs,
		"reviewPolicyProfile":        profile,
		"reviewPolicySha256":         hash,
		"recordedAt":                 "2026-08-30T12:00:00Z",
	}
}

func stringEnum(t *testing.T, value any) []string {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema definition is %T, want object", value)
	}
	items, ok := object["enum"].([]any)
	if !ok {
		t.Fatalf("schema enum is %T, want array", object["enum"])
	}
	result := make([]string, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("schema enum item is %T, want string", item)
		}
		result[index] = text
	}
	return result
}
