package acceptance_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type actionPinLedger struct {
	SchemaVersion      int         `json:"schemaVersion"`
	RetrievedAt        string      `json:"retrievedAt"`
	VerificationMethod string      `json:"verificationMethod"`
	Actions            []actionPin `json:"actions"`
}

type actionPin struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
	Source     string `json:"source"`
}

type workflowDocument struct {
	On          map[string]any         `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Env         map[string]string      `yaml:"env"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Needs       any               `yaml:"needs"`
	Environment any               `yaml:"environment"`
	RunsOn      string            `yaml:"runs-on"`
	Permissions map[string]string `yaml:"permissions"`
	Outputs     map[string]string `yaml:"outputs"`
	Env         map[string]string `yaml:"env"`
	Strategy    workflowStrategy  `yaml:"strategy"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStrategy struct {
	Matrix workflowMatrix `yaml:"matrix"`
}

type workflowMatrix struct {
	Include []workflowMatrixEntry `yaml:"include"`
}

type workflowMatrixEntry struct {
	Name   string `yaml:"name"`
	Runner string `yaml:"runner"`
}

type workflowStep struct {
	Name  string            `yaml:"name"`
	ID    string            `yaml:"id"`
	If    string            `yaml:"if"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env"`
	With  map[string]any    `yaml:"with"`
}

func decodeWorkflow(t *testing.T, relative string) workflowDocument {
	t.Helper()
	data := readRepositoryFile(t, relative)
	nodeDecoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := nodeDecoder.Decode(&document); err != nil {
		t.Fatalf("decode %s syntax tree: %v", relative, err)
	}
	var extra yaml.Node
	if err := nodeDecoder.Decode(&extra); err != io.EOF {
		t.Fatalf("%s must contain exactly one YAML document", relative)
	}
	assertNoDuplicateWorkflowKeys(t, &document, relative)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var workflow workflowDocument
	if err := decoder.Decode(&workflow); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	return workflow
}

func assertNoDuplicateWorkflowKeys(t *testing.T, node *yaml.Node, path string) {
	t.Helper()
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for index, child := range node.Content {
			assertNoDuplicateWorkflowKeys(t, child, path+"/"+strconv.Itoa(index))
		}
	case yaml.MappingNode:
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				t.Fatalf("%s contains a non-scalar workflow mapping key", path)
			}
			identity := key.Tag + "\x00" + key.Value
			if _, duplicate := seen[identity]; duplicate {
				t.Fatalf("%s contains duplicate YAML key %q at line %d", path, key.Value, key.Line)
			}
			seen[identity] = struct{}{}
			assertNoDuplicateWorkflowKeys(t, node.Content[index+1], path+"/"+key.Value)
		}
	}
}

func TestActionPinsCoverEveryWorkflowAction(t *testing.T) {
	var ledger actionPinLedger
	decoder := json.NewDecoder(bytes.NewReader(readRepositoryFile(t, ".github/actions-pins.json")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		t.Fatalf("decode action pin ledger: %v", err)
	}
	if ledger.SchemaVersion != 1 || ledger.RetrievedAt != "2026-09-03" || ledger.VerificationMethod == "" {
		t.Fatalf("action pin ledger metadata is incomplete: %+v", ledger)
	}

	commitPattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	pins := make(map[string]actionPin, len(ledger.Actions))
	for _, pin := range ledger.Actions {
		if !strings.HasPrefix(pin.Repository, "actions/") || pin.Source != "https://github.com/"+pin.Repository {
			t.Errorf("pin %q is not tied to its official actions repository", pin.Repository)
		}
		if !commitPattern.MatchString(pin.Commit) || !tagPattern.MatchString(pin.Tag) {
			t.Errorf("pin %q lacks an exact full commit and stable version tag", pin.Repository)
		}
		if _, duplicate := pins[pin.Repository]; duplicate {
			t.Fatalf("duplicate pin for %s", pin.Repository)
		}
		pins[pin.Repository] = pin
	}

	workflowPaths, err := filepath.Glob(filepath.Join(repositoryRoot(t), ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workflowPaths) == 0 {
		t.Fatal("no GitHub workflows found")
	}
	used := make(map[string]bool)
	usePattern := regexp.MustCompile(`^([^@]+)@([0-9a-f]{40})$`)
	for _, path := range workflowPaths {
		relative, err := filepath.Rel(repositoryRoot(t), path)
		if err != nil {
			t.Fatal(err)
		}
		workflow := decodeWorkflow(t, filepath.ToSlash(relative))
		for jobName, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if step.Uses == "" || strings.HasPrefix(step.Uses, "./") {
					continue
				}
				matches := usePattern.FindStringSubmatch(step.Uses)
				if matches == nil {
					t.Errorf("%s job %s has action not pinned by full commit: %q", relative, jobName, step.Uses)
					continue
				}
				pin, ok := pins[matches[1]]
				if !ok {
					t.Errorf("%s job %s uses %q without reviewed ledger entry", relative, jobName, matches[1])
					continue
				}
				if pin.Commit != matches[2] {
					t.Errorf("%s uses %s@%s, ledger requires %s", relative, matches[1], matches[2], pin.Commit)
				}
				used[matches[1]] = true
			}
		}
	}
	for repository := range pins {
		if !used[repository] {
			t.Errorf("action pin ledger contains unused entry %s", repository)
		}
	}
}

func TestReleaseWorkflowIsManualLeastPrivilegeAndOrdered(t *testing.T) {
	const path = ".github/workflows/release-candidate.yml"
	workflow := decodeWorkflow(t, path)
	if got := sortedKeys(workflow.On); !reflect.DeepEqual(got, []string{"workflow_dispatch"}) {
		t.Fatalf("release trigger must be workflow_dispatch only, got %v", got)
	}
	if len(workflow.Permissions) != 0 {
		t.Fatalf("release workflow must deny permissions by default, got %v", workflow.Permissions)
	}

	build := requiredWorkflowJob(t, workflow, "build")
	draft := requiredWorkflowJob(t, workflow, "draft")
	publish := requiredWorkflowJob(t, workflow, "publish")
	requirePermissions(t, "build", build.Permissions, map[string]string{
		"attestations": "write",
		"contents":     "read",
		"id-token":     "write",
	})
	requirePermissions(t, "draft", draft.Permissions, map[string]string{
		"actions":      "read",
		"attestations": "read",
		"contents":     "write",
	})
	requirePermissions(t, "publish", publish.Permissions, map[string]string{
		"actions":      "read",
		"attestations": "read",
		"contents":     "write",
	})
	if draft.Environment != "release-draft" || publish.Environment != "release-publish" {
		t.Fatalf("release write jobs must use distinct protected environments, got %q and %q", draft.Environment, publish.Environment)
	}
	if publish.If != "${{ inputs.publish }}" {
		t.Fatalf("publish job is not guarded by the explicit boolean input: %q", publish.If)
	}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/checkout@") {
				continue
			}
			if value, ok := step.With["persist-credentials"].(bool); !ok || value {
				t.Errorf("%s checkout must set persist-credentials: false", jobName)
			}
			if step.With["ref"] != "refs/tags/${{ inputs.tag }}" {
				t.Errorf("%s checkout is not constrained to the exact tag ref", jobName)
			}
		}
	}

	buildRun := joinedRun(build)
	for _, required := range []string{"GITHUB_REF", "refs/tags/$RELEASE_TAG", "GITHUB_SHA", "scripts/release.sh", "scripts/smoke-release.sh"} {
		if !strings.Contains(buildRun, required) {
			t.Errorf("build job lacks release constraint %q", required)
		}
	}
	if !strings.Contains(buildRun, `git show -s --format=%ct "$commit"`) {
		t.Fatal("build metadata timestamp is not bound to the already-validated commit")
	}
	attestIndex := stepIndex(build, "actions/attest@")
	uploadIndex := stepIndex(build, "actions/upload-artifact@")
	if attestIndex < 0 || uploadIndex < 0 || attestIndex >= uploadIndex {
		t.Fatal("exact subjects must be attested before their immutable artifact upload")
	}
	if build.Outputs["artifact-id"] != "${{ steps.upload.outputs.artifact-id }}" {
		t.Fatal("build job does not transfer the immutable upload artifact ID")
	}

	draftRun := joinedRun(draft)
	if !strings.Contains(draftRun, `verify-release-environment.sh "$GITHUB_REPOSITORY" release-draft "$GITHUB_REPOSITORY_OWNER"`) {
		t.Fatal("draft job does not fail closed on missing reviewer protection")
	}
	verifyIndex := strings.Index(draftRun, "verify-release-attestations.sh")
	createIndex := strings.Index(draftRun, "gh release create")
	if verifyIndex < 0 || createIndex < 0 || verifyIndex >= createIndex {
		t.Fatal("draft creation must occur only after exact attestation verification")
	}
	notesIndex := strings.Index(draftRun, "git tag --list")
	if notesIndex < 0 || notesIndex >= createIndex {
		t.Fatal("draft release notes must be derived from the verified annotated tag before release creation")
	}
	for _, required := range []string{
		`notes_file="$RUNNER_TEMP/release-notes.txt"`,
		`git tag --list "$RELEASE_TAG"`,
		`--format='%(contents:subject)%0a%0a%(contents:body)'`,
		`>"$notes_file"`,
		`grep -q '[^[:space:]]' "$notes_file"`,
	} {
		if !strings.Contains(draftRun, required) {
			t.Errorf("draft creation lacks safe explicit release-notes constraint %q", required)
		}
	}
	createEnd := strings.Index(draftRun[createIndex:], `--title "$RELEASE_TAG"`)
	if createEnd < 0 {
		t.Fatal("draft creation command lacks its explicit release title terminator")
	}
	createRun := draftRun[createIndex : createIndex+createEnd]
	for _, required := range []string{`--repo "$GITHUB_REPOSITORY"`, `--notes-file "$notes_file"`} {
		if !strings.Contains(createRun, required) {
			t.Errorf("gh release create lacks required scoped option %q", required)
		}
	}
	if strings.Contains(draftRun, "--notes-from-tag") {
		t.Fatal("draft creation uses the GitHub CLI-incompatible --notes-from-tag mode")
	}
	if !strings.Contains(draftRun, "compare-release-assets.sh") {
		t.Fatal("draft assets are not downloaded and byte-compared")
	}

	publishRun := joinedRun(publish)
	if !strings.Contains(publishRun, `verify-release-environment.sh "$GITHUB_REPOSITORY" release-publish "$GITHUB_REPOSITORY_OWNER"`) {
		t.Fatal("publish job does not fail closed on missing reviewer protection")
	}
	compareIndex := strings.Index(publishRun, "compare-release-assets.sh")
	publishIndex := strings.Index(publishRun, "gh release edit")
	if !strings.Contains(publishRun, "verify-release-attestations.sh") || compareIndex < 0 || publishIndex < 0 || compareIndex >= publishIndex {
		t.Fatal("publication must reverify provenance and exact draft bytes before publishing")
	}
	for name, run := range map[string]string{"draft": draftRun, "publish": publishRun} {
		if strings.Contains(run, "scripts/release.sh") || strings.Contains(run, "scripts/build-release.sh") {
			t.Errorf("%s job rebuilds release subjects instead of consuming the build artifact", name)
		}
	}
	if strings.Contains(buildRun, "gh release ") || strings.Contains(draftRun, "gh release edit") || strings.Contains(publishRun, "gh release create") {
		t.Fatal("release write authority is present in the wrong job")
	}
}

func TestReleaseTagNotesExtractionIsLiteralAndExcludesSignatures(t *testing.T) {
	repository := t.TempDir()
	emptyGlobalConfig := filepath.Join(t.TempDir(), "empty-gitconfig")
	if err := os.WriteFile(emptyGlobalConfig, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	gitEnvironment := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(strings.ToUpper(name), "GIT_") {
			continue
		}
		gitEnvironment = append(gitEnvironment, value)
	}
	gitEnvironment = append(gitEnvironment,
		"GIT_CONFIG_GLOBAL="+emptyGlobalConfig,
		"GIT_CONFIG_NOSYSTEM=1",
	)

	runGit := func(stdin string, arguments ...string) []byte {
		t.Helper()
		command := exec.Command("git", arguments...)
		command.Dir = repository
		command.Env = gitEnvironment
		if stdin != "" {
			command.Stdin = strings.NewReader(stdin)
		}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
		}
		return output
	}
	extract := func(tag string) []byte {
		t.Helper()
		return runGit("", "tag", "--list", tag, "--format=%(contents:subject)%0a%0a%(contents:body)")
	}

	runGit("", "init", "--quiet")
	runGit("", "config", "user.name", "CIRewind Test")
	runGit("", "config", "user.email", "test@example.invalid")
	runGit("", "config", "commit.gpgSign", "false")
	runGit("", "config", "tag.gpgSign", "false")
	runGit("", "commit", "--allow-empty", "--quiet", "--message", "initial")

	payload := "literal quotes ' \" and shell text $(touch cirewind-should-not-exist) `still-literal` <script>"
	runGit("", "tag", "--annotate", "v0.0.1", "--message", "Release subject", "--message", payload)
	want := "Release subject\n\n" + payload + "\n\n"
	if got := string(extract("v0.0.1")); got != want {
		t.Fatalf("literal tag notes = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(repository, "cirewind-should-not-exist")); !os.IsNotExist(err) {
		t.Fatalf("tag-message shell text was not inert: %v", err)
	}

	commit := strings.TrimSpace(string(runGit("", "rev-parse", "HEAD")))
	signedTag := strings.Join([]string{
		"object " + commit,
		"type commit",
		"tag v0.0.2",
		"tagger CIRewind Test <test@example.invalid> 0 +0000",
		"",
		"Signed subject",
		"",
		"Signed body",
		"-----BEGIN PGP SIGNATURE-----",
		"synthetic-signature-material",
		"-----END PGP SIGNATURE-----",
		"",
	}, "\n")
	tagObject := strings.TrimSpace(string(runGit(signedTag, "hash-object", "-t", "tag", "-w", "--stdin")))
	runGit("", "update-ref", "refs/tags/v0.0.2", tagObject)
	signedNotes := string(extract("v0.0.2"))
	if signedNotes != "Signed subject\n\nSigned body\n\n" || strings.Contains(signedNotes, "SIGNATURE") {
		t.Fatalf("signed tag notes did not exclude the signature: %q", signedNotes)
	}

	runGit("", "tag", "--annotate", "v0.0.3", "--message", "   ")
	if notes := extract("v0.0.3"); len(bytes.TrimSpace(notes)) != 0 {
		t.Fatalf("whitespace-only tag unexpectedly produced material notes: %q", notes)
	}
	if notes := extract("v9.9.9"); len(notes) != 0 {
		t.Fatalf("absent tag unexpectedly produced notes: %q", notes)
	}
}

func TestCIUsesExactSixTargetHostedRunnerMatrix(t *testing.T) {
	workflow := decodeWorkflow(t, ".github/workflows/ci.yml")
	testJob := requiredWorkflowJob(t, workflow, "test")
	if testJob.RunsOn != "${{ matrix.runner }}" {
		t.Fatalf("test job runs-on = %q, want matrix.runner", testJob.RunsOn)
	}
	want := []workflowMatrixEntry{
		{Name: "linux-amd64", Runner: "ubuntu-24.04"},
		{Name: "linux-arm64", Runner: "ubuntu-24.04-arm"},
		{Name: "darwin-amd64", Runner: "macos-15-intel"},
		{Name: "darwin-arm64", Runner: "macos-15"},
		{Name: "windows-amd64", Runner: "windows-2025"},
		{Name: "windows-arm64", Runner: "windows-11-arm"},
	}
	if !reflect.DeepEqual(testJob.Strategy.Matrix.Include, want) {
		t.Fatalf("CI test matrix = %#v, want exact supported matrix %#v", testJob.Strategy.Matrix.Include, want)
	}
}

func TestCIDarwinArm64RunsNativeDemoQualification(t *testing.T) {
	workflow := decodeWorkflow(t, ".github/workflows/ci.yml")
	testJob := requiredWorkflowJob(t, workflow, "test")
	var harnessTest, qualification *workflowStep
	for index := range testJob.Steps {
		step := &testJob.Steps[index]
		switch step.Name {
		case "Test native demo qualification harness":
			harnessTest = step
		case "Qualify native macOS 15 arm64 demo":
			qualification = step
		}
	}
	if harnessTest == nil {
		t.Fatal("CI omits the Linux-local demo qualification harness test")
	}
	if harnessTest.If != "matrix.name == 'linux-amd64'" || harnessTest.Run != "PYTHONDONTWRITEBYTECODE=1 python3 scripts/qualify_demo_test.py" {
		t.Fatalf("Linux-local harness test is not narrowly scoped: %+v", *harnessTest)
	}
	if qualification == nil {
		t.Fatal("CI omits native macOS 15 arm64 demo qualification")
	}
	if qualification.If != "matrix.name == 'darwin-arm64'" {
		t.Fatalf("native demo qualification condition = %q", qualification.If)
	}
	if strings.Contains(qualification.Run, `--binary "$GITHUB_WORKSPACE`) {
		t.Fatal("native demo qualification uses a binary inside the checkout")
	}
	for _, required := range []string{
		"python3 scripts/qualify_demo.py",
		`--source-root "$GITHUB_WORKSPACE"`,
		`--source-commit "$GITHUB_SHA"`,
		`--work-root "$RUNNER_TEMP/cirewind-demo-qualification"`,
		"--require-macos-major 15",
		"--require-machine arm64",
		"--require-homebrew",
	} {
		if !strings.Contains(qualification.Run, required) {
			t.Errorf("native demo qualification lacks %q", required)
		}
	}
}

func TestPackReviewSnapshotWorkflowKeepsAcquisitionNarrowAndTraceable(t *testing.T) {
	const path = ".github/workflows/pack-review-snapshot.yml"
	workflow := decodeWorkflow(t, path)
	if got := sortedKeys(workflow.On); !reflect.DeepEqual(got, []string{"workflow_dispatch"}) {
		t.Fatalf("snapshot workflow trigger = %v, want workflow_dispatch only", got)
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read", "pull-requests": "read"}) {
		t.Fatalf("snapshot workflow permissions are not the closed read-only set: %v", workflow.Permissions)
	}
	if workflow.Env["GOFLAGS"] != "-mod=readonly" {
		t.Fatalf("snapshot workflow must prohibit module-file mutation: %v", workflow.Env)
	}
	job := requiredWorkflowJob(t, workflow, "capture")
	if !strings.Contains(job.If, "github.event.repository.default_branch") {
		t.Fatalf("snapshot workflow is not gated to the selected default branch: %q", job.If)
	}
	buildIndex, captureIndex, normalizeIndex, uploadIndex := -1, -1, -1, -1
	for index, step := range job.Steps {
		switch step.Name {
		case "Check out governance tooling":
			if step.With["persist-credentials"] != false || step.With["ref"] != "${{ github.sha }}" {
				t.Fatalf("snapshot checkout is not exact and credential-free: %v", step.With)
			}
		case "Build tokenless normalizer before acquisition":
			buildIndex = index
			if !strings.Contains(step.Run, "go build -trimpath") {
				t.Fatalf("normalizer build step is missing the fixed build: %q", step.Run)
			}
		case "Verify pull-request head and capture projected review metadata":
			captureIndex = index
			if step.Env["GH_TOKEN"] != "${{ github.token }}" || strings.Contains(step.Run, "go run") || strings.Contains(step.Run, "--slurp") || strings.Count(step.Run, "reviews?per_page=100") != 1 || strings.Count(step.Run, "capture_reviews ") != 2 || !strings.Contains(step.Run, "body: .body") || !strings.Contains(step.Run, "head -c 8388609") || !strings.Contains(step.Run, "cmp -s") || strings.Count(step.Run, ".head.sha") != 2 {
				t.Fatalf("tokenful acquisition step is not the closed double-capture contract: env=%v run=%q", step.Env, step.Run)
			}
		case "Normalize without GitHub credentials":
			normalizeIndex = index
			if step.Env["GH_TOKEN"] != "" || !strings.Contains(step.Run, "jq -cs 'add'") || !strings.Contains(step.Run, `"$RUNNER_TEMP/cirewind-packreview" normalize-platform-approvals`) || !strings.Contains(step.Run, `--workflow-source-commit "$GITHUB_SHA"`) {
				t.Fatalf("normalization is not tokenless and source-bound: env=%v run=%q", step.Env, step.Run)
			}
		case "Transfer normalized snapshot by immutable artifact ID":
			uploadIndex = index
		}
	}
	if !(buildIndex >= 0 && buildIndex < captureIndex && captureIndex < normalizeIndex && normalizeIndex < uploadIndex) {
		t.Fatalf("snapshot workflow sequence build=%d capture=%d normalize=%d upload=%d", buildIndex, captureIndex, normalizeIndex, uploadIndex)
	}
}

func TestCIPackReviewContractBindsExternallySuppliedCandidateHead(t *testing.T) {
	workflow := decodeWorkflow(t, ".github/workflows/ci.yml")
	job := requiredWorkflowJob(t, workflow, "pack-review-contract")
	wantHead := "${{ github.event.pull_request.head.sha || github.sha }}"
	var checkout, contract *workflowStep
	for index := range job.Steps {
		step := &job.Steps[index]
		switch step.Name {
		case "Check out repository":
			checkout = step
		case "Validate synthetic review policy and governance contracts":
			contract = step
		}
	}
	if checkout == nil || checkout.With["ref"] != wantHead || checkout.With["persist-credentials"] != false {
		t.Fatalf("pack-review checkout is not exact and credential-free: %+v", checkout)
	}
	if contract == nil || contract.Env["PACK_REVIEW_HEAD"] != wantHead || contract.Run != "make pack-review-check" {
		t.Fatalf("pack-review validation does not bind the checked-out external C: %+v", contract)
	}
}

func TestCandidatePolicyUsesTrustedBaseWorkflowAndInertExactHead(t *testing.T) {
	workflow := decodeWorkflow(t, ".github/workflows/pack-review-candidate-policy.yml")
	if got := sortedKeys(workflow.On); !reflect.DeepEqual(got, []string{"pull_request_target"}) {
		t.Fatalf("candidate policy trigger = %v, want pull_request_target only", got)
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) {
		t.Fatalf("candidate policy permissions are not read-only: %v", workflow.Permissions)
	}
	job := requiredWorkflowJob(t, workflow, "candidate-change-contract")
	if job.RunsOn != "ubuntu-24.04" || job.Environment != nil || len(job.Steps) != 3 {
		t.Fatalf("candidate policy job is outside its fixed ephemeral three-step shape: %+v", job)
	}
	for _, required := range []string{
		"github.event.pull_request.base.repo.full_name == github.repository",
		"github.event.pull_request.base.ref == github.event.repository.default_branch",
	} {
		if !strings.Contains(job.If, required) {
			t.Fatalf("candidate policy is not restricted to the trusted default branch: %q", job.If)
		}
	}

	var trustedCheckout, checkout, guard *workflowStep
	for index := range job.Steps {
		step := &job.Steps[index]
		switch step.Name {
		case "Check out exact trusted base policy":
			trustedCheckout = step
		case "Check out pull-request head as inert Git data":
			checkout = step
		case "Enforce trusted candidate change-set policy":
			guard = step
		}
	}
	if trustedCheckout == nil || trustedCheckout.With["ref"] != "${{ github.event.pull_request.base.sha }}" ||
		trustedCheckout.With["repository"] != "${{ github.repository }}" || trustedCheckout.With["fetch-depth"] != 1 ||
		trustedCheckout.With["path"] != "trusted-policy" || trustedCheckout.With["persist-credentials"] != false ||
		trustedCheckout.With["allow-unsafe-pr-checkout"] != nil {
		t.Fatalf("candidate guard policy is not loaded from the exact trusted base: %+v", trustedCheckout)
	}
	if checkout == nil || checkout.With["ref"] != "refs/pull/${{ github.event.pull_request.number }}/head" ||
		checkout.With["repository"] != "${{ github.repository }}" || checkout.With["fetch-depth"] != 0 ||
		checkout.With["path"] != "pull-request" || checkout.With["persist-credentials"] != false ||
		checkout.With["allow-unsafe-pr-checkout"] != true {
		t.Fatalf("candidate guard checkout is not exact, complete, and credential-free: %+v", checkout)
	}
	if guard == nil || guard.Env["PACK_REVIEW_BASE"] != "${{ github.event.pull_request.base.sha }}" ||
		guard.Env["PACK_REVIEW_HEAD"] != "${{ github.event.pull_request.head.sha }}" ||
		guard.Env["PACK_REVIEW_NUMBER"] != "${{ github.event.pull_request.number }}" || guard.Shell != "bash" {
		t.Fatalf("candidate guard is not bound to exact pull-request endpoints: %+v", guard)
	}
	if strings.Count(guard.Run, "git -C pull-request rev-parse --verify") != 2 || strings.Count(guard.Run, "trusted-policy/scripts/pack-review-candidate-change-guard.sh") != 1 {
		t.Fatalf("candidate policy must perform exactly two inert Git identity reads and one trusted guard invocation: %q", guard.Run)
	}
	for _, required := range []string{
		"actual_head=$(git -C pull-request rev-parse --verify 'HEAD^{commit}')",
		`actual_base=$(git -C pull-request rev-parse --verify "${PACK_REVIEW_BASE}^{commit}")`,
		"trusted-policy/scripts/pack-review-candidate-change-guard.sh",
		"--repository-root pull-request",
		`--base "$PACK_REVIEW_BASE"`,
		`--head "$PACK_REVIEW_HEAD"`,
	} {
		if !strings.Contains(guard.Run, required) {
			t.Errorf("candidate guard invocation omits %q", required)
		}
	}
	for _, prohibited := range []string{"pull-request/scripts/", "go run", "go test", "make ", "source pull-request"} {
		if strings.Contains(guard.Run, prohibited) {
			t.Errorf("trusted pull_request_target job executes head-controlled content %q", prohibited)
		}
	}
}

func requiredWorkflowJob(t *testing.T, workflow workflowDocument, name string) workflowJob {
	t.Helper()
	job, ok := workflow.Jobs[name]
	if !ok {
		t.Fatalf("release workflow lacks %s job", name)
	}
	return job
}

func requirePermissions(t *testing.T, job string, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s permissions = %v, want exactly %v", job, got, want)
	}
}

func joinedRun(job workflowJob) string {
	var runs []string
	for _, step := range job.Steps {
		if step.Run != "" {
			runs = append(runs, step.Run)
		}
	}
	return strings.Join(runs, "\n")
}

func stepIndex(job workflowJob, prefix string) int {
	for index, step := range job.Steps {
		if strings.HasPrefix(step.Uses, prefix) {
			return index
		}
	}
	return -1
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestReleaseWorkflowPolicyFilesExist(t *testing.T) {
	for _, path := range []string{
		"scripts/verify-release-ref.sh",
		"scripts/verify-release-attestations.sh",
		"scripts/compare-release-assets.sh",
		"scripts/verify-release-environment.sh",
	} {
		info, err := os.Stat(filepath.Join(repositoryRoot(t), path))
		if err != nil {
			t.Errorf("required release policy file %s: %v", path, err)
			continue
		}
		// Windows does not expose the executable bits stored by Git. POSIX jobs
		// enforce the checkout mode, and Windows never executes these shell
		// policies directly.
		if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
			t.Errorf("required release policy file %s is not executable", path)
		}
	}

	attestationPolicy := string(readRepositoryFile(t, "scripts/verify-release-attestations.sh"))
	for _, required := range []string{
		"--signer-workflow",
		"--signer-digest",
		"--source-ref",
		"--source-digest",
		"--deny-self-hosted-runners",
		"asset_count\" -ne 14",
	} {
		if !strings.Contains(attestationPolicy, required) {
			t.Errorf("attestation policy omits %q", required)
		}
	}
	environmentPolicy := string(readRepositoryFile(t, "scripts/verify-release-environment.sh"))
	for _, required := range []string{
		"required_reviewers",
		"prevent_self_review == false",
		"can_admins_bypass == false",
		"custom_branch_policies == true",
		`.branch_policies[0].type == "tag"`,
		`.branch_policies[0].name == "v*"`,
		"2026-03-10",
	} {
		if !strings.Contains(environmentPolicy, required) {
			t.Errorf("environment policy omits %q", required)
		}
	}
	releaseScript := string(readRepositoryFile(t, "scripts/release.sh"))
	if !strings.Contains(releaseScript, `git show -s --format=%ct "$head_commit"`) ||
		strings.Contains(releaseScript, "--format=%ct HEAD") {
		t.Fatal("release source timestamp must be read from the already-validated full commit")
	}
}

func TestRepositoryCheckoutKeepsByteSensitiveTextLFNormalized(t *testing.T) {
	attributes := string(readRepositoryFile(t, ".gitattributes"))
	foundPolicy := false
	for _, line := range strings.Split(attributes, "\n") {
		line = strings.TrimSpace(line)
		if line == "* text=auto eol=lf" {
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		t.Fatal(".gitattributes must force LF checkouts for byte-hashed fixtures and license material")
	}

	for _, name := range []string{
		"testdata/fixture-inventory.json",
		"incidents/synthetic/mutable-tag.yaml",
		"third_party/licenses/github.com/dustin/go-humanize/v1.0.1/LICENSE",
	} {
		if bytes.Contains(readRepositoryFile(t, name), []byte("\r\n")) {
			t.Errorf("byte-sensitive repository file %s was checked out with CRLF", name)
		}
	}
}

func TestReleaseEnvironmentPolicyFailsClosedWithMockGitHubCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX release-policy script is exercised by Linux and macOS jobs")
	}

	root := repositoryRoot(t)
	fakeBin := t.TempDir()
	logPath := filepath.Join(fakeBin, "gh.log")
	fakeGH := filepath.Join(fakeBin, "gh")
	if err := os.WriteFile(fakeGH, []byte(`#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$MOCK_GH_LOG"
case "$*" in
  *deployment-branch-policies*) printf '%s\n' "${MOCK_TAG_POLICY:-true}" ;;
  *environments*) printf '%s\n' "${MOCK_ENVIRONMENT_POLICY:-true}" ;;
  *) printf '%s\n' "unexpected gh invocation" >&2; exit 64 ;;
esac
`), 0o700); err != nil {
		t.Fatal(err)
	}

	run := func(environmentPolicy, tagPolicy string) ([]byte, error) {
		t.Helper()
		command := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-environment.sh"), "torjan0/cirewind", "release-draft", "torjan0")
		command.Env = append(os.Environ(),
			"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"MOCK_GH_LOG="+logPath,
			"MOCK_ENVIRONMENT_POLICY="+environmentPolicy,
			"MOCK_TAG_POLICY="+tagPolicy,
		)
		return command.CombinedOutput()
	}

	if output, err := run("true", "true"); err != nil {
		t.Fatalf("valid solo-maintainer policy failed: %v\n%s", err, output)
	}
	if output, err := run("false", "true"); err == nil || !strings.Contains(string(output), "permit that initiator's review") {
		t.Fatalf("invalid environment policy did not fail closed: err=%v output=%s", err, output)
	}
	if output, err := run("true", "false"); err == nil || !strings.Contains(string(output), "tag v*") {
		t.Fatalf("invalid tag policy did not fail closed: err=%v output=%s", err, output)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	for _, required := range []string{
		"--method GET",
		"X-GitHub-Api-Version: 2026-03-10",
		"repos/torjan0/cirewind/environments/release-draft",
		"repos/torjan0/cirewind/environments/release-draft/deployment-branch-policies?per_page=100",
	} {
		if !strings.Contains(log, required) {
			t.Errorf("mock GitHub CLI log omits %q", required)
		}
	}
}
