package acceptance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
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
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Environment string            `yaml:"environment"`
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
	Name string         `yaml:"name"`
	ID   string         `yaml:"id"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

func decodeWorkflow(t *testing.T, relative string) workflowDocument {
	t.Helper()
	data := readRepositoryFile(t, relative)
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var workflow workflowDocument
	if err := decoder.Decode(&workflow); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	return workflow
}

func TestActionPinsCoverEveryWorkflowAction(t *testing.T) {
	var ledger actionPinLedger
	decoder := json.NewDecoder(bytes.NewReader(readRepositoryFile(t, ".github/actions-pins.json")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		t.Fatalf("decode action pin ledger: %v", err)
	}
	if ledger.SchemaVersion != 1 || ledger.RetrievedAt != "2026-08-21" || ledger.VerificationMethod == "" {
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
