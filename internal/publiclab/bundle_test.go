package publiclab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func sourceRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "lab", "public", "source")
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("public lab source root: %v", err)
	}
	return root
}

func TestDecodeManifestNeverEchoesHostileObjectNames(t *testing.T) {
	t.Parallel()
	hostile := strings.Join([]string{"Authorization", "Bearer", "SYNTHETIC_PRIVATE_MATERIAL"}, ": ")
	for _, input := range []string{
		`{"schemaVersion":"cirewind.public-lab-object-manifest/v1alpha1","` + hostile + `":true}`,
		`{"` + hostile + `":1,"` + hostile + `":2}`,
	} {
		_, err := DecodeManifest(strings.NewReader(input))
		if err == nil {
			t.Fatal("hostile manifest object name was accepted")
		}
		if strings.Contains(err.Error(), hostile) || strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MATERIAL") {
			t.Fatalf("manifest error echoed hostile object name: %q", err)
		}
	}
}

func TestBuildIsDeterministicAndSelfVerifying(t *testing.T) {
	first, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bundle, second.Bundle) || !bytes.Equal(first.Manifest, second.Manifest) {
		t.Fatal("identical public lab source did not produce byte-identical artifacts")
	}
	if err := VerifyArtifact(context.Background(), sourceRoot(t), first.Bundle, first.Manifest); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Manifest, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schemaVersion"] != ManifestSchema {
		t.Fatalf("manifest schema=%v", decoded["schemaVersion"])
	}

	tamperedBundle := append([]byte(nil), first.Bundle...)
	tamperedBundle[len(tamperedBundle)/2] ^= 1
	if err := VerifyArtifact(context.Background(), sourceRoot(t), tamperedBundle, first.Manifest); err == nil {
		t.Fatal("tampered bundle verified")
	}
	tamperedManifest := append([]byte(nil), first.Manifest...)
	tamperedManifest[len(tamperedManifest)-2] = ' '
	if err := VerifyArtifact(context.Background(), sourceRoot(t), first.Bundle, tamperedManifest); err == nil {
		t.Fatal("noncanonical manifest verified")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(canceled, sourceRoot(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled build error=%v", err)
	}
}

func TestRepositoryTemplateSubstitution(t *testing.T) {
	overlay, err := readOverlay(context.Background(), filepath.Join(sourceRoot(t), "import"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := substituteOverlay(overlay, map[string]string{
		"{{WRAPPER_COMMIT}}":  strings.Repeat("a", 40),
		"{{REUSABLE_COMMIT}}": strings.Repeat("b", 40),
		"{{LAB_REPOSITORY}}":  RepositoryName,
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, file := range resolved {
		for _, marker := range []string{"{{LAB_REPOSITORY}}", "{{WRAPPER_COMMIT}}", "{{REUSABLE_COMMIT}}"} {
			if bytes.Contains(file.data, []byte(marker)) {
				t.Fatalf("%s retains unresolved marker %s: %q", path, marker, file.data)
			}
		}
	}
}

func TestBundleImportsTwiceAndPassesGitVerification(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("Git integration is unavailable")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bundlePath := filepath.Join(root, BundleFilename)
	if err := os.WriteFile(bundlePath, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	verifyRepo := filepath.Join(root, "verify.git")
	runGit(t, git, "init", "--bare", "--initial-branch=main", verifyRepo)
	runGit(t, git, "-C", verifyRepo, "bundle", "verify", bundlePath)

	imports := []string{filepath.Join(root, "import-one"), filepath.Join(root, "import-two")}
	for _, target := range imports {
		runGit(t, git, "clone", "--quiet", bundlePath, target)
		runGit(t, git, "-C", target, "fsck", "--strict", "--full")
	}
	refsOne := runGit(t, git, "-C", imports[0], "show-ref")
	refsTwo := runGit(t, git, "-C", imports[1], "show-ref")
	if refsOne != refsTwo {
		t.Fatalf("independent imports differ:\n%s\n---\n%s", refsOne, refsTwo)
	}
	if got := strings.TrimSpace(runGit(t, git, "-C", imports[0], "rev-parse", "HEAD")); got != artifact.Model.Commits[5].ObjectID {
		t.Fatalf("import HEAD=%s want=%s", got, artifact.Model.Commits[5].ObjectID)
	}
	assertRef(t, git, imports[0], "refs/tags/v1", artifact.Model.Commits[1].ObjectID)
	assertRef(t, git, imports[0], "refs/tags/fixture-a^{}", artifact.Model.Commits[1].ObjectID)
	assertRef(t, git, imports[0], "refs/tags/fixture-b^{}", artifact.Model.Commits[2].ObjectID)
	if got := strings.TrimSpace(runGit(t, git, "-C", imports[0], "cat-file", "-t", "refs/tags/fixture-a")); got != "tag" {
		t.Fatalf("fixture-a object type=%q", got)
	}

	aMarker := runGit(t, git, "-C", imports[0], "show", "refs/tags/fixture-a^{}:actions/marker/action.yml")
	bMarker := runGit(t, git, "-C", imports[0], "show", "refs/tags/fixture-b^{}:actions/marker/action.yml")
	headMarker := runGit(t, git, "-C", imports[0], "show", "HEAD:actions/marker/action.yml")
	if !strings.Contains(aMarker, "cirewind-lab-marker=A") || !strings.Contains(bMarker, "cirewind-lab-marker=B") || headMarker != aMarker {
		t.Fatal("A/B/restored-A marker contents do not satisfy the reviewed topology")
	}
	composite := runGit(t, git, "-C", imports[0], "show", "HEAD:.github/workflows/composite.yml")
	reusableCaller := runGit(t, git, "-C", imports[0], "show", "HEAD:.github/workflows/reusable-caller.yml")
	if !strings.Contains(composite, "@"+artifact.Model.Commits[3].ObjectID) || !strings.Contains(reusableCaller, "@"+artifact.Model.Commits[4].ObjectID) {
		t.Fatal("consumer workflows do not pin exact support commits")
	}
	assertImportTree(t, git, imports[0], artifact.Model)
	assertDCO(t, git, imports[0], artifact.Model)
}

func TestWorkflowAndMarkerSafetyContract(t *testing.T) {
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Model.ImportFiles {
		lower := strings.ToLower(file.Path)
		if !strings.HasPrefix(lower, ".github/workflows/") && !strings.HasPrefix(lower, "actions/") {
			continue
		}
		data := importFileBytes(t, artifact.Model, file.Path, sourceRoot(t))
		text := string(data)
		for _, forbidden := range []string{
			"pull_request_target", "id-token: write", "contents: write", "packages: write",
			"releases: write", "deployments: write", "secrets.", "github.token", "curl ", "wget ",
			"gh api", "git push", "actions/checkout", "http://", "https://",
		} {
			if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
				t.Fatalf("%s contains forbidden workflow capability %q", file.Path, forbidden)
			}
		}
		if strings.HasPrefix(lower, ".github/workflows/") {
			var document map[string]any
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatalf("parse %s: %v", file.Path, err)
			}
			permissions, ok := document["permissions"].(map[string]any)
			if !ok || len(permissions) != 1 || permissions["contents"] != "read" {
				t.Fatalf("%s permissions=%#v", file.Path, document["permissions"])
			}
		}
	}

	const markerPrefix = "name: CIRewind lab marker\ndescription: Print a fixed public marker for the harmless temporal evidence lab\nruns:\n  using: composite\n  steps:\n    - name: Print fixed marker\n      shell: bash\n      run: printf '%s\\n' 'cirewind-lab-marker="
	wantA := []byte(markerPrefix + "A'\n")
	wantB := []byte(markerPrefix + "B'\n")
	markerA, err := os.ReadFile(filepath.Join(sourceRoot(t), "marker-a", "actions", "marker", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	markerB, err := os.ReadFile(filepath.Join(sourceRoot(t), "marker-b", "actions", "marker", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	restoredA, err := os.ReadFile(filepath.Join(sourceRoot(t), "wrapper", "actions", "marker", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(markerA, wantA) || !bytes.Equal(markerB, wantB) || !bytes.Equal(restoredA, wantA) {
		t.Fatalf("A/B/restored-A Action bytes differ from the single reviewed fixed-output shape")
	}
	if !bytes.Equal(bytes.Replace(markerA, []byte("marker=A"), []byte("marker=B"), 1), markerB) {
		t.Fatal("marker B differs from marker A by more than the one fixed public marker byte")
	}
	if got := importFileBytes(t, artifact.Model, "actions/marker/action.yml", sourceRoot(t)); !bytes.Equal(got, wantA) {
		t.Fatal("import commit does not restore exact marker A bytes")
	}
	wrapper := importFileBytes(t, artifact.Model, "actions/wrapper/action.yml", sourceRoot(t))
	if strings.Count(string(wrapper), "uses:") != 1 || !bytes.Contains(wrapper, []byte("torjan0/cirewind-lab/actions/marker@v1")) {
		t.Fatalf("wrapper does not contain exactly one mutable marker call: %s", wrapper)
	}
}

func TestWorkflowBytesMatchReviewedSafetyShapes(t *testing.T) {
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	wrapperCommit := artifact.Model.Commits[3].ObjectID
	reusableCommit := artifact.Model.Commits[4].ObjectID
	expected := map[string]string{
		".github/workflows/direct.yml": `name: Direct mutable marker fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  direct:
    name: Direct mutable marker
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Invoke mutable marker directly
        uses: torjan0/cirewind-lab/actions/marker@v1
`,
		".github/workflows/composite.yml": `name: Composite wrapper fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  composite:
    name: Stable composite wrapper
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Invoke stable wrapper
        uses: torjan0/cirewind-lab/actions/wrapper@` + wrapperCommit + `
`,
		".github/workflows/reusable.yml": `name: Reusable composite fixture

on:
  workflow_call:

permissions:
  contents: read

jobs:
  reusable-composite:
    name: Reusable composite fixture
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Invoke stable wrapper
        uses: torjan0/cirewind-lab/actions/wrapper@` + wrapperCommit + `
`,
		".github/workflows/reusable-caller.yml": `name: Reusable workflow fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  reusable-caller:
    name: Stable reusable workflow
    uses: torjan0/cirewind-lab/.github/workflows/reusable.yml@` + reusableCommit + `
`,
		".github/workflows/skipped.yml": `name: Downloaded but skipped fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  skipped:
    name: Marker step remains skipped
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Marker must not begin
        if: ${{ github.repository == '__cirewind_lab_never__' }}
        uses: torjan0/cirewind-lab/actions/marker@v1
`,
		".github/workflows/matrix.yml": `name: Two-axis matrix fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  matrix:
    name: Matrix ${{ matrix.axis }}
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    strategy:
      fail-fast: false
      matrix:
        axis:
          - alpha
          - beta
        shard:
          - one
          - two
    steps:
      - name: Invoke mutable marker
        uses: torjan0/cirewind-lab/actions/marker@v1
`,
		".github/workflows/rerun.yml": `name: Rerun identity fixture

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  marker-success:
    name: Marker success control
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Invoke mutable marker
        uses: torjan0/cirewind-lab/actions/marker@v1

  marker-fixed-failure:
    name: Marker fixed failure control
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: Invoke mutable marker before fixed failure
        uses: torjan0/cirewind-lab/actions/marker@v1
      - name: Exit with fixed nonzero status
        shell: bash
        run: exit 1
`,
	}
	for path, want := range expected {
		if got := string(importFileBytes(t, artifact.Model, path, sourceRoot(t))); got != want {
			t.Fatalf("%s differs from its exact reviewed workflow shape\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
		}
	}
}

func TestSourcePathAndArtifactPublicationLimits(t *testing.T) {
	for _, value := range []string{
		"", "/absolute", "../escape", "a/../../b", "a\\b", "a//b", "a/./b", "a\nb",
		"colon:name", "wild*card", "unicode-é", "trailing.", "CON", "aux.txt", "path/COM1.log",
	} {
		if err := validateSourcePath(value); err == nil {
			t.Fatalf("unsafe source path %q accepted", value)
		}
	}
	for _, value := range []string{"README.md", ".github/workflows/direct.yml", "actions/marker/action.yml"} {
		if err := validateSourcePath(value); err != nil {
			t.Fatalf("safe source path %q rejected: %v", value, err)
		}
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := WriteArtifact(context.Background(), out, artifact); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifact(context.Background(), out, artifact); err == nil {
		t.Fatal("artifact overwrite unexpectedly succeeded")
	}
}

func TestSourceHistoryContainsOnlyPublicSyntheticMaterial(t *testing.T) {
	root := sourceRoot(t)
	license, err := os.ReadFile(filepath.Join(root, "common", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	projectLicense, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(license, projectLicense) {
		t.Fatal("public lab Apache-2.0 license differs from the reviewed project license")
	}

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)github_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`(?i)gh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{30,}`),
		regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`),
	}
	for _, overlay := range []string{"common", "marker-a", "marker-b", "wrapper", "reusable", "import"} {
		files, err := readOverlay(context.Background(), filepath.Join(root, overlay))
		if err != nil {
			t.Fatal(err)
		}
		for path, file := range files {
			lower := strings.ToLower(path)
			for _, suffix := range []string{".pem", ".p12", ".pfx", ".key", "id_rsa", ".env"} {
				if strings.HasSuffix(lower, suffix) {
					t.Fatalf("forbidden credential-like source filename %s/%s", overlay, path)
				}
			}
			for _, pattern := range secretPatterns {
				if pattern.Find(file.data) != nil {
					t.Fatalf("credential-like material matched %s in %s/%s", pattern, overlay, path)
				}
			}
		}
	}
}

func runGit(t *testing.T, executable string, args ...string) string {
	t.Helper()
	gitArgs := append([]string{"-c", "core.hooksPath=" + gitNullDevice, "-c", "init.templateDir=", "-c", "protocol.file.allow=always"}, args...)
	command := exec.CommandContext(context.Background(), executable, gitArgs...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gitNullDevice, "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func assertRef(t *testing.T, git, repository, ref, want string) {
	t.Helper()
	got := strings.TrimSpace(runGit(t, git, "-C", repository, "rev-parse", ref))
	if got != want {
		t.Fatalf("%s=%s want=%s", ref, got, want)
	}
}

func assertImportTree(t *testing.T, git, repository string, manifest ObjectManifest) {
	t.Helper()
	output := runGit(t, git, "-C", repository, "ls-tree", "-r", "--format=%(objectmode)%x09%(objectname)%x09%(path)", "HEAD")
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != len(manifest.ImportFiles) {
		t.Fatalf("import tree files=%d manifest=%d", len(lines), len(manifest.ImportFiles))
	}
	for index, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("malformed ls-tree line %q", line)
		}
		want := manifest.ImportFiles[index]
		if parts[0] != want.Mode || parts[1] != want.BlobObject || parts[2] != want.Path {
			t.Fatalf("tree[%d]=%v want=%+v", index, parts, want)
		}
		data := []byte(runGit(t, git, "-C", repository, "show", "HEAD:"+want.Path))
		if len(data) != want.ByteLength {
			t.Fatalf("%s byte length=%d want=%d", want.Path, len(data), want.ByteLength)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want.SHA256 {
			t.Fatalf("%s SHA-256 differs", want.Path)
		}
	}
}

func assertDCO(t *testing.T, git, repository string, manifest ObjectManifest) {
	t.Helper()
	for _, commit := range manifest.Commits {
		body := runGit(t, git, "-C", repository, "show", "-s", "--format=%B", commit.ObjectID)
		want := fmt.Sprintf("Signed-off-by: %s <%s>\n", fixtureIdentity.Name, fixtureIdentity.Email)
		if !strings.HasSuffix(body, want+"\n") && !strings.HasSuffix(body, want) {
			t.Fatalf("commit %s lacks exact DCO trailer: %q", commit.Role, body)
		}
		command := exec.Command(git, "interpret-trailers", "--parse")
		command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+gitNullDevice, "LC_ALL=C")
		command.Stdin = strings.NewReader(body)
		output, err := command.Output()
		if err != nil || strings.TrimSpace(string(output)) != strings.TrimSpace(want) {
			t.Fatalf("commit %s trailer parse=%q err=%v", commit.Role, output, err)
		}
	}
}

func importFileBytes(t *testing.T, manifest ObjectManifest, path, root string) []byte {
	t.Helper()
	artifact, err := Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Model.ImportFiles {
		if file.Path == path {
			// Locate the corresponding blob directly through the deterministic
			// source overlay merge instead of executing Git or Action content.
			overlays := []string{"common", "marker-a", "wrapper", "reusable", "import"}
			files := map[string]sourceFile{}
			for _, name := range overlays {
				items, readErr := readOverlay(context.Background(), filepath.Join(root, name))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if name == "reusable" {
					items, readErr = substituteOverlay(items, map[string]string{"{{WRAPPER_COMMIT}}": artifact.Model.Commits[3].ObjectID, "{{LAB_REPOSITORY}}": artifact.Model.Repository})
				}
				if name == "import" {
					items, readErr = substituteOverlay(items, map[string]string{"{{WRAPPER_COMMIT}}": artifact.Model.Commits[3].ObjectID, "{{REUSABLE_COMMIT}}": artifact.Model.Commits[4].ObjectID, "{{LAB_REPOSITORY}}": artifact.Model.Repository})
				}
				if name == "wrapper" {
					items, readErr = substituteOverlay(items, map[string]string{"{{LAB_REPOSITORY}}": artifact.Model.Repository})
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				applyOverlay(files, items)
			}
			return files[path].data
		}
	}
	t.Fatalf("import file %q is absent", path)
	return nil
}

func TestManifestOrdering(t *testing.T) {
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(artifact.Model.ImportFiles))
	for _, file := range artifact.Model.ImportFiles {
		paths = append(paths, file.Path)
	}
	if !sort.StringsAreSorted(paths) {
		t.Fatal("import file descriptors are not sorted")
	}
}
