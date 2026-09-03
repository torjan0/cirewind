package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/publiclab"
)

func TestHelpAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("publiclab build")) {
		t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"build"}, &stdout, &stderr); code != 1 && code != 2 {
		t.Fatalf("usage code=%d stderr=%q", code, stderr.String())
	}
}

func TestBuildRefusesExistingOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	out := t.TempDir()
	source := filepath.Join("..", "..", "lab", "public", "source")
	code := run(context.Background(), []string{"build", "--source", source, "--out", out}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("build unexpectedly overwrote an existing output directory")
	}
}

func TestValidateRecordCommandUsesOnlyReviewedLocalSchemas(t *testing.T) {
	var stdout, stderr bytes.Buffer
	protocol := filepath.Join("..", "..", "lab", "public", "source", "import", "protocol")
	record := filepath.Join(protocol, "expected-findings.seed.json")
	code := run(context.Background(), []string{
		"validate-record",
		"--schema-dir", protocol,
		"--kind", string(publiclab.RecordExpectedSeed),
		"--record", record,
	}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "validated without network access") || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{
		"validate-record",
		"--schema-dir", protocol,
		"--kind", "not-reviewed",
		"--record", record,
	}, &stdout, &stderr)
	if code == 0 || strings.Contains(stderr.String(), record) {
		t.Fatalf("unknown kind code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "record.json")
		absoluteRecord, err := filepath.Abs(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(absoluteRecord, link); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		code = run(context.Background(), []string{
			"validate-record",
			"--schema-dir", protocol,
			"--kind", string(publiclab.RecordExpectedSeed),
			"--record", link,
		}, &stdout, &stderr)
		if code == 0 {
			t.Fatal("validate-record accepted a symlinked record")
		}
	}
}

func TestArtifactBuildAndVerifyCommandsRoundTrip(t *testing.T) {
	source := filepath.Join("..", "..", "lab", "public", "source")
	out := filepath.Join(t.TempDir(), "artifact")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"build", "--source", source, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"verify", "--source", source, "--artifact-dir", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPlanAndMoveV1OperateOnlyOnExactDisposableTag(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	source := filepath.Join("..", "..", "lab", "public", "source")
	artifact, err := publiclab.BuildForRepository(context.Background(), source, "example/cirewind-lab")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bundle := filepath.Join(root, publiclab.BundleFilename)
	if err := os.WriteFile(bundle, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(root, "disposable.git")
	worktree := filepath.Join(root, "worktree")
	runGit(t, git, "clone", "--bare", "--quiet", bundle, remote)
	runGit(t, git, "clone", "--quiet", remote, worktree)

	commitA := artifact.Model.Commits[1].ObjectID
	commitB := artifact.Model.Commits[2].ObjectID
	base := []string{
		"--worktree", worktree,
		"--repository", "example/cirewind-lab",
		"--assert-repository-id", "101",
		"--remote", remote,
		"--reviewed-main", artifact.Model.Commits[5].ObjectID,
		"--commit-a", commitA,
		"--commit-b", commitB,
		"--fixture-a-tag-object", artifact.Model.Tags[0].ObjectID,
		"--fixture-b-tag-object", artifact.Model.Tags[1].ObjectID,
	}
	observationPaths := make(map[string]string)
	moveSequence := 0
	argsFor := func(operation, oldTarget, newTarget string) []string {
		args := append([]string{operation}, base...)
		args = append(args,
			"--expected-old", oldTarget,
			"--new-target", newTarget,
			"--ack", publiclab.RequiredTagMoveAcknowledgement("example/cirewind-lab", oldTarget, newTarget),
		)
		if operation == "move-v1" {
			moveSequence++
			observationPath := filepath.Join(root, "move-"+strconv.Itoa(moveSequence)+"-"+oldTarget[:8]+"-"+newTarget[:8]+".json")
			observationPaths[oldTarget+newTarget] = observationPath
			args = append(args, "--git", git, "--observation-out", observationPath)
		}
		return args
	}

	var stdout, stderr bytes.Buffer
	if runtime.GOOS != "windows" {
		hookSentinel := filepath.Join(root, "receive-hook-ran")
		t.Setenv("PUBLICLAB_TEST_HOOK_SENTINEL", hookSentinel)
		hook := filepath.Join(remote, "hooks", "pre-receive")
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf ran > \"$PUBLICLAB_TEST_HOOK_SENTINEL\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		productionArgs := argsFor("move-v1", commitA, commitB)
		if code := run(context.Background(), productionArgs, &stdout, &stderr); code == 0 {
			t.Fatalf("production command accepted a filesystem remote: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if _, err := os.Stat(hookSentinel); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("filesystem remote receive hook was reached: %v", err)
		}
		if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitA {
			t.Fatalf("production rejection changed v1 to %s", got)
		}
		stdout.Reset()
		stderr.Reset()
	}
	if code := runLocalTagCommand(context.Background(), argsFor("plan-v1", commitA, commitB), &stdout, &stderr); code != 0 {
		t.Fatalf("plan code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitA {
		t.Fatalf("inert plan changed v1 to %s", got)
	}
	if strings.Contains(stdout.String(), remote) || strings.Contains(stdout.String(), "I acknowledge") {
		t.Fatalf("plan disclosed remote or acknowledgement: %q", stdout.String())
	}

	wrongAckArgs := argsFor("move-v1", commitA, commitB)
	for index := range wrongAckArgs {
		if wrongAckArgs[index] == "--ack" {
			wrongAckArgs[index+1] += " "
			break
		}
	}
	wrongAckRecord := wrongAckArgs[len(wrongAckArgs)-1]
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), wrongAckArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitA {
		t.Fatalf("wrong acknowledgement code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "before any Git command or remote contact") || strings.Contains(stderr.String(), "must be read back") || strings.Contains(stderr.String(), "unconfirmed") {
		t.Fatalf("policy rejection overclaimed remote uncertainty: %q", stderr.String())
	}
	if _, err := os.Lstat(wrongAckRecord); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy rejection left a reserved observation record: %v", err)
	}

	legacyArgs := argsFor("plan-v1", commitA, commitB)
	for index := range legacyArgs {
		if legacyArgs[index] == "--assert-repository-id" {
			legacyArgs[index] = "--repository-id"
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), legacyArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitA {
		t.Fatalf("unlabeled repository ID flag code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	insideArgs := argsFor("move-v1", commitA, commitB)
	insideArgs[len(insideArgs)-1] = filepath.Join(worktree, "observation.json")
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), insideArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitA {
		t.Fatalf("inside-worktree observation path mutated v1: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	existingObservation := filepath.Join(root, "existing-observation.json")
	if err := os.WriteFile(existingObservation, []byte("preserve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	existingArgs := argsFor("move-v1", commitA, commitB)
	existingArgs[len(existingArgs)-1] = existingObservation
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), existingArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitA {
		t.Fatalf("existing observation path mutated v1: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	missingParentArgs := argsFor("move-v1", commitA, commitB)
	missingParentArgs[len(missingParentArgs)-1] = filepath.Join(root, "missing-parent", "observation.json")
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), missingParentArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitA {
		t.Fatalf("unwritable observation path mutated v1: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	if runtime.GOOS != "windows" {
		pushComplete := filepath.Join(root, "synthetic-push-complete")
		gitWrapper := filepath.Join(root, "git-readback-failure")
		wrapper := "#!/bin/sh\n" +
			"saw_push=0\n" +
			"for argument do\n" +
			"  [ \"$argument\" = push ] && saw_push=1\n" +
			"  if [ \"$argument\" = ls-remote ] && [ -f \"$PUBLICLAB_TEST_PUSH_COMPLETE\" ]; then exit 23; fi\n" +
			"done\n" +
			"\"$PUBLICLAB_TEST_REAL_GIT\" \"$@\"\n" +
			"status=$?\n" +
			"if [ \"$saw_push\" -eq 1 ] && [ \"$status\" -eq 0 ]; then : > \"$PUBLICLAB_TEST_PUSH_COMPLETE\"; fi\n" +
			"exit \"$status\"\n"
		if err := os.WriteFile(gitWrapper, []byte(wrapper), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PUBLICLAB_TEST_REAL_GIT", git)
		t.Setenv("PUBLICLAB_TEST_PUSH_COMPLETE", pushComplete)
		unknownArgs := argsFor("move-v1", commitA, commitB)
		for index := range unknownArgs {
			if unknownArgs[index] == "--git" {
				unknownArgs[index+1] = gitWrapper
				break
			}
		}
		unknownRecord := unknownArgs[len(unknownArgs)-1]
		stdout.Reset()
		stderr.Reset()
		if code := runLocalTagCommand(context.Background(), unknownArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitB {
			t.Fatalf("post-push readback failure code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		unknownBytes, err := publiclab.ReadTagMoveRecord(context.Background(), filepath.Join(source, "import", "protocol"), unknownRecord)
		if err != nil {
			t.Fatalf("unknown-outcome observation was not preserved: %v", err)
		}
		var unknown map[string]any
		if err := json.Unmarshal(unknownBytes, &unknown); err != nil {
			t.Fatal(err)
		}
		recovery, _ := unknown["recovery"].(map[string]any)
		if unknown["outcome"] != "OUTCOME_UNKNOWN" || unknown["after"] != nil || recovery["observed_target"] != nil {
			t.Fatalf("unknown-outcome observation invented a post-push readback: %#v", unknown)
		}
		stdout.Reset()
		stderr.Reset()
		if code := runLocalTagCommand(context.Background(), argsFor("move-v1", commitB, commitA), &stdout, &stderr); code != 0 {
			t.Fatalf("unknown-outcome recovery code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitA {
			t.Fatalf("unknown-outcome recovery left v1 at %s", got)
		}
	}

	failing := &syntheticFailingReservation{}
	failedArgs := argsFor("move-v1", commitA, commitB)
	_, writeErr := runMoveV1WithReservation(context.Background(), failedArgs[1:], func(context.Context, string, string) (regularFileReservation, error) {
		return failing, nil
	}, true)
	if writeErr == nil || !failing.writeCalled || !failing.aborted || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitB {
		t.Fatalf("post-mutation record failure was not surfaced safely: err=%v reservation=%+v", writeErr, failing)
	}
	for _, required := range []string{commitB, commitA, "immediate recovery is required", publiclab.RequiredTagMoveAcknowledgement("example/cirewind-lab", commitB, commitA)} {
		if !strings.Contains(writeErr.Error(), required) {
			t.Fatalf("post-mutation record failure lacks %q: %v", required, writeErr)
		}
	}
	if strings.Contains(writeErr.Error(), remote) || strings.Contains(writeErr.Error(), worktree) {
		t.Fatalf("post-mutation record failure disclosed a local path: %v", writeErr)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), argsFor("move-v1", commitB, commitA), &stdout, &stderr); code != 0 {
		t.Fatalf("recovery restore code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitA {
		t.Fatalf("recovery restore left v1 at %s", got)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), argsFor("move-v1", commitA, commitB), &stdout, &stderr); code != 0 {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitB {
		t.Fatalf("move did not install B; got %s", got)
	}
	if strings.Contains(stdout.String(), remote) || strings.Contains(stdout.String(), "I acknowledge") {
		t.Fatalf("move disclosed remote or acknowledgement: %q", stdout.String())
	}
	installRecord := observationPaths[commitA+commitB]
	protocolDir := filepath.Join(source, "import", "protocol")
	installBytes, err := publiclab.ReadTagMoveRecord(context.Background(), protocolDir, installRecord)
	if err != nil || bytes.Contains(installBytes, []byte(remote)) || bytes.Contains(installBytes, []byte(worktree)) {
		t.Fatalf("unsafe or invalid install observation: err=%v record=%q", err, installBytes)
	}
	stdout.Reset()
	stderr.Reset()
	wrongOldArgs := argsFor("move-v1", commitA, commitB)
	if code := runLocalTagCommand(context.Background(), wrongOldArgs, &stdout, &stderr); code == 0 || remoteRef(t, git, remote, publiclab.MutableV1Ref) != commitB {
		t.Fatalf("wrong-old call was not rejected at retained B: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, required := range []string{"recovery ref refs/tags/v1", commitB, commitA, publiclab.RequiredTagMoveAcknowledgement("example/cirewind-lab", commitB, commitA)} {
		if !strings.Contains(stderr.String(), required) {
			t.Fatalf("wrong-old diagnostic lacks %q: %q", required, stderr.String())
		}
	}
	wrongOldRecord := wrongOldArgs[len(wrongOldArgs)-1]
	wrongOldBytes, err := publiclab.ReadTagMoveRecord(context.Background(), protocolDir, wrongOldRecord)
	if err != nil || !bytes.Contains(wrongOldBytes, []byte(commitB)) {
		t.Fatalf("wrong-old exact-B observation was not preserved: err=%v record=%q", err, wrongOldBytes)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runLocalTagCommand(context.Background(), argsFor("move-v1", commitB, commitA), &stdout, &stderr); code != 0 {
		t.Fatalf("restore code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := remoteRef(t, git, remote, publiclab.MutableV1Ref); got != commitA {
		t.Fatalf("move did not restore A; got %s", got)
	}
	restoreRecord := observationPaths[commitB+commitA]
	restoreBytes, err := publiclab.ReadTagMoveRecord(context.Background(), protocolDir, restoreRecord)
	if err != nil {
		t.Fatalf("invalid restore observation: %v", err)
	}

	artifactDir := t.TempDir()
	if err := publiclab.WriteArtifact(context.Background(), artifactDir, artifact); err != nil {
		t.Fatal(err)
	}
	packInput := filepath.Join(root, "pack-input.json")
	stdout.Reset()
	stderr.Reset()
	code := run(context.Background(), []string{
		"render-pack-input",
		"--source", source,
		"--schema-dir", filepath.Join(source, "import", "protocol"),
		"--artifact-dir", artifactDir,
		"--install-record", installRecord,
		"--restore-record", restoreRecord,
		"--created-at", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"--out", packInput,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("render-pack-input code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := publiclab.ReadAndValidateRecord(context.Background(), filepath.Join(source, "import", "protocol"), publiclab.RecordPackInput, packInput); err != nil {
		t.Fatalf("generated pack input is invalid: %v", err)
	}
	packInputBytes, err := os.ReadFile(packInput)
	if err != nil {
		t.Fatal(err)
	}
	var packInputValue map[string]any
	if err := json.Unmarshal(packInputBytes, &packInputValue); err != nil {
		t.Fatal(err)
	}
	recordID := packInputValue["record_id"].(string)
	runGit(t, git, "-C", worktree, "config", "user.name", "Synthetic Tool Test")
	runGit(t, git, "-C", worktree, "config", "user.email", "synthetic-tool@example.invalid")
	runGit(t, git, "-C", worktree, "switch", "--quiet", "-c", "observations")
	if err := os.Mkdir(filepath.Join(worktree, "observations"), 0o700); err != nil {
		t.Fatal(err)
	}
	retained := []struct {
		data []byte
		id   string
	}{
		{data: installBytes, id: tagMoveRecordID(t, installBytes)},
		{data: restoreBytes, id: tagMoveRecordID(t, restoreBytes)},
		{data: packInputBytes, id: recordID},
	}
	for _, item := range retained {
		if err := os.WriteFile(filepath.Join(worktree, "observations", item.id+".json"), item.data, 0o600); err != nil {
			t.Fatal(err)
		}
		runGit(t, git, "-C", worktree, "add", "observations/"+item.id+".json")
	}
	runGit(t, git, "-C", worktree, "commit", "--quiet", "-m", "docs: record synthetic observations")
	revision := strings.TrimSpace(runGit(t, git, "-C", worktree, "rev-parse", "HEAD"))
	recordURL := "https://github.com/example/cirewind-lab/blob/" + revision + "/observations/" + recordID + ".json"
	packPath := filepath.Join(root, "synthetic-incident.yaml")
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{
		"render-pack",
		"--source", source,
		"--schema-dir", protocolDir,
		"--artifact-dir", artifactDir,
		"--record", packInput,
		"--install-record", installRecord,
		"--restore-record", restoreRecord,
		"--record-source-url", recordURL,
		"--record-source-worktree", worktree,
		"--git", git,
		"--out", packPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("render-pack code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	packBytes, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incident.Validate(context.Background(), packBytes); err != nil {
		t.Fatalf("rendered synthetic pack invalid: %v", err)
	}
}

// runLocalTagCommand is deliberately test-only. It exercises the CLI parsing
// and output path while enabling the package's disposable-filesystem-remote
// seam; the production run function has no flag or environment override for it.
func runLocalTagCommand(ctx context.Context, args []string, stdout, stderr *bytes.Buffer) int {
	if len(args) == 0 {
		return 2
	}
	var (
		message string
		err     error
	)
	switch args[0] {
	case "plan-v1":
		message, err = runPlanV1WithRemotePolicy(ctx, args[1:], true)
	case "move-v1":
		message, err = runMoveV1WithReservation(ctx, args[1:], reserveNewRegularFile, true)
	default:
		return 2
	}
	if err != nil {
		_, _ = stderr.WriteString(err.Error() + "\n")
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return 1
	}
	_, _ = stdout.WriteString(message + "\n")
	return 0
}

func tagMoveRecordID(t *testing.T, data []byte) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	recordID, ok := value["record_id"].(string)
	if !ok || recordID == "" {
		t.Fatal("tag-move record omits its stable ID")
	}
	return recordID
}

type syntheticFailingReservation struct {
	writeCalled bool
	aborted     bool
}

func (reservation *syntheticFailingReservation) write(context.Context, []byte) error {
	reservation.writeCalled = true
	return errors.New("synthetic durable record failure")
}

func (reservation *syntheticFailingReservation) abort() {
	reservation.aborted = true
}

func TestCommandsHonorCancellationAndOutputRefusesOverwrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"plan-v1"}, &stdout, &stderr); code != 130 || !strings.Contains(stderr.String(), "context canceled") {
		t.Fatalf("canceled plan code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	out := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(out, []byte("preserve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewRegularFile(context.Background(), out, []byte("replace\n")); err == nil {
		t.Fatal("generated output overwrote an existing file")
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "preserve\n" {
		t.Fatalf("existing output changed: %q err=%v", got, err)
	}
	newPath := filepath.Join(t.TempDir(), "pack.yaml")
	if err := writeNewRegularFile(context.Background(), newPath, []byte("synthetic\n")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(newPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("output mode=%v", info.Mode().Perm())
		}
	}
	if err := writeNewRegularFile(ctx, filepath.Join(t.TempDir(), "canceled"), []byte("synthetic\n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write error=%v", err)
	}
}

func TestPersistenceFailureDoesNotClearInterruptedInstallAfterOneAReadback(t *testing.T) {
	commitA := strings.Repeat("a", 40)
	commitB := strings.Repeat("b", 40)
	policy := publiclab.TagMovePolicy{Repository: "example/cirewind-lab", CommitA: commitA, CommitB: commitB}
	result := publiclab.TagMoveResult{
		After: commitA,
		Recovery: &publiclab.RecoveryPlan{
			Required:          true,
			ObservedTarget:    commitA,
			KnownGoodTarget:   commitA,
			ReadbackArguments: []string{"ls-remote", "REDACTED", publiclab.MutableV1Ref},
		},
	}
	err := tagRecordPersistenceError(policy, result, errors.Join(context.Canceled, publiclab.ErrTagMoveUnknown), "synthetic failure")
	if !strings.Contains(err.Error(), "outcome remains unknown") || !strings.Contains(err.Error(), "fresh remote readback is required") || strings.Contains(err.Error(), "known-good A") {
		t.Fatalf("interrupted persistence diagnostic overclaimed the A readback: %v", err)
	}
}

func TestReservedOutputRejectsPathAndParentReplacementWithoutRemovingReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit the controlled rename of open files/directories used by this regression")
	}
	t.Run("pathname replacement", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "observation.json")
		reservation, err := reserveNewRegularFile(context.Background(), path, "")
		if err != nil {
			t.Fatal(err)
		}
		reserved := reservation.(*reservedRegularFile)
		moved := filepath.Join(parent, "original-reservation")
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reserved.write(context.Background(), []byte("must-not-land\n")); err == nil {
			t.Fatal("replaced output pathname was accepted")
		}
		reserved.abort()
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "replacement\n" {
			t.Fatalf("replacement file was changed or removed: %q err=%v", data, err)
		}
	})

	t.Run("parent replacement", func(t *testing.T) {
		root := t.TempDir()
		parent := filepath.Join(root, "evidence")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "observation.json")
		reservation, err := reserveNewRegularFile(context.Background(), path, "")
		if err != nil {
			t.Fatal(err)
		}
		reserved := reservation.(*reservedRegularFile)
		movedParent := filepath.Join(root, "original-evidence")
		if err := os.Rename(parent, movedParent); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reserved.write(context.Background(), []byte("must-not-land\n")); err == nil {
			t.Fatal("replaced output parent was accepted")
		}
		reserved.abort()
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "replacement\n" {
			t.Fatalf("replacement parent file was changed or removed: %q err=%v", data, err)
		}
	})
}

func TestTerminalOutputSanitizesHostileOperation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"bad\x1b[2J\rforged"}, &stdout, &stderr)
	if code != 2 || bytes.Contains(stderr.Bytes(), []byte{0x1b}) || strings.Contains(stderr.String(), "\rforged") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func runGit(t *testing.T, git string, arguments ...string) string {
	t.Helper()
	command := exec.Command(git, arguments...)
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func remoteRef(t *testing.T, git, remote, ref string) string {
	t.Helper()
	output := runGit(t, git, "--git-dir", remote, "rev-parse", "--verify", ref)
	value := strings.TrimSpace(output)
	if len(value) != 40 {
		t.Fatalf("unexpected ref object %q (%s)", value, strconv.Quote(ref))
	}
	return value
}
