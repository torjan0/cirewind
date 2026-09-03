package publiclab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const ObservationsRef = "refs/heads/observations"

// VerifyPackInputSourceCommit proves that the exact pack-input and both exact
// tag-move derivation records are present at the immutable URL revision in a
// local, owner-specialized lab clone. The default main ref must remain exact
// import I; observation and provenance commits live only on the dedicated
// non-default observations ref. This function performs no network request.
func VerifyPackInputSourceCommit(ctx context.Context, runner GitCommandBoundary, worktree string, artifact Artifact, packInput, installRecord, restoreRecord []byte, sourceURL string) error {
	if runner == nil || !filepath.IsAbs(worktree) || filepath.Clean(worktree) != worktree {
		return errors.New("pack-input source verification requires an absolute reviewed worktree")
	}
	if err := verifyArtifactModel(artifact); err != nil {
		return err
	}
	if err := rejectDuplicateJSONKeys(packInput); err != nil {
		return errors.New("pack-input source record is not strict JSON")
	}
	var document packInputDocument
	decoder := json.NewDecoder(bytes.NewReader(packInput))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return errors.New("decode pack-input source record")
	}
	record := document.labPackInputRecord
	if err := validatePackInputSemantics(record); err != nil {
		return err
	}
	if err := validatePackInputDerivation(record, installRecord, restoreRecord, artifact); err != nil {
		return err
	}
	revision, err := immutableRecordRevision(sourceURL, record.LabRepository.FullName, record.RecordID)
	if err != nil {
		return err
	}
	commits := make(map[string]string, len(artifact.Model.Commits))
	for _, commit := range artifact.Model.Commits {
		commits[commit.Role] = commit.ObjectID
	}
	importCommit := commits["import"]
	if !isSHA1(importCommit) || revision == importCommit {
		return errors.New("pack-input must live in a later observations commit, not import I")
	}
	for ref, want := range map[string]string{
		"refs/heads/main": importCommit,
		ObservationsRef:   revision,
	} {
		output, commandErr := runBounded(ctx, runner, worktree, "rev-parse", "--verify", ref)
		if commandErr != nil || trimOneLine(output) != want {
			return fmt.Errorf("local %s does not equal the required immutable commit", ref)
		}
	}
	typeOutput, err := runBounded(ctx, runner, worktree, "cat-file", "-t", revision)
	if err != nil || trimOneLine(typeOutput) != "commit" {
		return errors.New("pack-input source revision is not a local commit")
	}
	if _, err := runBounded(ctx, runner, worktree, "merge-base", "--is-ancestor", importCommit, revision); err != nil {
		return errors.New("observations commit does not descend from exact import I")
	}
	for _, retained := range []struct {
		kind     string
		recordID string
		data     []byte
	}{
		{kind: "install tag-move", recordID: record.DerivationInputs[0].RecordID, data: installRecord},
		{kind: "restore tag-move", recordID: record.DerivationInputs[1].RecordID, data: restoreRecord},
		{kind: "pack-input", recordID: record.RecordID, data: packInput},
	} {
		path := "observations/" + retained.recordID + ".json"
		content, contentErr := runBounded(ctx, runner, worktree, "cat-file", "-p", revision+":"+path)
		if contentErr != nil {
			return fmt.Errorf("%s path is absent from the immutable observations commit", retained.kind)
		}
		if !bytes.Equal(content, retained.data) {
			return fmt.Errorf("%s bytes differ from the immutable observations commit", retained.kind)
		}
	}
	if strings.Contains(sourceURL, "refs/heads/") {
		return errors.New("pack-input source URL must identify a commit, not a branch")
	}
	return nil
}
