package publiclab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// LoadArtifact reads the two fixed public-lab artifact files through the same
// bounded regular-file boundary used for reviewed source. It does not follow
// artifact-provided paths and validates that the manifest describes the bundle
// before returning either object to a caller.
func LoadArtifact(ctx context.Context, artifactDir string) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	if artifactDir == "" || filepath.Clean(artifactDir) != artifactDir || strings.IndexByte(artifactDir, 0) >= 0 {
		return Artifact{}, errors.New("artifact directory must be a nonempty clean path")
	}
	bundle, _, err := readRegularFileOnce(filepath.Join(artifactDir, BundleFilename), 16<<20)
	if err != nil {
		return Artifact{}, fmt.Errorf("read public-lab bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	manifestBytes, _, err := readRegularFileOnce(filepath.Join(artifactDir, ManifestFilename), 4<<20)
	if err != nil {
		return Artifact{}, fmt.Errorf("read public-lab object manifest: %w", err)
	}
	manifest, err := DecodeManifest(bytes.NewReader(manifestBytes))
	if err != nil {
		return Artifact{}, fmt.Errorf("decode public-lab object manifest: %w", err)
	}
	if err := validateManifest(manifest, bundle); err != nil {
		return Artifact{}, fmt.Errorf("validate public-lab artifact: %w", err)
	}
	return Artifact{Bundle: bundle, Manifest: manifestBytes, Model: manifest}, nil
}

// VerifyArtifact regenerates the reviewed source package without process or
// network access and requires exact bundle and sidecar bytes. This verifies
// deterministic construction; Git's own bundle/fsck checks remain a separate
// integration boundary.
func VerifyArtifact(ctx context.Context, sourceRoot string, bundle, manifestBytes []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(bundle) == 0 || len(bundle) > 16<<20 {
		return errors.New("bundle byte length is outside the accepted range")
	}
	if len(manifestBytes) == 0 || len(manifestBytes) > 4<<20 {
		return errors.New("manifest byte length is outside the accepted range")
	}
	manifest, err := DecodeManifest(bytes.NewReader(manifestBytes))
	if err != nil {
		return fmt.Errorf("decode object manifest: %w", err)
	}
	if err := validateManifest(manifest, bundle); err != nil {
		return err
	}
	regenerated, err := BuildForRepository(ctx, sourceRoot, manifest.Repository)
	if err != nil {
		return fmt.Errorf("regenerate public lab bundle: %w", err)
	}
	if !bytes.Equal(bundle, regenerated.Bundle) {
		return errors.New("bundle bytes differ from deterministic source regeneration")
	}
	if !bytes.Equal(manifestBytes, regenerated.Manifest) {
		return errors.New("object-manifest bytes differ from deterministic source regeneration")
	}
	return nil
}

func verifyArtifactValue(ctx context.Context, sourceRoot string, artifact Artifact) error {
	if err := verifyArtifactModel(artifact); err != nil {
		return err
	}
	return VerifyArtifact(ctx, sourceRoot, artifact.Bundle, artifact.Manifest)
}

func verifyArtifactModel(artifact Artifact) error {
	if _, err := DecodeManifest(bytes.NewReader(artifact.Manifest)); err != nil {
		return fmt.Errorf("decode artifact model manifest: %w", err)
	}
	modelBytes, err := json.MarshalIndent(artifact.Model, "", "  ")
	if err != nil {
		return errors.New("encode artifact model")
	}
	modelBytes = append(modelBytes, '\n')
	if !bytes.Equal(modelBytes, artifact.Manifest) {
		return errors.New("in-memory artifact model differs from its exact manifest bytes")
	}
	return nil
}

func validateManifest(manifest ObjectManifest, bundle []byte) error {
	if manifest.SchemaVersion != ManifestSchema {
		return fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	if !validRepositoryName(manifest.Repository) || manifest.ObjectFormat != "sha1" {
		return errors.New("manifest repository or Git object format is not the reviewed value")
	}
	if manifest.Identity != fixtureIdentity {
		return errors.New("manifest identity differs from the reviewed fixture identity")
	}
	if manifest.Bundle.Filename != BundleFilename || manifest.Bundle.Format != "git-bundle-v2" || manifest.Bundle.ByteLength != len(bundle) {
		return errors.New("manifest bundle descriptor does not match supplied bytes")
	}
	sum := sha256.Sum256(bundle)
	if manifest.Bundle.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("manifest bundle SHA-256 does not match supplied bytes")
	}
	if !manifest.Verification.BundleVerifyExpected || !manifest.Verification.FSCKExpected || manifest.Verification.PrerequisiteCount != 0 || manifest.Verification.IndependentImports != 2 {
		return errors.New("manifest verification contract is incomplete")
	}
	if len(manifest.Commits) != 6 || len(manifest.Tags) != 2 || len(manifest.Refs) != 5 || len(manifest.Objects) == 0 || len(manifest.ImportFiles) == 0 {
		return errors.New("manifest topology counts differ from the reviewed contract")
	}
	wantRoles := []string{"governance", "marker-a", "marker-b", "wrapper", "reusable", "import"}
	commitIDs := make(map[string]struct{}, len(manifest.Commits))
	for index, commit := range manifest.Commits {
		if commit.Role != wantRoles[index] || !isSHA1(commit.ObjectID) || !isSHA1(commit.TreeObjectID) {
			return fmt.Errorf("invalid commit descriptor at index %d", index)
		}
		if commit.Author != fixtureIdentity || commit.Committer != fixtureIdentity || commit.AuthorTime != commit.CommitterTime {
			return fmt.Errorf("invalid identity or timestamp for commit role %q", commit.Role)
		}
		if index == 0 {
			if len(commit.ParentObjects) != 0 {
				return errors.New("governance commit unexpectedly has a parent")
			}
		} else if len(commit.ParentObjects) != 1 || commit.ParentObjects[0] != manifest.Commits[index-1].ObjectID {
			return fmt.Errorf("invalid parent topology for commit role %q", commit.Role)
		}
		if _, duplicate := commitIDs[commit.ObjectID]; duplicate {
			return errors.New("duplicate commit object ID")
		}
		commitIDs[commit.ObjectID] = struct{}{}
	}
	wantRefs := []string{"HEAD", "refs/heads/main", "refs/tags/fixture-a", "refs/tags/fixture-b", MutableV1Ref}
	refByName := make(map[string]RefDescriptor, len(manifest.Refs))
	for index, ref := range manifest.Refs {
		if index > 0 && manifest.Refs[index-1].Name >= ref.Name {
			return errors.New("manifest refs are not strictly sorted")
		}
		if ref.Name != "HEAD" && !validRef(ref.Name) || !isSHA1(ref.ObjectID) || !isSHA1(ref.PeeledCommitID) {
			return fmt.Errorf("invalid manifest ref %q", ref.Name)
		}
		refByName[ref.Name] = ref
	}
	for _, name := range wantRefs {
		if _, ok := refByName[name]; !ok {
			return fmt.Errorf("manifest omits required ref %q", name)
		}
	}
	if refByName["HEAD"].ObjectID != manifest.Commits[5].ObjectID || refByName["refs/heads/main"].PeeledCommitID != manifest.Commits[5].ObjectID || refByName[MutableV1Ref].ObjectID != manifest.Commits[1].ObjectID {
		return errors.New("main or mutable-v1 ref does not identify the reviewed commit")
	}
	if manifest.Tags[0].Name != "fixture-a" || manifest.Tags[0].PeeledCommitID != manifest.Commits[1].ObjectID || manifest.Tags[1].Name != "fixture-b" || manifest.Tags[1].PeeledCommitID != manifest.Commits[2].ObjectID {
		return errors.New("fixture tag peel topology is invalid")
	}
	objectTypes := make(map[string]string, len(manifest.Objects))
	for _, object := range manifest.Objects {
		if !isSHA1(object.ObjectID) || object.ByteLength < 0 {
			return errors.New("invalid object descriptor")
		}
		switch object.Type {
		case "blob", "tree", "commit", "tag":
		default:
			return fmt.Errorf("unsupported object descriptor type %q", object.Type)
		}
		if _, duplicate := objectTypes[object.ObjectID]; duplicate {
			return errors.New("duplicate object descriptor")
		}
		objectTypes[object.ObjectID] = object.Type
	}
	for _, commit := range manifest.Commits {
		if objectTypes[commit.ObjectID] != "commit" || objectTypes[commit.TreeObjectID] != "tree" {
			return fmt.Errorf("commit role %q is not cross-bound to commit/tree object descriptors", commit.Role)
		}
	}
	for index, tag := range manifest.Tags {
		if tag.Kind != "annotated" || !isSHA1(tag.ObjectID) || !isSHA1(tag.PeeledCommitID) || tag.Tagger != fixtureIdentity || tag.TaggedAt == "" || objectTypes[tag.ObjectID] != "tag" || objectTypes[tag.PeeledCommitID] != "commit" {
			return fmt.Errorf("fixture tag descriptor %d is not cross-bound to reviewed Git objects", index)
		}
	}
	if refByName["refs/tags/fixture-a"].ObjectID != manifest.Tags[0].ObjectID || refByName["refs/tags/fixture-a"].PeeledCommitID != manifest.Tags[0].PeeledCommitID || refByName["refs/tags/fixture-b"].ObjectID != manifest.Tags[1].ObjectID || refByName["refs/tags/fixture-b"].PeeledCommitID != manifest.Tags[1].PeeledCommitID {
		return errors.New("fixture refs do not identify the annotated tag descriptors")
	}
	if objectTypes[refByName[MutableV1Ref].ObjectID] != "commit" {
		return errors.New("mutable v1 does not identify a commit object")
	}
	lastPath := ""
	for _, file := range manifest.ImportFiles {
		if err := validateSourcePath(file.Path); err != nil {
			return err
		}
		if lastPath != "" && lastPath >= file.Path {
			return errors.New("import files are not strictly sorted")
		}
		lastPath = file.Path
		if file.Mode != "100644" && file.Mode != "100755" || !isSHA1(file.BlobObject) || file.ByteLength < 0 || len(file.SHA256) != sha256.Size*2 || strings.ToLower(file.SHA256) != file.SHA256 {
			return fmt.Errorf("invalid import file descriptor for %q", file.Path)
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil {
			return fmt.Errorf("invalid import SHA-256 for %q", file.Path)
		}
	}
	return nil
}
