// Package publiclab builds and verifies the inert, exportable CIRewind public
// laboratory source package. It creates Git objects as data; it never executes
// the Action or workflow content contained in those objects.
package publiclab

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1" // Git SHA-1 object identity; never used as an integrity claim.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ManifestSchema = "cirewind.public-lab-object-manifest/v1alpha1"
	RepositoryName = "torjan0/cirewind-lab"
	MutableV1Ref   = "refs/tags/v1"

	BundleFilename   = "cirewind-lab.bundle"
	ManifestFilename = "object-manifest.json"

	maxSourceFiles = 192
	maxSourceFile  = 512 << 10
	maxSourceTotal = 4 << 20
	maxManifest    = 4 << 20
)

var (
	fixtureIdentity = Identity{
		Name:  "torjan0",
		Email: "38338151+torjan0@users.noreply.github.com",
	}
	baseObjectTime = time.Date(2026, time.August, 31, 0, 0, 0, 0, time.UTC)
)

// Identity is the reviewed deterministic author/tagger identity embedded in
// the exportable lab history. It contains no authentication material.
type Identity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Artifact is a complete deterministic lab bundle and its sidecar manifest.
type Artifact struct {
	Bundle   []byte
	Manifest []byte
	Model    ObjectManifest
}

// ObjectManifest binds the bundle bytes, Git object topology, intended refs,
// and final imported tree without creating a Git-object self-reference.
type ObjectManifest struct {
	SchemaVersion string               `json:"schemaVersion"`
	Repository    string               `json:"repository"`
	ObjectFormat  string               `json:"objectFormat"`
	Bundle        BundleDescriptor     `json:"bundle"`
	Identity      Identity             `json:"identity"`
	Commits       []CommitDescriptor   `json:"commits"`
	Tags          []TagDescriptor      `json:"tags"`
	Refs          []RefDescriptor      `json:"refs"`
	Objects       []ObjectDescriptor   `json:"objects"`
	ImportFiles   []ImportFile         `json:"importFiles"`
	Verification  VerificationContract `json:"verification"`
}

type BundleDescriptor struct {
	Filename   string `json:"filename"`
	Format     string `json:"format"`
	ByteLength int    `json:"byteLength"`
	SHA256     string `json:"sha256"`
}

type CommitDescriptor struct {
	Role          string   `json:"role"`
	ObjectID      string   `json:"objectId"`
	TreeObjectID  string   `json:"treeObjectId"`
	ParentObjects []string `json:"parentObjects"`
	Subject       string   `json:"subject"`
	Author        Identity `json:"author"`
	AuthorTime    string   `json:"authorTime"`
	Committer     Identity `json:"committer"`
	CommitterTime string   `json:"committerTime"`
}

type TagDescriptor struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	ObjectID       string   `json:"objectId"`
	PeeledCommitID string   `json:"peeledCommitId"`
	Tagger         Identity `json:"tagger"`
	TaggedAt       string   `json:"taggedAt"`
}

type RefDescriptor struct {
	Name           string `json:"name"`
	ObjectID       string `json:"objectId"`
	Kind           string `json:"kind"`
	PeeledCommitID string `json:"peeledCommitId,omitempty"`
}

type ObjectDescriptor struct {
	ObjectID   string `json:"objectId"`
	Type       string `json:"type"`
	ByteLength int    `json:"byteLength"`
}

type ImportFile struct {
	Path       string `json:"path"`
	Mode       string `json:"mode"`
	BlobObject string `json:"blobObjectId"`
	ByteLength int    `json:"byteLength"`
	SHA256     string `json:"sha256"`
}

type VerificationContract struct {
	BundleVerifyExpected bool `json:"bundleVerifyExpected"`
	FSCKExpected         bool `json:"fsckExpected"`
	PrerequisiteCount    int  `json:"prerequisiteCount"`
	IndependentImports   int  `json:"independentImports"`
}

type sourceFile struct {
	data []byte
	mode string
}

type gitObject struct {
	typ  string
	data []byte
}

type objectStore struct {
	objects map[string]gitObject
}

type commitBuild struct {
	role    string
	subject string
	oid     string
	tree    string
	parent  string
	at      time.Time
	files   map[string]sourceFile
}

// Build constructs the canonical CIRewind-owned public-lab bundle.
func Build(ctx context.Context, sourceRoot string) (Artifact, error) {
	return BuildForRepository(ctx, sourceRoot, RepositoryName)
}

// BuildForRepository constructs the complete deterministic bundle for one
// explicit GitHub owner/repository. Repository substitution is limited to the
// reviewed uses: fields; it lets an independently owned copy move its own v1
// instead of accidentally executing the canonical repository's mutable ref. No
// process or network operation occurs.
func BuildForRepository(ctx context.Context, sourceRoot, repository string) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	if !validRepositoryName(repository) {
		return Artifact{}, errors.New("public-lab repository must be an exact owner/name")
	}
	overlayNames := []string{"common", "marker-a", "marker-b", "wrapper", "reusable", "import"}
	overlays := make(map[string]map[string]sourceFile, len(overlayNames))
	for _, name := range overlayNames {
		files, err := readOverlay(ctx, filepath.Join(sourceRoot, name))
		if err != nil {
			return Artifact{}, fmt.Errorf("read %s overlay: %w", name, err)
		}
		overlays[name] = files
	}

	store := &objectStore{objects: make(map[string]gitObject)}
	base := cloneFiles(overlays["common"])
	commits := make([]commitBuild, 0, 6)

	governance, err := buildCommit(store, "governance", "chore: establish public lab governance", base, "", baseObjectTime)
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, governance)

	aFiles := cloneFiles(base)
	applyOverlay(aFiles, overlays["marker-a"])
	a, err := buildCommit(store, "marker-a", "feat: add harmless marker A", aFiles, governance.oid, baseObjectTime.Add(time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, a)

	bFiles := cloneFiles(aFiles)
	applyOverlay(bFiles, overlays["marker-b"])
	b, err := buildCommit(store, "marker-b", "test: add harmless affected marker B", bFiles, a.oid, baseObjectTime.Add(2*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, b)

	wrapperFiles := cloneFiles(bFiles)
	applyOverlay(wrapperFiles, overlays["marker-a"])
	wrapperOverlay, err := substituteOverlay(overlays["wrapper"], map[string]string{
		"{{LAB_REPOSITORY}}": repository,
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("substitute wrapper overlay: %w", err)
	}
	applyOverlay(wrapperFiles, wrapperOverlay)
	wrapper, err := buildCommit(store, "wrapper", "feat: restore marker A and add stable wrapper", wrapperFiles, b.oid, baseObjectTime.Add(3*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, wrapper)

	reusableOverlay, err := substituteOverlay(overlays["reusable"], map[string]string{
		"{{WRAPPER_COMMIT}}": wrapper.oid,
		"{{LAB_REPOSITORY}}": repository,
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("substitute reusable overlay: %w", err)
	}
	reusableFiles := cloneFiles(wrapperFiles)
	applyOverlay(reusableFiles, reusableOverlay)
	reusable, err := buildCommit(store, "reusable", "feat: add stable reusable workflow", reusableFiles, wrapper.oid, baseObjectTime.Add(4*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, reusable)

	importOverlay, err := substituteOverlay(overlays["import"], map[string]string{
		"{{WRAPPER_COMMIT}}":  wrapper.oid,
		"{{REUSABLE_COMMIT}}": reusable.oid,
		"{{LAB_REPOSITORY}}":  repository,
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("substitute import overlay: %w", err)
	}
	importFiles := cloneFiles(reusableFiles)
	applyOverlay(importFiles, importOverlay)
	if err := rejectTemplateMarkers(importFiles); err != nil {
		return Artifact{}, err
	}
	if err := validateResolvedFiles(importFiles); err != nil {
		return Artifact{}, err
	}
	importCommit, err := buildCommit(store, "import", "feat: add public A-to-B-to-A scenarios", importFiles, reusable.oid, baseObjectTime.Add(5*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	commits = append(commits, importCommit)

	fixtureA, err := buildAnnotatedTag(store, "fixture-a", a.oid, "CIRewind harmless public lab marker A", baseObjectTime.Add(6*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	fixtureB, err := buildAnnotatedTag(store, "fixture-b", b.oid, "CIRewind harmless affected public lab marker B", baseObjectTime.Add(7*time.Minute))
	if err != nil {
		return Artifact{}, err
	}
	if len(store.objects) > 512 {
		return Artifact{}, errors.New("generated Git object count exceeds 512")
	}

	refs := []RefDescriptor{
		{Name: "HEAD", ObjectID: importCommit.oid, Kind: "bundle-head", PeeledCommitID: importCommit.oid},
		{Name: "refs/heads/main", ObjectID: importCommit.oid, Kind: "branch", PeeledCommitID: importCommit.oid},
		{Name: "refs/tags/fixture-a", ObjectID: fixtureA, Kind: "annotated-tag", PeeledCommitID: a.oid},
		{Name: "refs/tags/fixture-b", ObjectID: fixtureB, Kind: "annotated-tag", PeeledCommitID: b.oid},
		{Name: MutableV1Ref, ObjectID: a.oid, Kind: "lightweight-tag", PeeledCommitID: a.oid},
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	bundle, err := encodeBundle(store, refs)
	if err != nil {
		return Artifact{}, err
	}
	if len(bundle) > 16<<20 {
		return Artifact{}, errors.New("generated bundle exceeds 16 MiB")
	}
	manifest := buildManifest(store, commits, refs, []TagDescriptor{
		{Name: "fixture-a", Kind: "annotated", ObjectID: fixtureA, PeeledCommitID: a.oid, Tagger: fixtureIdentity, TaggedAt: canonicalTime(baseObjectTime.Add(6 * time.Minute))},
		{Name: "fixture-b", Kind: "annotated", ObjectID: fixtureB, PeeledCommitID: b.oid, Tagger: fixtureIdentity, TaggedAt: canonicalTime(baseObjectTime.Add(7 * time.Minute))},
	}, repository, importFiles, bundle)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Artifact{}, fmt.Errorf("encode object manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	return Artifact{Bundle: bundle, Manifest: manifestBytes, Model: manifest}, nil
}

func buildCommit(store *objectStore, role, subject string, files map[string]sourceFile, parent string, at time.Time) (commitBuild, error) {
	tree, err := buildTree(store, files)
	if err != nil {
		return commitBuild{}, fmt.Errorf("build %s tree: %w", role, err)
	}
	var body strings.Builder
	fmt.Fprintf(&body, "tree %s\n", tree)
	if parent != "" {
		fmt.Fprintf(&body, "parent %s\n", parent)
	}
	identity := gitIdentity(fixtureIdentity, at)
	fmt.Fprintf(&body, "author %s\ncommitter %s\n\n%s\n\nSigned-off-by: %s <%s>\n", identity, identity, subject, fixtureIdentity.Name, fixtureIdentity.Email)
	oid, err := store.add("commit", []byte(body.String()))
	if err != nil {
		return commitBuild{}, err
	}
	return commitBuild{role: role, subject: subject, oid: oid, tree: tree, parent: parent, at: at, files: cloneFiles(files)}, nil
}

func buildAnnotatedTag(store *objectStore, name, commit, subject string, at time.Time) (string, error) {
	if !safeRefComponent(name) || !isSHA1(commit) {
		return "", errors.New("invalid annotated tag input")
	}
	data := fmt.Sprintf("object %s\ntype commit\ntag %s\ntagger %s\n\n%s\n\nSigned-off-by: %s <%s>\n",
		commit, name, gitIdentity(fixtureIdentity, at), subject, fixtureIdentity.Name, fixtureIdentity.Email)
	return store.add("tag", []byte(data))
}

func buildManifest(store *objectStore, commits []commitBuild, refs []RefDescriptor, tags []TagDescriptor, repository string, importFiles map[string]sourceFile, bundle []byte) ObjectManifest {
	digest := sha256.Sum256(bundle)
	model := ObjectManifest{
		SchemaVersion: ManifestSchema,
		Repository:    repository,
		ObjectFormat:  "sha1",
		Bundle: BundleDescriptor{
			Filename: BundleFilename, Format: "git-bundle-v2", ByteLength: len(bundle), SHA256: hex.EncodeToString(digest[:]),
		},
		Identity: fixtureIdentity,
		Tags:     append([]TagDescriptor(nil), tags...),
		Refs:     append([]RefDescriptor(nil), refs...),
		Verification: VerificationContract{
			BundleVerifyExpected: true, FSCKExpected: true, PrerequisiteCount: 0, IndependentImports: 2,
		},
	}
	for _, commit := range commits {
		parents := []string{}
		if commit.parent != "" {
			parents = append(parents, commit.parent)
		}
		model.Commits = append(model.Commits, CommitDescriptor{
			Role: commit.role, ObjectID: commit.oid, TreeObjectID: commit.tree, ParentObjects: parents,
			Subject: commit.subject, Author: fixtureIdentity, AuthorTime: canonicalTime(commit.at),
			Committer: fixtureIdentity, CommitterTime: canonicalTime(commit.at),
		})
	}
	objectIDs := sortedObjectIDs(store)
	for _, oid := range objectIDs {
		obj := store.objects[oid]
		model.Objects = append(model.Objects, ObjectDescriptor{ObjectID: oid, Type: obj.typ, ByteLength: len(obj.data)})
	}
	paths := make([]string, 0, len(importFiles))
	for path := range importFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file := importFiles[path]
		blob := objectID("blob", file.data)
		sum := sha256.Sum256(file.data)
		model.ImportFiles = append(model.ImportFiles, ImportFile{
			Path: path, Mode: file.mode, BlobObject: blob, ByteLength: len(file.data), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return model
}

func encodeBundle(store *objectStore, refs []RefDescriptor) ([]byte, error) {
	var header bytes.Buffer
	header.WriteString("# v2 git bundle\n")
	for _, ref := range refs {
		if !isSHA1(ref.ObjectID) || ref.Name != "HEAD" && !validRef(ref.Name) {
			return nil, fmt.Errorf("invalid bundle ref %q", ref.Name)
		}
		fmt.Fprintf(&header, "%s %s\n", ref.ObjectID, ref.Name)
	}
	header.WriteByte('\n')

	var pack bytes.Buffer
	pack.WriteString("PACK")
	_ = binary.Write(&pack, binary.BigEndian, uint32(2))
	ids := sortedObjectIDs(store)
	_ = binary.Write(&pack, binary.BigEndian, uint32(len(ids)))
	for _, oid := range ids {
		obj := store.objects[oid]
		typeCode, ok := map[string]byte{"commit": 1, "tree": 2, "blob": 3, "tag": 4}[obj.typ]
		if !ok {
			return nil, fmt.Errorf("unsupported Git object type %q", obj.typ)
		}
		pack.Write(encodePackObjectHeader(typeCode, len(obj.data)))
		writer, err := zlib.NewWriterLevel(&pack, zlib.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("create pack compressor: %w", err)
		}
		if _, err := writer.Write(obj.data); err != nil {
			return nil, fmt.Errorf("compress %s object: %w", obj.typ, err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("finish %s object compression: %w", obj.typ, err)
		}
	}
	checksum := sha1.Sum(pack.Bytes()) // Git pack trailer, not an integrity claim.
	pack.Write(checksum[:])
	header.Write(pack.Bytes())
	return header.Bytes(), nil
}

func encodePackObjectHeader(typeCode byte, size int) []byte {
	first := byte(size&0x0f) | typeCode<<4
	size >>= 4
	if size != 0 {
		first |= 0x80
	}
	out := []byte{first}
	for size != 0 {
		next := byte(size & 0x7f)
		size >>= 7
		if size != 0 {
			next |= 0x80
		}
		out = append(out, next)
	}
	return out
}

func buildTree(store *objectStore, files map[string]sourceFile) (string, error) {
	root := &treeNode{dirs: map[string]*treeNode{}, files: map[string]sourceFile{}}
	for path, file := range files {
		parts := strings.Split(path, "/")
		node := root
		for _, part := range parts[:len(parts)-1] {
			if _, exists := node.files[part]; exists {
				return "", fmt.Errorf("file/directory collision at %q", part)
			}
			child := node.dirs[part]
			if child == nil {
				child = &treeNode{dirs: map[string]*treeNode{}, files: map[string]sourceFile{}}
				node.dirs[part] = child
			}
			node = child
		}
		name := parts[len(parts)-1]
		if _, exists := node.dirs[name]; exists {
			return "", fmt.Errorf("directory/file collision at %q", name)
		}
		node.files[name] = file
	}
	return writeTree(store, root)
}

type treeNode struct {
	dirs  map[string]*treeNode
	files map[string]sourceFile
}

type treeEntry struct {
	name string
	mode string
	oid  string
	dir  bool
}

func writeTree(store *objectStore, node *treeNode) (string, error) {
	entries := make([]treeEntry, 0, len(node.dirs)+len(node.files))
	for name, child := range node.dirs {
		oid, err := writeTree(store, child)
		if err != nil {
			return "", err
		}
		entries = append(entries, treeEntry{name: name, mode: "40000", oid: oid, dir: true})
	}
	for name, file := range node.files {
		oid, err := store.add("blob", file.data)
		if err != nil {
			return "", err
		}
		entries = append(entries, treeEntry{name: name, mode: file.mode, oid: oid})
	}
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i].name, entries[j].name
		if entries[i].dir {
			left += "/"
		}
		if entries[j].dir {
			right += "/"
		}
		return left < right
	})
	var data bytes.Buffer
	for _, entry := range entries {
		fmt.Fprintf(&data, "%s %s", entry.mode, entry.name)
		data.WriteByte(0)
		raw, err := hex.DecodeString(entry.oid)
		if err != nil || len(raw) != sha1.Size {
			return "", fmt.Errorf("decode tree object ID %q", entry.oid)
		}
		data.Write(raw)
	}
	return store.add("tree", data.Bytes())
}

func (store *objectStore) add(typ string, data []byte) (string, error) {
	oid := objectID(typ, data)
	if existing, ok := store.objects[oid]; ok {
		if existing.typ != typ || !bytes.Equal(existing.data, data) {
			return "", errors.New("distinct Git objects have the same SHA-1 identity")
		}
		return oid, nil
	}
	store.objects[oid] = gitObject{typ: typ, data: append([]byte(nil), data...)}
	return oid, nil
}

func objectID(typ string, data []byte) string {
	h := sha1.New() // Git object identity, not evidence integrity.
	fmt.Fprintf(h, "%s %d%c", typ, len(data), byte(0))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func sortedObjectIDs(store *objectStore) []string {
	ids := make([]string, 0, len(store.objects))
	for oid := range store.objects {
		ids = append(ids, oid)
	}
	sort.Slice(ids, func(i, j int) bool {
		left, right := store.objects[ids[i]], store.objects[ids[j]]
		order := map[string]int{"commit": 1, "tree": 2, "blob": 3, "tag": 4}
		if order[left.typ] != order[right.typ] {
			return order[left.typ] < order[right.typ]
		}
		return ids[i] < ids[j]
	})
	return ids
}

func readOverlay(ctx context.Context, root string) (map[string]sourceFile, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("overlay root must be a real directory")
	}
	files := make(map[string]sourceFile)
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("unsupported source entry %q", path)
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validateSourcePath(rel); err != nil {
			return err
		}
		if len(files) >= maxSourceFiles {
			return fmt.Errorf("source file count exceeds %d", maxSourceFiles)
		}
		data, _, err := readRegularFileOnce(path, maxSourceFile)
		if err != nil {
			return fmt.Errorf("read source file %q: %w", rel, err)
		}
		total += int64(len(data))
		if total > maxSourceTotal {
			return fmt.Errorf("source overlay exceeds %d bytes", maxSourceTotal)
		}
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return fmt.Errorf("source file %q must be UTF-8 text without NUL", rel)
		}
		mode := "100644"
		if strings.HasSuffix(rel, ".sh") {
			mode = "100755"
		}
		files[rel] = sourceFile{data: data, mode: mode}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("overlay contains no files")
	}
	return files, nil
}

func validateSourcePath(path string) error {
	if path == "" || len(path) > 4096 || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || !utf8.ValidString(path) {
		return fmt.Errorf("unsafe source path %q", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || windowsReservedName(part) {
			return fmt.Errorf("unsafe source path %q", path)
		}
		for _, character := range part {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._+-", character) {
				continue
			}
			return fmt.Errorf("unsafe source path %q", path)
		}
	}
	return nil
}

func windowsReservedName(component string) bool {
	base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

// readRegularFileOnce opens one reviewed regular-file object, verifies that the
// pathname still identifies that opened object, and streams at most limit+1
// bytes from the single descriptor. It rejects symlink swaps and size or
// modification-time changes observed across the read.
func readRegularFileOnce(path string, limit int64) ([]byte, fs.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("input is not a regular file")
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil {
		return nil, nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return nil, nil, errors.New("input path changed while it was opened")
	}
	if opened.Size() < 0 || opened.Size() > limit {
		return nil, nil, errors.New("input exceeds the accepted byte limit")
	}
	data, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("input grew beyond the accepted byte limit")
	}
	finished, err := handle.Stat()
	if err != nil {
		return nil, nil, err
	}
	finalPath, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(opened, finished) || !os.SameFile(finalPath, finished) ||
		finished.Size() != opened.Size() || int64(len(data)) != finished.Size() ||
		!finished.ModTime().Equal(opened.ModTime()) {
		return nil, nil, errors.New("input changed while it was read")
	}
	return data, opened, nil
}

func substituteOverlay(in map[string]sourceFile, replacements map[string]string) (map[string]sourceFile, error) {
	out := cloneFiles(in)
	paths := make([]string, 0, len(out))
	for path := range out {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	markers := make([]string, 0, len(replacements))
	for marker := range replacements {
		markers = append(markers, marker)
	}
	sort.Strings(markers)
	for _, path := range paths {
		file := out[path]
		text := string(file.data)
		for _, marker := range markers {
			text = strings.ReplaceAll(text, marker, replacements[marker])
		}
		file.data = []byte(text)
		out[path] = file
	}
	for _, marker := range markers {
		found := false
		for _, file := range in {
			if bytes.Contains(file.data, []byte(marker)) {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("required template marker %s is absent", marker)
		}
	}
	return out, nil
}

func rejectTemplateMarkers(files map[string]sourceFile) error {
	for path, file := range files {
		for _, marker := range []string{"{{WRAPPER_COMMIT}}", "{{REUSABLE_COMMIT}}", "{{LAB_REPOSITORY}}"} {
			if bytes.Contains(file.data, []byte(marker)) {
				return fmt.Errorf("unresolved template marker %s in %q", marker, path)
			}
		}
	}
	return nil
}

func validateResolvedFiles(files map[string]sourceFile) error {
	if len(files) == 0 || len(files) > maxSourceFiles {
		return fmt.Errorf("resolved import file count %d is outside 1..%d", len(files), maxSourceFiles)
	}
	var total int
	for path, file := range files {
		if err := validateSourcePath(path); err != nil {
			return err
		}
		if len(file.data) > maxSourceFile {
			return fmt.Errorf("resolved source file %q exceeds %d bytes", path, maxSourceFile)
		}
		total += len(file.data)
		if total > maxSourceTotal {
			return fmt.Errorf("resolved source exceeds %d bytes", maxSourceTotal)
		}
		if file.mode != "100644" && file.mode != "100755" {
			return fmt.Errorf("resolved source file %q has unsupported mode %q", path, file.mode)
		}
	}
	return nil
}

func cloneFiles(in map[string]sourceFile) map[string]sourceFile {
	out := make(map[string]sourceFile, len(in))
	for path, file := range in {
		out[path] = sourceFile{data: append([]byte(nil), file.data...), mode: file.mode}
	}
	return out
}

func applyOverlay(dst, overlay map[string]sourceFile) {
	for path, file := range overlay {
		dst[path] = sourceFile{data: append([]byte(nil), file.data...), mode: file.mode}
	}
}

func gitIdentity(identity Identity, at time.Time) string {
	return fmt.Sprintf("%s <%s> %d +0000", identity.Name, identity.Email, at.Unix())
}

func canonicalTime(at time.Time) string { return at.UTC().Format(time.RFC3339) }

func isSHA1(value string) bool {
	if len(value) != sha1.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func safeRefComponent(value string) bool {
	return value != "" && !strings.ContainsAny(value, " ~^:?*[\\\r\n") && !strings.Contains(value, "..") && !strings.HasPrefix(value, ".") && !strings.HasSuffix(value, ".")
}

func validRef(value string) bool {
	if !strings.HasPrefix(value, "refs/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || strings.Contains(value, "@{") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !safeRefComponent(part) {
			return false
		}
	}
	return true
}

// WriteArtifact publishes generated files into an existing empty directory.
// Refusing overwrite keeps reviewed bytes from being silently replaced.
func WriteArtifact(ctx context.Context, outputDir string, artifact Artifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(outputDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output must be a real directory")
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("output directory must be empty")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{BundleFilename, artifact.Bundle}, {ManifestFilename, artifact.Manifest}} {
		path := filepath.Join(outputDir, file.name)
		handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", file.name, err)
		}
		if _, err := handle.Write(file.data); err != nil {
			_ = handle.Close()
			return fmt.Errorf("write %s: %w", file.name, err)
		}
		if err := handle.Sync(); err != nil {
			_ = handle.Close()
			return fmt.Errorf("sync %s: %w", file.name, err)
		}
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close %s: %w", file.name, err)
		}
	}
	return nil
}

// DecodeManifest rejects unknown fields and trailing data. More extensive
// topology verification is performed by VerifyArtifact.
func DecodeManifest(reader io.Reader) (ObjectManifest, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxManifest+1))
	if err != nil || len(data) == 0 || len(data) > maxManifest || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return ObjectManifest{}, errors.New("object manifest is empty, oversized, or not valid UTF-8 JSON")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return ObjectManifest{}, errors.New("object manifest is not strict JSON")
	}
	var untyped any
	if err := json.Unmarshal(data, &untyped); err != nil {
		return ObjectManifest{}, errors.New("object manifest is not valid JSON")
	}
	if err := scanPublicRecordStrings(untyped); err != nil {
		return ObjectManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest ObjectManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ObjectManifest{}, errors.New("object manifest violates the reviewed schema")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ObjectManifest{}, errors.New("object manifest has trailing JSON data")
	}
	return manifest, nil
}
