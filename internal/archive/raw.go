package archive

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	maxRawPayloadBytes = uint64(2 << 30)
	rawSidecarSuffix   = ".raw"
)

// RawInput describes one already-bounded exact source object. SourcePath is a
// local transient file selected by CIRewind, never a path obtained from GitHub
// content. The archive reopens, rehashes, and length-checks it before custody.
type RawInput struct {
	SHA256     string
	MediaType  string
	ByteLength uint64
	SourcePath string
}

// RawRelativePath is the portable logical path recorded in evidence and case
// bundles. Archive sidecars use the same content-hash basename under the
// archive-managed <archive.db>.raw directory.
func RawRelativePath(digest string) (string, error) {
	if !validRawDigest(digest) {
		return "", errors.New("raw payload SHA-256 is invalid")
	}
	return "raw/" + digest + ".bin", nil
}

// RetainRaw copies exact bytes into the archive's owner-only content-addressed
// sidecar and records the descriptor in SQLite. Repeating an identical input is
// a verified no-op. The sidecar is part of a raw-enabled archive set; the .db
// file alone is not a complete copy of opted-in raw evidence.
func (a *Archive) RetainRaw(ctx context.Context, input RawInput) error {
	if a == nil || a.store == nil {
		return errors.New("archive is nil")
	}
	if a.readOnly {
		return errors.New("cannot retain raw evidence in a read-only replay archive")
	}
	if err := validateRawInput(input); err != nil {
		return err
	}
	root, err := a.ensureRawRoot()
	if err != nil {
		return err
	}
	destination := filepath.Join(root, input.SHA256+".bin")
	if err := retainRawFile(ctx, input, destination); err != nil {
		return err
	}
	relative, _ := RawRelativePath(input.SHA256)
	if _, err := a.store.DB().ExecContext(ctx, `
		INSERT INTO evidence_payloads(payload_sha256,media_type,byte_length,payload,retained_path)
		VALUES(?,?,?,NULL,?) ON CONFLICT(payload_sha256) DO NOTHING`,
		input.SHA256, input.MediaType, input.ByteLength, relative); err != nil {
		return fmt.Errorf("record raw evidence payload: %w", err)
	}
	var mediaType, retainedPath string
	var byteLength int64
	var payload []byte
	if err := a.store.DB().QueryRowContext(ctx, `SELECT media_type,byte_length,payload,retained_path FROM evidence_payloads WHERE payload_sha256=?`, input.SHA256).
		Scan(&mediaType, &byteLength, &payload, &retainedPath); err != nil {
		return fmt.Errorf("verify raw evidence descriptor: %w", err)
	}
	if payload != nil || byteLength < 0 || uint64(byteLength) != input.ByteLength || mediaType != input.MediaType || retainedPath != relative {
		return errors.New("raw evidence descriptor conflicts with persisted content")
	}
	return nil
}

// CopyRaw verifies and streams one retained object to destination. It is an
// explicit raw-dependent operation: absent or corrupt sidecar content returns
// an error without affecting compact Snapshot replay.
func (a *Archive) CopyRaw(ctx context.Context, digest string, destination io.Writer) error {
	if a == nil || a.store == nil {
		return errors.New("archive is nil")
	}
	if destination == nil {
		return errors.New("raw copy destination is nil")
	}
	descriptor, err := a.rawDescriptor(ctx, digest)
	if err != nil {
		return err
	}
	path, err := a.rawObjectPath(digest)
	if err != nil {
		return err
	}
	return copyVerifiedRaw(ctx, path, descriptor.ByteLength, digest, destination)
}

// VerifyRaw verifies every raw object referenced by committed evidence. It is
// intentionally separate from Snapshot: corrupt or missing optional sidecars
// must not block replay of compact structured facts.
func (a *Archive) VerifyRaw(ctx context.Context) error {
	if a == nil || a.store == nil {
		return errors.New("archive is nil")
	}
	rows, err := a.store.DB().QueryContext(ctx, `
		SELECT DISTINCT eo.retained_payload_sha256
		FROM evidence_objects eo
		JOIN evidence_observations ob ON ob.evidence_id=eo.evidence_id
		JOIN archive_batch_collections bc ON bc.collection_id=ob.collection_id
		JOIN archive_batches b ON b.batch_id=bc.batch_id AND b.state='COMMITTED'
		WHERE eo.raw_retained=1
		ORDER BY eo.retained_payload_sha256`)
	if err != nil {
		return fmt.Errorf("enumerate raw evidence: %w", err)
	}
	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			_ = rows.Close()
			return err
		}
		digests = append(digests, digest)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, digest := range digests {
		if err := a.verifyRaw(ctx, digest); err != nil {
			return err
		}
	}
	return nil
}

func (a *Archive) applyRawAvailability(ctx context.Context, snapshot *Snapshot) error {
	digests := make(map[string]struct{})
	for _, envelope := range snapshot.Evidence {
		content := envelope.Evidence.Content
		if content.RawRetained {
			digests[content.SourceSHA256] = struct{}{}
		}
	}
	if len(digests) == 0 {
		return nil
	}
	unavailable := 0
	for digest := range digests {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.verifyRaw(ctx, digest); err != nil {
			unavailable++
		}
	}
	found := false
	for index := range snapshot.Capabilities {
		if snapshot.Capabilities[index].Name != "raw_logs" {
			continue
		}
		found = true
		details := make(map[string]string, len(snapshot.Capabilities[index].Details)+3)
		for key, value := range snapshot.Capabilities[index].Details {
			details[key] = value
		}
		details["unavailable_count"] = fmt.Sprint(unavailable)
		details["retained_count"] = fmt.Sprint(len(digests) - unavailable)
		if unavailable != 0 {
			details["availability"] = "sidecar-incomplete"
			snapshot.Capabilities[index].Status = CapabilityGap
		} else if snapshot.Capabilities[index].Status != CapabilityRetained {
			// Archive capabilities are latest-policy summaries. Existing raw
			// objects plus a later disabled collection is partial history, not a
			// claim that every collected log remains available as raw bytes.
			details["availability"] = "partial-collection-history"
			snapshot.Capabilities[index].Status = CapabilityGap
		}
		snapshot.Capabilities[index].Details = details
	}
	if !found {
		availability := "retained"
		status := CapabilityRetained
		if unavailable != 0 {
			availability, status = "sidecar-incomplete", CapabilityGap
		}
		snapshot.Capabilities = append(snapshot.Capabilities, Capability{
			Name: "raw_logs", Status: status,
			Details: map[string]string{
				"availability": availability, "unavailable_count": fmt.Sprint(unavailable),
				"retained_count": fmt.Sprint(len(digests) - unavailable),
			},
		})
	}
	return nil
}

func snapshotHasRaw(snapshot Snapshot) bool {
	for _, envelope := range snapshot.Evidence {
		if envelope.Evidence.Content.RawRetained {
			return true
		}
	}
	return false
}

func (a *Archive) verifyBatchRawPayloads(ctx context.Context, batch Batch) error {
	seen := make(map[string]struct{})
	for _, envelope := range batch.Evidence {
		content := envelope.Evidence.Content
		if !content.RawRetained {
			continue
		}
		digest := content.SourceSHA256
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}
		if err := a.verifyRaw(ctx, digest); err != nil {
			return fmt.Errorf("raw evidence %s was not safely retained before archive commit: %w", digest, err)
		}
	}
	return nil
}

func (a *Archive) verifyRaw(ctx context.Context, digest string) error {
	descriptor, err := a.rawDescriptor(ctx, digest)
	if err != nil {
		return err
	}
	path, err := a.rawObjectPath(digest)
	if err != nil {
		return err
	}
	return copyVerifiedRaw(ctx, path, descriptor.ByteLength, digest, io.Discard)
}

func (a *Archive) rawDescriptor(ctx context.Context, digest string) (RawInput, error) {
	if !validRawDigest(digest) {
		return RawInput{}, errors.New("raw payload SHA-256 is invalid")
	}
	expectedPath, _ := RawRelativePath(digest)
	var result RawInput
	var byteLength int64
	var payload []byte
	var retainedPath sql.NullString
	if err := a.store.DB().QueryRowContext(ctx, `SELECT media_type,byte_length,payload,retained_path FROM evidence_payloads WHERE payload_sha256=?`, digest).
		Scan(&result.MediaType, &byteLength, &payload, &retainedPath); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RawInput{}, errors.New("raw evidence descriptor is missing")
		}
		return RawInput{}, fmt.Errorf("read raw evidence descriptor: %w", err)
	}
	if byteLength < 0 || uint64(byteLength) > maxRawPayloadBytes || payload != nil || !retainedPath.Valid || retainedPath.String != expectedPath {
		return RawInput{}, errors.New("raw evidence descriptor is invalid")
	}
	result.SHA256, result.ByteLength = digest, uint64(byteLength)
	if err := validateRawDescriptor(result); err != nil {
		return RawInput{}, err
	}
	return result, nil
}

func (a *Archive) rawRoot() string { return a.store.Path() + rawSidecarSuffix }

func (a *Archive) rawObjectPath(digest string) (string, error) {
	if !validRawDigest(digest) {
		return "", errors.New("raw payload SHA-256 is invalid")
	}
	root := a.rawRoot()
	if err := rejectRawSymlinkComponents(filepath.Dir(root)); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect raw evidence sidecar: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !rawPermissionsAreRestrictive(info) {
		return "", errors.New("raw evidence sidecar is not an owner-only regular directory")
	}
	return filepath.Join(root, digest+".bin"), nil
}

func (a *Archive) ensureRawRoot() (string, error) {
	root := a.rawRoot()
	if err := rejectRawSymlinkComponents(filepath.Dir(root)); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return "", fmt.Errorf("create raw evidence sidecar: %w", err)
		}
		info, err = os.Lstat(root)
	}
	if err != nil {
		return "", fmt.Errorf("inspect raw evidence sidecar: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("raw evidence sidecar is not a regular directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", fmt.Errorf("protect raw evidence sidecar: %w", err)
	}
	return root, nil
}

func retainRawFile(ctx context.Context, input RawInput, destination string) error {
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("raw evidence destination is not a regular file")
		}
		if err := copyVerifiedRaw(ctx, destination, input.ByteLength, input.SHA256, io.Discard); err != nil {
			return fmt.Errorf("existing raw evidence object failed verification: %w", err)
		}
		if err := os.Chmod(destination, 0o600); err != nil {
			return fmt.Errorf("protect retained raw evidence: %w", err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect raw evidence destination: %w", err)
	}

	source, sourceInfo, err := openSameRegular(input.SourcePath)
	if err != nil {
		return fmt.Errorf("open transient raw evidence: %w", err)
	}
	defer source.Close()
	if sourceInfo.Size() < 0 || uint64(sourceInfo.Size()) != input.ByteLength {
		return errors.New("transient raw evidence length disagrees with its descriptor")
	}
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create retained raw evidence: %w", err)
	}
	keep := false
	defer func() {
		_ = destinationFile.Close()
		if !keep {
			_ = os.Remove(destination)
		}
	}()
	hasher := sha256.New()
	if err := copyRawStream(ctx, source, io.MultiWriter(destinationFile, hasher), input.ByteLength); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != input.SHA256 {
		return errors.New("transient raw evidence SHA-256 disagrees with its descriptor")
	}
	if err := destinationFile.Sync(); err != nil {
		return fmt.Errorf("sync retained raw evidence: %w", err)
	}
	if err := destinationFile.Close(); err != nil {
		return fmt.Errorf("close retained raw evidence: %w", err)
	}
	keep = true
	return nil
}

func copyVerifiedRaw(ctx context.Context, sourcePath string, expectedLength uint64, expectedSHA string, destination io.Writer) error {
	source, info, err := openSameRegular(sourcePath)
	if err != nil {
		return fmt.Errorf("open retained raw evidence: %w", err)
	}
	defer source.Close()
	if !rawPermissionsAreRestrictive(info) {
		return errors.New("retained raw evidence permissions are not owner-only")
	}
	if info.Size() < 0 || uint64(info.Size()) != expectedLength {
		return errors.New("retained raw evidence length differs from its descriptor")
	}
	hasher := sha256.New()
	if err := copyRawStream(ctx, source, io.MultiWriter(destination, hasher), expectedLength); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedSHA {
		return errors.New("retained raw evidence SHA-256 differs from its descriptor")
	}
	return nil
}

func copyRawStream(ctx context.Context, source io.Reader, destination io.Writer, expected uint64) error {
	if expected > maxRawPayloadBytes {
		return errors.New("raw evidence exceeds the compiled byte limit")
	}
	buffer := make([]byte, 128<<10)
	var copied uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := expected - copied
		readSize := len(buffer)
		if remaining < uint64(readSize) {
			readSize = int(remaining) + 1
		}
		count, readErr := source.Read(buffer[:readSize])
		if count > 0 {
			if uint64(count) > remaining {
				return errors.New("raw evidence is longer than its descriptor")
			}
			written, writeErr := destination.Write(buffer[:count])
			copied += uint64(written)
			if writeErr != nil {
				return fmt.Errorf("write raw evidence: %w", writeErr)
			}
			if written != count {
				return io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			if copied != expected {
				return errors.New("raw evidence is shorter than its descriptor")
			}
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read raw evidence: %w", readErr)
		}
		if count == 0 {
			return errors.New("raw evidence reader made no progress")
		}
	}
}

func openSameRegular(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, errors.New("raw evidence source is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, errors.New("raw evidence source changed while opening")
	}
	return file, after, nil
}

func validateRawInput(input RawInput) error {
	if err := validateRawDescriptor(input); err != nil {
		return err
	}
	if strings.TrimSpace(input.SourcePath) == "" {
		return errors.New("raw evidence source path is empty")
	}
	return nil
}

func validateRawDescriptor(input RawInput) error {
	if !validRawDigest(input.SHA256) {
		return errors.New("raw payload SHA-256 is invalid")
	}
	if input.ByteLength > maxRawPayloadBytes {
		return errors.New("raw evidence exceeds the compiled byte limit")
	}
	if err := safeText(input.MediaType, 256, false); err != nil {
		return errors.New("raw evidence media type is invalid")
	}
	return nil
}

func validRawDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func rejectRawSymlinkComponents(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("raw evidence path contains a symlink component")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect raw evidence path: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func rawPermissionsAreRestrictive(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
}
