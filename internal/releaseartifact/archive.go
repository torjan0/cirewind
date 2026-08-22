package releaseartifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// ArchiveFile is one controlled regular file in a release archive.
type ArchiveFile struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// DeterministicArchive produces stable tar.gz or ZIP bytes. Source mtimes,
// owners, permissions, locale, and host archive tools never affect the result.
func DeterministicArchive(target Target, top string, epoch int64, input []ArchiveFile) ([]byte, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if _, err := safeRelativeSlashPath(top); err != nil || strings.Contains(top, "/") {
		return nil, errors.New("archive top directory must be one safe path component")
	}
	files := append([]ArchiveFile(nil), input...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	seen := make(map[string]bool, len(files))
	for i := range files {
		clean, err := safeRelativeSlashPath(files[i].Name)
		if err != nil {
			return nil, fmt.Errorf("archive entry %q: %w", files[i].Name, err)
		}
		if seen[clean] {
			return nil, fmt.Errorf("duplicate archive entry %q", clean)
		}
		seen[clean] = true
		files[i].Name = top + "/" + clean
		if files[i].Mode != 0o644 && files[i].Mode != 0o755 {
			return nil, fmt.Errorf("archive entry %q has unsupported mode %04o", clean, files[i].Mode.Perm())
		}
	}
	if len(files) == 0 {
		return nil, errors.New("release archive cannot be empty")
	}
	instant := time.Unix(epoch, 0).UTC()
	if target.OS == "windows" {
		return deterministicZIP(files, instant)
	}
	return deterministicTarGzip(files, instant)
}

func deterministicZIP(files []ArchiveFile, instant time.Time) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range files {
		header := &zip.FileHeader{Name: file.Name, Method: zip.Deflate, Modified: instant}
		header.SetMode(file.Mode)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("create ZIP entry %q: %w", file.Name, err)
		}
		if _, err := entry.Write(file.Data); err != nil {
			return nil, fmt.Errorf("write ZIP entry %q: %w", file.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close ZIP: %w", err)
	}
	return output.Bytes(), nil
}

func deterministicTarGzip(files []ArchiveFile, instant time.Time) ([]byte, error) {
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}
	gzipWriter.Header.ModTime = instant
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, file := range files {
		header := &tar.Header{
			Name:       file.Name,
			Mode:       int64(file.Mode.Perm()),
			Size:       int64(len(file.Data)),
			ModTime:    instant,
			Typeflag:   tar.TypeReg,
			Format:     tar.FormatUSTAR,
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write tar header %q: %w", file.Name, err)
		}
		if _, err := tarWriter.Write(file.Data); err != nil {
			return nil, fmt.Errorf("write tar entry %q: %w", file.Name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return output.Bytes(), nil
}

func digestHex(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

// ReadArchive returns the regular-file entries from a generated archive while
// rejecting links, devices, traversal, duplicates, excessive sizes, and other
// unexpected types.
func ReadArchive(target Target, contents []byte, maxFiles int, maxTotal int64) (map[string][]byte, error) {
	if len(contents) == 0 {
		return nil, errors.New("archive is empty")
	}
	if target.OS == "windows" {
		return readZIP(contents, maxFiles, maxTotal)
	}
	return readTarGzip(contents, maxFiles, maxTotal)
}

func readZIP(contents []byte, maxFiles int, maxTotal int64) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return nil, fmt.Errorf("open ZIP: %w", err)
	}
	if len(reader.File) > maxFiles {
		return nil, fmt.Errorf("ZIP contains %d entries, limit is %d", len(reader.File), maxFiles)
	}
	result := make(map[string][]byte, len(reader.File))
	var total int64
	for _, file := range reader.File {
		if !file.Mode().IsRegular() {
			return nil, fmt.Errorf("ZIP entry %q is not a regular file", file.Name)
		}
		clean, err := safeRelativeSlashPath(file.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe ZIP entry %q: %w", file.Name, err)
		}
		if _, duplicate := result[clean]; duplicate {
			return nil, fmt.Errorf("duplicate ZIP entry %q", clean)
		}
		if file.UncompressedSize64 > uint64(maxTotal-total) {
			return nil, errors.New("ZIP exceeds release verification size limit")
		}
		entry, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open ZIP entry %q: %w", clean, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(entry, maxTotal-total+1))
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		total += int64(len(data))
		if total > maxTotal {
			return nil, errors.New("ZIP exceeds release verification size limit")
		}
		result[clean] = data
	}
	return result, nil
}

func readTarGzip(contents []byte, maxFiles int, maxTotal int64) (map[string][]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(contents))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gzipReader.Close()
	// Account for bounded tar headers and end padding separately from retained
	// regular-file bytes; otherwise tiny valid archives can exceed maxTotal only
	// because of format overhead.
	streamLimit := maxTotal + int64(maxFiles)*4096 + 1024
	tarReader := tar.NewReader(io.LimitReader(gzipReader, streamLimit+1))
	result := make(map[string][]byte)
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if len(result) >= maxFiles {
			return nil, fmt.Errorf("tar contains more than %d entries", maxFiles)
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("tar entry %q is not a regular file", header.Name)
		}
		clean, err := safeRelativeSlashPath(header.Name)
		if err != nil {
			return nil, fmt.Errorf("unsafe tar entry %q: %w", header.Name, err)
		}
		if _, duplicate := result[clean]; duplicate {
			return nil, fmt.Errorf("duplicate tar entry %q", clean)
		}
		if header.Size < 0 || header.Size > maxTotal-total {
			return nil, errors.New("tar exceeds release verification size limit")
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read tar entry %q: %w", clean, err)
		}
		if int64(len(data)) != header.Size {
			return nil, fmt.Errorf("tar entry %q length mismatch", clean)
		}
		total += int64(len(data))
		result[clean] = data
	}
	return result, nil
}
