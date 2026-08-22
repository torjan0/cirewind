package logparse

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ArchiveLimits are hard parser budgets. Values must be positive and must not
// exceed the compiled ceilings returned by HardArchiveLimits.
type ArchiveLimits struct {
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	MaxEntryBytes        int64
	MaxFiles             int
	MaxCompressionRatio  uint64
	MaxNameBytes         int
}

func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxCompressedBytes:   512 << 20,
		MaxUncompressedBytes: 2 << 30,
		MaxEntryBytes:        256 << 20,
		MaxFiles:             20_000,
		MaxCompressionRatio:  100,
		MaxNameBytes:         4_096,
	}
}

func HardArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxCompressedBytes:   2 << 30,
		MaxUncompressedBytes: 8 << 30,
		MaxEntryBytes:        1 << 30,
		MaxFiles:             100_000,
		MaxCompressionRatio:  200,
		MaxNameBytes:         4_096,
	}
}

func (l ArchiveLimits) Validate() error {
	hard := HardArchiveLimits()
	if l.MaxCompressedBytes <= 0 || l.MaxCompressedBytes > hard.MaxCompressedBytes ||
		l.MaxUncompressedBytes <= 0 || l.MaxUncompressedBytes > hard.MaxUncompressedBytes ||
		l.MaxEntryBytes <= 0 || l.MaxEntryBytes > hard.MaxEntryBytes ||
		l.MaxFiles <= 0 || l.MaxFiles > hard.MaxFiles ||
		l.MaxCompressionRatio <= 0 || l.MaxCompressionRatio > hard.MaxCompressionRatio ||
		l.MaxNameBytes <= 0 || l.MaxNameBytes > hard.MaxNameBytes {
		return errors.New("archive limits must be positive and within compiled hard ceilings")
	}
	return nil
}

type ArchiveDiagnostic struct {
	Entry string `json:"entry,omitempty"`
	Code  string `json:"code"`
	Fatal bool   `json:"fatal"`
	Error string `json:"error,omitempty"`
}

type ArchiveResult struct {
	EntriesRead int                 `json:"entriesRead"`
	BytesRead   int64               `json:"bytesRead"`
	Complete    bool                `json:"complete"`
	Diagnostics []ArchiveDiagnostic `json:"diagnostics,omitempty"`
}

type Entry struct {
	Index            int    `json:"index"`
	LogicalName      string `json:"logicalName"`
	CompressedSize   uint64 `json:"compressedSize"`
	UncompressedSize uint64 `json:"uncompressedSize"`
}

type EntryHandler func(context.Context, Entry, io.Reader) error

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:`)

// ReadZIP streams regular entries without materializing archive-provided paths.
// Unsafe entries are rejected and make the result incomplete.
func ReadZIP(ctx context.Context, source io.ReaderAt, compressedSize int64, limits ArchiveLimits, handler EntryHandler) (ArchiveResult, error) {
	result := ArchiveResult{Complete: true}
	if err := limits.Validate(); err != nil {
		return result, err
	}
	if compressedSize < 0 || compressedSize > limits.MaxCompressedBytes {
		return result, fmt.Errorf("compressed archive exceeds limit: %d", compressedSize)
	}
	zr, err := zip.NewReader(source, compressedSize)
	if err != nil {
		return result, fmt.Errorf("open workflow log ZIP: %w", err)
	}
	if len(zr.File) > limits.MaxFiles {
		return result, fmt.Errorf("ZIP file count %d exceeds limit %d", len(zr.File), limits.MaxFiles)
	}

	seen := make(map[string]string, len(zr.File))
	for index, file := range zr.File {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		name, err := validateEntry(file, limits)
		if err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: boundedName(file.Name), Code: "UNSAFE_ARCHIVE_ENTRY", Error: err.Error()})
			continue
		}
		folded := strings.ToLower(name)
		if previous, exists := seen[folded]; exists {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: name, Code: "AMBIGUOUS_DUPLICATE_ENTRY", Error: fmt.Sprintf("collides with %q", previous)})
			continue
		}
		seen[folded] = name

		if file.FileInfo().IsDir() {
			continue
		}
		if file.UncompressedSize64 > uint64(limits.MaxEntryBytes) {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: name, Code: "ENTRY_SIZE_LIMIT"})
			continue
		}
		if exceedsCompressionRatio(file.UncompressedSize64, file.CompressedSize64, limits.MaxCompressionRatio) {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: name, Code: "COMPRESSION_RATIO_LIMIT"})
			continue
		}

		rc, err := file.Open()
		if err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: name, Code: "MALFORMED_ARCHIVE", Error: err.Error()})
			continue
		}
		remainingTotal := limits.MaxUncompressedBytes - result.BytesRead
		entryLimit := limits.MaxEntryBytes
		if remainingTotal < entryLimit {
			entryLimit = remainingTotal
		}
		if entryLimit <= 0 {
			_ = rc.Close()
			return result, errors.New("archive uncompressed byte limit exceeded")
		}
		counter := &countingLimitReader{reader: rc, remaining: entryLimit + 1, ctx: ctx}
		entry := Entry{Index: index, LogicalName: name, CompressedSize: file.CompressedSize64, UncompressedSize: file.UncompressedSize64}
		handlerErr := handler(ctx, entry, counter)
		_, drainErr := io.Copy(io.Discard, counter)
		closeErr := rc.Close()
		result.BytesRead += counter.read
		result.EntriesRead++
		if counter.read > entryLimit {
			return result, fmt.Errorf("entry %q exceeds byte budget", name)
		}
		if result.BytesRead > limits.MaxUncompressedBytes {
			return result, errors.New("archive uncompressed byte limit exceeded")
		}
		if err := errors.Join(handlerErr, drainErr, closeErr); err != nil {
			result.Complete = false
			result.Diagnostics = append(result.Diagnostics, ArchiveDiagnostic{Entry: name, Code: "MALFORMED_ARCHIVE", Error: err.Error()})
		}
	}
	return result, nil
}

// exceedsCompressionRatio compares the exact rational sizes without
// multiplication overflow. Integer division alone would incorrectly accept a
// ratio such as 801:100 under an 8:1 ceiling.
func exceedsCompressionRatio(uncompressed, compressed, limit uint64) bool {
	if compressed == 0 {
		return uncompressed > 0
	}
	quotient, remainder := uncompressed/compressed, uncompressed%compressed
	return quotient > limit || (quotient == limit && remainder != 0)
}

func validateEntry(file *zip.File, limits ArchiveLimits) (string, error) {
	name := file.Name
	if len(name) == 0 || len(name) > limits.MaxNameBytes || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid entry name")
	}
	if strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "//") || windowsDrive.MatchString(name) || strings.Contains(name, ":") {
		return "", errors.New("absolute, Windows, backslash, or alternate-stream path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
		return "", errors.New("non-canonical or traversing path")
	}
	mode := file.Mode()
	if !file.FileInfo().IsDir() && !mode.IsRegular() {
		return "", fmt.Errorf("non-regular entry mode %v", mode.Type())
	}
	return clean, nil
}

type countingLimitReader struct {
	reader    io.Reader
	remaining int64
	read      int64
	ctx       context.Context
}

func (r *countingLimitReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, err
}

func boundedName(name string) string {
	name = strings.ToValidUTF8(name, "\uFFFD")
	if len(name) > 256 {
		name = name[:256]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	return name
}
