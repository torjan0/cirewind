package logparse

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fuzzZIPEntry struct {
	name   string
	body   []byte
	mode   os.FileMode
	method uint16
}

func fuzzArchiveLimits() ArchiveLimits {
	return ArchiveLimits{
		MaxCompressedBytes: 32 << 10, MaxUncompressedBytes: 8 << 10,
		MaxEntryBytes: 4 << 10, MaxFiles: 16,
		MaxCompressionRatio: 8, MaxNameBytes: 512,
	}
}

func buildFuzzZIP(t testing.TB, entries []fuzzZIPEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, input := range entries {
		header := &zip.FileHeader{Name: input.name, Method: input.method}
		if input.mode != 0 {
			header.SetMode(input.mode)
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create fuzz seed entry: %v", err)
		}
		if _, err := entry.Write(input.body); err != nil {
			t.Fatalf("write fuzz seed entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close fuzz seed ZIP: %v", err)
	}
	return buffer.Bytes()
}

// FuzzReadZIPHostileBoundary exercises the ZIP reader itself, not the
// runner-control text parser. The callback only drains accepted in-memory
// entries and asserts that no archive-controlled path escapes normalization.
func FuzzReadZIPHostileBoundary(f *testing.F) {
	seeds := [][]byte{
		buildFuzzZIP(f, []fuzzZIPEntry{{name: "job/1_Set up job.txt", body: []byte("safe"), method: zip.Deflate}}),
		buildFuzzZIP(f, []fuzzZIPEntry{
			{name: "../outside", body: []byte("x"), method: zip.Store},
			{name: "/absolute", body: []byte("x"), method: zip.Store},
			{name: `C:/windows/path`, body: []byte("x"), method: zip.Store},
			{name: `job\backslash.txt`, body: []byte("x"), method: zip.Store},
			{name: "job/./noncanonical.txt", body: []byte("x"), method: zip.Store},
		}),
		buildFuzzZIP(f, []fuzzZIPEntry{
			{name: "job/A.txt", body: []byte("first"), method: zip.Store},
			{name: "JOB/a.txt", body: []byte("second"), method: zip.Store},
			{name: "job/A.txt", body: []byte("third"), method: zip.Store},
		}),
		buildFuzzZIP(f, []fuzzZIPEntry{
			{name: "job/link", body: []byte("../outside"), mode: os.ModeSymlink | 0o777, method: zip.Store},
			{name: "job/pipe", mode: os.ModeNamedPipe | 0o600, method: zip.Store},
			{name: "job/", mode: os.ModeDir | 0o755, method: zip.Store},
		}),
		buildFuzzZIP(f, []fuzzZIPEntry{{name: "job/high-ratio.txt", body: bytes.Repeat([]byte("A"), 4<<10), method: zip.Deflate}}),
		buildFuzzZIP(f, []fuzzZIPEntry{{name: "job/oversize.txt", body: bytes.Repeat([]byte("B"), 5<<10), method: zip.Store}}),
		buildFuzzZIP(f, []fuzzZIPEntry{{name: strings.Repeat("a", 255) + "é" + strings.Repeat("b", 300), body: []byte("x"), method: zip.Store}}),
		[]byte("not a ZIP archive"),
		{},
	}
	valid := buildFuzzZIP(f, []fuzzZIPEntry{{name: "job/truncated.txt", body: []byte("safe"), method: zip.Store}})
	seeds = append(seeds, valid[:len(valid)/2])
	for _, seed := range seeds {
		f.Add(seed, int64(len(seed)))
	}

	limits := fuzzArchiveLimits()
	f.Fuzz(func(t *testing.T, data []byte, declaredSize int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		seen := make(map[string]struct{})
		result, _ := ReadZIP(ctx, bytes.NewReader(data), declaredSize, limits, func(callbackContext context.Context, entry Entry, reader io.Reader) error {
			if callbackContext == nil {
				t.Fatal("callback received a nil context")
			}
			if callbackContext.Err() != nil {
				return callbackContext.Err()
			}
			name := entry.LogicalName
			clean := path.Clean(name)
			if name == "" || clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
				strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || strings.Contains(name, ":") ||
				strings.ContainsRune(name, 0) || !utf8.ValidString(name) || len(name) > limits.MaxNameBytes {
				t.Fatalf("callback received unsafe archive path %q", name)
			}
			folded := strings.ToLower(name)
			if _, duplicate := seen[folded]; duplicate {
				t.Fatalf("callback received duplicate normalized archive path %q", name)
			}
			seen[folded] = struct{}{}
			if entry.Index < 0 || entry.Index >= limits.MaxFiles || entry.UncompressedSize > uint64(limits.MaxEntryBytes) {
				t.Fatalf("callback received out-of-budget entry: %+v", entry)
			}
			if exceedsCompressionRatio(entry.UncompressedSize, entry.CompressedSize, limits.MaxCompressionRatio) {
				t.Fatalf("callback received over-ratio entry: %+v", entry)
			}
			read, err := io.Copy(io.Discard, io.LimitReader(reader, limits.MaxEntryBytes+1))
			if read > limits.MaxEntryBytes {
				t.Fatalf("callback reader exceeded entry budget: %d", read)
			}
			return err
		})
		if result.EntriesRead > limits.MaxFiles || result.BytesRead > limits.MaxUncompressedBytes {
			t.Fatalf("archive counters exceeded limits: %+v", result)
		}
		for _, diagnostic := range result.Diagnostics {
			if !utf8.ValidString(diagnostic.Entry) || !utf8.ValidString(diagnostic.Error) {
				t.Fatalf("diagnostic retained invalid UTF-8: %+v", diagnostic)
			}
		}
	})
}

func TestCompressionRatioComparisonUsesExactRationalSizes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uncompressed uint64
		compressed   uint64
		limit        uint64
		want         bool
	}{
		{uncompressed: 0, compressed: 0, limit: 8, want: false},
		{uncompressed: 1, compressed: 0, limit: 8, want: true},
		{uncompressed: 800, compressed: 100, limit: 8, want: false},
		{uncompressed: 801, compressed: 100, limit: 8, want: true},
		{uncompressed: ^uint64(0), compressed: ^uint64(0), limit: 1, want: false},
		{uncompressed: ^uint64(0), compressed: 1, limit: 200, want: true},
	}
	for _, test := range tests {
		if got := exceedsCompressionRatio(test.uncompressed, test.compressed, test.limit); got != test.want {
			t.Errorf("exceedsCompressionRatio(%d,%d,%d)=%v want %v", test.uncompressed, test.compressed, test.limit, got, test.want)
		}
	}
}

func TestReadZIPCancellationStopsBeforeCallback(t *testing.T) {
	t.Parallel()
	body := buildFuzzZIP(t, []fuzzZIPEntry{{name: "job/safe.txt", body: []byte("safe"), method: zip.Store}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := ReadZIP(ctx, bytes.NewReader(body), int64(len(body)), fuzzArchiveLimits(), func(context.Context, Entry, io.Reader) error {
		called = true
		return nil
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled archive reached callback: called=%v err=%v", called, err)
	}
}

func TestReadZIPRejectsRatioSizeAndLinkEntriesBeforeCallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body []byte
		code string
	}{
		{
			name: "compression ratio",
			body: buildFuzzZIP(t, []fuzzZIPEntry{{name: "job/ratio.txt", body: bytes.Repeat([]byte("A"), 4<<10), method: zip.Deflate}}),
			code: "COMPRESSION_RATIO_LIMIT",
		},
		{
			name: "entry size",
			body: buildFuzzZIP(t, []fuzzZIPEntry{{name: "job/size.txt", body: bytes.Repeat([]byte("B"), 5<<10), method: zip.Store}}),
			code: "ENTRY_SIZE_LIMIT",
		},
		{
			name: "symlink",
			body: buildFuzzZIP(t, []fuzzZIPEntry{{name: "job/link", body: []byte("../outside"), mode: os.ModeSymlink | 0o777, method: zip.Store}}),
			code: "UNSAFE_ARCHIVE_ENTRY",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			result, err := ReadZIP(context.Background(), bytes.NewReader(test.body), int64(len(test.body)), fuzzArchiveLimits(), func(context.Context, Entry, io.Reader) error {
				called = true
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if called || result.Complete || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != test.code {
				t.Fatalf("unsafe entry reached callback: called=%v result=%+v", called, result)
			}
		})
	}
}
