package logparse

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"testing"
)

func makeZIP(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestReadZIPValid(t *testing.T) {
	t.Parallel()
	body := makeZIP(t, map[string]string{"job/1_Set up job.txt": "safe"})
	var got string
	result, err := ReadZIP(context.Background(), bytes.NewReader(body), int64(len(body)), DefaultArchiveLimits(), func(_ context.Context, entry Entry, r io.Reader) error {
		data, err := io.ReadAll(r)
		got = entry.LogicalName + ":" + string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || got != "job/1_Set up job.txt:safe" {
		t.Fatalf("result=%+v got=%q", result, got)
	}
}

func TestReadZIPRejectsTraversalAndCollision(t *testing.T) {
	t.Parallel()
	body := makeZIP(t, map[string]string{"../outside": "x", "JOB/a.txt": "x", "job/A.txt": "y"})
	result, err := ReadZIP(context.Background(), bytes.NewReader(body), int64(len(body)), DefaultArchiveLimits(), func(_ context.Context, _ Entry, _ io.Reader) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Diagnostics) < 2 {
		t.Fatalf("unsafe archive accepted: %+v", result)
	}
}

func TestArchiveLimitsCannotExceedHardCeiling(t *testing.T) {
	t.Parallel()
	limits := DefaultArchiveLimits()
	limits.MaxFiles = HardArchiveLimits().MaxFiles + 1
	if err := limits.Validate(); err == nil {
		t.Fatal("unsafe hard-limit override accepted")
	}
}
