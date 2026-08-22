package ledger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriterProducesSingleOrderedJSONRecords(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	w, err := Create(path, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func(value int) {
			defer group.Done()
			if _, err := w.Append("test", map[string]int{"value": value}); err != nil {
				t.Errorf("Append() error = %v", err)
			}
		}(i)
	}
	group.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var want uint64 = 1
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("invalid JSONL: %v", err)
		}
		if record.Sequence != want {
			t.Fatalf("sequence = %d, want %d", record.Sequence, want)
		}
		want++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if want != 21 {
		t.Fatalf("record count = %d", want-1)
	}
}

func TestWriterRejectsSensitiveFields(t *testing.T) {
	t.Parallel()
	w, err := Create(filepath.Join(t.TempDir(), "evidence.jsonl"), "session-1")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append("bad", map[string]string{"authorization": "Bearer marker"}); err == nil {
		t.Fatal("sensitive field accepted")
	}
}
