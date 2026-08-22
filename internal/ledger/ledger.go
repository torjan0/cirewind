// Package ledger writes CIRewind's append-only JSONL evidence stream.
package ledger

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

const Version = "cirewind.ledger/v1alpha1"

// Record is one writer-framed ledger object. Payload must be a typed value;
// callers must not pass authentication material or secret values.
type Record struct {
	LedgerVersion string          `json:"ledgerVersion"`
	Sequence      uint64          `json:"sequence"`
	SessionID     string          `json:"sessionId"`
	RecordType    string          `json:"recordType"`
	Payload       json.RawMessage `json:"payload"`
}

// Writer serializes complete records through one owner-only file descriptor.
type Writer struct {
	mu        sync.Mutex
	file      *os.File
	buffer    *bufio.Writer
	sessionID string
	sequence  uint64
	closed    bool
}

// Create creates a new ledger. Existing paths are rejected.
func Create(path, sessionID string) (*Writer, error) {
	if sessionID == "" {
		return nil, errors.New("ledger session ID is required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create evidence ledger: %w", err)
	}
	return &Writer{file: f, buffer: bufio.NewWriterSize(f, 64*1024), sessionID: sessionID}, nil
}

// Append JSON-encodes one typed payload and appends exactly one JSONL record.
func (w *Writer) Append(recordType string, payload any) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Record{}, errors.New("evidence ledger is closed")
	}
	if recordType == "" {
		return Record{}, errors.New("ledger record type is required")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Record{}, fmt.Errorf("encode ledger payload: %w", err)
	}
	if err := rejectSensitiveJSONKeys(raw); err != nil {
		return Record{}, err
	}
	next := w.sequence + 1
	record := Record{
		LedgerVersion: Version,
		Sequence:      next,
		SessionID:     w.sessionID,
		RecordType:    recordType,
		Payload:       raw,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return Record{}, fmt.Errorf("encode ledger record: %w", err)
	}
	line = append(line, '\n')
	if _, err := w.buffer.Write(line); err != nil {
		return Record{}, fmt.Errorf("append evidence ledger: %w", err)
	}
	w.sequence = next
	return record, nil
}

// Sync flushes records and asks the operating system to persist them.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("evidence ledger is closed")
	}
	if err := w.buffer.Flush(); err != nil {
		return fmt.Errorf("flush evidence ledger: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync evidence ledger: %w", err)
	}
	return nil
}

// Close durably flushes and closes the ledger.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	flushErr := w.buffer.Flush()
	syncErr := w.file.Sync()
	closeErr := w.file.Close()
	return errors.Join(flushErr, syncErr, closeErr)
}

func rejectSensitiveJSONKeys(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("inspect ledger payload: %w", err)
	}
	forbidden := map[string]struct{}{
		"authorization": {}, "authorizationHeader": {}, "githubToken": {},
		"accessToken": {}, "tokenValue": {}, "cookie": {}, "setCookie": {},
		"secretValue": {}, "signedUrl": {}, "signedURL": {},
	}
	var walk func(any) error
	walk = func(current any) error {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, bad := forbidden[key]; bad {
					return fmt.Errorf("ledger payload contains prohibited field %q", key)
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value)
}
