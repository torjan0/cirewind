package packextract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/torjan0/cirewind/internal/evidence"
)

// sealable is any extraction record that carries its own output hash.
type sealable interface {
	outputHash() *string
}

func (e *Extraction) outputHash() *string   { return &e.OutputSHA256 }
func (t *TagInventory) outputHash() *string { return &t.OutputSHA256 }

// seal computes the record's output hash over its canonical bytes with the
// hash field empty, then stores it. Canonical returns the same bytes with the
// hash present, so a reviewer verifies a record by clearing the field,
// re-encoding, and hashing.
func seal(record sealable) error {
	*record.outputHash() = ""
	data, err := evidence.CanonicalJSON(record)
	if err != nil {
		return fmt.Errorf("canonicalize extraction: %w", err)
	}
	sum := sha256.Sum256(append(data, '\n'))
	*record.outputHash() = hex.EncodeToString(sum[:])
	return nil
}

// Canonical renders a sealed record as RFC 8785 canonical JSON plus one
// trailing line feed, the byte form committed in a candidate packet.
func Canonical(record any) ([]byte, error) {
	data, err := evidence.CanonicalJSON(record)
	if err != nil {
		return nil, fmt.Errorf("canonicalize extraction: %w", err)
	}
	return append(data, '\n'), nil
}

// VerifyExtraction recomputes the output hash of a decoded extraction record
// and reports whether it matches the stored value.
func VerifyExtraction(record *Extraction) (bool, error) {
	stored := record.OutputSHA256
	copied := *record
	if err := seal(&copied); err != nil {
		return false, err
	}
	return copied.OutputSHA256 == stored, nil
}
