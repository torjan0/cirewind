package archive

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/store"
)

func FuzzDecodeSnapshot(f *testing.F) {
	valid, err := json.Marshal(Snapshot{
		Metadata: SnapshotMetadata{
			SchemaVersion: SnapshotSchemaVersion, StoreSchemaVersion: store.SchemaVersion,
			ArchiveID: "arc1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			CreatedAt: testInstant(0),
		},
		Collections: []CollectionSession{}, Payloads: []Payload{}, Facts: []Fact{},
		Evidence: []evidence.Envelope{}, Capabilities: []Capability{}, Checkpoints: []Checkpoint{},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"metadata":{},"unexpected":true}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		first, firstErr := DecodeSnapshot(bytes.NewReader(data))
		second, secondErr := DecodeSnapshot(bytes.NewReader(data))
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("snapshot decoder acceptance is nondeterministic")
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatal("snapshot decoder diagnostic is nondeterministic")
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("snapshot normalization is nondeterministic")
		}
	})
}
