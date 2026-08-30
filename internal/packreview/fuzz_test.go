package packreview

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzRejectDuplicateJSONKeys(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"a":1}`), []byte(`{"a":1,"a":2}`), []byte(`{"nested":{"x":1,"x":2}}`), []byte(`[1,{"x":2}]`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = rejectDuplicateJSONKeys(data)
	})
}

func FuzzParseManifest(f *testing.F) {
	for _, seed := range []string{
		stringOf('a', 64) + "  fixture.txt\n",
		stringOf('a', 64) + "  ../escape.txt\n",
		stringOf('a', 64) + "  CON.txt\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) { _, _ = parseManifest([]byte(input), "manifest.sha256") })
}

func FuzzStrictPacketJSON(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"cirewind.review-packet/v1alpha1"}`))
	f.Add([]byte(`{"schemaVersion":"x","schemaVersion":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		directory := t.TempDir()
		path := filepath.Join(directory, "packet.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, _ = readStrictJSON[Packet](context.Background(), path)
	})
}
