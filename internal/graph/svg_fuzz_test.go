package graph

import (
	"bytes"
	"context"
	"encoding/xml"
	"testing"
)

func FuzzTemporalEvidencePathSVG(f *testing.F) {
	f.Add([]byte("normal label"))
	f.Add([]byte("</text><script>alert(1)</script>\x1b[2J\u202e"))
	f.Add([]byte{0xff, 0xfe, '<', '&', '"', '\n', '='})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64<<10 {
			input = input[:64<<10]
		}
		g := testGraphV2(t)
		g.Nodes[0].Label = string(input)
		firstPath, first, err := RenderGraphSVG(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatalf("render hostile label: %v", err)
		}
		secondPath, second, err := RenderGraphSVG(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatalf("render hostile label again: %v", err)
		}
		if firstPath.Width != secondPath.Width || firstPath.Height != secondPath.Height || !bytes.Equal(first, second) {
			t.Fatal("hostile-label rendering is nondeterministic")
		}
		if len(first) > MaxSVGBytes {
			t.Fatalf("SVG exceeded hard limit: %d", len(first))
		}
		decoder := xml.NewDecoder(bytes.NewReader(first))
		for {
			_, decodeErr := decoder.Token()
			if decodeErr != nil {
				if decodeErr.Error() == "EOF" {
					break
				}
				t.Fatalf("invalid XML: %v", decodeErr)
			}
		}
	})
}
