package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// canonicalJSON emits a whitespace-free JSON form with lexicographically
// sorted object keys. The pack schema contains no floating-point values, so
// JSON number canonicalization is limited to validated decimal integers.
func canonicalJSON(pack Pack) ([]byte, error) {
	raw, err := json.Marshal(pack)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("unexpected trailing canonical JSON value")
	}
	var out bytes.Buffer
	if err := writeCanonicalJSON(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonicalJSON(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		out.Write(encoded)
	case json.Number:
		if _, err := v.Int64(); err != nil {
			return fmt.Errorf("non-integer number %q in incident pack", v)
		}
		out.WriteString(v.String())
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			out.Write(encoded)
			out.WriteByte(':')
			if err := writeCanonicalJSON(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
	return nil
}
