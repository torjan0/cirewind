package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON returns the restricted RFC 8785 representation used by v0.1
// stable IDs. Identity inputs may contain integers but never floating-point
// values. Map keys are ordered by UTF-16 code units as required by RFC 8785.
func CanonicalJSON(value any) ([]byte, error) {
	if err := validateCanonicalInput(reflect.ValueOf(value), make(map[visit]bool), 0); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical input: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode canonical input: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	var result bytes.Buffer
	if err := writeCanonical(&result, normalized); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

func validateCanonicalInput(value reflect.Value, seen map[visit]bool, depth int) error {
	if !value.IsValid() {
		return nil
	}
	if depth > 128 {
		return errors.New("canonical input exceeds maximum nesting")
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		return validateCanonicalInput(value.Elem(), seen, depth+1)
	}
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("identity input contains invalid UTF-8")
		}
	case reflect.Float32, reflect.Float64:
		return errors.New("floating-point values are forbidden in identity input")
	case reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		key := visit{typ: value.Type(), ptr: value.Pointer()}
		if seen[key] {
			return errors.New("canonical input contains a pointer cycle")
		}
		seen[key] = true
		err := validateCanonicalInput(value.Elem(), seen, depth+1)
		delete(seen, key)
		return err
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		if value.Type().Key().Kind() != reflect.String {
			return errors.New("canonical maps must have string keys")
		}
		key := visit{typ: value.Type(), ptr: value.Pointer()}
		if seen[key] {
			return errors.New("canonical input contains a map cycle")
		}
		seen[key] = true
		iterator := value.MapRange()
		for iterator.Next() {
			if !utf8.ValidString(iterator.Key().String()) {
				return errors.New("identity input contains an invalid UTF-8 map key")
			}
			if err := validateCanonicalInput(iterator.Value(), seen, depth+1); err != nil {
				return err
			}
		}
		delete(seen, key)
	case reflect.Slice:
		if value.IsNil() {
			return nil
		}
		key := visit{typ: value.Type(), ptr: value.Pointer()}
		if seen[key] {
			return errors.New("canonical input contains a slice cycle")
		}
		seen[key] = true
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalInput(value.Index(index), seen, depth+1); err != nil {
				return err
			}
		}
		delete(seen, key)
	case reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalInput(value.Index(index), seen, depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if field.PkgPath != "" {
				continue
			}
			if err := validateCanonicalInput(value.Field(index), seen, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing canonical input: %w", err)
	}
	return errors.New("canonical input contains multiple JSON values")
}

func writeCanonical(dst *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		dst.WriteString("null")
	case bool:
		if typed {
			dst.WriteString("true")
		} else {
			dst.WriteString("false")
		}
	case string:
		if err := writeJSONString(dst, typed); err != nil {
			return err
		}
	case json.Number:
		text := typed.String()
		if strings.ContainsAny(text, ".eE+") || text == "-0" {
			return fmt.Errorf("floating-point or non-canonical number %q is forbidden in identity input", text)
		}
		if text == "" || (len(text) > 1 && text[0] == '0') || (len(text) > 2 && strings.HasPrefix(text, "-0")) {
			return fmt.Errorf("non-canonical integer %q", text)
		}
		dst.WriteString(text)
	case []any:
		dst.WriteByte('[')
		for index, element := range typed {
			if index != 0 {
				dst.WriteByte(',')
			}
			if err := writeCanonical(dst, element); err != nil {
				return err
			}
		}
		dst.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		dst.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				dst.WriteByte(',')
			}
			if err := writeJSONString(dst, key); err != nil {
				return err
			}
			dst.WriteByte(':')
			if err := writeCanonical(dst, typed[key]); err != nil {
				return err
			}
		}
		dst.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
	return nil
}

func lessUTF16(left, right string) bool {
	l := utf16.Encode([]rune(left))
	r := utf16.Encode([]rune(right))
	limit := len(l)
	if len(r) < limit {
		limit = len(r)
	}
	for index := 0; index < limit; index++ {
		if l[index] != r[index] {
			return l[index] < r[index]
		}
	}
	return len(l) < len(r)
}

func writeJSONString(dst *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("identity input contains invalid UTF-8")
	}
	const hex = "0123456789abcdef"
	dst.WriteByte('"')
	for _, char := range value {
		switch char {
		case '"', '\\':
			dst.WriteByte('\\')
			dst.WriteRune(char)
		case '\b':
			dst.WriteString(`\b`)
		case '\t':
			dst.WriteString(`\t`)
		case '\n':
			dst.WriteString(`\n`)
		case '\f':
			dst.WriteString(`\f`)
		case '\r':
			dst.WriteString(`\r`)
		default:
			if char >= 0 && char < 0x20 {
				dst.WriteString(`\u00`)
				dst.WriteByte(hex[byte(char)>>4])
				dst.WriteByte(hex[byte(char)&0x0f])
			} else {
				dst.WriteRune(char)
			}
		}
	}
	dst.WriteByte('"')
	return nil
}
