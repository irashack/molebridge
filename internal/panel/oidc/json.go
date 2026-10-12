package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// errJSON is the one error loads returns: callers say only that the document
// is not valid JSON, so nothing of the input can reach a message.
var errJSON = errors.New("invalid JSON")

// loads is oidc.py's _loads: strict UTF-8, one JSON document, a repeated
// object key (after unescaping) refused at any depth. The result holds
// map[string]any, []any, string, bool, nil, int64 (a number written without
// fraction or exponent, as Python reads an int) and float64.
//
// Python's json module also accepts NaN, Infinity and -Infinity; this does
// not (a deviation toward refusing). Both accept a number far beyond int64
// as a float here.
func loads(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, errJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errJSON
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errJSON
				}
				if _, dup := obj[key]; dup {
					return nil, errJSON
				}
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = value
			}
			if _, err := dec.Token(); err != nil { // the closing brace
				return nil, err
			}
			return obj, nil
		case '[':
			list := []any{}
			for dec.More() {
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return list, nil
		}
		return nil, errJSON
	case json.Number:
		text := string(t)
		if !strings.ContainsAny(text, ".eE") {
			if n, err := strconv.ParseInt(text, 10, 64); err == nil {
				return n, nil
			}
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, err
		}
		if math.IsInf(f, 0) {
			return nil, errJSON
		}
		return f, nil
	default: // string, bool, nil
		return t, nil
	}
}

// number is isinstance(value, (int, float)) and not a bool.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}
