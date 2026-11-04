package safeio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DecodeJSON validates data and then unmarshals it into v. It rejects:
//   - nesting deeper than MaxJSONDepth (checked on the token stream, so a
//     hostile document cannot drive recursion);
//   - duplicate object keys at any level, compared case-insensitively
//     because encoding/json would otherwise let "A" silently overwrite "a"
//     when decoding into a struct;
//   - any data after the first value.
func DecodeJSON(data []byte, v any) error {
	if err := validateJSON(data); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrJSON, err)
	}
	return nil
}

// ReadJSON is ReadFile followed by DecodeJSON.
func ReadJSON(path string, o Opts, v any) error {
	b, err := ReadFile(path, o)
	if err != nil {
		return err
	}
	return DecodeJSON(b, v)
}

type frame struct {
	obj     bool
	keys    map[string]struct{}
	wantKey bool
}

func validateJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame
	started := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !started || len(stack) != 0 {
				return fmt.Errorf("%w: truncated", ErrJSON)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJSON, err)
		}
		if started && len(stack) == 0 {
			return fmt.Errorf("%w: trailing data", ErrJSON)
		}
		started = true
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= MaxJSONDepth {
					return fmt.Errorf("%w: nesting deeper than %d", ErrJSON, MaxJSONDepth)
				}
				consumeValue(stack)
				f := frame{obj: t == '{'}
				if f.obj {
					f.keys = map[string]struct{}{}
					f.wantKey = true
				}
				stack = append(stack, f)
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
			}
			continue
		case string:
			if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].wantKey {
				k := strings.ToLower(t)
				if _, dup := stack[n-1].keys[k]; dup {
					return fmt.Errorf("%w: duplicate key %q", ErrJSON, t)
				}
				stack[n-1].keys[k] = struct{}{}
				stack[n-1].wantKey = false
				continue
			}
		}
		consumeValue(stack)
	}
}

// consumeValue marks that a value was read in the enclosing object, so the
// next string token is a key again.
func consumeValue(stack []frame) {
	if n := len(stack); n > 0 && stack[n-1].obj && !stack[n-1].wantKey {
		stack[n-1].wantKey = true
	}
}
