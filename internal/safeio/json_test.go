package safeio

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeJSONCorpus(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"object", `{"a":1,"b":{"c":[1,2,{"d":null}]}}`, true},
		{"depth at limit", deep(MaxJSONDepth), true},
		{"depth over limit", deep(MaxJSONDepth + 1), false},
		{"very deep", deep(100000), false},
		{"dup top", `{"a":1,"a":2}`, false},
		{"dup nested", `{"x":{"a":1,"b":2,"a":3}}`, false},
		{"dup in array element", `[{"a":1},{"a":1,"a":2}]`, false},
		{"dup case fold", `{"max_rss_gb":1,"MAX_RSS_GB":100}`, false},
		{"same key in sibling objects", `{"x":{"a":1},"y":{"a":2}}`, true},
		{"same key as value", `{"a":"a","b":"a"}`, true},
		{"trailing value", `{"a":1} {"b":2}`, false},
		{"trailing garbage", `{"a":1}x`, false},
		{"trailing scalar", `1 2`, false},
		{"truncated", `{"a":[1,2`, false},
		{"empty", ``, false},
		{"nan", `{"a":NaN}`, false},
	}
	for _, c := range cases {
		var v any
		err := DecodeJSON([]byte(c.in), &v)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrJSON) {
			t.Errorf("%s: want ErrJSON, got %v", c.name, err)
		}
	}
}

func FuzzDecodeJSON(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `[[[[]]]]`, `{"a":1,"a":2}`, `{"a":{"b":[1,2,3]}}`, ``, `{`, `1 2`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var v any
		if err := DecodeJSON(b, &v); err != nil {
			return
		}
		// Anything accepted must be one valid value within the depth bound.
		if err := validateJSON(b); err != nil {
			t.Fatalf("accepted but revalidation failed: %v", err)
		}
	})
}
