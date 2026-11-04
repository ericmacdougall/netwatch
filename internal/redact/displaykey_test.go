package redact

import "testing"

func TestDisplayKeyHidesPaths(t *testing.T) {
	for in, want := range map[string]string{
		"inel:exe:/home/someone/bin/tool": "tool",
		"inel:Google Chrome":              "Google Chrome",
		"exe:/Users/someone/x":            "x",
		"pg:1:2":                          "pg:1:2",
		"uid:0":                           "uid:0",
	} {
		if got := DisplayKey(in); got != want {
			t.Errorf("DisplayKey(%q)=%q want %q", in, got, want)
		}
	}
}
