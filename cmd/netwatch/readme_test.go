package main

import (
	"os"
	"strings"
	"testing"
)

// The README must keep the guard documentation the spec requires (AC-12):
// the guard section, the opt-out, the rollback steps, the Codex alert-only
// note and the wall-clock timer warning.
func TestReadmeDocumentsTheGuard(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"## Memory guard",
		"netwatch guard alert",
		"**Rollback.**",
		"netwatch resume --all",
		"netwatch resume --pid PID",
		"Codex and other agent harnesses get alerts only",
		"Wall-clock timer warning",
		"prevents the host reset",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("README lacks %q", want)
		}
	}
}
