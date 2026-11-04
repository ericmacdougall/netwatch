package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const incidentFixtures = "../../internal/jetsam/testdata/incident"

// The CLI replay runs end to end on the synthetic incident fixtures and
// prints the AC-6 checks; JSON output decodes.
func TestIncidentReplayCLI(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"--log-dir", t.TempDir(), "incident", "--dir", incidentFixtures, "--replay-guard"}
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"Guard replay", "Culprit:", "[pass] without the fast path", "[pass] with the fast path", "control: guard off"} {
		if !strings.Contains(s, want) {
			t.Errorf("replay output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "[fail]") {
		t.Errorf("replay has a failing check:\n%s", s)
	}
	out.Reset()
	args = append(args, "--json")
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("json exit %d, stderr %q", code, errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("replay --json is not JSON: %v", err)
	}
}

// A missing evidence directory is reported as not verified, never as a
// pass, and is not an error.
func TestIncidentMissingEvidenceNotVerified(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"--log-dir", t.TempDir(), "incident", "--dir", t.TempDir() + "/none", "--replay-guard"}
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(strings.ToLower(out.String()), "not verified") {
		t.Fatalf("missing evidence not reported as not verified:\n%s", out.String())
	}
}

func TestTopUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	// Check the message too: an unknown command also exits 2.
	if code := run([]string{"top", "--mem", "--cpu"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "exclusive") {
		t.Fatalf("--mem --cpu: code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"top", "-n", "0"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "-n must be") {
		t.Fatalf("-n 0: code %d stderr %q", code, errb.String())
	}
}
