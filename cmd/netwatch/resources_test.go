package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const incidentFixtures = "../../internal/jetsam/testdata/incident"

// The CLI replay runs end to end on the synthetic incident fixtures and
// prints the AC-6 checks; JSON output decodes.
func TestIncidentReplayCLI(t *testing.T) {
	// One synthetic Bash call 10.8s before the fixture culprit started, so
	// attribution is medium and the guard may act in the replay.
	tr := t.TempDir()
	call := map[string]any{"timestamp": "2026-11-04T16:06:32.200Z", "sessionId": "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0",
		"agentId": "aaaa1111", "message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "name": "Bash",
			"id": "toolu_1", "input": map[string]any{"command": "python3 big.py"}}}}}
	line, _ := json.Marshal(call)
	if err := os.MkdirAll(filepath.Join(tr, "-proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tr, "-proj", "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.jsonl"), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := []string{"--log-dir", t.TempDir(), "incident", "--dir", incidentFixtures, "--transcripts", tr, "--replay-guard"}
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"Guard replay", "Culprit:", "[pass] without the fast path", "[pass] with the fast path", "control: guard off"} {
		if !strings.Contains(s, want) {
			t.Errorf("replay output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(strings.ToLower(s), "[fail]") {
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
	args := []string{"--log-dir", t.TempDir(), "incident", "--dir", t.TempDir() + "/none", "--transcripts", "", "--replay-guard"}
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

// With no transcript candidate the culprit is not attributable, so the
// guard takes no action; every bound and the tracker control must say
// "not verified", never pass and never FAIL.
func TestIncidentReplayUnattributedIsNotVerified(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"--log-dir", t.TempDir(), "incident", "--dir", incidentFixtures, "--transcripts", t.TempDir(), "--replay-guard"}
	if code := run(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	s := out.String()
	if strings.Contains(s, "[FAIL]") || strings.Contains(s, "[pass] without the fast path") {
		t.Fatalf("unattributed replay must be not verified:\n%s", s)
	}
	if !strings.Contains(s, "attribution unknown, not eligible") || !strings.Contains(s, "[not verified] control: with the tracker disabled") {
		t.Fatalf("missing not-eligible note or not-verified control:\n%s", s)
	}
}
