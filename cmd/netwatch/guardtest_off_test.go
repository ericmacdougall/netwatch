//go:build !guardtest && !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A release build has no danger injection and no kill tier for the test
// daemon (scripts/build-release.sh checks the same on the shipped binary).
func TestReleaseBuildHasNoGuardtestHooks(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--log-dir", t.TempDir(), "guard", "simulate", "critical"}, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), `unknown guard subcommand "simulate"`) {
		t.Fatalf("guard simulate: exit %d %q", code, errb.String())
	}
	cfgFile := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(cfgFile, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	logDir := t.TempDir()
	if code := run([]string{"--config", cfgFile, "--log-dir", logDir, "run", "--test-daemon", "--test-tier", "kill", "--", "true"}, &out, &errb); code == 0 ||
		!strings.Contains(errb.String(), "needs a guardtest build") {
		t.Fatalf("--test-tier kill: exit %d %q", code, errb.String())
	}
	if ents, _ := os.ReadDir(logDir); len(ents) != 0 {
		t.Fatalf("refused kill tier left %d entries in its log dir", len(ents))
	}
}
