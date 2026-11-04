//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
)

// CR-10: install states the mode and the one-command opt-out.
func TestGuardInstallNote(t *testing.T) {
	cfg := config.Default()
	logDir := t.TempDir()
	n := guardInstallNote(&cfg, logDir, "darwin")
	for _, want := range []string{"mode pause+kill", "platform default", "netwatch guard alert", "last resort"} {
		if !strings.Contains(n, want) {
			t.Errorf("darwin note lacks %q: %s", want, n)
		}
	}
	n = guardInstallNote(&cfg, logDir, "linux")
	if !strings.Contains(n, "mode alert") || strings.Contains(n, "kills") {
		t.Errorf("linux note: %s", n)
	}
}

// A test daemon refuses to start without explicit paths, on the installed
// agent's log directory, or without a valid live target.
func TestTestDaemonRefusals(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(cfgFile, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no explicit paths", []string{"run", "--test-daemon"}, "explicit --config and --log-dir"},
		{"installed log dir", []string{"--config", cfgFile, "--log-dir", collector.DefaultLogDir(), "run", "--test-daemon"}, "installed agent"},
		{"no target", []string{"--config", cfgFile, "--log-dir", t.TempDir(), "run", "--test-daemon"}, "guard_test_target"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		code := run(c.args, &out, &errb)
		if code == 0 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%s: exit %d stderr %q, want failure mentioning %q", c.name, code, errb.String(), c.want)
		}
	}
}

// A refused test daemon leaves no trace in its log directory: the refusal
// comes before the run lock, the incident check and the state directory.
func TestRefusedTestDaemonHasNoSideEffects(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(cfgFile, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logDir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"--config", cfgFile, "--log-dir", logDir, "run", "--test-daemon"}, &out, &errb); code == 0 {
		t.Fatal("test daemon without a target started")
	}
	ents, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("refused test daemon created %v in its log dir", names)
	}
}

// `once` does not accept --test-daemon (the flag exists only for run).
func TestOnceRejectsTestDaemon(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"once", "--test-daemon"}, &out, &errb); code != 2 {
		t.Fatalf("once --test-daemon: exit %d", code)
	}
}
