//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
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
// agent's log directory, or without a job of its own to guard.
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
		{"no job", []string{"--config", cfgFile, "--log-dir", t.TempDir(), "run", "--test-daemon"}, "needs a job"},
		{"empty job", []string{"--config", cfgFile, "--log-dir", t.TempDir(), "run", "--test-daemon", "--"}, "needs a job"},
		{"bad tier", []string{"--config", cfgFile, "--log-dir", t.TempDir(), "run", "--test-daemon", "--test-tier", "nuke", "--", "true"}, "want pause or kill"},
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
		t.Fatal("test daemon without a job started")
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

// The daemon's shape check reads transcripts only from just before the
// oldest tool-shell-shaped child; with none it reads nothing.
func TestShapeWindowStart(t *testing.T) {
	base := time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)
	kids := []shapecheck.Child{
		{PID: 1, Start: base.Add(-3 * time.Hour), Shape: shapecheck.Shape{Setsid: false, NoTTY: true}}, // MCP-like: ignored
		{PID: 2, Start: base.Add(-10 * time.Second), Shape: shapecheck.Shape{Setsid: true, NoTTY: true}},
		{PID: 3, Start: base.Add(-2 * time.Second), Shape: shapecheck.Shape{Setsid: true, NoTTY: true}},
		{PID: 4, Start: base.Add(-time.Hour), Shape: shapecheck.Shape{Setsid: true, NoTTY: false}}, // has a tty: ignored
	}
	ws, ok := shapeWindowStart(kids)
	if !ok || !ws.Equal(base.Add(-10*time.Second-shapeSlack)) {
		t.Fatalf("window start = %v, %v", ws, ok)
	}
	if _, ok := shapeWindowStart(kids[:1]); ok {
		t.Fatal("no shaped child must mean no transcript read")
	}
}

// A job passed without --test-daemon is an unexpected argument: only a
// test daemon spawns anything.
func TestRunRejectsJobWithoutTestDaemon(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--log-dir", t.TempDir(), "run", "--", "true"}, &out, &errb); code != 2 {
		t.Fatalf("run -- true: exit %d %s", code, errb.String())
	}
}

// The test daemon spawns its job as the leader of a new session and group,
// records that group, and exits when the job does.
func TestTestDaemonSpawnsJobInOwnGroup(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(cfgFile, []byte(`{"notify":false,"guard_mode":"alert"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ids")
	job := []string{"sh", "-c", "echo $$ $(ps -o pgid= -p $$) $(ps -o stat= -p $$) > " + marker + "; sleep 1"}
	var out, errb bytes.Buffer
	code := make(chan int, 1)
	go func() {
		code <- run(append([]string{"--config", cfgFile, "--log-dir", logDir, "run", "--test-daemon", "--"}, job...), &out, &errb)
	}()
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("exit %d: %s", c, errb.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("test daemon did not exit after its job")
	}
	ids, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(ids))
	// stat flag "s": session leader (Linux and macOS ps).
	if len(f) != 3 || f[0] != f[1] || !strings.Contains(f[2], "s") {
		t.Fatalf("job is not its own session and group leader (pid pgid stat): %q", ids)
	}
	rec, err := os.ReadFile(filepath.Join(logDir, "state", "test-target"))
	if err != nil || strings.Fields(string(rec))[0] != f[0] {
		t.Fatalf("state/test-target %q (%v), want pgid %s", rec, err, f[0])
	}
	if !strings.Contains(errb.String(), "test job exited: status 0") {
		t.Fatalf("stderr: %s", errb.String())
	}
}
