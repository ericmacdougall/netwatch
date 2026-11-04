//go:build guardtest && !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

type sysOnly struct{ resources.Full }

func (sysOnly) System() (resources.System, error) {
	return resources.System{Pressure: resources.LevelNormal}, nil
}

// guard simulate drives the test daemon's reading; clear restores normal,
// and a missing or foreign-permission file leaves the real reading.
func TestGuardSimulateInjects(t *testing.T) {
	logDir := t.TempDir()
	stateDir := filepath.Join(logDir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := testReader(sysOnly{}, stateDir)
	if s, _ := r.System(); s.Pressure != resources.LevelNormal {
		t.Fatalf("no file: %v", s.Pressure)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--log-dir", logDir, "guard", "simulate", "critical", "0.9"}, &out, &errb); code != 0 {
		t.Fatalf("simulate: %d %s", code, errb.String())
	}
	s, _ := r.System()
	if s.Pressure != resources.LevelCritical || danger.CompressorFrac(s) < 0.89 {
		t.Fatalf("injected: %v %v", s.Pressure, danger.CompressorFrac(s))
	}
	if err := os.Chmod(filepath.Join(stateDir, injectFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.System(); s.Pressure != resources.LevelNormal {
		t.Fatalf("a group/world-readable inject file must be ignored: %v", s.Pressure)
	}
	if code := run([]string{"--log-dir", logDir, "guard", "simulate", "clear"}, &out, &errb); code != 0 {
		t.Fatalf("clear: %d %s", code, errb.String())
	}
	if s, _ := r.System(); s.Pressure != resources.LevelNormal {
		t.Fatalf("cleared: %v", s.Pressure)
	}
	if code := run([]string{"--log-dir", logDir, "guard", "simulate", "boom"}, &out, &errb); code != 2 {
		t.Fatalf("bad level: %d", code)
	}
}
