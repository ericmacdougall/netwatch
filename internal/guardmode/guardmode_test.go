//go:build !windows

package guardmode

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/guard"
)

func tmp(t *testing.T) string {
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRoundTripAndLabelRedaction(t *testing.T) {
	d := tmp(t)
	for _, m := range []guard.Mode{guard.ModeOff, guard.ModeAlert, guard.ModePause, guard.ModePauseKill} {
		if err := Write(d, m, "agent-1"); err != nil {
			t.Fatal(err)
		}
		got, ok := Read(d)
		if !ok || got != m {
			t.Fatalf("round trip %s: %v %v", m, got, ok)
		}
	}
	fi, _ := os.Stat(filepath.Join(d, File))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode file perm %v", fi.Mode().Perm())
	}
	if err := Write(d, guard.ModeAlert, "agent --token hunter2hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	r, _ := ReadRecord(d)
	if strings.Contains(r.By, "hunter2") || r.SetAt.IsZero() {
		t.Fatalf("label not redacted: %+v", r)
	}
	long := strings.Repeat("x", 500)
	Write(d, guard.ModeAlert, long)
	if r, _ = ReadRecord(d); len(r.By) > 80 {
		t.Fatalf("label not bounded: %d", len(r.By))
	}
}

func TestWriteRejectsInvalidMode(t *testing.T) {
	d := tmp(t)
	if err := Write(d, guard.Mode("yolo"), "x"); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
	if _, ok := Read(d); ok {
		t.Fatal("nothing may have been written")
	}
	if _, err := Parse("pause+kill"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("PAUSE"); err == nil {
		t.Fatal("mode strings are exact")
	}
}

func TestReadRefusesUnsafeFiles(t *testing.T) {
	// Control: a good file reads.
	d := tmp(t)
	Write(d, guard.ModePause, "u")
	if _, ok := Read(d); !ok {
		t.Fatal("control must read")
	}
	p := filepath.Join(d, File)

	os.Chmod(p, 0o644)
	if _, ok := Read(d); ok {
		t.Fatal("0644 must be refused")
	}
	os.Remove(p)

	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte(`{"mode":"off"}`), 0o600)
	os.Symlink(target, p)
	if _, ok := Read(d); ok {
		t.Fatal("a symlink must be refused")
	}
	if err := Write(d, guard.ModeAlert, "u"); err == nil {
		t.Fatal("writing over a symlink must be refused")
	}
	if b, _ := os.ReadFile(target); string(b) != `{"mode":"off"}` {
		t.Fatal("symlink target modified")
	}
	os.Remove(p)

	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if _, ok := Read(d); ok { // must return, not block
		t.Fatal("a FIFO must be refused")
	}
	os.Remove(p)

	os.WriteFile(p, []byte(`{"mode":"banana"}`), 0o600)
	if _, ok := Read(d); ok {
		t.Fatal("an invalid stored mode must be refused")
	}
	os.WriteFile(p, []byte(`not json`), 0o600)
	if _, ok := Read(d); ok {
		t.Fatal("garbage must be refused")
	}
	os.WriteFile(p, []byte(`{"mode":"off","mode":"pause"}`), 0o600)
	if _, ok := Read(d); ok {
		t.Fatal("duplicate keys must be refused")
	}
	os.Remove(p)
	if _, ok := Read(d); ok {
		t.Fatal("missing must be ok=false")
	}
}
