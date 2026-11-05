//go:build windows

package safeio

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A file we just created is ours, whatever default owner the token gives
// (the user, or BUILTIN\Administrators for an elevated administrator).
func TestWindowsOwnFileIsAccepted(t *testing.T) {
	p := writeTemp(t)
	if _, err := ReadFile(p, Opts{Max: 100, RequireOwner: true, MaxPerm: 0o600}); err != nil {
		t.Fatalf("own file refused: %v", err)
	}
}

// Granting write to the Users group must fail the private check (control:
// the same file passed above), and a read-only grant must not.
func TestWindowsWritableByOthersIsRefused(t *testing.T) {
	p := writeTemp(t)
	if out, err := exec.Command("icacls", p, "/grant", "*S-1-5-32-545:(R)").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	if _, err := ReadFile(p, Opts{Max: 100, RequireOwner: true, MaxPerm: 0o600}); err != nil {
		t.Fatalf("read-only grant to Users must pass: %v", err)
	}
	if out, err := exec.Command("icacls", p, "/grant", "*S-1-5-32-545:(W)").CombinedOutput(); err != nil {
		t.Skipf("icacls: %v %s", err, out)
	}
	if _, err := ReadFile(p, Opts{Max: 100, RequireOwner: true, MaxPerm: 0o600}); !errors.Is(err, ErrPerm) {
		t.Fatalf("write grant to Users: want ErrPerm, got %v", err)
	}
	// Without MaxPerm only the owner is checked.
	if _, err := ReadFile(p, Opts{Max: 100, RequireOwner: true}); err != nil {
		t.Fatalf("owner-only check: %v", err)
	}
}

func TestWindowsPrivateDirWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFileAtomic(dir, "x.json", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("write into own dir: %v", err)
	}
	if _, err := ReadFile(filepath.Join(dir, "x.json"), Opts{Max: 100, RequireOwner: true, MaxPerm: 0o600}); err != nil {
		t.Fatalf("read back: %v", err)
	}
}
