//go:build !windows

package resmon

import (
	"os"
	"reflect"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/shapecheck"
)

// The kill allowlist is the configured versions plus running versions the
// shape check verified; a running version that was never verified, or a
// verified version that is not running, adds nothing.
func TestAllowlistIsConfiguredPlusVerifiedRunning(t *testing.T) {
	dir := privDir(t)
	if _, err := shapecheck.Allow(dir, "2.1.318", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := shapecheck.Allow(dir, "9.9.9", t0); err != nil { // verified, not running
		t.Fatal(err)
	}
	scan := []resources.Proc{
		{PID: 10, UID: 501, Exe: "/Users/user/.local/share/claude/versions/2.1.318"},
		{PID: 11, UID: 501, Exe: "/Users/user/.local/share/claude/versions/2.1.400"}, // never verified
		{PID: 12, UID: 501, Exe: "/tmp/x/claude/versions/1.0.0/../2.1.500"},          // not a clean path
	}
	e := &Elig{Versions: []string{"2.0.0"}, AllowlistDir: dir}
	got := e.allowlist(scan)
	want := []string{"2.0.0", "2.1.318"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist = %v, want %v", got, want)
	}
	if got := (&Elig{AllowlistDir: privDir(t)}).allowlist(scan); len(got) != 0 {
		t.Fatalf("empty config and empty allowlist dir gave %v", got)
	}
}

// privDir is a 0700 directory, as the allowlist writer requires.
func privDir(t *testing.T) string {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}
