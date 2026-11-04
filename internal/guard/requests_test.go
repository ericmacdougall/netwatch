//go:build !windows

package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirRequestsRoundTripAndHygiene(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { // the daemon's state dir is 0700
		t.Fatal(err)
	}
	d := DirRequests{Dir: dir}
	for _, k := range []string{"pg:100:1762000000000000000", "pg:200:1762000000000000001"} {
		if err := d.Add(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Add("../etc"); err == nil {
		t.Fatal("a non-key must be refused")
	}
	// A planted, world-readable request is ignored (and removed).
	if err := os.WriteFile(filepath.Join(dir, "resume-planted"), []byte("pg:300:1"), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := d.Take()
	if err != nil || len(keys) != 2 {
		t.Fatalf("take: %v %v", keys, err)
	}
	if again, _ := d.Take(); len(again) != 0 {
		t.Fatalf("requests must be consumed once: %v", again)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("leftover files: %d", len(ents))
	}
	if k, err := (DirRequests{Dir: filepath.Join(dir, "missing")}).Take(); err != nil || k != nil {
		t.Fatalf("missing dir: %v %v", k, err)
	}
}
