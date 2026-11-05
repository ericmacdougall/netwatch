//go:build !windows

package guard

import (
	"os"
	"path/filepath"
	"strconv"
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

// A flooded request dir must not make one poll do unbounded work: Take
// returns at most maxTake keys per call and the rest on later calls.
func TestDirRequestsTakeIsBounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := DirRequests{Dir: dir}
	const total = maxTake + 44
	for i := 0; i < total; i++ {
		if err := d.Add("pg:" + strconv.Itoa(1000+i) + ":1"); err != nil {
			t.Fatal(err)
		}
	}
	first, err := d.Take()
	if err != nil || len(first) != maxTake {
		t.Fatalf("first take: got %d keys, want %d (err %v)", len(first), maxTake, err)
	}
	second, _ := d.Take()
	if len(second) != total-maxTake {
		t.Fatalf("second take: got %d keys, want %d", len(second), total-maxTake)
	}
}

// Clear must finish on a dir with more entries than one scan window and
// still remove every request while keeping unrelated files.
func TestDirRequestsClearIsBoundedButThorough(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	n := maxScanNames + 500
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, reqPrefix+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (DirRequests{Dir: dir}).Clear(); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "keep.json" {
		t.Fatalf("after Clear: %d entries left", len(ents))
	}
}
