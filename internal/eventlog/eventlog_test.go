package eventlog

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type rec struct {
	TS string `json:"ts"`
	N  int    `json:"n"`
}

func tsOf(r rec) string { return r.TS }

func TestAppendRotatesAndKeepsOneGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "events.jsonl")
	w := NewWriter(path, 100)
	now := time.Now().Format(TimeFormat)
	for i := 0; i < 20; i++ {
		if err := w.Append(rec{TS: now, N: i}); err != nil {
			t.Fatal(err)
		}
	}
	cur, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatal("rotated generation missing:", err)
	}
	// One record is ~50 bytes, so neither file may exceed limit + one record.
	if cur.Size() > 160 || old.Size() > 160 {
		t.Fatalf("rotation not bounding size: cur %d old %d", cur.Size(), old.Size())
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Fatal("only one old generation should exist")
	}
	if runtime.GOOS != "windows" {
		if cur.Mode().Perm() != 0o600 {
			t.Fatalf("log file mode %v, want 0600", cur.Mode().Perm())
		}
		d, _ := os.Stat(filepath.Dir(path))
		if d.Mode().Perm() != 0o700 {
			t.Fatalf("log dir mode %v, want 0700", d.Mode().Perm())
		}
	}
	got, err := ReadSince(path, time.Time{}, tsOf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[len(got)-1].N != 19 {
		t.Fatalf("last record should be newest: %+v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i].N != got[i-1].N+1 {
			t.Fatalf("records out of order across generations: %+v", got)
		}
	}
}

func TestReadSinceFiltersAndToleratesJunk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "samples.jsonl")
	old := time.Now().Add(-3 * time.Hour)
	recent := time.Now().Add(-10 * time.Minute)
	lines := []string{
		`{"ts":"` + old.Format(TimeFormat) + `","n":1}`,
		`not json`,
		`{"ts":"garbage","n":2}`,
		`{"ts":"` + recent.Format(legacyFormat) + `","n":3}`, // prototype format
		`{"ts":"` + recent.Format(TimeFormat) + `","n":4}`,
		`{"ts":"` + recent.Format(TimeFormat) + `","n":5`, // torn write, no newline
		strings.Repeat("x", 200<<10),                      // long junk line
		`{"ts":"` + recent.Format(TimeFormat) + `","n":6}`,
		// A valid record longer than the read buffer (a big ORPHANS_KILLED).
		`{"ts":"` + recent.Format(TimeFormat) + `","n":7,"pad":"` + strings.Repeat("p", 300<<10) + `"}`,
		strings.Repeat("y", maxLine+10), // over the limit: skipped
		`{"ts":"` + recent.Format(TimeFormat) + `","n":8}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSince(path, time.Now().Add(-time.Hour), tsOf)
	if err != nil {
		t.Fatal(err)
	}
	var ns []int
	for _, r := range got {
		ns = append(ns, r.N)
	}
	if want := []int{3, 4, 6, 7, 8}; !reflect.DeepEqual(ns, want) {
		t.Fatalf("got %v, want %v", ns, want)
	}
}

func TestReadSinceMissingFiles(t *testing.T) {
	got, err := ReadSince(filepath.Join(t.TempDir(), "none.jsonl"), time.Time{}, tsOf)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing file: %v %v", got, err)
	}
}

func TestParseTime(t *testing.T) {
	if _, ok := ParseTime("2026-11-03T21:52:01-08:00"); !ok {
		t.Fatal("rfc3339 rejected")
	}
	if _, ok := ParseTime("2026-11-03T21:52:01"); !ok {
		t.Fatal("legacy rejected")
	}
	if _, ok := ParseTime("yesterday"); ok {
		t.Fatal("junk accepted")
	}
}

func TestAppendTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil { // as the prototype left it
		t.Fatal(err)
	}
	if err := NewWriter(path, 1<<20).Append(rec{TS: "x"}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
}

// One file can mix offsets (local lifecycle events, UTC "Z" resource
// alerts); the cutoff is an instant, so all in-window rows match whatever
// the offset and none outside it do.
func TestReadSinceMixedOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	now := time.Now()
	in := now.Add(-20 * time.Minute)
	out := now.Add(-3 * time.Hour)
	mst := time.FixedZone("MST", -7*3600)
	lines := []string{
		`{"ts":"` + in.In(mst).Format(TimeFormat) + `","n":1}`,
		`{"ts":"` + in.UTC().Format(TimeFormat) + `","n":2}`,
		`{"ts":"` + in.In(time.FixedZone("E", 5*3600+1800)).Format(TimeFormat) + `","n":3}`,
		`{"ts":"` + out.In(mst).Format(TimeFormat) + `","n":4}`,
		`{"ts":"` + out.UTC().Format(TimeFormat) + `","n":5}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSince(path, now.Add(-time.Hour), tsOf)
	if err != nil {
		t.Fatal(err)
	}
	var ns []int
	for _, r := range got {
		ns = append(ns, r.N)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(ns, want) {
		t.Fatalf("got %v, want %v", ns, want)
	}
}
