package jetsam

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

const fixtureDir = "testdata/incident"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func within(t *testing.T, got, want time.Time, tol time.Duration, what string) {
	t.Helper()
	d := got.Sub(want)
	if d < 0 {
		d = -d
	}
	if d > tol {
		t.Errorf("%s: got %s want %s (+-%s)", what, got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano), tol)
	}
}

// The synthetic fixture mirrors the numbers of the real incident: report
// date 16:07:07.05Z, timeDelta 13415 ms (snapshot 16:06:53.6Z), Python at
// 64.97 GiB and age 10.6 s (start about 16:06:43Z).
func TestCalibrationAgainstIncidentArithmetic(t *testing.T) {
	r, err := ParseFile(filepath.Join(fixtureDir, "JetsamEvent-2026-11-04-160707.ips"))
	if err != nil {
		t.Fatal(err)
	}
	within(t, r.Date, mustTime(t, "2026-11-04T16:07:07.05Z"), time.Millisecond, "date")
	within(t, r.Written, mustTime(t, "2026-11-04T16:07:07Z"), time.Millisecond, "written")
	within(t, r.Snapshot, mustTime(t, "2026-11-04T16:06:53.635Z"), time.Millisecond, "snapshot")
	if r.TimeDeltaMS != 13415 {
		t.Errorf("timeDelta %d", r.TimeDeltaMS)
	}
	top := r.Top()
	if top == nil || top.Name != "Python" || top.PID != 10934 {
		t.Fatalf("top process: %+v", top)
	}
	within(t, top.Start, mustTime(t, "2026-11-04T16:06:43Z"), 500*time.Millisecond, "python start")
	gib := float64(top.Bytes) / (1 << 30)
	if gib < 64.9 || gib > 65.0 {
		t.Errorf("python size %.3f GiB", gib)
	}
	if !r.NonIdleKill {
		t.Error("report has non-idle kills")
	}
	for i := 1; i < len(r.Procs); i++ {
		if r.Procs[i].Bytes > r.Procs[i-1].Bytes {
			t.Fatal("procs not sorted descending by bytes")
		}
	}
	var idle, killed int
	for _, p := range r.Procs {
		if p.Idle {
			idle++
		} else if p.Reason != "" {
			killed++
		}
	}
	if idle != 1 || killed != 2 {
		t.Errorf("idle=%d killed=%d", idle, killed)
	}
}

// Each of these is a naive variant of the arithmetic that must be caught.
func TestArithmeticVariantsAreDistinguishable(t *testing.T) {
	r, err := ParseFile(filepath.Join(fixtureDir, "JetsamEvent-2026-11-04-160707.ips"))
	if err != nil {
		t.Fatal(err)
	}
	// Using the report date as the snapshot would be 13.4 s late.
	if r.Snapshot.Equal(r.Date) {
		t.Error("snapshot must be date - timeDelta")
	}
	// Treating age as seconds or nanoseconds instead of 24 MHz ticks.
	if d := r.Snapshot.Sub(r.Procs[0].Start); d < 10*time.Second || d > 11*time.Second {
		t.Errorf("age conversion: %s", d)
	}
}

func TestOddAges(t *testing.T) {
	hdr := `{"bug_type":"298","timestamp":"2026-11-04 16:07:07.00 +0000"}` + "\n"
	r, err := Parse([]byte(hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":0,"processes":[
	 {"pid":1,"rpages":3,"age":18446744073709551615},{"pid":2,"rpages":2,"age":9000000000000000000},{"pid":3,"rpages":1,"age":24000000}]}`))
	if err != nil {
		t.Fatal(err)
	}
	by := map[int]Proc{}
	for _, p := range r.Procs {
		by[p.PID] = p
	}
	// Wrapped age -1 tick: started a hair after the snapshot, not rejected.
	if d := by[1].Start.Sub(r.Snapshot); d <= 0 || d > time.Millisecond {
		t.Errorf("wrapped age start offset %s", d)
	}
	if !by[2].Start.IsZero() {
		t.Error("implausible age must leave Start unknown")
	}
	if d := r.Snapshot.Sub(by[3].Start); d != time.Second {
		t.Errorf("1s age: %s", d)
	}
}

func TestPageSize(t *testing.T) {
	mk := func(mem string) []byte {
		return []byte(`{"bug_type":"298","timestamp":"2026-11-04 16:07:07.00 +0000"}` + "\n" +
			`{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1000,` + mem +
			`"processes":[{"pid":5,"name":"x","rpages":100,"age":24000000}]}`)
	}
	r, err := Parse(mk(``))
	if err != nil || r.PageSize != 16384 || r.Procs[0].Bytes != 100*16384 {
		t.Fatalf("default page size: %v %+v", err, r)
	}
	r, err = Parse(mk(`"memoryStatus":{"pageSize":4096},`))
	if err != nil || r.PageSize != 4096 || r.Procs[0].Bytes != 100*4096 {
		t.Fatalf("explicit page size: %v %+v", err, r)
	}
	if _, err = Parse(mk(`"memoryStatus":{"pageSize":3000},`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("non power of two page size accepted: %v", err)
	}
}

func goodReport() string {
	return `{"bug_type":"298","timestamp":"2026-11-04 16:07:07.00 +0000"}` + "\n" +
		`{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1000,"processes":[{"pid":5,"name":"x","rpages":100,"age":24000000}]}`
}

func TestMalformedNeverPanics(t *testing.T) {
	hdr := `{"bug_type":"298","timestamp":"2026-11-04 16:07:07.00 +0000"}` + "\n"
	cases := map[string]string{
		"empty":             ``,
		"header only":       strings.TrimSuffix(hdr, "\n"),
		"header newline":    hdr,
		"truncated body":    hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1000,"processes":[{"pid":5`,
		"wrong bug type":    `{"bug_type":"309","timestamp":"2026-11-04 16:07:07.00 +0000"}` + "\n{}",
		"bad header json":   "{nope\n{}",
		"no processes":      hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1,"processes":[]}`,
		"bad date":          hdr + `{"date":"yesterday","timeDelta":1,"processes":[{"pid":1,"rpages":1,"age":1}]}`,
		"negative delta":    hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":-5,"processes":[{"pid":1,"rpages":1,"age":1}]}`,
		"huge delta":        hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1e300,"processes":[{"pid":1,"rpages":1,"age":1}]}`,
		"rpages overflow":   hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1,"processes":[{"pid":1,"rpages":18446744073709551615,"age":1}]}`,
		"negative rpages":   hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1,"processes":[{"pid":1,"rpages":-1,"age":1}]}`,
		"deep nesting":      hdr + strings.Repeat("[", 5000),
		"deep in body":      hdr + `{"date":"x","processes":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`,
		"duplicate keys":    hdr + `{"date":"2026-11-04 16:07:07.05 +0000","date":"2026-11-04 16:07:08.05 +0000","timeDelta":1,"processes":[{"pid":1,"rpages":1,"age":1}]}`,
		"trailing data":     goodReport() + ` {"x":1}`,
		"wrong types":       hdr + `{"date":5,"timeDelta":"a","processes":"p"}`,
		"processes null":    hdr + `{"date":"2026-11-04 16:07:07.05 +0000","timeDelta":1,"processes":null}`,
		"binary":            "\x00\x01\x02\n\xff\xfe",
		"header 298 as int": `{"bug_type":298}` + "\n{}",
	}
	for name, in := range cases {
		name, in := name, in
		t.Run(name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic: %v", p)
				}
			}()
			if r, err := Parse([]byte(in)); err == nil {
				t.Errorf("accepted malformed input: %+v", r)
			}
		})
	}
	if _, err := Parse([]byte(goodReport())); err != nil {
		t.Fatalf("control: good report rejected: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(goodReport()))
	f.Add([]byte(`{"bug_type":"298"}` + "\n{}"))
	f.Add([]byte("x\n"))
	if b, err := os.ReadFile(filepath.Join(fixtureDir, "JetsamEvent-2026-11-04-160707.ips")); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Parse(b)
		if err != nil {
			return
		}
		if len(r.Procs) == 0 || r.PageSize == 0 {
			t.Fatalf("accepted an empty report: %+v", r)
		}
	})
}

func TestParseFileHostileFiles(t *testing.T) {
	dir := t.TempDir()
	// Oversize: a sparse file one byte past the cap must be refused
	// without reading it.
	big := filepath.Join(dir, "big.ips")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxReportBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ParseFile(big); !errors.Is(err, safeio.ErrTooLarge) {
		t.Errorf("oversize: %v", err)
	}
	good := filepath.Join(dir, "good.ips")
	os.WriteFile(good, []byte(goodReport()), 0o600)
	link := filepath.Join(dir, "link.ips")
	if err := os.Symlink(good, link); err == nil {
		if _, err := ParseFile(link); !errors.Is(err, safeio.ErrNotRegular) {
			t.Errorf("symlink: %v", err)
		}
	}
	if _, err := ParseFile("/dev/zero"); !errors.Is(err, safeio.ErrNotRegular) {
		t.Errorf("/dev/zero: %v", err)
	}
	if _, err := ParseFile(good); err != nil {
		t.Errorf("control: %v", err)
	}
}

func writeReports(t *testing.T, dir string, n int, pad int) {
	t.Helper()
	for i := 0; i < n; i++ {
		body := strings.Replace(goodReport(), `"name":"x"`, fmt.Sprintf(`"name":"%s"`, strings.Repeat("p", pad)), 1)
		name := fmt.Sprintf("JetsamEvent-2026-11-04-%06d.ips", 100000+i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanDirBounds(t *testing.T) {
	t.Run("fixture set", func(t *testing.T) {
		res, err := ScanDir(fixtureDir, ScanLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Reports) != 3 || len(res.Skipped) != 0 {
			t.Fatalf("reports=%d skipped=%v", len(res.Reports), res.Skipped)
		}
		for i := 1; i < len(res.Reports); i++ {
			if res.Reports[i].Snapshot.Before(res.Reports[i-1].Snapshot) {
				t.Error("not oldest first")
			}
		}
	})
	t.Run("file count", func(t *testing.T) {
		dir := t.TempDir()
		writeReports(t, dir, 10, 1)
		res, err := ScanDir(dir, ScanLimits{MaxFiles: 4})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Reports) != 4 || len(res.Skipped) != 6 {
			t.Fatalf("reports=%d skipped=%d", len(res.Reports), len(res.Skipped))
		}
		// The newest four names are kept.
		if !strings.HasSuffix(res.Reports[3].Path, "100009.ips") {
			t.Errorf("newest not kept: %s", res.Reports[3].Path)
		}
	})
	t.Run("byte budget", func(t *testing.T) {
		dir := t.TempDir()
		writeReports(t, dir, 10, 1000)
		res, err := ScanDir(dir, ScanLimits{MaxBytes: 4000})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Reports) != 3 || len(res.Skipped) != 7 {
			t.Fatalf("reports=%d skipped=%d", len(res.Reports), len(res.Skipped))
		}
	})
	t.Run("bad files are skipped with a note", func(t *testing.T) {
		dir := t.TempDir()
		writeReports(t, dir, 2, 1)
		os.WriteFile(filepath.Join(dir, "JetsamEvent-2026-11-04-999998.ips"), []byte("junk"), 0o600)
		os.Symlink(filepath.Join(dir, "JetsamEvent-2026-11-04-100000.ips"), filepath.Join(dir, "JetsamEvent-2026-11-04-999999.ips"))
		os.WriteFile(filepath.Join(dir, "other.ips"), []byte(goodReport()), 0o600)
		res, err := ScanDir(dir, ScanLimits{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Reports) != 2 || len(res.Skipped) != 2 {
			t.Fatalf("reports=%d skipped=%v", len(res.Reports), res.Skipped)
		}
	})
	t.Run("missing dir", func(t *testing.T) {
		if _, err := ScanDir(filepath.Join(t.TempDir(), "nope"), ScanLimits{}); err == nil {
			t.Error("want error")
		}
	})
}

// Red-team F5: the daemon scans every few seconds. A report older than
// Since (by modification time) or already seen is not read again, and the
// per-report cap can be lowered.
func TestScanDirSkipsOldAndSeenWithoutParsing(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	junk := filepath.Join(dir, "JetsamEvent-2026-11-01-000001.ips")
	if err := os.WriteFile(junk, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(junk, old, old)
	res, err := ScanDir(dir, ScanLimits{Since: old.Add(time.Hour)})
	if err != nil || len(res.Skipped) != 0 || len(res.Reports) != 0 {
		t.Fatalf("an old file was read: %+v %v", res, err)
	}
	writeReports(t, dir, 2, 1)
	seen := map[string]bool{}
	mark := func(n string, size int64, mod time.Time) bool { return seen[n] }
	res, _ = ScanDir(dir, ScanLimits{Since: old.Add(time.Hour), Seen: mark})
	if len(res.Reports) != 2 {
		t.Fatalf("new reports: %d", len(res.Reports))
	}
	for _, r := range res.Reports {
		seen[filepath.Base(r.Path)] = true
	}
	if res, _ = ScanDir(dir, ScanLimits{Since: old.Add(time.Hour), Seen: mark}); len(res.Reports) != 0 {
		t.Fatalf("seen reports parsed again: %d", len(res.Reports))
	}
	seen[filepath.Base(junk)] = true
	big := filepath.Join(dir, "JetsamEvent-2026-11-04-999999.ips")
	os.WriteFile(big, make([]byte, 5<<20), 0o600)
	res, _ = ScanDir(dir, ScanLimits{MaxReport: 4 << 20, Seen: mark})
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Err, "4 MiB") {
		t.Fatalf("lower cap not applied: %+v", res.Skipped)
	}
}
