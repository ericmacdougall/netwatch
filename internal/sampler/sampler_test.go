package sampler

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

const mb = 1 << 20

type fakeReader struct {
	sys   resources.System
	procs []resources.Proc
	args  map[int][]string
	cwd   map[int]string
	calls int
	// cpu advances each Procs call by this much per pid
	cpuStep map[int]time.Duration
}

func (f *fakeReader) System() (resources.System, error) { return f.sys, nil }
func (f *fakeReader) Procs() ([]resources.Proc, error) {
	f.calls++
	out := make([]resources.Proc, len(f.procs))
	copy(out, f.procs)
	if f.calls > 1 {
		for i := range out {
			out[i].CPUTime += f.cpuStep[out[i].PID]
		}
	}
	return out, nil
}
func (f *fakeReader) Footprint(int) (uint64, time.Time, error) { return 0, time.Time{}, nil }
func (f *fakeReader) GroupMembers(int) ([]int, error)          { return nil, nil }
func (f *fakeReader) Children(int) ([]int, error)              { return nil, nil }
func (f *fakeReader) Sid(int) (int, error)                     { return 0, nil }
func (f *fakeReader) Args(pid int) []string                    { return f.args[pid] }
func (f *fakeReader) Env(int, ...string) map[string]string     { return nil }
func (f *fakeReader) Cwd(pid int) string                       { return f.cwd[pid] }
func (f *fakeReader) SelfTest() error                          { return nil }

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func fixture() *fakeReader {
	p := func(pid int, name string, fp uint64, ok bool) resources.Proc {
		return resources.Proc{PID: pid, PPID: 1, Name: name, Start: t0.Add(time.Duration(pid) * time.Second), Footprint: fp, FootprintOK: ok}
	}
	return &fakeReader{
		sys: resources.System{RAM: 16 << 30, PageSize: 16384, Free: 1000, Pressure: resources.LevelWarn, SwapUsed: 3 << 30},
		procs: []resources.Proc{
			p(10, "small", 100*mb, true),
			p(11, "big", 9<<30, true),
			p(12, "mid", 2<<30, true),
			p(13, "root-owned", 0, false),
			p(14, "tie-a", 500*mb, true),
			p(15, "tie-b", 500*mb, true),
		},
		args: map[int][]string{
			11: {"python", "train.py", "--api-key=sk-live-abcdef123456", "https://user:hunter2@example.com/x"},
			12: {"node", strings.Repeat("a", 400)},
		},
		cwd:     map[int]string{11: "/home/user/proj\x1b[2J"},
		cpuStep: map[int]time.Duration{10: 900 * time.Millisecond, 11: 100 * time.Millisecond, 12: 500 * time.Millisecond},
	}
}

// CR-7: `top --mem` ranks by footprint, redacts the command line, truncates
// it, excludes unreadable processes (and says so) and breaks ties by pid.
func TestCR7TopMem(t *testing.T) {
	rows, unread, err := Top(fixture(), ByMem, 4, 0, func() time.Time { return t0 }, nil)
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, r := range rows {
		pids = append(pids, r.PID)
	}
	if want := []int{11, 12, 14, 15}; len(pids) != 4 || pids[0] != want[0] || pids[1] != want[1] || pids[2] != want[2] || pids[3] != want[3] {
		t.Fatalf("order %v, want %v", pids, want)
	}
	if unread != 1 {
		t.Fatalf("unreadable %d", unread)
	}
	if strings.Contains(rows[0].Cmd, "sk-live") || strings.Contains(rows[0].Cmd, "hunter2") {
		t.Fatalf("secret in cmd: %q", rows[0].Cmd)
	}
	if len([]rune(rows[1].Cmd)) > MaxCmdRunes {
		t.Fatalf("cmd not truncated: %d runes", len([]rune(rows[1].Cmd)))
	}
	if strings.ContainsRune(rows[0].Cwd, 0x1b) || !strings.HasPrefix(rows[0].Cwd, "/home/user/proj") {
		t.Fatalf("cwd %q", rows[0].Cwd)
	}
	if rows[2].Cmd != "tie-a" {
		t.Fatalf("name fallback: %q", rows[2].Cmd)
	}

	var buf bytes.Buffer
	if err := Write(&buf, ByMem, rows, unread, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "FOOTPRINT") || !strings.Contains(out, "9.0 GB") || strings.Contains(out, "sk-live") ||
		!strings.Contains(out, "not readable") || strings.Index(out, "python") > strings.Index(out, "node") {
		t.Fatalf("table:\n%s", out)
	}
	buf.Reset()
	if err := Write(&buf, ByMem, rows, unread, true); err != nil {
		t.Fatal(err)
	}
	var js struct {
		Mode       string `json:"mode"`
		Rows       []Row  `json:"rows"`
		Unreadable int    `json:"unreadable_procs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &js); err != nil || js.Mode != "mem" || len(js.Rows) != 4 || js.Rows[0].PID != 11 ||
		js.Rows[0].Footprint != 9<<30 || js.Rows[0].Start == "" || js.Unreadable != 1 {
		t.Fatalf("json %v %+v\n%s", err, js, buf.String())
	}
	if strings.Contains(buf.String(), "sk-live") {
		t.Fatal("secret in json")
	}
}

func TestTopCPUUsesTwoScans(t *testing.T) {
	f := fixture()
	clock := t0
	var slept time.Duration
	rows, _, err := Top(f, ByCPU, 3, time.Second,
		func() time.Time { return clock },
		func(d time.Duration) { slept += d; clock = clock.Add(d) })
	if err != nil {
		t.Fatal(err)
	}
	if slept != time.Second || f.calls != 2 {
		t.Fatalf("slept %v, scans %d", slept, f.calls)
	}
	// 900ms over 1s = 90%, 500ms = 50%, 100ms = 10%.
	want := []struct {
		pid int
		pct float64
	}{{10, 90}, {12, 50}, {11, 10}}
	for i, w := range want {
		if rows[i].PID != w.pid || rows[i].CPUPct < w.pct-0.01 || rows[i].CPUPct > w.pct+0.01 {
			t.Fatalf("row %d = %+v, want pid %d at %.0f%%", i, rows[i], w.pid, w.pct)
		}
	}
}

func TestSamplerRecordShape(t *testing.T) {
	f := fixture()
	clock := t0
	s := New(f, 3)
	s.Now = func() time.Time { return clock }
	first, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range first.TopCPU {
		if r.CPUPct != 0 {
			t.Fatal("first sample has no CPU baseline")
		}
	}
	clock = clock.Add(10 * time.Second)
	rec, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.TopMem) != 3 || len(rec.TopCPU) != 3 || rec.TopMem[0].PID != 11 || rec.TopCPU[0].PID != 10 {
		t.Fatalf("%+v", rec)
	}
	if rec.TopCPU[0].CPUPct < 8.9 || rec.TopCPU[0].CPUPct > 9.1 { // 0.9s over 10s
		t.Fatalf("cpu %v", rec.TopCPU[0].CPUPct)
	}
	if rec.Sys.Pressure != "warn" || rec.Sys.SwapUsed != 3<<30 || rec.Sys.HeadroomBytes != 1000*16384 || rec.Unread != 1 {
		t.Fatalf("sys %+v", rec.Sys)
	}
	line, err := rec.Line()
	if err != nil || bytes.Contains(line, []byte("\n")) || !json.Valid(line) {
		t.Fatalf("line %v %q", err, line)
	}
	if strings.Contains(string(line), "hunter2") || strings.Contains(string(line), "sk-live") {
		t.Fatal("secret in resources.jsonl line")
	}
	// A reused pid (same pid, new start) gets no CPU delta from the old one.
	f.procs[0].Start = f.procs[0].Start.Add(time.Hour)
	f.procs[0].CPUTime = 0
	clock = clock.Add(10 * time.Second)
	rec, _ = s.Sample()
	for _, r := range rec.TopCPU {
		if r.PID == 10 && r.CPUPct != 0 {
			t.Fatalf("pid reuse inherited a CPU baseline: %v", r.CPUPct)
		}
	}
}

func TestTopDefaultAndEmpty(t *testing.T) {
	f := &fakeReader{}
	rows, unread, err := Top(f, ByMem, 0, 0, nil, nil)
	if err != nil || len(rows) != 0 || unread != 0 {
		t.Fatalf("%v %v %v", rows, unread, err)
	}
	var buf bytes.Buffer
	Write(&buf, ByMem, rows, 0, false)
	if !strings.Contains(buf.String(), "PID") {
		t.Fatal("header missing for an empty list")
	}
}
