package resmon

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/alerts"
	"github.com/ericmacdougall/netwatch/internal/budget"
	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/tracker"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

const gib = uint64(1) << 30

var t0 = time.Date(2026, 11, 4, 16, 6, 40, 0, time.UTC)

// fake is a process table plus a scripted system reading. Footprints grow
// by grow[pid] bytes per second of fake time.
type fake struct {
	mu      sync.Mutex
	now     time.Time
	procs   map[int]*resources.Proc
	grow    map[int]uint64
	sys     func(now time.Time) resources.System
	sysErr  error
	scanErr error
}

func newFake() *fake {
	return &fake{now: t0, procs: map[int]*resources.Proc{}, grow: map[int]uint64{}}
}

func (f *fake) add(pid, ppid, pgid int, fp, grow uint64) {
	f.procs[pid] = &resources.Proc{PID: pid, PPID: ppid, PGID: pgid, SID: pgid, UID: 501,
		Start: t0.Add(-time.Minute), Name: "python3", Footprint: fp, FootprintOK: true}
	f.grow[pid] = grow
}

func (f *fake) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	for pid, g := range f.grow {
		if p := f.procs[pid]; p != nil && !p.Stopped {
			p.Footprint += uint64(d.Seconds() * float64(g))
		}
	}
}

func (f *fake) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }

func (f *fake) System() (resources.System, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sysErr != nil {
		return resources.System{}, f.sysErr
	}
	return f.sys(f.now), nil
}

func (f *fake) Procs() ([]resources.Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	out := make([]resources.Proc, 0, len(f.procs))
	for _, p := range f.procs {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fake) Footprint(pid int) (uint64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.procs[pid]
	if p == nil {
		return 0, time.Time{}, resources.ErrGone
	}
	return p.Footprint, p.Start, nil
}

func (f *fake) Probe(pid int, out *resources.Proc) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.procs[pid]
	if p == nil {
		return resources.ErrGone
	}
	*out = *p
	return nil
}

func (f *fake) AppendGroupMembers(dst []int, pgid int) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.procs {
		if p.PGID == pgid {
			dst = append(dst, p.PID)
		}
	}
	return dst, nil
}

func (f *fake) AppendChildren(dst []int, pid int) ([]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.procs {
		if p.PPID == pid {
			dst = append(dst, p.PID)
		}
	}
	return dst, nil
}

func (f *fake) GroupMembers(pgid int) ([]int, error) { return f.AppendGroupMembers(nil, pgid) }
func (f *fake) Children(pid int) ([]int, error)      { return f.AppendChildren(nil, pid) }
func (f *fake) Sid(pid int) (int, error)             { return pid, nil }
func (f *fake) Args(int) []string                    { return []string{"python3", "job.py"} }
func (f *fake) Env(int, ...string) map[string]string { return nil }
func (f *fake) Cwd(int) string                       { return "" }
func (f *fake) SelfTest() error                      { return nil }
func (f *fake) ExePath(int) string                   { return "/usr/bin/python3" }

// Signal is the fake Signaller: it records every signal and applies stop.
func (f *fake) record(log *[]sig) guard.Signaller { return sigFunc{f, log} }

type sig struct {
	pid int
	s   syscall.Signal
}

type sigFunc struct {
	f   *fake
	log *[]sig
}

func (s sigFunc) Signal(pid int, start time.Time, sg syscall.Signal) error {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	p := s.f.procs[pid]
	if p == nil || !p.Start.Equal(start) {
		return errors.New("gone")
	}
	*s.log = append(*s.log, sig{pid, sg})
	switch sg {
	case syscall.SIGSTOP:
		p.Stopped = true
	case syscall.SIGCONT:
		p.Stopped = false
	}
	return nil
}

// fixedClassifier marks the listed pgids as verified tool groups.
type fixedClassifier struct{ tool []int }

func (c fixedClassifier) Classify(scan []resources.Proc, _ []watcher.Record, _ map[int]budget.Declared) Classification {
	var gs []tracker.GroupInfo
	for _, pg := range c.tool {
		for _, p := range scan {
			if p.PID == pg {
				gs = append(gs, tracker.GroupInfo{PGID: pg, LeaderStart: p.Start, Tier: guard.TierTool,
					Agent: "agent:test", ClaudeVer: "2.1.318", Allowlisted: true, EnvOK: true, FromWatcher: true})
			}
		}
	}
	return Classification{Groups: gs, OwnerOf: func(resources.Proc) string { return "other" }}
}

type events struct {
	mu  sync.Mutex
	got []string
}

func (e *events) Event(name string, _ map[string]any) {
	e.mu.Lock()
	e.got = append(e.got, name)
	e.mu.Unlock()
}

func (e *events) has(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, g := range e.got {
		if g == name {
			return true
		}
	}
	return false
}

// critical is a 16 GiB host under critical pressure with a nearly full
// compressor: every danger path is open.
func critical(now time.Time) resources.System {
	return resources.System{At: now, RAM: 16 * gib, PageSize: 16384, Free: 1000,
		PagesCompressed: 98, PagesCompressedLimit: 100, Pressure: resources.LevelCritical}
}

func healthy(now time.Time) resources.System {
	return resources.System{At: now, RAM: 16 * gib, PageSize: 16384, Free: 500000,
		PagesCompressed: 10, PagesCompressedLimit: 100, Pressure: resources.LevelNormal}
}

type harness struct {
	f    *fake
	loop *Loop
	sigs []sig
	ev   *events
	out  bytes.Buffer
	m    *guard.Machine
}

func newHarness(t *testing.T, f *fake, mode guard.Mode, cls Classifier, tt *TestTarget) *harness {
	t.Helper()
	h := &harness{f: f, ev: &events{}}
	h.m = guard.NewMachine(guard.DefaultConfig(mode))
	exec := &guard.Executor{M: h.m, Sig: f.record(&h.sigs), Store: &guard.MemStore{},
		View: guard.ReaderView{R: f}, Clock: f, Events: h.ev}
	h.loop = New(Deps{R: f, Classifier: cls, Machine: h.m, Exec: exec,
		Alerts: alerts.New(alerts.Config{}, nil, nil), Sampler: sampler.New(f, 5),
		Resources: lineAppender{&h.out}, Events: h.ev, Now: f.Now, TestTarget: tt})
	return h
}

// run ticks for d of fake time at the interval the loop asks for.
func (h *harness) run(d time.Duration) {
	end := h.f.Now().Add(d)
	for h.f.Now().Before(end) {
		hot := h.loop.Tick()
		step := 10 * time.Second
		if hot {
			step = 2 * time.Second
		}
		h.f.advance(step)
	}
}

func (h *harness) stopped(pid int) bool {
	for _, s := range h.sigs {
		if s.pid == pid && s.s == syscall.SIGSTOP {
			return true
		}
	}
	return false
}

// Two fast-growing verified groups under critical pressure: only the test
// target may be signalled, even though the other group is larger and grows
// faster (spec AC-5 control: a second job not matching guard_test_target is
// never signalled). Without demoteOthers the larger group is paused.
func TestTestTargetIsTheOnlyGroupSignalled(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.add(100, 1, 100, 2*gib, gib/2) // target
	f.add(200, 1, 200, 6*gib, gib)   // bystander: larger, faster
	tt := &TestTarget{PGID: 100, Start: f.procs[100].Start, Tier: guard.TierTool}
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100, 200}}, tt)
	h.run(3 * time.Minute)
	if h.stopped(200) {
		t.Fatalf("bystander group 200 was signalled: %v", h.sigs)
	}
	for _, s := range h.sigs {
		if s.pid != 100 {
			t.Fatalf("signal to non-target pid %d: %v", s.pid, h.sigs)
		}
	}
	if !h.stopped(100) {
		t.Fatalf("target was never paused (test would be vacuous): %v", h.sigs)
	}
}

// Control for the above: without a test target the larger causal group is
// paused, so the target filter is what protects it.
func TestWithoutTargetTheLargerGroupIsPaused(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.add(100, 1, 100, 2*gib, gib/2)
	f.add(200, 1, 200, 6*gib, gib)
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100, 200}}, nil)
	h.run(3 * time.Minute)
	if !h.stopped(200) {
		t.Fatalf("larger causal group not paused without a target: %v", h.sigs)
	}
}

// A failed system read takes no guard action at all.
func TestFailedSystemReadSignalsNothing(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.sysErr = errors.New("sysctl failed")
	f.add(100, 1, 100, 12*gib, gib)
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100}}, nil)
	h.run(2 * time.Minute)
	if len(h.sigs) != 0 {
		t.Fatalf("signals on failed reads: %v", h.sigs)
	}
}

// Readings that fail after a pause must not hold the group past the
// 30 minute pause limit (red-team F7).
func TestFailedReadsStillReleaseAfterMaxPause(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.add(100, 1, 100, 12*gib, gib)
	h := newHarness(t, f, guard.ModePause, fixedClassifier{tool: []int{100}}, nil)
	h.run(3 * time.Minute)
	if !h.stopped(100) {
		t.Fatalf("setup: group not paused: %v", h.sigs)
	}
	f.sysErr = errors.New("sysctl failed")
	h.run(31 * time.Minute)
	cont := false
	for _, s := range h.sigs {
		if s.pid == 100 && s.s == syscall.SIGCONT {
			cont = true
		}
	}
	if !cont {
		t.Fatalf("paused group held past 30m while readings failed: %v", h.sigs)
	}
}

// A healthy host gives zero guard signals and writes samples.
func TestHealthyHostNoSignalsAndSamplesWritten(t *testing.T) {
	f := newFake()
	f.sys = healthy
	f.add(100, 1, 100, 4*gib, 0)
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100}}, nil)
	h.run(time.Minute)
	if len(h.sigs) != 0 {
		t.Fatalf("signals on a healthy host: %v", h.sigs)
	}
	if n := bytes.Count(h.out.Bytes(), []byte("\n")); n < 5 {
		t.Fatalf("resources.jsonl has %d lines after 60s, want about 6", n)
	}
	if !bytes.Contains(h.out.Bytes(), []byte(`"agent":"agent:test"`)) {
		t.Fatalf("sample rows are not labelled with the group's agent: %s", h.out.String())
	}
}

// The mode source switches the machine and logs MODE_CHANGE; with alert
// mode nothing is signalled even under danger.
func TestModeSourceSwitchesMode(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.add(100, 1, 100, 12*gib, gib)
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100}}, nil)
	h.loop.d.Mode = func() (guard.Mode, bool) { return guard.ModeAlert, true }
	h.run(2 * time.Minute)
	if h.m.Mode() != guard.ModeAlert || !h.ev.has("MODE_CHANGE") {
		t.Fatalf("mode = %s, MODE_CHANGE logged = %v", h.m.Mode(), h.ev.has("MODE_CHANGE"))
	}
	if len(h.sigs) != 0 {
		t.Fatalf("signals in alert mode: %v", h.sigs)
	}
}

type recWatcher struct{ scans []watcher.Scan }

func (w *recWatcher) Watch([]resources.Proc)    {}
func (w *recWatcher) Records() []watcher.Record { return nil }
func (w *recWatcher) AfterScan(s watcher.Scan)  { w.scans = append(w.scans, s) }

// A failed scan reaches the watcher as OK=false, so it retires nothing
// (CR-11), and the classification from the last good scan is kept.
func TestFailedScanIsPassedOnAsNotOK(t *testing.T) {
	f := newFake()
	f.sys = healthy
	f.add(100, 1, 100, gib, 0)
	h := newHarness(t, f, guard.ModeAlert, fixedClassifier{tool: []int{100}}, nil)
	w := &recWatcher{}
	h.loop.d.Watcher = w
	h.loop.Tick()
	f.scanErr = errors.New("scan failed")
	f.advance(11 * time.Second)
	h.loop.Tick()
	if len(w.scans) != 2 || !w.scans[0].OK || w.scans[1].OK {
		t.Fatalf("scans passed to watcher: %+v", w.scans)
	}
	if len(h.loop.cls.Groups) != 1 {
		t.Fatalf("failed scan dropped the last good classification")
	}
}

// lineAppender writes each record as one JSON line, like eventlog.Writer.
type lineAppender struct{ b *bytes.Buffer }

func (a lineAppender) Append(rec any) error {
	j, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	a.b.Write(append(j, '\n'))
	return nil
}

// The detector uses the configured danger thresholds (guard_min_share and
// friends), not the defaults; nil keeps the defaults.
func TestDetectorUsesConfiguredDanger(t *testing.T) {
	dc := danger.Defaults()
	dc.MinShare, dc.HeadroomFrac, dc.P1Horizon = 0.1, 0.95, time.Minute
	l := New(Deps{R: newFake(), Danger: &dc})
	if l.det.Cfg != dc {
		t.Fatalf("detector config %+v, want %+v", l.det.Cfg, dc)
	}
	if l := New(Deps{R: newFake()}); l.det.Cfg != danger.Defaults() {
		t.Fatalf("nil Danger: %+v, want defaults", l.det.Cfg)
	}
}
