package guard

import (
	"fmt"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

const (
	gib = uint64(1) << 30
	ram = 16 * gib
	pgz = uint64(4096)
)

var t0 = time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)

// proc is one fake process.
type proc struct {
	pid, ppid, pgid int
	start           time.Time
	stopped, dead   bool
	termPending     bool
	excluded        bool
	ignoreTerm      bool // survives SIGTERM, so SIGKILL is needed
}

type sigRec struct {
	pid int
	sig syscall.Signal
}

// world is the fake process table. It is the Signaller (with the
// start-time check the real one does), the ProcView and the source of
// group members.
type world struct {
	mu    sync.Mutex
	procs map[int]*proc
	log   []sigRec
	// refuse, if set, makes Signal fail for these pids with ErrRefused.
	refuse map[int]bool
}

func newWorld() *world { return &world{procs: map[int]*proc{}, refuse: map[int]bool{}} }

func (w *world) add(pid, ppid, pgid int, start time.Time) *proc {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := &proc{pid: pid, ppid: ppid, pgid: pgid, start: start}
	w.procs[pid] = p
	return p
}

// Signal implements Signaller like OSSignaller: it refuses a start-time
// mismatch, then applies the signal's effect to the fake process.
func (w *world) Signal(pid int, start time.Time, sig syscall.Signal) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.refuse[pid] {
		return ErrRefused
	}
	p := w.procs[pid]
	if p == nil || p.dead || !sameStart(p.start, start) {
		return ErrStartMismatch
	}
	w.log = append(w.log, sigRec{pid, sig})
	switch sig {
	case sigSTOP:
		p.stopped = true
	case sigCONT:
		p.stopped = false
		if p.termPending {
			p.dead = true
		}
	case sigTERM:
		if p.ignoreTerm {
			break
		}
		if p.stopped {
			p.termPending = true // stays pending until SIGCONT
		} else {
			p.dead = true
		}
	case sigKILL:
		p.dead = true
	}
	return nil
}

func (w *world) sigs(sig syscall.Signal) []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []int
	for _, l := range w.log {
		if l.sig == sig {
			out = append(out, l.pid)
		}
	}
	return out
}

func (w *world) count(sig syscall.Signal) int { return len(w.sigs(sig)) }

func (w *world) stoppedPIDs() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []int
	for _, p := range w.procs {
		if p.stopped && !p.dead {
			out = append(out, p.pid)
		}
	}
	sort.Ints(out)
	return out
}

func (w *world) members(pgid int) []Member {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []Member
	for _, p := range w.procs {
		if p.pgid == pgid && !p.dead {
			out = append(out, Member{PID: p.pid, PPID: p.ppid, Start: p.start, Excluded: p.excluded, Stopped: p.stopped})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// ProcView.
func (w *world) Group(pgid int) ([]ProcInfo, error) {
	var out []ProcInfo
	for _, m := range w.members(pgid) {
		out = append(out, ProcInfo{PID: m.PID, PGID: pgid, Start: m.Start, Stopped: m.Stopped})
	}
	return out, nil
}

func (w *world) Alive(pid int, start time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.procs[pid]
	return p != nil && !p.dead && sameStart(p.start, start)
}

func (w *world) Stopped() ([]ProcInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []ProcInfo
	for _, p := range w.procs {
		if p.stopped && !p.dead {
			out = append(out, ProcInfo{PID: p.pid, PGID: p.pgid, Start: p.start, Stopped: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// sink collects events.
type sink struct {
	mu sync.Mutex
	ev []evt
}
type evt struct {
	name string
	f    map[string]any
}

func (s *sink) Event(name string, f map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, evt{name, f})
}

func (s *sink) named(n string) []evt {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []evt
	for _, e := range s.ev {
		if e.name == n {
			out = append(out, e)
		}
	}
	return out
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (n *fakeNotifier) Notify(key, title, msg string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, key+"|"+title+"|"+msg)
	return true, nil
}

// gdef defines one agent group in a scenario.
type gdef struct {
	pgid       int
	start      time.Time
	fp         uint64
	tier       Tier
	envOK      bool
	allow      bool
	budget     *Budget
	cmd        string
	ver        string
	ineligible bool // Tier stays TierNone (a Codex-shaped group)
}

// rig drives machine, detector, executor and fake world together.
type rig struct {
	t    *testing.T
	w    *world
	m    *Machine
	ex   *Executor
	st   *MemStore
	det  danger.Detector
	ev   *sink
	nt   *fakeNotifier
	cfg  Config
	at   time.Time
	hist map[string][]danger.Point

	groups map[int]*gdef
	inel   map[string]uint64
	unattr uint64

	comp     uint64 // pages_compressed of 1000
	compB    uint64 // compressor physical bytes
	swap     uint64
	disk     uint64 // free disk bytes (0 = 200 GiB)
	headroom uint64 // bytes
	d5       bool
	scanAge  time.Duration // how old the last scan is
	scanOK   bool
	selfTest error
	acts     []Action // all actions so far
	timed    []timedAct
	lastSig  danger.Signals
	lastSnap Snapshot
}

type timedAct struct {
	at time.Time
	a  Action
}

func newRig(t *testing.T, mode Mode) *rig {
	cfg := DefaultConfig(mode)
	r := &rig{
		t: t, w: newWorld(), cfg: cfg, at: t0,
		st: &MemStore{}, ev: &sink{}, nt: &fakeNotifier{},
		hist:   map[string][]danger.Point{},
		groups: map[int]*gdef{}, inel: map[string]uint64{},
		headroom: 6 * gib, scanOK: true,
	}
	r.det = danger.Detector{Cfg: cfg.Danger}
	r.m = NewMachine(cfg)
	r.newExecutor()
	return r
}

func (r *rig) newExecutor() {
	r.ex = &Executor{M: r.m, Sig: r.w, Store: r.st, View: r.w, Clock: clockFn(func() time.Time { return r.at }),
		Events: r.ev, Notify: r.nt, SlowFsync: 2 * time.Second, Batch: r.cfg.BatchSize}
}

type clockFn func() time.Time

func (c clockFn) Now() time.Time { return c() }

// addGroup creates a group leader process and its definition.
func (r *rig) addGroup(g gdef, children ...int) *gdef {
	if g.start.IsZero() {
		g.start = r.at.Add(-time.Hour)
	}
	if g.tier == TierNone && !g.ineligible {
		g.tier = TierTool
	}
	if g.cmd == "" {
		g.cmd = fmt.Sprintf("job%d", g.pgid)
	}
	r.w.add(g.pgid, 1, g.pgid, g.start)
	for _, c := range children {
		r.w.add(c, g.pgid, g.pgid, g.start.Add(time.Second))
	}
	r.groups[g.pgid] = &g
	return &g
}

func (r *rig) tool(pgid int, fp uint64, children ...int) *gdef {
	return r.addGroup(gdef{pgid: pgid, fp: fp, tier: TierTool, envOK: true, allow: true}, children...)
}

func (r *rig) sys(lvl resources.Level) resources.System {
	return resources.System{
		At: r.at, RAM: ram, PageSize: pgz, Free: r.headroom / pgz, Pressure: lvl,
		CompressorBytes: r.compB, PagesCompressed: r.comp, PagesCompressedLimit: 1000, SegmentLimit: 1000,
		SwapUsed: r.swap, DiskFree: r.diskFree(),
	}
}

func (r *rig) diskFree() uint64 {
	if r.disk == 0 {
		return 200 * gib
	}
	return r.disk
}

func (r *rig) setMinShare(f float64) {
	r.cfg.Danger.MinShare = f
	r.det.Cfg.MinShare = f
	r.m.mu.Lock()
	r.m.cfg.Danger.MinShare = f
	r.m.mu.Unlock()
}

// poll advances dt and runs one guard poll at pressure lvl.
func (r *rig) poll(dt time.Duration, lvl resources.Level) []Action {
	r.at = r.at.Add(dt)
	sys := r.sys(lvl)
	var terms []Term
	var gs []danger.GroupSeries
	pgids := make([]int, 0, len(r.groups))
	for p := range r.groups {
		pgids = append(pgids, p)
	}
	sort.Ints(pgids)
	for _, p := range pgids {
		g := r.groups[p]
		if len(r.w.members(p)) == 0 {
			continue
		}
		key := keyOf(g.pgid, g.start)
		series := append(r.hist[key], danger.Point{At: r.at, Bytes: g.fp})
		for len(series) > 1 && r.at.Sub(series[0].At) > time.Minute {
			series = series[1:]
		}
		r.hist[key] = series
		grp := &Group{PGID: g.pgid, LeaderStart: g.start, Tier: g.tier, Members: r.w.members(p), Footprint: g.fp,
			Cmd: g.cmd, ClaudeVer: g.ver, Allowlisted: g.allow, EnvOK: g.envOK, Budget: g.budget, Agent: "agent-x"}
		terms = append(terms, Term{Key: key, Group: grp, Series: series})
		if g.tier != TierNone {
			gs = append(gs, danger.GroupSeries{PGID: g.pgid, Series: series})
		}
	}
	for k, fp := range r.inel {
		key := "inel:" + k
		series := append(r.hist[key], danger.Point{At: r.at, Bytes: fp})
		for len(series) > 1 && r.at.Sub(series[0].At) > time.Minute {
			series = series[1:]
		}
		r.hist[key] = series
		terms = append(terms, Term{Key: key, Series: series})
	}
	{
		series := append(r.hist["unattributed"], danger.Point{At: r.at, Bytes: r.unattr})
		for len(series) > 1 && r.at.Sub(series[0].At) > time.Minute {
			series = series[1:]
		}
		r.hist["unattributed"] = series
		terms = append(terms, Term{Key: "unattributed", Series: series})
	}
	sig := r.det.Observe(sys, r.d5, gs)
	snap := Snapshot{At: r.at, Sys: sys, Signals: sig, Terms: terms,
		ScanAt: r.at.Add(-r.scanAge), ScanOK: r.scanOK, SelfTest: r.selfTest, Alive: r.w.Alive}
	r.lastSig = sig
	r.lastSnap = snap
	acts := r.m.Step(snap)
	for _, a := range acts {
		r.timed = append(r.timed, timedAct{r.at, a})
	}
	r.ex.Apply(acts)
	r.acts = append(r.acts, acts...)
	return acts
}

// run polls n times at step dt.
func (r *rig) run(n int, dt time.Duration, lvl resources.Level) {
	for i := 0; i < n; i++ {
		r.poll(dt, lvl)
	}
}

func (r *rig) countKind(k ActionKind) int {
	n := 0
	for _, a := range r.acts {
		if a.Kind == k {
			n++
		}
	}
	return n
}

// first returns the time of the first action of kind k for pgid (0 = any).
func (r *rig) first(k ActionKind, pgid int) (time.Time, bool) {
	for _, t := range r.timed {
		if t.a.Kind == k && (pgid == 0 || t.a.PGID == pgid) {
			return t.at, true
		}
	}
	return time.Time{}, false
}

func (r *rig) grow(pgid int, d uint64) { r.groups[pgid].fp += d }

func (r *rig) rec(pgid int) *Record {
	for _, rc := range r.m.State().Groups {
		if rc.PGID == pgid {
			return rc
		}
	}
	return nil
}

func (r *rig) paused(pgid int) bool {
	rc := r.rec(pgid)
	return rc != nil && rc.Phase == PhasePaused
}

func (r *rig) noneStopped() bool { return len(r.w.stoppedPIDs()) == 0 }

func must(t *testing.T, ok bool, f string, a ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(f, a...)
	}
}
