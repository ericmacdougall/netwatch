package guard

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
)

// restart simulates a daemon restart: a new machine, detector and executor
// on the same store and the same processes. It returns the recovery report.
func (r *rig) restart(mode Mode) RecoverReport {
	r.cfg.Mode = mode
	r.m = NewMachine(r.cfg)
	r.det = danger.Detector{Cfg: r.cfg.Danger}
	r.hist = map[string][]danger.Point{}
	r.newExecutor()
	return r.ex.Recover()
}

func TestRestartMidEpisodeKeepsPauseAndKillEligibility(t *testing.T) {
	r := killRig(t, ModePauseKill)
	rep := r.restart(ModePauseKill)
	must(t, len(rep.Adopted) == 1 && rep.Adopted[0] == 100 && len(rep.Resumed) == 0, "must adopt the pause: %+v", rep)
	must(t, r.paused(100) && !r.noneStopped(), "the group must stay paused")
	r.runCrit(80, 2*time.Second)
	_, ok := r.termAt()
	must(t, ok, "kill eligibility (latched D4, facts) must survive the restart")
}

func TestRestartResumesInTheSpecifiedCases(t *testing.T) {
	cases := map[string]func(r *rig) Mode{
		"mode now alert": func(r *rig) Mode { return ModeAlert },
		"mode now off":   func(r *rig) Mode { return ModeOff },
		"max pause passed": func(r *rig) Mode {
			r.at = r.at.Add(31 * time.Minute)
			return ModePauseKill
		},
		"episode cleared": func(r *rig) Mode {
			st, _ := r.st.Load()
			st.Episode.Cleared = true
			r.st.Save(st)
			return ModePauseKill
		},
	}
	for name, prep := range cases {
		r := killRig(t, ModePauseKill)
		mode := prep(r)
		rep := r.restart(mode)
		must(t, len(rep.Resumed) == 1 && r.noneStopped(), "%s: must resume on restart: %+v", name, rep)
	}
	// Unreadable version: valid JSON with a version we cannot read.
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	fs := &FileStore{Path: filepath.Join(dir, "state.json")}
	r := killRig(t, ModePauseKill)
	good, _ := r.st.Load()
	_, err := fs.Save(good)
	must(t, err == nil, "save: %v", err)
	b, _ := os.ReadFile(fs.Path)
	b = []byte(string(b[:len(b)-1]) + `,"future":1}`)
	b = []byte(replaceOnce(string(b), `"version":1`, `"version":99`))
	os.WriteFile(fs.Path, b, 0o600)
	r.st = nil
	rr := &Executor{M: NewMachine(r.cfg), Sig: r.w, Store: fs, View: r.w, Clock: clockFn(func() time.Time { return r.at }), Events: r.ev}
	rep := rr.Recover()
	must(t, len(rep.Resumed) == 1 && r.noneStopped(), "an unreadable version must resume: %+v", rep)
	// Control: the unmodified state adopts.
	c := killRig(t, ModePauseKill)
	rep = c.restart(ModePauseKill)
	must(t, len(rep.Adopted) == 1 && !c.noneStopped(), "control: adopts")
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func TestClearHoldRestartsAfterCrash(t *testing.T) {
	r := pausedTwo(t, ModePause)
	r.restart(ModePause)
	t1 := r.at.Add(5 * time.Second)
	// A snapshot that claims Clear 5s after the restart must not resume.
	snap := func(at time.Time) []Action {
		s := r.lastSnap
		s.At, s.Sys.At = at, at
		s.Signals = danger.Signals{Clear: true}
		return r.m.Step(s)
	}
	r.m.mu.Lock()
	r.m.restoredAt = r.at
	r.m.mu.Unlock()
	must(t, len(snap(t1)) == 0, "no resume within 30s of a restart")
	acts := snap(r.at.Add(31 * time.Second))
	must(t, len(acts) == 1 && acts[0].Kind == ActResume, "resume after the hold: %+v", acts)
}

type failAfter struct {
	inner Signaller
	n     int
	sent  int
}

func (f *failAfter) Signal(pid int, start time.Time, sig syscall.Signal) error {
	if sig == syscall.SIGSTOP {
		if f.sent >= f.n {
			return errors.New("daemon killed")
		}
		f.sent++
	}
	return f.inner.Signal(pid, start, sig)
}

func TestCrashBetweenIntentAndSigstopIsRecovered(t *testing.T) {
	// NEG-9: the intent is saved, then the daemon dies before any SIGSTOP.
	for _, mode := range []Mode{ModePause, ModeAlert} {
		r := newRig(t, ModePause)
		r.tool(100, 10*gib, 101, 102)
		r.ex.Sig = &failAfter{inner: r.w, n: 0}
		r.run(3, 2*time.Second, normal)
		for i := 0; i < 3; i++ {
			r.grow(100, gib)
			r.poll(2*time.Second, warn)
		}
		must(t, r.noneStopped(), "setup: the crash left nothing stopped")
		saved, err := r.st.Load()
		must(t, err == nil && len(saved.Groups) == 1, "the intent must be on disk first: %v", err)
		r.restart(mode)
		if mode == ModePause {
			must(t, r.paused(100), "restart in pause mode keeps the record")
			r.poll(2*time.Second, warn)
			must(t, !r.w.procs[100].stopped || true, "")
			must(t, r.w.procs[100].stopped && r.w.procs[101].stopped && r.w.procs[102].stopped, "running members of a recorded group must be stopped on the next poll")
		} else {
			must(t, r.rec(100) == nil && r.noneStopped(), "alert mode: resumed and cleared")
		}
	}
}

func TestKillNineAfterThreeOfEightMembersStopped(t *testing.T) {
	build := func() *rig {
		r := newRig(t, ModePause)
		r.tool(100, 10*gib, 101, 102, 103, 104, 105, 106, 107)
		r.ex.Sig = &failAfter{inner: r.w, n: 3}
		r.run(3, 2*time.Second, normal)
		for i := 0; i < 3; i++ {
			r.grow(100, gib)
			r.poll(2*time.Second, warn)
		}
		must(t, len(r.w.stoppedPIDs()) == 3, "setup: exactly 3 of 8 stopped, got %v", r.w.stoppedPIDs())
		return r
	}
	// Restart in alert mode: everything resumed, the record cleared.
	a := build()
	a.restart(ModeAlert)
	must(t, a.noneStopped(), "all members must run after the restart resume")
	// Restart in pause mode: the record is kept and the rest get stopped.
	b := build()
	b.restart(ModePause)
	b.poll(2*time.Second, warn)
	must(t, len(b.w.stoppedPIDs()) == 8 && b.paused(100), "pause mode adopts and completes the pause: %v", b.w.stoppedPIDs())
	// Control: a daemon variant that does nothing on restart leaves T.
	c := build()
	must(t, !c.noneStopped(), "control: without recovery the members stay stopped")
}

func TestSlowFsyncDoesNotBlockPauseAndIsRecorded(t *testing.T) {
	r := newRig(t, ModePause)
	r.st.Delay = 60 * time.Millisecond
	r.ex.SlowFsync = 20 * time.Millisecond
	r.tool(100, 10*gib, 101)
	r.run(3, 2*time.Second, normal)
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	_ = t0
	must(t, r.paused(100) && !r.noneStopped(), "the pause must go ahead despite the slow store")
	evs := r.ev.named("GUARD_PAUSE")
	must(t, len(evs) == 1, "GUARD_PAUSE event")
	f := evs[0].f
	must(t, f["slow_fsync"] == true && f["fsync_ms"].(int64) >= 20, "fsync_ms must be recorded: %v", f)
	// Slow fsync, then kill -9: the background write lands, and a restart
	// resumes a member netwatch stopped but never got to record.
	time.Sleep(1500 * time.Millisecond) // let the queued background writes land
	r.w.add(150, 100, 100, r.at)
	r.w.procs[150].stopped = true // stopped by the dead daemon after its last save
	rep := r.restart(ModeAlert)
	must(t, len(rep.Resumed) == 1 && r.noneStopped(), "every member netwatch stopped must be resumed: stopped %v", r.w.stoppedPIDs())
}

func TestMissingOrCorruptStateFailsClosedWithLoudAlert(t *testing.T) {
	// A corrupt state with a stopped process around: loud alert, nothing adopted.
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	fs := &FileStore{Path: filepath.Join(dir, "state.json")}
	w := newWorld()
	w.add(100, 1, 100, t0).stopped = true
	nt := &fakeNotifier{}
	ev := &sink{}
	mk := func() *Executor {
		return &Executor{M: NewMachine(DefaultConfig(ModePauseKill)), Sig: w, Store: fs, View: w, Events: ev, Notify: nt}
	}
	os.WriteFile(fs.Path, []byte("{not json"), 0o600)
	e := mk()
	rep := e.Recover()
	must(t, errors.Is(rep.Err, ErrCorrupt) && rep.FailedOK && len(rep.Stopped) == 1, "corrupt: %+v", rep)
	must(t, len(e.M.RecordKeys()) == 0, "nothing may be adopted")
	must(t, len(nt.msgs) == 1 && contains2(nt.msgs[0], "LOUD") && contains2(nt.msgs[0], "100"), "loud alert listing the stopped pids: %v", nt.msgs)
	must(t, w.procs[100].stopped, "netwatch must not touch what it cannot attribute")
	// Missing file with a stopped process: also loud.
	os.Remove(fs.Path)
	rep = mk().Recover()
	must(t, errors.Is(rep.Err, ErrMissing) && rep.FailedOK, "missing with stopped procs: %+v", rep)
	// Missing file on a clean host: first run, quiet.
	w.procs[100].stopped = false
	n := len(nt.msgs)
	rep = mk().Recover()
	must(t, !rep.FailedOK && len(nt.msgs) == n, "a first run with nothing stopped must be quiet: %+v", rep)
}

func TestFileStoreHardening(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "sub", "state.json")
	fs := &FileStore{Path: p}
	st := newState()
	st.Groups["k"] = &Record{PGID: 5, LeaderStart: t0, Phase: PhasePaused}
	_, err := fs.Save(st)
	must(t, err == nil, "save: %v", err)
	fi, _ := os.Stat(p)
	di, _ := os.Stat(filepath.Dir(p))
	must(t, fi.Mode().Perm() == 0o600 && di.Mode().Perm() == 0o700, "modes %v %v", fi.Mode().Perm(), di.Mode().Perm())
	got, err := fs.Load()
	must(t, err == nil && got.Groups["k"].PGID == 5 && got.Version == StateVersion, "roundtrip: %v %+v", err, got)
	ents, _ := os.ReadDir(filepath.Dir(p))
	must(t, len(ents) == 1, "no temp files may be left: %v", ents)

	// A symlinked state file is refused for read and write.
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("{}"), 0o600)
	os.Remove(p)
	os.Symlink(target, p)
	_, err = fs.Load()
	must(t, errors.Is(err, ErrUnsafe), "symlink read: %v", err)
	_, err = fs.Save(st)
	must(t, errors.Is(err, ErrUnsafe), "symlink write: %v", err)
	b, _ := os.ReadFile(target)
	must(t, string(b) == "{}", "the symlink target must be untouched")
	os.Remove(p)

	// A group-writable directory is refused.
	os.Chmod(filepath.Dir(p), 0o770)
	_, err = fs.Save(st)
	must(t, errors.Is(err, ErrUnsafe), "wide directory: %v", err)
	os.Chmod(filepath.Dir(p), 0o700)

	// Wide file mode, FIFO-like non-regular, missing, corrupt.
	fs.Save(st)
	os.Chmod(p, 0o644)
	_, err = fs.Load()
	must(t, errors.Is(err, ErrUnsafe), "wide file mode: %v", err)
	os.Remove(p)
	_, err = fs.Load()
	must(t, errors.Is(err, ErrMissing), "missing: %v", err)
	os.WriteFile(p, []byte(`{"groups":1}`), 0o600)
	_, err = fs.Load()
	must(t, errors.Is(err, ErrCorrupt), "no version is corrupt: %v", err)
	// Directory in place of the file.
	os.Remove(p)
	os.Mkdir(p, 0o700)
	_, err = fs.Load()
	must(t, errors.Is(err, ErrUnsafe), "a directory is not a state file: %v", err)
}

func TestManualResumeRules(t *testing.T) {
	r := pausedTwo(t, ModePause)
	// Refuses a group netwatch did not stop.
	_, err := ManualResume(r.st, r.w, r.w, r.at, 999, false)
	must(t, errors.Is(err, ErrNotRecorded), "unrecorded group: %v", err)
	n := len(r.w.log)

	// A pid reused since the pause is pruned, never signalled.
	r.w.procs[101] = &proc{pid: 101, ppid: 1, pgid: 9, start: r.at, stopped: true}
	rep, err := ManualResume(r.st, r.w, r.w, r.at, 100, false)
	must(t, err == nil && len(rep.Resumed) == 1, "resume 100: %v %+v", err, rep)
	for _, l := range r.w.log[n:] {
		must(t, l.pid != 101, "reused pid 101 signalled")
	}
	must(t, r.w.procs[101].stopped, "the stranger stays as it was")

	// A group whose members are all dead is pruned and reported.
	r.w.procs[200].dead, r.w.procs[201].dead = true, true
	rep, err = ManualResume(r.st, r.w, r.w, r.at, 0, true)
	must(t, err == nil && len(rep.Pruned) == 1 && rep.Pruned[0] == 200 && len(rep.Resumed) == 0, "prune dead: %v %+v", err, rep)
	st, _ := r.st.Load()
	must(t, len(st.Groups) == 0, "nothing left recorded")

	// --all resumes everything recorded.
	a := pausedTwo(t, ModePause)
	rep, err = ManualResume(a.st, a.w, a.w, a.at, 0, true)
	must(t, err == nil && len(rep.Resumed) == 2 && a.noneStopped(), "--all: %v %+v", err, rep)
}

func TestManualResumeFailsClosed(t *testing.T) {
	w := newWorld()
	w.add(100, 1, 100, t0).stopped = true
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	fs := &FileStore{Path: filepath.Join(dir, "state.json")}
	try := func(name string) {
		_, err := ManualResume(fs, w, w, t0, 0, true)
		must(t, err != nil, "%s: must refuse", name)
		must(t, w.procs[100].stopped && len(w.log) == 0, "%s: must not signal anything", name)
	}
	try("missing")
	os.WriteFile(fs.Path, []byte("garbage"), 0o600)
	try("corrupt")
	os.Remove(fs.Path)
	os.Symlink(filepath.Join(dir, "x"), fs.Path)
	try("symlink")
}

func TestRollbackGate(t *testing.T) {
	r := pausedTwo(t, ModePause)
	rep, err := RollbackGate(r.st, r.w, false)
	must(t, errors.Is(err, ErrPausedRemain) && len(rep.Live) == 2, "must refuse while live paused groups remain: %v %+v", err, rep)
	rep, err = RollbackGate(r.st, r.w, true)
	must(t, err == nil && rep.Forced && contains(rep.StoppedPIDs, 101) && contains(rep.StoppedPIDs, 201), "--force lists the stopped pids: %v %+v", err, rep)
	// The documented order: alert (resumes everything), resume --all, swap.
	r.m.SetMode(ModeAlert)
	r.poll(2*time.Second, normal)
	_, err = ManualResume(r.st, r.w, r.w, r.at, 0, true)
	must(t, err == nil, "resume --all after alert: %v", err)
	_, err = RollbackGate(r.st, r.w, false)
	must(t, err == nil, "gate passes once nothing is paused: %v", err)
	// Records whose pids are dead do not block.
	d := pausedTwo(t, ModePause)
	for _, p := range d.w.procs {
		p.dead = true
	}
	_, err = RollbackGate(d.st, d.w, false)
	must(t, err == nil, "dead groups are pruned, not blocking: %v", err)
	// A missing file means nothing paused; a corrupt one refuses unless forced.
	d2 := t.TempDir()
	os.Chmod(d2, 0o700)
	fs := &FileStore{Path: filepath.Join(d2, "s.json")}
	_, err = RollbackGate(fs, d.w, false)
	must(t, err == nil, "missing: %v", err)
	os.WriteFile(fs.Path, []byte("x"), 0o600)
	_, err = RollbackGate(fs, d.w, false)
	must(t, err != nil, "corrupt must refuse")
	_, err = RollbackGate(fs, d.w, true)
	must(t, err == nil, "corrupt with --force proceeds")
}

// intentSig fails the test if a SIGSTOP goes out before the record is on disk.
type intentSig struct {
	inner Signaller
	st    Store
	bad   *[]int
}

func (s intentSig) Signal(pid int, start time.Time, sig syscall.Signal) error {
	if sig == syscall.SIGSTOP || sig == syscall.SIGTERM {
		got, err := s.st.Load()
		if err != nil || len(got.Groups) == 0 {
			*s.bad = append(*s.bad, pid)
		}
	}
	return s.inner.Signal(pid, start, sig)
}

func TestIntentIsDurableBeforeAnySignal(t *testing.T) {
	var bad []int
	r := newRig(t, ModePauseKill)
	r.ex.Sig = intentSig{inner: r.w, st: r.st, bad: &bad}
	r.tool(100, 10*gib, 101)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	r.runCrit(70, 2*time.Second)
	must(t, r.w.count(syscall.SIGSTOP) > 0 && r.w.count(syscall.SIGTERM) > 0, "setup: pause and term happened")
	must(t, len(bad) == 0, "signals sent before the intent was saved: %v", bad)
}

// TestKillInFlightNeverEndsInSIGKILLWhenKillDisabled pins red-team F4: a
// SIGTERM sent by a pause+kill daemon must not be followed by SIGKILL after a
// restart into a config that cannot kill (pause mode, or NoKill on macOS).
func TestKillInFlightNeverEndsInSIGKILLWhenKillDisabled(t *testing.T) {
	for _, name := range []string{"pause mode", "NoKill", "control", "shutdown at once"} {
		r := killRig(t, ModePauseKill)
		r.w.procs[101].ignoreTerm = true
		r.runCrit(60, 2*time.Second)
		_, ok := r.termAt()
		must(t, ok && r.w.count(syscall.SIGKILL) == 0, "%s: setup: SIGTERM sent, no SIGKILL yet", name)
		switch name {
		case "pause mode":
			r.restart(ModePause)
		case "NoKill":
			r.cfg.NoKill = true
			r.restart(ModePauseKill)
		case "control":
			r.restart(ModePauseKill)
		case "shutdown at once":
			r.restart(ModePause)
			r.ex.Shutdown()
			must(t, r.w.count(syscall.SIGKILL) == 0 && r.noneStopped(), "%s: shutdown must resume, not SIGKILL", name)
			continue
		}
		r.run(10, 2*time.Second, crit)
		if name == "control" {
			must(t, r.w.count(syscall.SIGKILL) > 0, "control: pause+kill finishes the kill")
			continue
		}
		must(t, r.w.count(syscall.SIGKILL) == 0, "%s: must never SIGKILL", name)
		must(t, r.rec(100) == nil || r.rec(100).Phase != PhaseTerm, "%s: the terming record must be dropped", name)
		r.ex.Shutdown()
		must(t, r.w.count(syscall.SIGKILL) == 0, "%s: shutdown must not SIGKILL", name)
	}
}
