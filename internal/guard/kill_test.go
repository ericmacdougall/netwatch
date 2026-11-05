package guard

import (
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
)

type dgs = danger.GroupSeries

func pointAt(at time.Time, b uint64) danger.Point { return danger.Point{At: at, Bytes: b} }

func killRig(t *testing.T, mode Mode) *rig {
	r := d4Rig(t, mode)
	must(t, r.paused(100), "killRig setup: group must be paused")
	return r
}

func (r *rig) termAt() (time.Time, bool) { return r.first(ActTerm, 100) }

// runCrit polls critical until a SIGTERM is sent or n polls pass.
func (r *rig) runCrit(n int, dt time.Duration) {
	for i := 0; i < n; i++ {
		if _, ok := r.termAt(); ok {
			return
		}
		r.poll(dt, crit)
	}
}

func TestKillPathATiming(t *testing.T) {
	r := killRig(t, ModePauseKill)
	start := r.at.Add(2 * time.Second) // the first critical poll after the pause
	r.runCrit(60, 2*time.Second)
	at, ok := r.termAt()
	must(t, ok, "path A must kill after 60s of critical pressure")
	must(t, at.Sub(start) == 60*time.Second, "SIGTERM at +%v, want +60s", at.Sub(start))
}

func TestKillPathAFlappingAndResets(t *testing.T) {
	// Warn polls inside the window do not reset it.
	r := killRig(t, ModePauseKill)
	start := r.at.Add(2 * time.Second)
	for i := 0; i < 60; i++ {
		if _, ok := r.termAt(); ok {
			break
		}
		lvl := crit
		if i%8 == 7 {
			lvl = warn
		}
		r.poll(2*time.Second, lvl)
	}
	at, ok := r.termAt()
	must(t, ok && at.Sub(start) == 60*time.Second, "warn flapping must not reset path A (term %v ok=%v)", at.Sub(start), ok)

	// A normal poll resets it.
	n := killRig(t, ModePauseKill)
	for i := 0; i < 20; i++ { // 40s of critical
		n.poll(2*time.Second, crit)
	}
	n.poll(2*time.Second, normal) // reset
	resetStart := n.at.Add(2 * time.Second)
	n.runCrit(60, 2*time.Second)
	at, ok = n.termAt()
	must(t, ok && at.Sub(resetStart) == 60*time.Second, "a normal poll must restart the window: term +%v from the restart", at.Sub(resetStart))

	// A gap over 6s restarts it too.
	g := killRig(t, ModePauseKill)
	for i := 0; i < 15; i++ {
		g.poll(2*time.Second, crit)
	}
	g.poll(8*time.Second, crit) // a stall
	gapStart := g.at
	g.runCrit(60, 2*time.Second)
	at, ok = g.termAt()
	must(t, ok && at.Sub(gapStart) == 60*time.Second, "a poll gap over 6s must restart the window: term +%v", at.Sub(gapStart))
}

func TestKillPathATooFewPollsNoKill(t *testing.T) {
	// 5s polls give only 12 polls per 60s: never 25.
	r := killRig(t, ModePauseKill)
	r.run(60, 5*time.Second, crit) // 5 minutes
	_, ok := r.termAt()
	must(t, !ok, "too few polls in the window must not kill")
	// Control: 2s polls do.
	c := killRig(t, ModePauseKill)
	c.runCrit(60, 2*time.Second)
	_, ok = c.termAt()
	must(t, ok, "control: 2s polls kill")
}

func TestKillOnlyInPauseKillMode(t *testing.T) {
	r := killRig(t, ModePause)
	r.run(80, 2*time.Second, crit)
	must(t, r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "pause mode must never kill")
	must(t, r.paused(100), "the group stays paused")
}

func TestD4OrP1AloneFor10MinutesPausesNeverKills(t *testing.T) {
	r := killRig(t, ModePauseKill)
	r.run(300, 2*time.Second, warn) // 10 minutes of warn: no critical, no 95% level
	must(t, r.w.count(sigTERM) == 0, "D4 alone must never kill")
	must(t, r.paused(100), "D4 alone pauses and holds")
}

func TestD1ClearD1NoKill(t *testing.T) {
	r := newRig(t, ModePauseKill)
	r.tool(100, 5*gib, 101)
	r.run(20, 2*time.Second, crit) // 40s critical: paused by the largest-consumer rule
	must(t, r.paused(100), "setup")
	r.run(14, 5*time.Second, normal) // clear and resume
	must(t, r.rec(100) == nil, "setup: resumed")
	r.run(20, 2*time.Second, crit) // 40s critical again
	must(t, r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "two 40s episodes must not add up to a kill")
}

func TestKillSequenceOrderAndSurvivors(t *testing.T) {
	r := killRig(t, ModePauseKill)
	r.w.procs[101].ignoreTerm = true // survives SIGTERM
	r.runCrit(60, 2*time.Second)
	termAt, ok := r.termAt()
	must(t, ok, "must term")
	// SIGTERM is delivered while stopped, then SIGCONT, then (5s later) SIGKILL.
	idx := func(sig syscall.Signal, pid int) int {
		for i, l := range r.w.log {
			if l.pid == pid && l.sig == sig && (sig != sigSTOP || true) {
				return i
			}
		}
		return -1
	}
	must(t, idx(sigTERM, 100) > idx(sigSTOP, 100), "TERM after STOP")
	must(t, idx(sigCONT, 100) > idx(sigTERM, 101), "CONT after every TERM")
	must(t, r.w.procs[100].dead, "pid 100 took the pending SIGTERM on SIGCONT")
	must(t, !r.w.procs[101].dead && !r.w.procs[101].stopped, "pid 101 ignores TERM and now runs")
	must(t, r.w.count(sigKILL) == 0, "no SIGKILL before 5s")
	r.poll(2*time.Second, crit)
	r.poll(2*time.Second, crit)
	must(t, r.w.count(sigKILL) == 0, "no SIGKILL at +4s")
	r.poll(2*time.Second, crit)
	killAt, ok := r.first(ActKill, 100)
	must(t, ok && killAt.Sub(termAt) >= 5*time.Second && killAt.Sub(termAt) <= 6*time.Second, "SIGKILL at +%v", killAt.Sub(termAt))
	must(t, r.w.procs[101].dead && r.w.noneAlive(), "survivor killed")
	must(t, r.rec(100) == nil, "record removed after the kill")
}

func (w *world) noneAlive() bool {
	for _, p := range w.procs {
		if !p.dead {
			return false
		}
	}
	return true
}

func TestEarlySigkillOnGrowthOverOneGB(t *testing.T) {
	r := killRig(t, ModePauseKill)
	r.w.procs[101].ignoreTerm = true
	r.runCrit(60, 2*time.Second)
	termAt, _ := r.termAt()
	r.grow(100, gib+gib/2) // grows more than 1 GB in the grace window
	r.poll(2*time.Second, crit)
	killAt, ok := r.first(ActKill, 100)
	must(t, ok && killAt.Sub(termAt) < 5*time.Second, "early SIGKILL expected, got ok=%v +%v", ok, killAt.Sub(termAt))
	// Control: growth under 1 GB waits for the 5s.
	c := killRig(t, ModePauseKill)
	c.w.procs[101].ignoreTerm = true
	c.runCrit(60, 2*time.Second)
	c.grow(100, gib/2)
	c.poll(2*time.Second, crit)
	_, ok = c.first(ActKill, 100)
	must(t, !ok, "growth under 1 GB must not trigger an early SIGKILL")
}

func TestGuardKillEventHasLabelCommandAndCheckpointNote(t *testing.T) {
	r := killRig(t, ModePauseKill)
	r.runCrit(60, 2*time.Second)
	evs := r.ev.named("GUARD_KILL")
	must(t, len(evs) == 1, "want 1 GUARD_KILL event, got %d", len(evs))
	f := evs[0].f
	must(t, f["agent"] == "agent-x" && f["cmd"] == "job100", "label/command missing: %v", f)
	must(t, f["note"] == "resume from your last checkpoint", "checkpoint note missing: %v", f)
	must(t, contains2(f["prong"].(string), "path=A") && contains2(f["prong"].(string), "causation=D4"), "prong not named: %v", f["prong"])
	found := false
	for _, m := range r.nt.msgs {
		if contains2(m, "kill-100") && contains2(m, "last checkpoint") {
			found = true
		}
	}
	must(t, found, "the kill notification must be sent: %v", r.nt.msgs)
}

func TestKillCooldown(t *testing.T) {
	// Two killable D4 groups, paused 10s apart; both reach path A.
	r := newRig(t, ModePauseKill)
	r.tool(100, 10*gib, 101)
	r.tool(200, 10*gib, 201)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.grow(200, gib)
		r.poll(2*time.Second, warn)
	}
	r.run(6, 2*time.Second, warn)
	must(t, r.paused(100) && r.paused(200), "setup: both paused")
	r.run(150, 2*time.Second, crit)
	first, ok1 := r.first(ActTerm, 0)
	var second time.Time
	for _, ta := range r.timed {
		if ta.a.Kind == ActTerm && ta.at.After(first) {
			second = ta.at
			break
		}
	}
	must(t, ok1 && !second.IsZero(), "both groups must eventually be killed")
	must(t, second.Sub(first) >= 120*time.Second, "second kill %v after the first, want >= 120s", second.Sub(first))
}

func TestShutdownDuringEachKillPhaseLeavesNothingStopped(t *testing.T) {
	// Phase 1: paused, kill not started.
	a := killRig(t, ModePauseKill)
	a.ex.Shutdown()
	must(t, a.noneStopped(), "shutdown while paused must resume everything")

	// Phase 2: SIGTERM delivered but SIGCONT not yet (a crash window): the
	// members are stopped with a pending TERM.
	b := killRig(t, ModePauseKill)
	b.w.procs[101].ignoreTerm = true
	key := keyOf(100, b.groups[100].start)
	b.m.mu.Lock()
	rc := b.m.st.Groups[key]
	rc.Phase = PhaseTerm
	rc.TermAt = b.at
	b.m.mu.Unlock()
	for _, pid := range []int{100, 101} {
		must(t, b.w.Signal(pid, b.w.procs[pid].start, sigTERM) == nil, "term")
		b.m.markSig(key, pid, false, true)
	}
	must(t, !b.noneStopped(), "setup: members stopped")
	b.ex.Shutdown()
	must(t, b.noneStopped(), "shutdown after SIGTERM must send SIGCONT")
	must(t, b.w.procs[100].dead && b.w.procs[101].dead, "members that were sent SIGTERM must get SIGKILL")

	// Phase 3: SIGTERM and SIGCONT done, survivors waiting for SIGKILL.
	c := killRig(t, ModePauseKill)
	c.w.procs[101].ignoreTerm = true
	c.runCrit(60, 2*time.Second)
	must(t, !c.w.procs[101].dead, "setup: a survivor")
	c.ex.Shutdown()
	must(t, c.w.procs[101].dead && c.noneStopped(), "shutdown during the SIGKILL wait must kill the TERMed survivors")
}

func TestOrderlyShutdownResumesAllRecordedGroups(t *testing.T) {
	r := pausedTwo(t, ModePauseKill)
	r.ex.Shutdown()
	must(t, r.noneStopped(), "every group must be resumed")
	got, err := r.st.Load()
	must(t, err == nil && len(got.Groups) == 0, "the persisted state must be cleared: %v %v", err, got.Groups)
	// Control: without Shutdown members remain stopped.
	c := pausedTwo(t, ModePauseKill)
	must(t, !c.noneStopped(), "control: stopped without a shutdown")
}

func TestKillBlockedWhenFactsChangeAfterPause(t *testing.T) {
	cases := map[string]func(r *rig){
		"tier downgraded":     func(r *rig) { r.groups[100].tier = TierFallback },
		"budget appears":      func(r *rig) { r.groups[100].budget = &Budget{MaxBytes: 15 * gib, MaxProcs: 10} },
		"exclusion appears":   func(r *rig) { r.w.procs[101].excluded = true },
		"allowlist withdrawn": func(r *rig) { r.groups[100].allow = false },
		"env no longer ok":    func(r *rig) { r.groups[100].envOK = false },
	}
	for name, mut := range cases {
		r := killRig(t, ModePauseKill)
		mut(r)
		r.run(60, 2*time.Second, crit)
		_, ok := r.termAt()
		must(t, !ok, "%s: a changed fact must block the kill", name)
	}
	r := killRig(t, ModePauseKill)
	r.run(60, 2*time.Second, crit)
	_, ok := r.termAt()
	must(t, ok, "control: unchanged facts kill")
}

func TestNonKillableTiersArePausedNeverKilled(t *testing.T) {
	for name, g := range map[string]gdef{
		"fallback tier (NEG-13)": {pgid: 100, fp: 10 * gib, tier: TierFallback, envOK: true, allow: true},
		"unverified tier":        {pgid: 100, fp: 10 * gib, tier: TierUnverified, envOK: true, allow: true},
		"unallowlisted version":  {pgid: 100, fp: 10 * gib, tier: TierTool, envOK: true, allow: false},
		"scrubbed env (CR-6)":    {pgid: 100, fp: 10 * gib, tier: TierTool, envOK: false, allow: true},
	} {
		r := newRig(t, ModePauseKill)
		r.addGroup(g, 101)
		r.run(3, 2*time.Second, normal)
		for i := 0; i < 3; i++ {
			r.grow(100, gib)
			r.poll(2*time.Second, warn)
		}
		must(t, r.paused(100), "%s: must be paused", name)
		r.run(120, 2*time.Second, crit)
		must(t, r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "%s: must never be killed", name)
		must(t, r.paused(100), "%s: stays paused", name)
	}
}

func budgeted(max uint64) *Budget { return &Budget{MaxBytes: max, MaxProcs: 8} }

func TestWithinBudgetGroupIsPausedLastAndNeverKilled(t *testing.T) {
	// Alone under danger a within-budget causal group is paused, never killed.
	r := newRig(t, ModePauseKill)
	r.addGroup(gdef{pgid: 100, fp: 7 * gib, tier: TierTool, envOK: true, allow: true, budget: budgeted(8 * gib)}, 101)
	r.run(3, 2*time.Second, normal)
	r.run(10, 2*time.Second, crit)
	must(t, r.paused(100), "a within-budget causal group must be paused")
	r.comp = 980
	r.run(150, 2*time.Second, crit) // every kill path is reachable
	must(t, r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "a within-budget group is never killed")

	// With an undeclared causal group present it is paused first, even when
	// the within-budget group is larger.
	o := newRig(t, ModePause)
	o.addGroup(gdef{pgid: 100, fp: 7 * gib, tier: TierTool, envOK: true, allow: true, budget: budgeted(8 * gib)}, 101)
	o.tool(200, 5*gib, 201)
	o.run(3, 2*time.Second, normal)
	o.run(3, 2*time.Second, crit)
	must(t, o.paused(200), "the undeclared group must be paused first")
	must(t, !o.paused(100), "the within-budget group waits until the undeclared one is paused")
	o.run(7, 2*time.Second, crit)
	must(t, o.paused(100), "the within-budget group is paused once the rate limit allows")
	f1, _ := o.first(ActPause, 200)
	f2, _ := o.first(ActPause, 100)
	must(t, f1.Before(f2), "order wrong: %v then %v", f1, f2)

	// An over-budget group counts as undeclared and may be killed.
	c := newRig(t, ModePauseKill)
	c.addGroup(gdef{pgid: 100, fp: 9 * gib, tier: TierTool, envOK: true, allow: true, budget: budgeted(8 * gib)}, 101)
	c.run(3, 2*time.Second, normal)
	c.run(10, 2*time.Second, crit)
	must(t, c.paused(100), "control: over budget is paused")
}

func TestNEG2HealthyHostZeroActionsWithOrWithoutBudget(t *testing.T) {
	for _, b := range []*Budget{nil, budgeted(8 * gib)} {
		r := newRig(t, ModePauseKill)
		r.addGroup(gdef{pgid: 100, fp: 12 * gib, tier: TierTool, envOK: true, allow: true, budget: b}, 101)
		r.run(100, 2*time.Second, normal)
		for i := 0; i < 100; i++ { // growing 0.5 GB/min, healthy
			r.grow(100, gib/60)
			r.poll(2*time.Second, normal)
		}
		must(t, len(r.acts) == 0 && len(r.w.log) == 0, "healthy host (budget %v) must see zero actions, got %d", b, len(r.acts))
	}
}

func TestPidReuseIsNeverSignalled(t *testing.T) {
	// NEG-8 stage 1: sample to pause. A member's pid is reused between the
	// snapshot and the signal.
	r := newRig(t, ModePause)
	r.tool(100, 10*gib, 101)
	r.run(3, 2*time.Second, normal)
	r.grow(100, gib)
	r.poll(2*time.Second, warn)
	// Build the pause snapshot by hand so we can swap pid 101 first.
	r.grow(100, gib)
	r.at = r.at.Add(2 * time.Second)
	old := r.w.procs[101].start
	r.w.procs[101] = &proc{pid: 101, ppid: 1, pgid: 999, start: r.at} // reused by an unrelated process
	_ = old
	// The machine still believes (101, old start) is a member.
	g := &Group{PGID: 100, LeaderStart: r.groups[100].start, Tier: TierTool, EnvOK: true, Allowlisted: true, Footprint: 12 * gib,
		Members: []Member{{PID: 100, PPID: 1, Start: r.groups[100].start}, {PID: 101, PPID: 100, Start: old}}}
	key := keyOf(100, g.LeaderStart)
	series := append(r.hist[key], pointAt(r.at, 12*gib))
	sys := r.sys(warn)
	sig := r.det.Observe(sys, false, []dgs{{PGID: 100, Series: series}})
	acts := r.m.Step(Snapshot{At: r.at, Sys: sys, Signals: sig, Terms: []Term{{Key: key, Group: g, Series: series}}, ScanAt: r.at, ScanOK: true})
	r.ex.Apply(acts)
	must(t, !contains(r.w.sigs(sigSTOP), 101), "a reused pid must never be stopped: %v", r.w.log)
	must(t, !r.w.procs[101].stopped, "the unrelated process must keep running")

	// Stage 2: pause to resume.
	r2 := d4Rig(t, ModePause)
	r2.w.procs[101] = &proc{pid: 101, ppid: 1, pgid: 555, start: r2.at, stopped: true} // reused while we held it paused
	r2.m.SetMode(ModeAlert)
	r2.poll(2*time.Second, warn)
	must(t, r2.w.procs[101].stopped, "resume must not CONT a reused pid (the stranger stays as it was)")
	must(t, !contains(r2.w.sigs(sigCONT), 101), "SIGCONT sent to a reused pid")

	// Stage 3: SIGTERM to SIGKILL.
	r3 := killRig(t, ModePauseKill)
	r3.w.procs[101].ignoreTerm = true
	r3.runCrit(60, 2*time.Second)
	r3.w.procs[101] = &proc{pid: 101, ppid: 1, pgid: 777, start: r3.at} // the survivor died and its pid was reused
	r3.run(4, 2*time.Second, crit)
	must(t, !r3.w.procs[101].dead, "SIGKILL must not hit a reused pid")
	must(t, !contains(r3.w.sigs(sigKILL), 101), "SIGKILL sent to a reused pid")
}

// Code-inspection F2: a recorded member that is excluded now (it exec'd a
// never-signal program after the pause) never gets the SIGKILL stage.
func TestLiveMembersDropsNowExcludedRecordedPid(t *testing.T) {
	m := NewMachine(DefaultConfig(ModePauseKill))
	r := &Record{PGID: 100, Members: []RecMember{{PID: 100}, {PID: 101}, {PID: 102}}}
	g := &gview{G: &Group{PGID: 100, Members: []Member{{PID: 100}, {PID: 101, Excluded: true}, {PID: 103}}}}
	got := map[int]bool{}
	for _, mem := range m.liveMembers(r, g) {
		got[mem.PID] = true
	}
	if got[101] || !got[100] || !got[102] || !got[103] {
		t.Fatalf("live members %v: want 100, 102 (recorded, gone from the view), 103 (new); never 101", got)
	}
}

// macOS: NoKill disables the kill stage in pause+kill mode, for a group
// that is otherwise kill-eligible (the control above kills at +60s).
func TestNoKillNeverKillsInPauseKillMode(t *testing.T) {
	r := killRig(t, ModePauseKill)
	r.m.cfg.NoKill = true
	r.run(80, 2*time.Second, crit)
	_, termed := r.termAt()
	must(t, !termed && r.w.count(sigTERM) == 0 && r.w.count(sigKILL) == 0, "NoKill must never kill")
	must(t, r.paused(100), "the group stays paused")
}

// Clone must not share the Held map: a save encodes the clone on another
// goroutine while the loop may add a hold (code-inspection r3 F1).
func TestCloneCopiesHeld(t *testing.T) {
	st := State{Episode: &Episode{Held: map[string]bool{"pg:1:1": true}}}
	st.init()
	c := st.Clone()
	st.Episode.Held["pg:2:2"] = true
	must(t, c.Episode.Held["pg:1:1"] && !c.Episode.Held["pg:2:2"], "clone shares Held: %v", c.Episode.Held)
}
