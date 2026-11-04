package guard

import (
	"syscall"
	"testing"
	"time"
)

// pausedTwo returns a rig with groups 100 (5 GiB) and 200 (6 GiB) paused
// by critical pressure, 10s apart.
func pausedTwo(t *testing.T, mode Mode) *rig {
	r := newRig(t, mode)
	r.tool(100, 5*gib, 101)
	r.tool(200, 6*gib, 201)
	r.run(14, 2*time.Second, crit)
	must(t, r.paused(100) && r.paused(200), "setup: both groups must be paused")
	return r
}

func TestResumeOnlyAfterClearSmallestFirstOnePerPoll(t *testing.T) {
	r := pausedTwo(t, ModePause)
	// 25s of normal is not enough.
	r.run(5, 5*time.Second, normal)
	must(t, r.paused(100) && r.paused(200), "no resume before the 30s clear hold")
	// Run until the first resume.
	var resumedAt []time.Time
	for i := 0; i < 12; i++ {
		before := len(r.timed)
		r.poll(5*time.Second, normal)
		for _, ta := range r.timed[before:] {
			if ta.a.Kind == ActResume {
				resumedAt = append(resumedAt, ta.at)
				must(t, ta.a.PGID == 100 && len(resumedAt) == 1 || ta.a.PGID == 200 && len(resumedAt) == 2,
					"resume order wrong: pgid %d as resume #%d", ta.a.PGID, len(resumedAt))
			}
		}
	}
	must(t, len(resumedAt) == 2, "both groups must resume, got %d", len(resumedAt))
	must(t, resumedAt[1].Sub(resumedAt[0]) == 5*time.Second, "one group per poll, got %v", resumedAt)
	must(t, r.noneStopped(), "no member may stay stopped")
}

func TestNoResumeWhileSwapRising(t *testing.T) {
	r := pausedTwo(t, ModePause)
	for i := 0; i < 20; i++ {
		r.swap += gib / 2
		r.poll(5*time.Second, normal)
	}
	must(t, r.paused(100) && r.paused(200), "swap rising must hold the groups paused")
	// The compressor rising holds them too.
	k := pausedTwo(t, ModePause)
	for i := 0; i < 20; i++ {
		k.compB += gib / 2
		k.poll(5*time.Second, normal)
	}
	must(t, k.paused(100) && k.paused(200), "compressor rising must hold the groups paused")
	// Control: the same without the swap rise resumes (see the smallest-first test).
	c := pausedTwo(t, ModePause)
	c.run(20, 5*time.Second, normal)
	must(t, !c.paused(100), "control: flat swap resumes")
}

func TestStaleHighLevelsDoNotHoldGroupsPausedPastClear(t *testing.T) {
	// NEG-4: swap and compressor are high but flat, pressure is normal.
	r := pausedTwo(t, ModePause)
	r.swap = 4 * gib
	r.comp = 700
	r.run(25, 5*time.Second, normal)
	must(t, !r.paused(100) && !r.paused(200), "flat stale levels must not hold the groups paused")
	must(t, r.noneStopped(), "all members must run")
}

func TestStickyRePauseWithinEpisode(t *testing.T) {
	r := pausedTwo(t, ModePause)
	// Clear until the first (smaller) group resumes, then danger returns
	// while the other group is still paused: same episode.
	for i := 0; i < 20 && r.paused(100); i++ {
		r.poll(5*time.Second, normal)
	}
	must(t, !r.paused(100), "setup: group 100 must have resumed")
	must(t, r.paused(200) || r.rec(200) == nil, "setup")
	if r.rec(200) == nil {
		t.Skip("both resumed before danger returned; the poll cadence changed")
	}
	r.m.mu.Lock()
	r.m.st.LastResume = map[string]time.Time{} // as if the resume was long ago: the episode alone decides
	r.m.mu.Unlock()
	r.run(6, 2*time.Second, crit)
	rc := r.rec(100)
	must(t, rc != nil && rc.Sticky, "a re-pause in the same episode must be sticky: %+v", rc)
	r.run(25, 5*time.Second, normal)
	must(t, r.paused(100), "a sticky group stays paused through a clear")
	must(t, !r.paused(200), "the non-sticky group resumes")
}

func TestLaterPauseIsNotSticky(t *testing.T) {
	mk := func(wait time.Duration) *Record {
		r := newRig(t, ModePause)
		r.tool(100, 5*gib, 101)
		r.run(6, 2*time.Second, crit)
		must(t, r.paused(100), "setup")
		r.run(14, 5*time.Second, normal)
		must(t, r.rec(100) == nil, "setup: resumed and episode ended")
		r.run(int(wait/(30*time.Second)), 30*time.Second, normal)
		r.run(6, 2*time.Second, crit)
		return r.rec(100)
	}
	soon := mk(2 * time.Minute)
	must(t, soon != nil && soon.Sticky, "a pause within 10 minutes of the last resume is sticky")
	later := mk(12 * time.Minute)
	must(t, later != nil && !later.Sticky, "a pause after 10 minutes must not be sticky: %+v", later)
}

// maxPauseRig pauses one fallback-tier group (pause-only, so it also
// behaves under pause+kill) and then lets only the pressure vary.
func maxPauseRig(t *testing.T, mode Mode) *rig {
	r := newRig(t, mode)
	r.addGroup(gdef{pgid: 100, fp: 5 * gib, tier: TierFallback, envOK: true}, 101)
	r.run(6, 2*time.Second, crit)
	must(t, r.paused(100), "setup")
	return r
}

func TestMaxPauseAppliesInEveryMode(t *testing.T) {
	for _, mode := range []Mode{ModePause, ModePauseKill} {
		r := maxPauseRig(t, mode)
		// Steady warn pressure never clears; at 29 minutes it is still paused.
		r.run(29, time.Minute, warn)
		must(t, r.paused(100), "%s: must stay paused before 30m", mode)
		r.run(3, time.Minute, warn)
		must(t, !r.paused(100) && r.noneStopped(), "%s: must resume after 30m of steady warn", mode)
	}
}

func TestMaxPauseHoldsUnderCriticalAndAbsoluteCapResumes(t *testing.T) {
	r := maxPauseRig(t, ModePause)
	r.run(31, time.Minute, crit)
	must(t, r.paused(100), "still critical at 30m: must stay paused")
	warns := 0
	for _, ta := range r.timed {
		if ta.a.Kind == ActAlert && contains2(ta.a.Reason, "paused over 30m") {
			warns++
		}
	}
	must(t, warns >= 1, "must alert while still critical past 30m")
	r.run(40, time.Minute, crit)
	repeat := 0
	for _, ta := range r.timed {
		if ta.a.Kind == ActAlert && contains2(ta.a.Reason, "paused over 30m") {
			repeat++
		}
	}
	must(t, repeat >= 5 && repeat <= 9, "alert must repeat about every 10 minutes (got %d over 70m)", repeat)
	pausedAt := r.rec(100).PausedAt
	r.run(50, time.Minute, crit) // passes 2h since the pause
	loud := false
	for _, ta := range r.timed {
		if ta.a.Kind == ActAlert && contains2(ta.a.Reason, "LOUD") {
			loud = true
		}
	}
	must(t, loud, "the 2h cap must raise a loud alert")
	// CR-6: the group is not exempt after the cap. Danger persists, so it
	// is paused again, with a fresh pause time and a fresh cap clock.
	rc := r.rec(100)
	must(t, rc != nil && rc.PausedAt.After(pausedAt.Add(2*time.Hour-time.Second)), "re-pause after the 2h cap expected, rec %+v", rc)
	must(t, rc.Sticky, "the re-pause is sticky")
	r.run(2, time.Minute, crit)
	must(t, r.paused(100), "stays paused again until the next cap")
}

type memRequests struct{ keys []string }

func (m *memRequests) Add(k string) error { m.keys = append(m.keys, k); return nil }
func (m *memRequests) Take() ([]string, error) {
	k := m.keys
	m.keys = nil
	return k, nil
}

// netwatch resume while the daemon runs: the CLI resumes at once, never
// writes the state file, and the daemon drops the record on its next poll.
func TestManualResumeUsesSameRecordsAndReconcile(t *testing.T) {
	r := pausedTwo(t, ModePause)
	req := &memRequests{}
	r.ex.Requests = req
	before, _ := r.st.Load()
	rep, err := ManualResumeLive(r.st, r.w, r.w, r.at, 100, false, req)
	must(t, err == nil && len(rep.Resumed) == 1 && rep.Resumed[0] == 100, "manual resume: %v %+v", err, rep)
	must(t, !r.w.procs[100].stopped && !r.w.procs[101].stopped, "members must run")
	after, _ := r.st.Load()
	must(t, len(after.Groups) == len(before.Groups), "the CLI must not write the state file while the daemon runs")
	must(t, r.ex.Reconcile() == nil, "reconcile")
	must(t, r.rec(100) == nil, "the daemon must drop the record the CLI released")
	n := r.w.count(syscall.SIGSTOP)
	r.poll(2*time.Second, normal)
	must(t, r.w.count(syscall.SIGSTOP) == n, "a manually resumed group must not be paused again by new-children logic")
}

// Code-inspection F1: the daemon pauses another group after the CLI read
// the state, and stops a new child of the released group before the
// request is taken. Neither may be lost: the other group stays recorded
// (and resumable), and the daemon's own resume reaches the new child.
func TestManualResumeRacesWithDaemon(t *testing.T) {
	r := newRig(t, ModePause)
	r.tool(100, 5*gib, 101)
	r.run(14, 2*time.Second, crit)
	must(t, r.paused(100), "setup: 100 paused")
	req := &memRequests{}
	r.ex.Requests = req
	// CLI: releases 100 (reads the state, signals, files a request).
	_, err := ManualResumeLive(r.st, r.w, r.w, r.at, 100, false, req)
	must(t, err == nil, "resume: %v", err)
	// Daemon, before taking the request: pauses a new group 200 and
	// re-stops 100's members plus a new child 102 as "new children".
	r.tool(200, 6*gib, 201)
	r.w.add(102, 100, 100, r.at)
	r.run(6, 2*time.Second, crit)
	must(t, r.paused(200), "setup: 200 paused after the CLI read the state")
	// The daemon takes the request on its next poll.
	must(t, r.ex.Reconcile() == nil, "reconcile")
	must(t, r.rec(100) == nil, "100 released")
	for _, pid := range []int{100, 101, 102} {
		must(t, !r.w.procs[pid].stopped, "pid %d left stopped after the manual resume", pid)
	}
	must(t, r.paused(200), "200 must stay recorded")
	st, _ := r.st.Load()
	_, ok := st.Groups[r.rec(200).Key()]
	must(t, ok, "200 must stay in the state file")
	rep, err := ManualResume(r.st, r.w, r.w, r.at, 200, false)
	must(t, err == nil && len(rep.Resumed) == 1, "200 stays resumable: %v %+v", err, rep)
}
