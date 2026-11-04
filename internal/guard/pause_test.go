package guard

import (
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

const (
	normal = resources.LevelNormal
	warn   = resources.LevelWarn
	crit   = resources.LevelCritical
)

// d4Rig returns a rig with one big group that has just fired D4.
func d4Rig(t *testing.T, mode Mode) *rig {
	r := newRig(t, mode)
	r.tool(100, 10*gib, 101)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	return r
}

func TestPauseSelectsOnlyCausalGroup(t *testing.T) {
	r := newRig(t, ModePause)
	r.tool(100, 10*gib, 101)
	r.tool(200, 1*gib, 201) // small, steady: not causal
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	must(t, r.paused(100), "the D4 group must be paused")
	must(t, r.rec(200) == nil, "a small non-causal group must not be paused")
	for _, pid := range r.w.sigs(syscall.SIGSTOP) {
		must(t, pid == 100 || pid == 101, "signalled outsider pid %d", pid)
	}

	// Failing control: the same series at normal pressure gives no D4 and
	// no pause, so the pause above comes from the rule and not the rig.
	c := newRig(t, ModePause)
	c.tool(100, 10*gib, 101)
	c.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		c.grow(100, gib)
		c.poll(2*time.Second, normal)
	}
	must(t, c.rec(100) == nil && c.w.count(syscall.SIGSTOP) == 0, "normal pressure must not pause")
}

func TestP1WithHealthyPressureAndHeadroomAlertsOnly(t *testing.T) {
	// 0.5 GiB/s ramp of a 5 GiB group with 3 GiB of headroom: P1 fires
	// (7.5 GiB in the horizon > 3 GiB) but, with pressure normal and
	// headroom above 8% of RAM, it is not corroborated: no pause.
	r := newRig(t, ModePause)
	r.headroom = 3 * gib
	r.tool(100, 5*gib, 101)
	r.run(2, 2*time.Second, normal)
	for i := 0; i < 6; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, normal)
	}
	must(t, r.lastSig.P1 && !r.lastSig.P1Corroborated, "want P1 uncorroborated, got %+v", r.lastSig)
	must(t, r.rec(100) == nil && r.w.count(syscall.SIGSTOP) == 0, "uncorroborated P1 must not pause")

	// Control: headroom 1 GiB (< 1.28 GiB) plus pressure warn corroborates.
	c := newRig(t, ModePause)
	c.headroom = 1 * gib
	c.tool(100, 5*gib, 101)
	c.run(2, 2*time.Second, normal)
	for i := 0; i < 6; i++ {
		c.grow(100, gib)
		c.poll(2*time.Second, warn)
	}
	must(t, c.lastSig.P1Corroborated && c.paused(100), "corroborated P1 must pause: %+v", c.lastSig)
}

func TestStopOrderLeaderFirstThenTopDown(t *testing.T) {
	r := newRig(t, ModePause)
	r.tool(100, 10*gib)
	// 100 -> 110 -> 111 (grandchild), 100 -> 120
	r.w.add(111, 110, 100, t0)
	r.w.add(110, 100, 100, t0)
	r.w.add(120, 100, 100, t0)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	got := r.w.sigs(syscall.SIGSTOP)
	want := []int{100, 110, 120, 111}
	must(t, len(got) == len(want), "stops %v", got)
	for i := range want {
		must(t, got[i] == want[i], "stop order %v, want %v", got, want)
	}
}

func TestNewChildrenAreReEnumeratedAndStopped(t *testing.T) {
	r := d4Rig(t, ModePause)
	must(t, r.paused(100), "setup")
	r.w.add(150, 100, 100, r.at) // forked after the pause
	r.poll(2*time.Second, warn)
	must(t, r.w.procs[150].stopped, "a child forked after the pause must be stopped")
	must(t, r.w.count(syscall.SIGSTOP) == 3, "each member stopped once, got %v", r.w.sigs(syscall.SIGSTOP))
}

func TestAlreadyStoppedMembersAreNeverResumed(t *testing.T) {
	r := newRig(t, ModePause)
	r.tool(100, 10*gib, 101, 102)
	r.w.procs[102].stopped = true // the user's own Ctrl-Z
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	must(t, !contains(r.w.sigs(syscall.SIGSTOP), 102), "an already-stopped member must not be signalled")
	rc := r.rec(100)
	must(t, rc != nil && len(rc.Already) == 1 && rc.Already[0].PID == 102, "already-stopped member must be recorded: %+v", rc)
	r.run(16, 5*time.Second, normal) // clear and resume
	must(t, !r.paused(100), "group must be resumed after the clear")
	must(t, r.w.procs[102].stopped, "the user's stopped member must stay stopped")
	must(t, !r.w.procs[100].stopped && !r.w.procs[101].stopped, "netwatch's members must run again")
	must(t, !contains(r.w.sigs(syscall.SIGCONT), 102), "SIGCONT must never go to a member netwatch did not stop")
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestRateLimitsOnePausePer10sAndThreeAtOnce(t *testing.T) {
	r := newRig(t, ModePause)
	for i := 0; i < 4; i++ {
		r.tool(100+10*i, 5*gib, 101+10*i)
	}
	// All four are >= min share (4 GiB) and none is smaller than the largest
	// ineligible aggregate (0): all causal under critical pressure.
	r.run(2, 2*time.Second, crit)
	r.run(30, 2*time.Second, crit)
	var pauseTimes []time.Time
	for _, ta := range r.timed {
		if ta.a.Kind == ActPause && ta.a.Reason == "pause" {
			pauseTimes = append(pauseTimes, ta.at)
		}
	}
	must(t, len(pauseTimes) == 3, "at most 3 groups paused at once, got %d", len(pauseTimes))
	for i := 1; i < len(pauseTimes); i++ {
		must(t, pauseTimes[i].Sub(pauseTimes[i-1]) >= 10*time.Second, "pauses %v closer than 10s", pauseTimes)
	}
}

func TestInelligibleNeverSignalledAndUnprotectedRaised(t *testing.T) {
	// NEG-1 / NEG-3: Chrome (an ineligible aggregate) grows 10 GB under
	// danger; a steady 4 GiB agent job is never paused.
	r := newRig(t, ModePauseKill)
	r.tool(100, 4*gib, 101)
	r.inel["chrome"] = 6 * gib // already the largest consumer when danger starts
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 40; i++ {
		r.inel["chrome"] += gib / 4
		r.poll(2*time.Second, crit)
	}
	must(t, r.w.count(syscall.SIGSTOP) == 0 && r.w.count(syscall.SIGTERM) == 0 && r.w.count(syscall.SIGKILL) == 0,
		"nothing may be signalled, log %v", r.w.log)
	must(t, r.countKind(ActUnprotected) == 1, "HOST_AT_RISK_UNPROTECTED must be raised once, got %d", r.countKind(ActUnprotected))
	must(t, len(r.ev.named("HOST_AT_RISK_UNPROTECTED")) == 1, "event not written")
}

// Control for NEG-3: when the steady 4 GiB job is the largest consumer at
// the onset of danger, the "largest consumer" rule does select it.
func TestSteadyJobThatIsLargestConsumerIsPaused(t *testing.T) {
	r := newRig(t, ModePause)
	r.tool(100, 4*gib, 101)
	r.inel["chrome"] = 2 * gib
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 8; i++ {
		r.poll(2*time.Second, crit)
	}
	must(t, r.paused(100), "control: the largest consumer must be paused")
}

func TestCodexShapedGroupGetsAlertsOnly(t *testing.T) {
	r := newRig(t, ModePauseKill)
	r.addGroup(gdef{pgid: 300, fp: 14 * gib, tier: TierNone, ineligible: true, cmd: "codex"}, 301)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 80; i++ {
		r.grow(300, gib/8)
		r.poll(2*time.Second, crit)
	}
	must(t, len(r.w.log) == 0, "a Codex-shaped group must never be signalled: %v", r.w.log)
	must(t, r.countKind(ActUnprotected) >= 1, "must alert HOST_AT_RISK_UNPROTECTED")
}

func TestExcludedMembersAndSubtreeNeverSignalled(t *testing.T) {
	r := newRig(t, ModePauseKill)
	r.tool(100, 10*gib, 101, 102)
	r.w.add(103, 102, 100, t0) // child of the excluded member
	r.w.procs[102].excluded = true
	r.w.procs[103].excluded = true // the exclusion covers the subtree
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 3; i++ {
		r.grow(100, gib)
		r.poll(2*time.Second, warn)
	}
	must(t, r.paused(100), "group must still be paused around the excluded members")
	for _, l := range r.w.log {
		must(t, l.pid != 102 && l.pid != 103, "excluded pid %d signalled with %v", l.pid, l.sig)
	}
	must(t, r.w.procs[101].stopped && !r.w.procs[102].stopped && !r.w.procs[103].stopped, "wrong stop set")
}

func TestOffAndAlertModesNeverSignal(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModeAlert} {
		r := newRig(t, mode)
		r.tool(100, 13*gib, 101)
		r.run(3, 2*time.Second, normal)
		for i := 0; i < 80; i++ {
			r.grow(100, gib/4)
			r.poll(2*time.Second, crit)
		}
		must(t, len(r.w.log) == 0, "mode %s signalled: %v", mode, r.w.log)
	}
	// Control: the identical scenario in pause+kill mode does signal.
	r := newRig(t, ModePauseKill)
	r.tool(100, 13*gib, 101)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 80; i++ {
		r.grow(100, gib/4)
		r.poll(2*time.Second, crit)
	}
	must(t, len(r.w.log) > 0, "control must signal")
}

func TestModeSwitchToAlertResumesEverything(t *testing.T) {
	r := d4Rig(t, ModePauseKill)
	must(t, r.paused(100) && !r.noneStopped(), "setup")
	r.m.SetMode(ModeAlert)
	r.poll(2*time.Second, warn)
	must(t, r.noneStopped() && r.rec(100) == nil, "switching to alert must resume every group")
	got, _ := r.st.Load()
	must(t, len(got.Groups) == 0, "the persisted record must be cleared")
}

func TestFailedSystemReadTakesNoAction(t *testing.T) {
	r := d4Rig(t, ModePauseKill)
	n := len(r.w.log)
	acts := r.m.Step(Snapshot{At: r.at.Add(2 * time.Second)}) // zero System: a failed read
	must(t, acts == nil && len(r.w.log) == n, "a failed read must take no action")
	must(t, r.m.LastError() != "", "the failure must be reported")
}

func TestSelfTestFailureDisablesPauseAndKill(t *testing.T) {
	r := newRig(t, ModePauseKill)
	r.selfTest = errTest("own footprint unreadable")
	r.tool(100, 13*gib, 101)
	r.run(3, 2*time.Second, normal)
	for i := 0; i < 40; i++ {
		r.grow(100, gib/4)
		r.poll(2*time.Second, crit)
	}
	must(t, len(r.w.log) == 0, "no signals with a failed self-test: %v", r.w.log)
	n := 0
	for _, a := range r.acts {
		if a.Kind == ActAlert && contains2(a.Reason, "self-test") {
			n++
		}
	}
	must(t, n == 1, "the self-test failure must be alerted exactly once, got %d", n)
}

type errTest string

func (e errTest) Error() string { return string(e) }

func contains2(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
