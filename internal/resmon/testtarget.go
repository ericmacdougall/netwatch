package resmon

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/tracker"
)

// TestTarget is the one process group a test daemon may act on: the job
// the daemon spawned itself in its own process group.
type TestTarget struct {
	PGID  int
	Start time.Time // the group leader's start time
	// Tier is what the guard may do to it: TierFallback (pause only) by
	// default; TierTool (pause and kill) only in a guardtest build.
	Tier guard.Tier
}

// ErrNotTarget is returned for any signal outside the test target.
var ErrNotTarget = errors.New("test daemon: refusing to signal a process outside its own spawned job")

// SpawnedOnly is the test daemon's signaller. It is the hard boundary for
// live tests: whatever the classifier or the state machine decide, it
// refuses any pid that is not a member of the spawned job's process group,
// or whose group leader is no longer the process that was spawned.
type SpawnedOnly struct {
	Inner  guard.Signaller
	R      resources.Prober
	Target TestTarget
}

// startTol absorbs start-time precision differences between readers.
const startTol = 10 * time.Millisecond

func near(a, b time.Time) bool {
	d := a.Sub(b)
	return d < startTol && d > -startTol
}

// Signal implements guard.Signaller.
func (s SpawnedOnly) Signal(pid int, start time.Time, sig syscall.Signal) error {
	if pid <= 1 || s.Target.PGID <= 1 {
		return ErrNotTarget
	}
	var p resources.Proc
	if err := s.R.Probe(pid, &p); err != nil {
		return fmt.Errorf("%w: pid %d: %v", ErrNotTarget, pid, err)
	}
	if p.PGID != s.Target.PGID {
		return fmt.Errorf("%w: pid %d is in group %d, not %d", ErrNotTarget, pid, p.PGID, s.Target.PGID)
	}
	var leader resources.Proc
	if err := s.R.Probe(s.Target.PGID, &leader); err != nil {
		// The leader exited; members may remain, but we can no longer prove
		// the group is the one we spawned unless the pid is the leader.
		return fmt.Errorf("%w: group leader %d gone", ErrNotTarget, s.Target.PGID)
	}
	if !near(leader.Start, s.Target.Start) {
		return fmt.Errorf("%w: group leader %d was reused", ErrNotTarget, s.Target.PGID)
	}
	return s.Inner.Signal(pid, start, sig)
}

// withTarget makes the test target a guard group even though no Claude
// Code process started it (the daemon did), and demotes nothing else here:
// demoteOthers runs on the tracker's terms each poll.
func withTarget(groups []tracker.GroupInfo, t TestTarget) []tracker.GroupInfo {
	out := groups[:0:0]
	for _, g := range groups {
		if g.PGID != t.PGID {
			out = append(out, g)
		}
	}
	g := tracker.GroupInfo{PGID: t.PGID, LeaderStart: t.Start, Tier: t.Tier, Agent: "test-daemon", Cmd: "test job"}
	if t.Tier == guard.TierTool {
		g.EnvOK, g.Allowlisted, g.ClaudeVer = true, true, "test"
	}
	return append(out, g)
}
