//go:build !windows

package guard

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// psStart reads a pid's start via ps (portable across macOS and Linux).
type psStart struct{}

func (psStart) Start(pid int) (time.Time, error) {
	out, err := exec.Command("ps", "-o", "lstart=", "-p", itoa(pid)).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return time.Time{}, errors.New("no such process")
	}
	f := strings.Fields(string(out))
	return time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(f, " "), time.Local)
}

func itoa(n int) string { return strconv.Itoa(n) }

func psState(pid int) string {
	out, _ := exec.Command("ps", "-o", "stat=", "-p", itoa(pid)).Output()
	return strings.TrimSpace(string(out))
}

// ownOnly refuses any pid the test did not spawn itself, then does the
// real start-time-checked signal.
type ownOnly struct {
	spawned map[int]bool
	inner   OSSignaller
	refused []int
}

func (o *ownOnly) Signal(pid int, start time.Time, sig syscall.Signal) error {
	if !o.spawned[pid] {
		o.refused = append(o.refused, pid)
		return ErrRefused
	}
	return o.inner.Signal(pid, start, sig)
}

type realJob struct {
	leader, child *exec.Cmd
	pgid          int
	start, cstart time.Time
}

func spawn(t *testing.T) *realJob {
	t.Helper()
	l := exec.Command("sleep", "120")
	l.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := l.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	c := exec.Command("sleep", "120")
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: l.Process.Pid}
	if err := c.Start(); err != nil {
		l.Process.Kill()
		t.Fatal(err)
	}
	j := &realJob{leader: l, child: c, pgid: l.Process.Pid}
	t.Cleanup(func() {
		// Only our own spawn is ever signalled here.
		l.Process.Kill()
		c.Process.Kill()
		l.Wait()
		c.Wait()
	})
	var err error
	if j.start, err = (psStart{}).Start(l.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if j.cstart, err = (psStart{}).Start(c.Process.Pid); err != nil {
		t.Fatal(err)
	}
	return j
}

func (j *realJob) snap(at time.Time, lvl resources.Level, danger_ bool, clear bool) Snapshot {
	g := &Group{PGID: j.pgid, LeaderStart: j.start, Tier: TierTool, EnvOK: true, Allowlisted: true, Footprint: 13 * gib, Cmd: "sleep",
		Members: []Member{{PID: j.pgid, PPID: 1, Start: j.start}, {PID: j.child.Process.Pid, PPID: j.pgid, Start: j.cstart}}}
	for i := range g.Members {
		g.Members[i].Stopped = strings.HasPrefix(psState(g.Members[i].PID), "T")
	}
	key := keyOf(j.pgid, j.start)
	sig := danger.Signals{Danger: danger_, Clear: clear}
	if danger_ {
		sig.D4PGIDs = []int{j.pgid}
	}
	return Snapshot{At: at, Sys: resources.System{At: at, RAM: ram, PageSize: pgz, Pressure: lvl}, Signals: sig,
		Terms:  []Term{{Key: key, Group: g, Series: []Point{{At: at, Bytes: 13 * gib}}}},
		ScanAt: at, ScanOK: true}
}

func TestRealSignalsPauseResumeAndKillSequence(t *testing.T) {
	j := spawn(t)
	other := exec.Command("sleep", "120") // a bystander the guard must never touch
	if err := other.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { other.Process.Kill(); other.Wait() }()

	sig := &ownOnly{spawned: map[int]bool{j.pgid: true, j.child.Process.Pid: true}, inner: OSSignaller{Starts: psStart{}, Self: -1}}
	m := NewMachine(DefaultConfig(ModePauseKill))
	ex := &Executor{M: m, Sig: sig, Store: &MemStore{}, Events: &sink{}}
	at := time.Now()
	step := func(s Snapshot) { ex.Apply(m.Step(s)) }

	// Pause: the leader and its child go to state T; the bystander does not.
	step(j.snap(at, warn, true, false))
	for _, pid := range []int{j.pgid, j.child.Process.Pid} {
		must(t, strings.HasPrefix(psState(pid), "T"), "pid %d must be stopped, state %q", pid, psState(pid))
	}
	must(t, !strings.HasPrefix(psState(other.Process.Pid), "T"), "the bystander must not be stopped")

	// Resume: after a clear (the clear hold only applies after a restart).
	at = at.Add(2 * time.Second)
	step(j.snap(at, normal, false, true))
	for _, pid := range []int{j.pgid, j.child.Process.Pid} {
		must(t, !strings.HasPrefix(psState(pid), "T"), "pid %d must run again, state %q", pid, psState(pid))
	}

	// Kill sequence on a fresh spawn: pause, 60s of critical polls, then
	// SIGTERM while stopped, SIGCONT, and the process is gone.
	k := spawn(t)
	sig.spawned[k.pgid], sig.spawned[k.child.Process.Pid] = true, true
	m2 := NewMachine(DefaultConfig(ModePauseKill))
	ex2 := &Executor{M: m2, Sig: sig, Store: &MemStore{}, Events: &sink{}}
	at = time.Now()
	ex2.Apply(m2.Step(k.snap(at, warn, true, false)))
	must(t, strings.HasPrefix(psState(k.pgid), "T"), "paused before the kill sequence")
	done := make(chan error, 2)
	go func() { done <- k.leader.Wait() }()
	go func() { done <- k.child.Wait() }()
	for i := 0; i < 40; i++ {
		at = at.Add(2 * time.Second)
		ex2.Apply(m2.Step(k.snap(at, crit, true, false)))
	}
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("the killed group must be gone")
		}
	}
	for _, pid := range sig.refused {
		t.Errorf("signaller was asked to touch pid %d outside the spawn set", pid)
	}
}
