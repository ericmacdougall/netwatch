//go:build !windows

package resmon

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/guard"
)

type countSig struct{ n int }

func (c *countSig) Signal(int, time.Time, syscall.Signal) error { c.n++; return nil }

// SpawnedOnly passes signals for members of the spawned group and refuses
// everything else: another group, pid 1, a vanished pid, and a group whose
// leader pid was reused by a different process.
func TestSpawnedOnlyRefusesEverythingOutsideTheJob(t *testing.T) {
	f := newFake()
	f.add(100, 1, 100, gib, 0) // the spawned leader
	f.add(101, 100, 100, gib, 0)
	f.add(200, 1, 200, gib, 0) // bystander
	in := &countSig{}
	s := SpawnedOnly{Inner: in, R: f, Target: TestTarget{PGID: 100, Start: f.procs[100].Start}}

	for _, pid := range []int{100, 101} {
		if err := s.Signal(pid, f.procs[pid].Start, syscall.SIGSTOP); err != nil {
			t.Fatalf("member %d refused: %v", pid, err)
		}
	}
	for _, pid := range []int{200, 1, 0} {
		if err := s.Signal(pid, time.Time{}, syscall.SIGSTOP); !errors.Is(err, ErrNotTarget) {
			t.Errorf("pid %d: err %v, want ErrNotTarget", pid, err)
		}
	}
	// A vanished pid reads as gone, like the real signaller reports it.
	if err := s.Signal(999, time.Time{}, syscall.SIGSTOP); !errors.Is(err, guard.ErrStartMismatch) {
		t.Errorf("gone pid: err %v, want ErrStartMismatch", err)
	}
	// A process in the group that predates the job is not ours.
	f.add(102, 1, 100, gib, 0)
	f.procs[102].Start = f.procs[100].Start.Add(-time.Hour)
	if err := s.Signal(102, f.procs[102].Start, syscall.SIGCONT); !errors.Is(err, ErrNotTarget) {
		t.Errorf("older process in the group: err %v, want ErrNotTarget", err)
	}
	// Leader pid reused: same pgid, different start time.
	f.procs[100].Start = f.procs[100].Start.Add(time.Hour)
	if err := s.Signal(101, f.procs[101].Start, syscall.SIGSTOP); !errors.Is(err, ErrNotTarget) {
		t.Errorf("reused leader: err %v, want ErrNotTarget", err)
	}
	if in.n != 2 {
		t.Fatalf("inner signaller called %d times, want 2", in.n)
	}
}

// The boundary holds even if the machine wanted to signal another group:
// with demotion removed (bystander left as a verified tool group), only the
// spawned job is ever signalled.
func TestSpawnedOnlyHoldsWithoutDemotion(t *testing.T) {
	f := newFake()
	f.sys = critical
	f.add(100, 1, 100, 2*gib, gib/2)
	f.add(200, 1, 200, 6*gib, gib)
	tt := TestTarget{PGID: 100, Start: f.procs[100].Start, Tier: guard.TierTool}
	h := newHarness(t, f, guard.ModePauseKill, fixedClassifier{tool: []int{100, 200}}, nil) // no TestTarget: no demotion
	h.loop.d.Exec.Sig = SpawnedOnly{Inner: f.record(&h.sigs), R: f, Target: tt}
	h.run(3 * time.Minute)
	for _, s := range h.sigs {
		if s.pid != 100 {
			t.Fatalf("signal reached pid %d outside the spawned job: %v", s.pid, h.sigs)
		}
	}
}

// When the leader has exited, a stopped member can still be resumed
// (SIGCONT) but never stopped or killed: the group is no longer provable.
func TestSpawnedOnlyLeaderGoneAllowsOnlyCont(t *testing.T) {
	f := newFake()
	f.add(100, 1, 100, gib, 0)
	f.add(101, 100, 100, gib, 0)
	in := &countSig{}
	s := SpawnedOnly{Inner: in, R: f, Target: TestTarget{PGID: 100, Start: f.procs[100].Start}}
	delete(f.procs, 100)
	for _, sig := range []syscall.Signal{syscall.SIGSTOP, syscall.SIGTERM, syscall.SIGKILL} {
		if err := s.Signal(101, f.procs[101].Start, sig); !errors.Is(err, ErrNotTarget) {
			t.Errorf("%v with leader gone: err %v, want ErrNotTarget", sig, err)
		}
	}
	if err := s.Signal(101, f.procs[101].Start, syscall.SIGCONT); err != nil {
		t.Fatalf("SIGCONT with leader gone refused: %v", err)
	}
	if in.n != 1 {
		t.Fatalf("inner called %d times, want 1 (the SIGCONT)", in.n)
	}
}
