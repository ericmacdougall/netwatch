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
	for _, pid := range []int{200, 1, 0, 999} {
		if err := s.Signal(pid, time.Time{}, syscall.SIGSTOP); !errors.Is(err, ErrNotTarget) {
			t.Errorf("pid %d: err %v, want ErrNotTarget", pid, err)
		}
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
