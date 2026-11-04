//go:build linux

package linux

import (
	"context"
	"os"
	"testing"
)

// Collector tests read the real /proc and only run on Linux.
func TestProcessesIncludesSelf(t *testing.T) {
	c := New()
	procs, err := c.Processes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == os.Getpid() {
			if !p.Own || p.Start.IsZero() || p.Cmd == "" || p.RSSMB < 0 || p.PPID != os.Getppid() {
				t.Fatalf("self entry wrong: %+v", p)
			}
			return
		}
	}
	t.Fatalf("own pid %d not in %d processes", os.Getpid(), len(procs))
}

func TestGatewayAndNetDoNotFail(t *testing.T) {
	c := New()
	g, err := c.Gateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Net(context.Background(), g.Iface); err != nil {
		t.Skipf("ss unavailable: %v", err)
	}
}

func TestExePathOfSelf(t *testing.T) {
	want, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if got := New().ExePath(os.Getpid()); !sameFile(t, got, want) {
		t.Fatalf("ExePath(self) = %q, want %q", got, want)
	}
	if got := New().ExePath(1 << 30); got != "" {
		t.Fatalf("ExePath of a missing PID = %q, want empty", got)
	}
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	if a == "" {
		return false
	}
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

func TestArgsOfSelf(t *testing.T) {
	got := New().Args(os.Getpid())
	if len(got) != len(os.Args) || (len(got) > 1 && got[1] != os.Args[1]) {
		t.Fatalf("Args(self) = %q, want %q", got, os.Args)
	}
	if New().Args(1<<30) != nil {
		t.Fatal("Args of a missing PID should be nil")
	}
}
