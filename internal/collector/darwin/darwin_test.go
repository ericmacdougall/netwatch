//go:build darwin

package darwin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/procscan"
)

// Collector tests run the real ps/route/nettop and only run on macOS.
func TestProcessesIncludesSelf(t *testing.T) {
	procs, err := New().Processes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == os.Getpid() {
			if !p.Own || p.Start.IsZero() || p.Cmd == "" || p.PPID != os.Getppid() {
				t.Fatalf("self entry wrong: %+v", p)
			}
			return
		}
	}
	t.Fatalf("own pid %d not in %d processes", os.Getpid(), len(procs))
}

func TestGatewayAndNetDoNotFail(t *testing.T) {
	c := New()
	if _, err := c.Gateway(context.Background()); err != nil {
		t.Skipf("no default route: %v", err)
	}
	snap, err := c.Net(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !snap.HasBytes || len(snap.Procs) == 0 {
		t.Fatalf("nettop returned no processes: %+v", snap)
	}
}

func TestTerminateRechecksStartTime(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	c := New()
	procs, err := c.Processes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var p procscan.Process
	for _, x := range procs {
		if x.PID == cmd.Process.Pid {
			p = x
		}
	}
	if p.PID == 0 {
		t.Fatal("child not in process table")
	}
	stale := p
	stale.Start = p.Start.Add(-time.Hour) // as if the PID had been reused
	if err := c.Terminate(stale, false); !errors.Is(err, procscan.ErrChanged) {
		t.Fatalf("stale start: got %v, want ErrChanged", err)
	}
	if err := c.Terminate(p, false); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if err := cmd.Wait(); err == nil || !strings.Contains(err.Error(), "terminated") {
		t.Fatalf("child did not die from SIGTERM: %v", err)
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
