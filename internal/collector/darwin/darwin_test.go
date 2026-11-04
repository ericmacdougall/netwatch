//go:build darwin

package darwin

import (
	"context"
	"os"
	"testing"
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
	if testing.Short() {
		t.Skip("nettop can take tens of seconds to start")
	}
	snap, err := c.Net(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !snap.HasBytes || len(snap.Procs) == 0 {
		t.Fatalf("nettop returned no processes: %+v", snap)
	}
}
