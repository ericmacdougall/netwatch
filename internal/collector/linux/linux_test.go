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
