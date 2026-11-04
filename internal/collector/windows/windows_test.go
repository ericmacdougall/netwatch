//go:build windows

package windows

import (
	"context"
	"os"
	"testing"
)

// Collector tests use the real Windows APIs and only run on Windows.
func TestProcessesIncludesSelfWithDetails(t *testing.T) {
	c := New()
	procs, err := c.Processes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]bool{}
	for _, p := range procs {
		byPID[p.PID] = true
	}
	for _, p := range procs {
		if p.PID != os.Getpid() {
			continue
		}
		if !p.Own || p.Start.IsZero() || p.Cmd == "" || p.RSSMB <= 0 || p.PPID != os.Getppid() || p.Match == "" {
			t.Fatalf("self entry incomplete: %+v", p)
		}
		return
	}
	t.Fatalf("own pid %d not among %d processes", os.Getpid(), len(procs))
}

func TestGatewayNetAndPing(t *testing.T) {
	c := New()
	g, err := c.Gateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.Addr == "" {
		t.Skip("no IPv4 default route")
	}
	snap, err := c.Net(context.Background(), g.Iface)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.HasIf {
		t.Fatalf("no interface totals for %q", g.Iface)
	}
	if p := c.Ping(context.Background(), g.Addr, 2); p.Avg == nil {
		t.Fatalf("gateway %s did not answer: %+v", g.Addr, p)
	}
}
