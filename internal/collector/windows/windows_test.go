//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
	"strings"
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
	// Loopback always answers, so IcmpSendEcho itself is checked even on
	// hosted CI runners whose gateway drops ICMP.
	if p := c.Ping(context.Background(), "127.0.0.1", 2); p.Avg == nil || p.Loss != 0 {
		t.Fatalf("loopback did not answer: %+v", p)
	}
	if p := c.Ping(context.Background(), g.Addr, 2); p.Avg == nil {
		t.Logf("gateway %s did not answer ICMP: %+v", g.Addr, p)
	}
}

// TestToastScriptParses checks the toast script with PowerShell's own
// parser, without showing a toast. A broken script is the control: it must
// report errors, or the check would pass vacuously.
func TestToastScriptParses(t *testing.T) {
	parseErrors := func(script string) string {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:NW_SCRIPT, [ref]$null, [ref]$e); $e.Count`)
		cmd.Env = append(os.Environ(), "NW_SCRIPT="+script)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("powershell: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if n := parseErrors(toastScript + "\n$x = ("); n == "0" {
		t.Fatal("control: a broken script reported no parse errors")
	}
	if n := parseErrors(toastScript); n != "0" {
		t.Fatalf("toast script has %s parse errors", n)
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
