//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
	"github.com/ericmacdougall/netwatch/internal/procscan"
)

// Collector implements the collector and service interfaces for macOS.
type Collector struct{}

// New returns a Collector.
func New() *Collector { return &Collector{} }

// DefaultLogDir is ~/Library/Logs/netwatch, matching the prototype.
func DefaultLogDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "netwatch-logs"
	}
	return filepath.Join(home, "Library", "Logs", "netwatch")
}

// Processes lists all processes via ps.
func (c *Collector) Processes(ctx context.Context) ([]procscan.Process, error) {
	// The C locale makes ps print lstart in the layout ParsePS expects.
	out, err := execx.OutputEnv(ctx, 30*time.Second, []string{"LC_ALL=C"}, "/bin/ps", PSArgs...)
	if err != nil {
		return nil, err
	}
	return ParsePS(string(out), os.Getuid(), time.Local), nil
}

// Net samples nettop once. macOS gives per-process bytes without root, so
// interface totals are not collected separately.
func (c *Collector) Net(ctx context.Context, _ string) (netrate.Snapshot, error) {
	out, err := execx.Output(ctx, 30*time.Second, "/usr/bin/nettop", NettopArgs...)
	snap := netrate.Snapshot{At: time.Now(), HasBytes: true, Procs: map[netrate.Key]netrate.Counter{}}
	if err != nil {
		return snap, err
	}
	snap.Procs = ParseNettop(string(out))
	return snap, nil
}

// Gateway reads the default route.
func (c *Collector) Gateway(ctx context.Context) (platform.Gateway, error) {
	out, err := execx.Output(ctx, 10*time.Second, "/sbin/route", "-n", "get", "default")
	if err != nil {
		return platform.Gateway{}, err
	}
	return ParseRoute(string(out)), nil
}

// Ping uses the system ping, which is setuid on macOS and needs no root
// from the caller. Intervals below one second are allowed for non-root.
func (c *Collector) Ping(ctx context.Context, host string, count int) *health.Ping {
	// A non-zero exit just means some replies were lost; parse regardless.
	out, _ := execx.Output(ctx, 15*time.Second, "/sbin/ping", "-n", "-c", fmt.Sprint(count), "-i", "0.2", "-t", "4", host)
	p := health.ParsePingOutput(string(out), count)
	return &p
}

// OrphanRule: macOS reparents orphans to launchd (pid 1).
func (c *Collector) OrphanRule() procscan.OrphanRule { return procscan.InitParent }

// Terminate sends SIGTERM. force is not supported: netwatch never SIGKILLs.
func (c *Collector) Terminate(p procscan.Process, force bool) error {
	if force {
		return fmt.Errorf("--force is only meaningful on Windows; netwatch sends SIGTERM only")
	}
	// Re-check the process immediately before signalling. VerifyForKill
	// compared a ps snapshot taken moments earlier; the kernel's start
	// time (microsecond resolution) and owner narrow the window in which a
	// reused PID could be hit to the gap between this call and kill(2).
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", p.PID)
	if err != nil {
		return fmt.Errorf("read process: %w", err)
	}
	st := kp.Proc.P_starttime
	start := time.Unix(int64(st.Sec), int64(st.Usec)*1000)
	if kp.Proc.P_pid != int32(p.PID) || kp.Eproc.Pcred.P_ruid != uint32(os.Getuid()) ||
		p.Start.IsZero() || absDuration(start.Sub(p.Start)) > procscan.StartTolerance {
		return procscan.ErrChanged
	}
	return syscall.Kill(p.PID, syscall.SIGTERM)
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Notify shows a notification through osascript. Text is passed as argv,
// never spliced into the script, so it cannot inject AppleScript.
func (c *Collector) Notify(title, msg string) error {
	_, err := execx.Output(context.Background(), 10*time.Second, "/usr/bin/osascript",
		"-e", "on run argv",
		"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
		"-e", "end run",
		msg, "netwatch: "+title)
	return err
}
