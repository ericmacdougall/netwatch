//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
	"github.com/ericmacdougall/netwatch/internal/procscan"
)

// clkTck is USER_HZ. It is 100 on every mainstream Linux architecture and
// reading it properly (sysconf) would need cgo.
const clkTck = 100

// Collector implements the collector and service interfaces for Linux.
type Collector struct {
	proc string // procfs mount, overridable in tests

	mu      sync.Mutex
	prevCPU map[int]cpuMark
}

type cpuMark struct {
	start uint64 // start ticks, to detect PID reuse
	ticks uint64
	at    time.Time
}

// New returns a Collector reading /proc.
func New() *Collector { return &Collector{proc: "/proc", prevCPU: map[int]cpuMark{}} }

// DefaultLogDir is $XDG_STATE_HOME/netwatch, or ~/.local/state/netwatch.
func DefaultLogDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "netwatch")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "netwatch-logs"
	}
	return filepath.Join(home, ".local", "state", "netwatch")
}

func (c *Collector) bootTime() (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(c.proc, "stat"))
	if err != nil {
		return time.Time{}, err
	}
	bt, err := ParseBootTime(string(b))
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(bt, 0), nil
}

// readProcess reads one /proc/<pid>; ok is false for kernel threads and
// processes that exited while being read.
func (c *Collector) readProcess(pid int, boot time.Time, uid uint32) (procscan.Process, Stat, bool) {
	dir := filepath.Join(c.proc, strconv.Itoa(pid))
	statB, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return procscan.Process{}, Stat{}, false
	}
	st, err := ParseStat(string(statB))
	if err != nil {
		return procscan.Process{}, Stat{}, false
	}
	cmdB, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil || len(cmdB) == 0 {
		return procscan.Process{}, Stat{}, false // kernel thread or zombie
	}
	var own bool
	if fi, err := os.Stat(dir); err == nil {
		if s, ok := fi.Sys().(*syscall.Stat_t); ok {
			own = s.Uid == uid
		}
	}
	start := boot.Add(time.Duration(st.StartTime) * time.Second / clkTck)
	return procscan.Process{
		PID: st.PID, PPID: st.PPID, Own: own, Name: st.Comm,
		RSSMB: int(st.RSSPages * int64(os.Getpagesize()) >> 20),
		Start: start, Age: time.Since(start), Cmd: ParseCmdline(cmdB),
	}, st, true
}

// Processes reads every /proc/<pid>. CPU is measured since the previous
// call; on the first call (or for new processes) it is the lifetime average.
func (c *Collector) Processes(ctx context.Context) ([]procscan.Process, error) {
	boot, err := c.bootTime()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(c.proc)
	if err != nil {
		return nil, err
	}
	uid := uint32(os.Getuid())
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[int]cpuMark, len(c.prevCPU))
	var procs []procscan.Process
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, st, ok := c.readProcess(pid, boot, uid)
		if !ok {
			continue
		}
		ticks := st.UTime + st.STime
		if prev, ok := c.prevCPU[pid]; ok && prev.start == st.StartTime && now.After(prev.at) && ticks >= prev.ticks {
			p.CPU = float64(ticks-prev.ticks) / clkTck / now.Sub(prev.at).Seconds() * 100
		} else if p.Age > 0 {
			p.CPU = float64(ticks) / clkTck / p.Age.Seconds() * 100
		}
		p.CPU = math.Round(p.CPU*10) / 10
		next[pid] = cpuMark{start: st.StartTime, ticks: ticks, at: now}
		procs = append(procs, p)
	}
	c.prevCPU = next
	return procs, nil
}

// Net sums TCP byte counters per process from ss, plus totals for iface
// from /proc/net/dev.
func (c *Collector) Net(ctx context.Context, iface string) (netrate.Snapshot, error) {
	snap := netrate.Snapshot{At: time.Now(), HasBytes: true, Procs: map[netrate.Key]netrate.Counter{}}
	if iface != "" {
		if b, err := os.ReadFile(filepath.Join(c.proc, "net", "dev")); err == nil {
			snap.IfIn, snap.IfOut, snap.HasIf = ParseNetDev(string(b), iface)
		}
	}
	out, err := execx.Output(ctx, 30*time.Second, "ss", SSArgs...)
	if err != nil {
		return snap, err
	}
	snap.Procs = ParseSS(string(out))
	return snap, nil
}

// Gateway reads /proc/net/route (IPv4 only).
func (c *Collector) Gateway(context.Context) (platform.Gateway, error) {
	b, err := os.ReadFile(filepath.Join(c.proc, "net", "route"))
	if err != nil {
		return platform.Gateway{}, err
	}
	return ParseRoute(string(b)), nil
}

// Ping uses the system ping, which works without root through either
// unprivileged ICMP sockets (net.ipv4.ping_group_range) or the file
// capability most distributions give it. 200 ms is iputils' minimum
// interval for unprivileged users.
func (c *Collector) Ping(ctx context.Context, host string, count int) *health.Ping {
	out, _ := execx.Output(ctx, 15*time.Second, "ping", "-n", "-c", strconv.Itoa(count), "-i", "0.2", "-W", "2", "-w", "5", host)
	p := health.ParsePingOutput(string(out), count)
	return &p
}

// ExePath reads /proc/<pid>/exe, which works for the user's own processes.
func (c *Collector) ExePath(pid int) string {
	p, err := os.Readlink(filepath.Join(c.proc, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(p, " (deleted)")
}

// OrphanRule: reparented to init or to a user-session subreaper.
func (c *Collector) OrphanRule() procscan.OrphanRule { return procscan.InitOrSubreaper("systemd") }

// Terminate sends SIGTERM through a pidfd when the kernel supports it
// (5.3+): the pidfd pins the process, so after re-checking its start time
// the signal cannot reach a different process that reused the PID.
func (c *Collector) Terminate(p procscan.Process, force bool) error {
	if force {
		return errors.New("--force is only meaningful on Windows; netwatch sends SIGTERM only")
	}
	boot, err := c.bootTime()
	if err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(p.PID, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOSYS) {
			return fmt.Errorf("pidfd_open: %w", err)
		}
		fd = -1 // old kernel: fall back to kill(2) after the same check
	} else {
		defer unix.Close(fd)
	}
	cur, _, ok := c.readProcess(p.PID, boot, uint32(os.Getuid()))
	// Compare with the same tolerance as VerifyForKill: the start time is
	// derived from btime, which moves slightly when NTP steps the clock.
	if d := cur.Start.Sub(p.Start); !ok || p.Start.IsZero() || d > procscan.StartTolerance || d < -procscan.StartTolerance {
		return procscan.ErrChanged
	}
	if fd >= 0 {
		return unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
	}
	return syscall.Kill(p.PID, syscall.SIGTERM)
}

// Notify uses notify-send when a desktop session is available.
func (c *Collector) Notify(title, msg string) error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return errors.ErrUnsupported
	}
	if _, err := exec.LookPath("notify-send"); err != nil {
		return errors.ErrUnsupported
	}
	_, err := execx.Output(context.Background(), 10*time.Second, "notify-send", "--app-name=netwatch", "--", "netwatch: "+title, msg)
	return err
}
