//go:build linux

package resources

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestLinuxLiveSelf(t *testing.T) {
	r := New()
	if err := r.SelfTest(); err != nil {
		t.Fatal(err)
	}
	sys, err := r.System()
	if err != nil || sys.RAM == 0 || sys.PageSize == 0 || sys.MemAvailable == 0 {
		t.Fatalf("system %+v %v", sys, err)
	}
	// A child we spawn: group, start, env subset, cwd, footprint = RSS+swap.
	c := exec.Command("sleep", "30")
	c.Env = []string{"CLAUDECODE=1", "CLAUDE_PID=" + strconv.Itoa(os.Getpid()), "SECRET_TOKEN=zzz"}
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	var p Proc
	if err := r.(*linuxReader).Probe(c.Process.Pid, &p); err != nil {
		t.Fatal(err)
	}
	if p.PGID != c.Process.Pid || p.PPID != os.Getpid() || p.Name != "sleep" || !p.FootprintOK || p.Footprint == 0 || p.Footprint < p.RSS {
		t.Fatalf("%+v", p)
	}
	if d := time.Since(p.Start); d < 0 || d > time.Minute {
		t.Fatalf("start %v off by %v", p.Start, d)
	}
	env := r.Env(c.Process.Pid, "CLAUDECODE", "CLAUDE_PID")
	if env["CLAUDECODE"] != "1" || env["CLAUDE_PID"] != strconv.Itoa(os.Getpid()) || len(env) != 2 {
		t.Fatalf("env %v", env)
	}
	if cwd, _ := os.Getwd(); r.Cwd(c.Process.Pid) != cwd {
		t.Fatalf("cwd %q", r.Cwd(c.Process.Pid))
	}
	if m, _ := r.GroupMembers(c.Process.Pid); len(m) != 1 || m[0] != c.Process.Pid {
		t.Fatalf("members %v", m)
	}
	if k, _ := r.Children(os.Getpid()); !contains(k, c.Process.Pid) {
		t.Fatalf("children %v", k)
	}
	if sid, err := r.Sid(c.Process.Pid); err != nil || sid == 0 {
		t.Fatalf("sid %d %v", sid, err)
	}
	// Stopped state is visible.
	syscall.Kill(c.Process.Pid, syscall.SIGSTOP) // our own spawned child only
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.(*linuxReader).Probe(c.Process.Pid, &p)
		if p.Stopped {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !p.Stopped {
		t.Fatal("stopped child not reported as Stopped")
	}
	if err := r.(*linuxReader).Probe(1<<30, &p); err != ErrGone {
		t.Fatalf("missing pid err = %v", err)
	}
}

func TestLinuxFixtureRoot(t *testing.T) {
	root := t.TempDir()
	w := func(rel, body string) {
		p := root + "/" + rel
		os.MkdirAll(p[:len(p)-len(baseName(p))-1], 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("stat", "btime 1700000000\n")
	w("meminfo", "MemTotal: 16777216 kB\nMemFree: 1048576 kB\nMemAvailable: 8388608 kB\nInactive: 2097152 kB\nSwapTotal: 4194304 kB\nSwapFree: 1048576 kB\n")
	w("pressure/memory", "some avg10=20.00 avg60=0 avg300=0 total=1\nfull avg10=12.00 avg60=0 avg300=0 total=1\n")
	w("loadavg", "2.50 1.0 1.0 1/100 5\n")
	r := newLinux(root)
	s, err := r.System()
	if err != nil {
		t.Fatal(err)
	}
	if s.RAM != 16<<30 || s.SwapUsed != 3<<30 || s.Pressure != LevelWarn || s.PSIFullAvg10 != 12 || s.Load1 != 2.5 ||
		s.MemAvailable != 8<<30 || s.Inactive*s.PageSize != 2<<30 {
		t.Fatalf("%+v", s)
	}
	// No PSI file: pressure unknown, not normal.
	os.Remove(root + "/pressure/memory")
	if s, _ := r.System(); s.Pressure != LevelUnknown {
		t.Fatalf("pressure without PSI = %v", s.Pressure)
	}
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func TestLinuxBatchMatchesPerGroup(t *testing.T) {
	r := New().(*linuxReader)
	var cmds []*exec.Cmd
	var pgs []int
	for i := 0; i < 3; i++ {
		c := exec.Command("sh", "-c", "sleep 30 & sleep 30 & wait")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
		pgs = append(pgs, c.Process.Pid)
	}
	t.Cleanup(func() {
		for _, c := range cmds { // our own spawned groups only
			syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			c.Wait()
		}
	})
	time.Sleep(300 * time.Millisecond)
	out := map[int][]int{}
	if err := r.GroupsMembers(pgs, out); err != nil {
		t.Fatal(err)
	}
	for _, pg := range pgs {
		one, _ := r.GroupMembers(pg)
		got := out[pg]
		if len(one) < 3 || len(got) != len(one) {
			t.Fatalf("group %d: batch %v per-group %v", pg, got, one)
		}
	}
}
