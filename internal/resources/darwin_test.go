//go:build darwin

package resources

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperHog is re-executed as a child by the tests below. It touches
// HOG_MB megabytes, spins for HOG_SPIN, prints READY and then sleeps. It
// is only a helper when HOG_HELPER is set, so a normal run skips it.
func TestHelperHog(t *testing.T) {
	if os.Getenv("HOG_HELPER") != "1" {
		t.Skip("helper process")
	}
	mb, _ := strconv.Atoi(os.Getenv("HOG_MB"))
	buf := make([]byte, mb<<20)
	for i := 0; i < len(buf); i += 4096 {
		buf[i] = byte(i)
	}
	spin, _ := time.ParseDuration(os.Getenv("HOG_SPIN"))
	end := time.Now().Add(spin)
	for time.Now().Before(end) {
	}
	os.Stdout.WriteString("READY\n")
	time.Sleep(20 * time.Second)
	_ = buf[len(buf)-1]
}

// spawnHog starts the helper in its own process group and waits for READY.
// Only this child is ever signalled by these tests.
func spawnHog(t *testing.T, mb int, spin time.Duration) *exec.Cmd {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^TestHelperHog$", "-test.v")
	c.Env = []string{"HOG_HELPER=1", "HOG_MB=" + strconv.Itoa(mb), "HOG_SPIN=" + spin.String(),
		"CLAUDECODE=1", "CLAUDE_PID=" + strconv.Itoa(os.Getpid()), "UNRELATED_SECRET=hunter2"}
	c.Dir = t.TempDir()
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	sc := bufio.NewScanner(out)
	done := make(chan bool, 1)
	go func() {
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "READY" {
				done <- true
				return
			}
		}
		done <- false
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("helper exited before READY")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not become ready")
	}
	return c
}

func TestDarwinSelfTest(t *testing.T) {
	if err := New().SelfTest(); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinFootprintTracksTouchedMemory(t *testing.T) {
	r := New()
	c := spawnHog(t, 300, 0)
	var p Proc
	if err := r.Probe(c.Process.Pid, &p); err != nil {
		t.Fatal(err)
	}
	if !p.FootprintOK {
		t.Fatalf("own child footprint not readable: %+v", p)
	}
	// 300 MB touched; allow for the runtime baseline and compression.
	if p.Footprint < 280<<20 || p.Footprint > 600<<20 {
		t.Fatalf("footprint %d MiB, want about 300", p.Footprint>>20)
	}
	if p.RSS == 0 || p.RSS > p.Footprint+64<<20 {
		t.Fatalf("rss %d footprint %d", p.RSS, p.Footprint)
	}
	if p.PID != c.Process.Pid || p.PPID != os.Getpid() || p.PGID != c.Process.Pid || p.SID != os.Getpid() && p.SID <= 0 {
		t.Fatalf("ids %+v", p)
	}
	if d := time.Since(p.Start); d < 0 || d > time.Minute {
		t.Fatalf("start %v (age %v)", p.Start, d)
	}
	if p.Stopped {
		t.Fatal("running child reported stopped")
	}
}

func TestDarwinCPUTimeUnits(t *testing.T) {
	// A child that spins for 1.5s of wall time must report about that much
	// CPU: mach absolute ticks are 24 MHz on Apple silicon, so reading them
	// as nanoseconds would give a value 40x too small.
	r := New()
	c := spawnHog(t, 1, 1500*time.Millisecond)
	var p Proc
	if err := r.Probe(c.Process.Pid, &p); err != nil {
		t.Fatal(err)
	}
	if p.CPUTime < 1000*time.Millisecond || p.CPUTime > 4*time.Second {
		t.Fatalf("cpu time %v, want about 1.5s", p.CPUTime)
	}
}

func TestDarwinOtherUIDGetsNoFootprint(t *testing.T) {
	r := New()
	var p Proc
	if err := r.Probe(1, &p); err != nil { // launchd, owned by root
		t.Fatal(err)
	}
	if p.FootprintOK || p.Footprint != 0 || p.PID != 1 {
		t.Fatalf("pid 1 must be listed with FootprintOK=false: %+v", p)
	}
	if _, _, err := r.Footprint(1); err != ErrNoAccess {
		t.Fatalf("Footprint(1) err = %v, want ErrNoAccess", err)
	}
	if os.Geteuid() != 0 {
		ps, err := r.Procs()
		if err != nil || len(ps) < 50 {
			t.Fatalf("procs %d %v", len(ps), err)
		}
		var self, root *Proc
		for i := range ps {
			switch ps[i].PID {
			case os.Getpid():
				self = &ps[i]
			case 1:
				root = &ps[i]
			}
		}
		if self == nil || !self.FootprintOK || self.Exe == "" || self.Name == "" {
			t.Fatalf("self entry %+v", self)
		}
		if root == nil || root.FootprintOK {
			t.Fatalf("root entry %+v", root)
		}
	}
}

func TestDarwinGroupsChildrenEnvArgsCwd(t *testing.T) {
	r := New()
	c := spawnHog(t, 1, 0)
	pid := c.Process.Pid
	if m, err := r.GroupMembers(pid); err != nil || len(m) != 1 || m[0] != pid {
		t.Fatalf("PGRP_ONLY members %v %v", m, err)
	}
	if k, err := r.Children(os.Getpid()); err != nil || !contains(k, pid) {
		t.Fatalf("PPID_ONLY children %v %v", k, err)
	}
	if m, _ := r.GroupMembers(1 << 29); len(m) != 0 {
		t.Fatalf("members of a missing group: %v", m)
	}
	env := r.Env(pid, "CLAUDECODE", "CLAUDE_PID")
	if len(env) != 2 || env["CLAUDECODE"] != "1" || env["CLAUDE_PID"] != strconv.Itoa(os.Getpid()) {
		t.Fatalf("env %v", env)
	}
	args := r.Args(pid)
	if len(args) < 2 || !strings.Contains(strings.Join(args, " "), "TestHelperHog") {
		t.Fatalf("args %q", args)
	}
	cwd := r.Cwd(pid)
	want, _ := filepath.EvalSymlinks(c.Dir)
	if cwd != want {
		t.Fatalf("cwd %q want %q", cwd, want)
	}
	if sid, err := r.Sid(pid); err != nil || sid != os.Getpid() && sid <= 0 {
		t.Fatalf("sid %d %v", sid, err)
	}
	// A process of another uid reveals neither env nor cwd.
	if e := r.Env(1, "CLAUDECODE"); e != nil {
		t.Fatalf("env of pid 1: %v", e)
	}
	if r.Cwd(1) != "" {
		t.Fatal("cwd of pid 1 readable")
	}
}

func TestDarwinStoppedAndGone(t *testing.T) {
	r := New()
	c := spawnHog(t, 1, 0)
	syscall.Kill(c.Process.Pid, syscall.SIGSTOP) // our own spawned child only
	var p Proc
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Probe(c.Process.Pid, &p) == nil && p.Stopped {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !p.Stopped {
		t.Fatalf("stopped child not seen: %+v", p)
	}
	if err := r.Probe(1<<29, &p); err != ErrGone {
		t.Fatalf("missing pid err = %v", err)
	}
}

func TestDarwinSystem(t *testing.T) {
	s, err := New().System()
	if err != nil {
		t.Fatal(err)
	}
	if s.RAM < 1<<30 || s.PageSize == 0 || s.Free == 0 || s.Pressure == LevelUnknown || s.DiskFree == 0 {
		t.Fatalf("%+v", s)
	}
	if s.PagesCompressedLimit == 0 || s.SegmentLimit == 0 || s.PagesCompressed > s.PagesCompressedLimit {
		t.Fatalf("compressor %+v", s)
	}
	if !s.InactiveEstimated && s.Inactive == 0 {
		t.Fatal("inactive pages neither measured nor estimated")
	}
	if s.Load1 <= 0 || s.Load1 > 10000 {
		t.Fatalf("load %v", s.Load1)
	}
	if s.SwapUsed > s.SwapTotal {
		t.Fatalf("swap %d/%d", s.SwapUsed, s.SwapTotal)
	}
}

func TestDarwinLayoutSizes(t *testing.T) {
	// The compile-time asserts in darwin_procinfo.go pin these; this keeps
	// a human-readable record and fails if the file's constants drift.
	var ti procTaskInfo
	var ru rusageInfoV2
	var vp vnodePathInfo
	if sizeTaskInfo != 96 || sizeRusageV2 != 160 || sizeVnode != 2352 || ti.Priority != 0 || ru.PhysFootprint != 0 || vp.Path[0] != 0 {
		t.Fatal("layout constants")
	}
}
