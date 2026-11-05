package budget

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	wrapperPID = 4242
	childPID   = 4243
	gibU       = uint64(1) << 30
	ram16      = 16 * gibU
	runCapped  = "/home/user/bin/run_capped"
)

var startedAt = time.Unix(1793808400, 500000000)

type fproc struct {
	start      time.Time
	ppid, pgid int
	argv       []string
}

type fakeFacts struct{ procs map[int]fproc }

func (f *fakeFacts) Start(pid int) (time.Time, bool) { p, ok := f.procs[pid]; return p.start, ok }
func (f *fakeFacts) Argv(pid int) []string           { return f.procs[pid].argv }
func (f *fakeFacts) Parent(pid int) (int, bool)      { p, ok := f.procs[pid]; return p.ppid, ok }
func (f *fakeFacts) PGID(pid int) (int, bool)        { p, ok := f.procs[pid]; return p.pgid, ok }
func (f *fakeFacts) GroupSize(pgid int) int {
	n := 0
	for _, p := range f.procs {
		if p.pgid == pgid {
			n++
		}
	}
	return n
}

// baseFacts is the genuine layout: shell -> wrapper (run_capped) -> child
// leading its own group, with one grandchild.
func baseFacts() *fakeFacts {
	return &fakeFacts{procs: map[int]fproc{
		100:        {start: startedAt.Add(-time.Hour), ppid: 1, pgid: 100, argv: []string{"/bin/zsh"}},
		wrapperPID: {start: startedAt.Add(300 * time.Millisecond), ppid: 100, pgid: 100, argv: []string{"/usr/bin/python3", runCapped, "--", "make"}},
		childPID:   {start: startedAt.Add(time.Second), ppid: wrapperPID, pgid: childPID, argv: []string{"make"}},
		4244:       {start: startedAt.Add(2 * time.Second), ppid: childPID, pgid: childPID, argv: []string{"cc"}},
	}}
}

type env struct {
	dir   string
	cfg   Config
	facts *fakeFacts
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile("testdata/run_capped/4242.json")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{dir: dir, facts: baseFacts()}
	e.put(t, "4242.json", string(b), 0o600)
	e.cfg = Config{
		Dir: dir, RunCappedPaths: []string{runCapped}, RAM: ram16,
		Realpath: func(p string) (string, error) { return p, nil },
	}
	return e
}

func (e *env) put(t *testing.T, name, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func (e *env) load(t *testing.T) *Result {
	t.Helper()
	r, err := Load(e.cfg, e.facts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestControlGenuineSidecarIsHonoured(t *testing.T) {
	skipOnWindows(t)
	e := newEnv(t)
	r := e.load(t)
	d, ok := r.Budgets[childPID]
	if !ok || len(r.Rejected) != 0 {
		t.Fatalf("genuine sidecar rejected: %+v", r.Rejected)
	}
	if d.MaxBytes != 8*gibU || d.MaxProcs != 32 || d.Wrapper != wrapperPID {
		t.Errorf("declared: %+v", d)
	}
	if _, within := r.Within(childPID, 4*gibU, 2); !within {
		t.Error("4 GiB, 2 procs must be within an 8 GiB, 32 proc budget")
	}
}

// Each variant changes exactly one thing from the control and must be
// rejected for that reason. The control above proves they are not vacuous.
func TestSidecarRules(t *testing.T) {
	skipOnWindows(t)
	good := func(t *testing.T, e *env) string {
		b, _ := os.ReadFile("testdata/run_capped/4242.json")
		return string(b)
	}
	cases := []struct {
		name   string
		reason string
		mut    func(t *testing.T, e *env)
	}{
		{"name not digits", "digits.json", func(t *testing.T, e *env) {
			os.Rename(filepath.Join(e.dir, "4242.json"), filepath.Join(e.dir, "4242x.json"))
		}},
		{"name has path-ish suffix", "digits.json", func(t *testing.T, e *env) {
			os.Rename(filepath.Join(e.dir, "4242.json"), filepath.Join(e.dir, "4242.json.bak"))
		}},
		{"name does not match wrapper_pid", "does not match wrapper_pid", func(t *testing.T, e *env) {
			os.Rename(filepath.Join(e.dir, "4242.json"), filepath.Join(e.dir, "4999.json"))
		}},
		{"mode 0644", "permissions", func(t *testing.T, e *env) {
			os.Chmod(filepath.Join(e.dir, "4242.json"), 0o644)
		}},
		{"mode 0640", "permissions", func(t *testing.T, e *env) {
			os.Chmod(filepath.Join(e.dir, "4242.json"), 0o640)
		}},
		{"foreign owner", "wrong owner", func(t *testing.T, e *env) {
			other := os.Getuid() + 1
			e.cfg.OwnerUID = &other
		}},
		{"symlink", "not a regular file", func(t *testing.T, e *env) {
			real := filepath.Join(t.TempDir(), "real.json")
			os.WriteFile(real, []byte(good(t, e)), 0o600)
			p := filepath.Join(e.dir, "4242.json")
			os.Remove(p)
			os.Symlink(real, p)
		}},
		{"oversize", "exceeds limit", func(t *testing.T, e *env) {
			pad := strings.Repeat(" ", MaxSidecarBytes)
			e.put(t, "4242.json", good(t, e)+pad, 0o600)
		}},
		{"duplicate key", "duplicate key", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"max_procs": 32,`, `"max_procs": 32, "max_procs": 9999,`, 1), 0o600)
		}},
		{"trailing data", "trailing data", func(t *testing.T, e *env) {
			e.put(t, "4242.json", good(t, e)+`{}`, 0o600)
		}},
		{"wrong type", "rejected JSON", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"max_procs": 32`, `"max_procs": "32"`, 1), 0o600)
		}},
		{"fractional pid", "rejected JSON", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"pgid": 4243`, `"pgid": 4243.5`, 1), 0o600)
		}},
		{"negative rss", "max_rss_gb out of range", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"max_rss_gb": 8`, `"max_rss_gb": -8`, 1), 0o600)
		}},
		{"zero procs", "max_procs out of range", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"max_procs": 32`, `"max_procs": 0`, 1), 0o600)
		}},
		{"negative timeout", "timeout_s out of range", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"timeout_s": 600`, `"timeout_s": -1`, 1), 0o600)
		}},
		{"overflowing number", "rejected JSON", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"max_rss_gb": 8`, `"max_rss_gb": 1e999`, 1), 0o600)
		}},
		{"missing pgid", "pids must be positive", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"pgid": 4243,`, ``, 1), 0o600)
		}},
		{"wrapper dead", "wrapper is not alive", func(t *testing.T, e *env) {
			delete(e.facts.procs, wrapperPID)
		}},
		{"wrapper pid reused (start 6s off)", "start does not match", func(t *testing.T, e *env) {
			p := e.facts.procs[wrapperPID]
			p.start = startedAt.Add(6 * time.Second)
			e.facts.procs[wrapperPID] = p
		}},
		{"wrapper only named run_capped", "not a configured run_capped", func(t *testing.T, e *env) {
			p := e.facts.procs[wrapperPID]
			p.argv = []string{"/tmp/evil/run_capped", "--", "make"}
			e.facts.procs[wrapperPID] = p
		}},
		{"wrapper relative argv0", "not a configured run_capped", func(t *testing.T, e *env) {
			p := e.facts.procs[wrapperPID]
			p.argv = []string{"run_capped"}
			e.facts.procs[wrapperPID] = p
		}},
		{"symlink named run_capped to elsewhere", "not a configured run_capped", func(t *testing.T, e *env) {
			e.cfg.Realpath = func(p string) (string, error) {
				if p == "/tmp/run_capped" {
					return "/tmp/other-script", nil
				}
				return p, nil
			}
			p := e.facts.procs[wrapperPID]
			p.argv = []string{"/tmp/run_capped"}
			e.facts.procs[wrapperPID] = p
		}},
		{"no configured run_capped path", "not a configured run_capped", func(t *testing.T, e *env) {
			e.cfg.RunCappedPaths = nil
		}},
		{"wrapper not an ancestor", "not an ancestor", func(t *testing.T, e *env) {
			// The child (and its group) hang off an unrelated parent; the
			// wrapper is still its declared parent in the sidecar only.
			e.facts.procs[900] = fproc{start: startedAt, ppid: 1, pgid: 900, argv: []string{"x"}}
			c := e.facts.procs[childPID]
			c.ppid = 900
			e.facts.procs[childPID] = c
		}},
		{"child dead", "child is not alive", func(t *testing.T, e *env) {
			e.put(t, "4242.json", strings.Replace(good(t, e), `"child_pid": 4243`, `"child_pid": 4999`, 1), 0o600)
		}},
		{"child of a different wrapper", "not a child of the wrapper", func(t *testing.T, e *env) {
			// The group leader still descends from the wrapper, so only the
			// child rule can trip.
			e.facts.procs[4300] = fproc{start: startedAt, ppid: 100, pgid: childPID, argv: []string{"other"}}
			e.put(t, "4242.json", strings.Replace(good(t, e), `"child_pid": 4243`, `"child_pid": 4300`, 1), 0o600)
		}},
		{"child in another group", "not in the stated process group", func(t *testing.T, e *env) {
			e.facts.procs[4300] = fproc{start: startedAt, ppid: wrapperPID, pgid: 100, argv: []string{"other"}}
			e.put(t, "4242.json", strings.Replace(good(t, e), `"child_pid": 4243`, `"child_pid": 4300`, 1), 0o600)
		}},
		{"group larger than max_procs", "over max_procs", func(t *testing.T, e *env) {
			for i := 0; i < 40; i++ {
				e.facts.procs[5000+i] = fproc{start: startedAt, ppid: childPID, pgid: childPID, argv: []string{"w"}}
			}
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.mut(t, e)
			r := e.load(t)
			if len(r.Budgets) != 0 {
				t.Fatalf("sidecar honoured: %+v", r.Budgets)
			}
			if len(r.Rejected) == 0 {
				t.Fatal("no rejection recorded")
			}
			var got []string
			for _, rj := range r.Rejected {
				got = append(got, rj.Reason)
			}
			if !strings.Contains(strings.Join(got, "|"), c.reason) {
				t.Errorf("want reason containing %q, got %q", c.reason, got)
			}
		})
	}
}

func TestClampAndMostRestrictiveWins(t *testing.T) {
	skipOnWindows(t)
	t.Run("clamped to half of RAM", func(t *testing.T) {
		e := newEnv(t)
		b, _ := os.ReadFile("testdata/run_capped/4242.json")
		e.put(t, "4242.json", strings.Replace(string(b), `"max_rss_gb": 8`, `"max_rss_gb": 500`, 1), 0o600)
		d := e.load(t).Budgets[childPID]
		if d.MaxBytes != ram16/2 {
			t.Errorf("MaxBytes %d want %d", d.MaxBytes, ram16/2)
		}
	})
	t.Run("forged sidecars cannot change a genuine budget", func(t *testing.T) {
		e := newEnv(t)
		// Two other processes claim the same group with different limits
		// but are not the group's ancestors, so both are rejected.
		for _, w := range []struct{ pid, gb, procs int }{{4250, 2, 4}, {4251, 12, 200}} {
			e.facts.procs[w.pid] = fproc{start: startedAt, ppid: 100, pgid: 100, argv: []string{runCapped}}
			b := strings.NewReplacer(
				`"wrapper_pid": 4242`, `"wrapper_pid": `+strconv.Itoa(w.pid),
				`"max_rss_gb": 8`, `"max_rss_gb": `+strconv.Itoa(w.gb),
				`"max_procs": 32`, `"max_procs": `+strconv.Itoa(w.procs),
			).Replace(readFixture(t))
			e.put(t, strconv.Itoa(w.pid)+".json", b, 0o600)
		}
		r := e.load(t)
		if d := r.Budgets[childPID]; d.MaxBytes != 8*gibU || d.MaxProcs != 32 {
			t.Errorf("forged sidecars changed the budget: %+v", d)
		}
		if len(r.Rejected) != 2 {
			t.Errorf("rejected: %+v", r.Rejected)
		}
	})
}

func TestMergeKeepsMostRestrictive(t *testing.T) {
	r := &Result{Budgets: map[int]Declared{}}
	cfg := Config{RAM: ram16}
	r.merge(cfg, &Sidecar{WrapperPID: 1, PGID: 7, MaxRSSGB: 8, MaxProcs: 32, StartedAt: 1})
	r.merge(cfg, &Sidecar{WrapperPID: 2, PGID: 7, MaxRSSGB: 2, MaxProcs: 64, StartedAt: 1})
	r.merge(cfg, &Sidecar{WrapperPID: 3, PGID: 7, MaxRSSGB: 12, MaxProcs: 4, StartedAt: 1})
	d := r.Budgets[7]
	if d.MaxBytes != 2*gibU || d.MaxProcs != 4 || d.Wrapper != 2 {
		t.Errorf("merged: %+v", d)
	}
}

func TestOverBudgetCountsAsUndeclared(t *testing.T) {
	skipOnWindows(t)
	e := newEnv(t)
	r := e.load(t)
	for _, c := range []struct {
		name   string
		bytes  uint64
		procs  int
		within bool
	}{
		{"inside", 8 * gibU, 32, true},
		{"one byte over", 8*gibU + 1, 1, false},
		{"one proc over", gibU, 33, false},
		{"unknown group", gibU, 1, false},
	} {
		pg := childPID
		if c.name == "unknown group" {
			pg = 777
		}
		if _, ok := r.Within(pg, c.bytes, c.procs); ok != c.within {
			t.Errorf("%s: within=%v", c.name, ok)
		}
	}
}

func TestMissingDirIsEmpty(t *testing.T) {
	r, err := Load(Config{Dir: filepath.Join(t.TempDir(), "none")}, baseFacts())
	if err != nil || len(r.Budgets) != 0 {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestHostileEntriesInDir(t *testing.T) {
	skipOnWindows(t)
	e := newEnv(t)
	os.Mkdir(filepath.Join(e.dir, "4300.json"), 0o700) // a directory named like a sidecar
	e.put(t, "garbage.json", "{", 0o600)
	r := e.load(t)
	if _, ok := r.Budgets[childPID]; !ok {
		t.Error("genuine sidecar lost among hostile entries")
	}
	if len(r.Rejected) != 2 {
		t.Errorf("rejected: %+v", r.Rejected)
	}
}

func readFixture(t *testing.T) string {
	b, err := os.ReadFile("testdata/run_capped/4242.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// skipOnWindows: sidecars name a unix run_capped wrapper script and process
// ancestry; the budget feature is not offered on Windows.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("budget sidecars need the unix run_capped wrapper")
	}
}
