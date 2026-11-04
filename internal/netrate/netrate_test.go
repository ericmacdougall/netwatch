package netrate

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func snap(at time.Duration, procs map[Key]Counter) Snapshot {
	return Snapshot{At: t0.Add(at), Procs: procs, HasBytes: true}
}

func TestComputeRatesDeltasAndOrdering(t *testing.T) {
	a, b, c, gone := Key{"curl", 10}, Key{"node", 20}, Key{"idle", 30}, Key{"old", 40}
	prev := snap(0, map[Key]Counter{a: {In: 1000, Out: 0}, b: {In: 0, Out: 0}, c: {In: 5, Out: 5}, gone: {In: 9, Out: 9}})
	cur := snap(10*time.Second, map[Key]Counter{
		a: {In: 1000 + 102400, Out: 0}, // 10 kB/s in
		b: {In: 0, Out: 512000},        // 50 kB/s out
		c: {In: 5, Out: 5},             // idle: omitted
	})
	r := Compute(prev, cur)
	if len(r.Procs) != 2 {
		t.Fatalf("want 2 active procs, got %+v", r.Procs)
	}
	if r.Procs[0].Key != b || r.Procs[1].Key != a {
		t.Fatalf("not sorted by total: %+v", r.Procs)
	}
	if r.Procs[0].OutKBps != 50 || r.Procs[1].InKBps != 10 {
		t.Fatalf("bad rates: %+v", r.Procs)
	}
	if r.InKBps != 10 || r.OutKBps != 50 {
		t.Fatalf("bad totals: in %v out %v", r.InKBps, r.OutKBps)
	}
}

func TestComputeCounterResetIsZeroNotNegative(t *testing.T) {
	k := Key{"node", 1}
	prev := snap(0, map[Key]Counter{k: {In: 5000, Out: 5000}})
	cur := snap(time.Second, map[Key]Counter{k: {In: 100, Out: 6024}})
	r := Compute(prev, cur)
	if len(r.Procs) != 1 || r.Procs[0].InKBps != 0 || r.Procs[0].OutKBps != 1 {
		t.Fatalf("reset handling wrong: %+v", r.Procs)
	}
}

func TestComputeNewProcessCountsFromZeroAndTinyInterval(t *testing.T) {
	k := Key{"new", 7}
	prev := snap(0, map[Key]Counter{})
	cur := snap(0, map[Key]Counter{k: {In: 1024}}) // same timestamp: dt clamps to 0.1 s
	r := Compute(prev, cur)
	if len(r.Procs) != 1 || r.Procs[0].InKBps != 10 {
		t.Fatalf("want 10 kB/s with clamped dt, got %+v", r.Procs)
	}
}

func TestComputeInterfaceTotalsAndConnectionsOnly(t *testing.T) {
	k1, k2 := Key{"a", 1}, Key{"b", 2}
	prev := Snapshot{At: t0, Procs: map[Key]Counter{}, HasIf: true, IfIn: 0, IfOut: 0}
	cur := Snapshot{At: t0.Add(2 * time.Second), Procs: map[Key]Counter{k1: {Conns: 1}, k2: {Conns: 3}, {"c", 3}: {}},
		HasIf: true, IfIn: 4096, IfOut: 2048}
	r := Compute(prev, cur)
	if !r.HasIf || r.IfInKBps != 2 || r.IfOutKBps != 1 {
		t.Fatalf("bad interface rates: %+v", r)
	}
	if len(r.Procs) != 2 || r.Procs[0].Key != k2 {
		t.Fatalf("connection-only ranking wrong: %+v", r.Procs)
	}
}

func TestDetectorNewAppOncePerProcessAndFirstName(t *testing.T) {
	boot := Key{"Safari", 1}
	initial := snap(0, map[Key]Counter{boot: {}})
	// Two different executables share the (truncated) name "zoom".
	paths := map[int]string{3: "/apps/zoom", 4: "/opt/other/zoom"}
	d := NewDetector(initial, Identify{Exe: func(pid int) string { return paths[pid] }})

	slow, fast, fast2 := Key{"slow", 2}, Key{"zoom", 3}, Key{"zoom", 4}
	cur := snap(10*time.Second, map[Key]Counter{
		boot: {In: 1 << 30},
		slow: {In: 2 * 1024}, // 0.2 kB/s = 1.6 kbit/s, below threshold
		fast: {In: 100 * 1024},
	})
	got := d.Observe(cur, Compute(initial, cur), 50)
	if len(got) != 1 || got[0].Key != fast || !got[0].FirstName {
		t.Fatalf("want only zoom/3 as first-time name, got %+v", got)
	}
	next := snap(20*time.Second, map[Key]Counter{
		boot: {In: 1 << 31}, fast: {In: 200 * 1024}, fast2: {In: 100 * 1024},
		slow: {In: 2*1024 + 100*1024},
	})
	got = d.Observe(next, Compute(cur, next), 50)
	if len(got) != 2 {
		t.Fatalf("want slow (now fast) and zoom/4, got %+v", got)
	}
	for _, a := range got {
		if a.Key == fast2 && a.FirstName {
			t.Fatal("second zoom process must not be a first-time name")
		}
		if a.Key == fast {
			t.Fatal("zoom/3 reported twice")
		}
	}
}

func TestDetectorConnectionsWhenNoBytes(t *testing.T) {
	d := NewDetector(Snapshot{At: t0, Procs: map[Key]Counter{}}, Identify{})
	k := Key{"node.exe", 9}
	cur := Snapshot{At: t0.Add(10 * time.Second), Procs: map[Key]Counter{k: {Conns: 2}}}
	got := d.Observe(cur, Compute(Snapshot{At: t0}, cur), 50)
	if len(got) != 1 || got[0].Conns != 2 {
		t.Fatalf("connection-only process should come online: %+v", got)
	}
}

func TestDetectorForgetsLongGoneProcesses(t *testing.T) {
	k := Key{"a", 1}
	d := NewDetector(snap(0, map[Key]Counter{k: {}}), Identify{})
	empty := snap(0, map[Key]Counter{})
	for i := 0; i <= forgetAfter; i++ {
		d.Observe(empty, Rates{}, 50)
	}
	if d.Known() != 0 {
		t.Fatalf("process should be forgotten, still know %d", d.Known())
	}
}

// A tool that runs over and over gets a new PID each time; it is one app.
func TestDetectorReportsAnExecutableOnceAcrossPIDs(t *testing.T) {
	exe := func(pid int) string {
		if pid > 1000 {
			return "/usr/bin/git"
		}
		return ""
	}
	d := NewDetector(snap(0, map[Key]Counter{}), Identify{Exe: exe})
	prev := snap(0, map[Key]Counter{})
	events := 0
	for i := 1; i <= 20; i++ {
		// Each sample a fresh git PID moves traffic and the previous one is gone.
		cur := snap(time.Duration(i)*10*time.Second, map[Key]Counter{{"git", 1000 + i}: {In: 100 * 1024}})
		events += len(d.Observe(cur, Compute(prev, cur), 50))
		prev = cur
	}
	if events != 1 {
		t.Fatalf("20 runs of one executable gave %d NEW_NET_APP events, want 1", events)
	}
}

// Without a readable path, apps are told apart by name.
func TestDetectorFallsBackToNameWithoutPath(t *testing.T) {
	d := NewDetector(snap(0, map[Key]Counter{}), Identify{Exe: func(int) string { return "" }})
	cur := snap(10*time.Second, map[Key]Counter{{"curl", 7}: {In: 100 * 1024}, {"curl", 8}: {In: 100 * 1024}, {"ssh", 9}: {In: 100 * 1024}})
	got := d.Observe(cur, Compute(snap(0, nil), cur), 50)
	if len(got) != 2 {
		t.Fatalf("want one curl and one ssh event, got %+v", got)
	}
}

// An app that has been offline longer than the forget window is new again.
func TestDetectorReportsAppAgainAfterForgetWindow(t *testing.T) {
	d := NewDetector(snap(0, map[Key]Counter{}), Identify{Exe: func(int) string { return "/usr/bin/rsync" }})
	first := snap(10*time.Second, map[Key]Counter{{"rsync", 1}: {In: 100 * 1024}})
	if got := d.Observe(first, Compute(snap(0, nil), first), 50); len(got) != 1 {
		t.Fatalf("first run should be reported: %+v", got)
	}
	empty := snap(0, map[Key]Counter{})
	for i := 0; i <= forgetAfter; i++ {
		d.Observe(empty, Rates{}, 50)
	}
	again := snap(20*time.Second, map[Key]Counter{{"rsync", 2}: {In: 100 * 1024}})
	got := d.Observe(again, Compute(snap(10*time.Second, nil), again), 50)
	if len(got) != 1 || got[0].FirstName {
		t.Fatalf("returning app should be reported once, not as a first-time name: %+v", got)
	}
}

// Every python program shares the interpreter's path; each stays its own app.
func TestDetectorKeepsInterpretersPerProcess(t *testing.T) {
	exe := func(pid int) string {
		switch pid {
		case 1, 2:
			return "/usr/bin/python3.12"
		case 3, 4:
			return `C:\Program Files\nodejs\node.exe`
		}
		return ""
	}
	// No command lines (as on Windows): each interpreter process is its own app.
	d := NewDetector(snap(0, map[Key]Counter{{"python3", 1}: {}}), Identify{Exe: exe})
	cur := snap(10*time.Second, map[Key]Counter{
		{"python3", 1}: {In: 1 << 20}, {"python3", 2}: {In: 100 * 1024},
		{"node.exe", 3}: {In: 100 * 1024}, {"node.exe", 4}: {In: 100 * 1024},
		{"ruby", 5}: {In: 100 * 1024}, {"ruby", 6}: {In: 100 * 1024}, // unreadable path, interpreter name
	})
	got := d.Observe(cur, Compute(snap(0, map[Key]Counter{{"python3", 1}: {}}), cur), 50)
	if len(got) != 5 {
		t.Fatalf("want python3/2, both node.exe and both ruby reported, got %+v", got)
	}
}

// After a restart, the seeded processes' executables count as already online.
func TestDetectorSeedsByExecutable(t *testing.T) {
	initial := snap(0, map[Key]Counter{{"git", 1}: {}})
	d := NewDetector(initial, Identify{Exe: func(int) string { return "/usr/bin/git" }})
	cur := snap(10*time.Second, map[Key]Counter{{"git", 2}: {In: 100 * 1024}})
	if got := d.Observe(cur, Compute(initial, cur), 50); len(got) != 0 {
		t.Fatalf("a new PID of a seeded executable is not new: %+v", got)
	}
}

// The suppression window is exactly forgetAfter samples since last seen.
func TestDetectorForgetBoundary(t *testing.T) {
	for _, tc := range []struct {
		idle int
		want int
	}{{forgetAfter - 1, 0}, {forgetAfter, 1}} {
		d := NewDetector(snap(0, map[Key]Counter{}), Identify{Exe: func(int) string { return "/usr/bin/rsync" }})
		first := snap(10*time.Second, map[Key]Counter{{"rsync", 1}: {In: 100 * 1024}})
		d.Observe(first, Compute(snap(0, nil), first), 50)
		empty := snap(0, map[Key]Counter{})
		for i := 0; i < tc.idle; i++ {
			d.Observe(empty, Rates{}, 50)
		}
		again := snap(20*time.Second, map[Key]Counter{{"rsync", 2}: {In: 100 * 1024}})
		if got := d.Observe(again, Compute(snap(10*time.Second, nil), again), 50); len(got) != tc.want {
			t.Fatalf("after %d idle samples got %d events, want %d", tc.idle, len(got), tc.want)
		}
	}
}

// Test workers of one runner share a script; a different script is a new app.
func TestDetectorIdentifiesInterpreterByProgram(t *testing.T) {
	args := map[int][]string{
		1: {"node", "/repo/node_modules/vitest/dist/workers/forks.js"},
		2: {"node", "--max-old-space-size=4096", "/repo/node_modules/vitest/dist/workers/forks.js"},
		3: {"node", "/repo/server.js"},
		4: {"python3", "-m", "http.server"},
		5: {"python3", "-m", "http.server", "9000"},
		6: {"node"}, // no program: stays per process
		7: {"node"},
	}
	id := Identify{
		Exe: func(pid int) string {
			if pid >= 4 && pid <= 5 {
				return "/usr/bin/python3.12"
			}
			return "/usr/bin/node"
		},
		Args: func(pid int) []string { return args[pid] },
	}
	d := NewDetector(snap(0, map[Key]Counter{}), id)
	procs := map[Key]Counter{}
	for pid := range args {
		procs[Key{"node", pid}] = Counter{In: 100 * 1024}
	}
	cur := snap(10*time.Second, procs)
	got := d.Observe(cur, Compute(snap(0, nil), cur), 50)
	if len(got) != 5 {
		t.Fatalf("want forks.js once, server.js, http.server once, and both bare nodes; got %d: %+v", len(got), got)
	}
}

func TestProgramArg(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"node", "app.js"}, "app.js"},
		{[]string{"node", "--inspect", "-r", "ts-node/register", "app.ts"}, "app.ts"},
		{[]string{"python3", "-u", "-m", "pip", "install"}, "-m pip"},
		{[]string{"java", "-cp", "a.jar", "Main"}, "Main"},
		{[]string{"java", "-jar", "app.jar"}, "-jar app.jar"},
		{[]string{"bash", "-c", "sleep 1"}, "-c sleep 1"},
		{[]string{"node"}, ""},
		{nil, ""},
	} {
		if got := programArg(tc.args); got != tc.want {
			t.Errorf("programArg(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
	if got := programArg([]string{"sh", "-c", strings.Repeat("x", 1000)}); len(got) != maxProgram {
		t.Errorf("long program not truncated: %d bytes", len(got))
	}
}

// The same script name under different runtimes is two apps.
func TestDetectorProgramKeyIncludesRuntime(t *testing.T) {
	id := Identify{
		Exe: func(pid int) string {
			if pid == 1 {
				return "/usr/bin/python3"
			}
			return "/usr/bin/node"
		},
		Args: func(pid int) []string { return []string{"x", "main.js"} },
	}
	d := NewDetector(snap(0, map[Key]Counter{}), id)
	cur := snap(10*time.Second, map[Key]Counter{{"python3", 1}: {In: 100 * 1024}, {"node", 2}: {In: 100 * 1024}})
	if got := d.Observe(cur, Compute(snap(0, nil), cur), 50); len(got) != 2 {
		t.Fatalf("python and node running main.js are different apps: %+v", got)
	}
}
