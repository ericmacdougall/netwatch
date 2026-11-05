package resmon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/guard"
	"github.com/ericmacdougall/netwatch/internal/incident"
	"github.com/ericmacdougall/netwatch/internal/jetsam"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// annFake adds environments and working directories to the fake reader.
type annFake struct {
	*fake
	env   map[int]map[string]string
	cwd   map[int]string
	reads *int
}

func (a annFake) Env(pid int, keys ...string) map[string]string {
	if a.reads != nil {
		*a.reads++
	}
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := a.env[pid][k]; ok {
			out[k] = v
		}
	}
	return out
}
func (a annFake) Cwd(pid int) string { return a.cwd[pid] }

// AC-1/AC-2: a tool-shell job's sample rows carry every attribution field:
// owner app Claude Code, its Claude root, the session, the agent label
// with a confidence level, sid, uid and a cwd relative to the root.
func TestSampleRowsCarryAttribution(t *testing.T) {
	const claudeExe = "/home/u/.local/share/claude/versions/2.1.318"
	f := newFake()
	f.procs[1] = &resources.Proc{PID: 1, Name: "launchd", Exe: "/sbin/launchd", Start: t0.Add(-time.Hour), FootprintOK: true}
	f.procs[90] = &resources.Proc{PID: 90, PPID: 1, PGID: 90, SID: 90, UID: 501, Name: "Terminal",
		Exe: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Start: t0.Add(-time.Hour), FootprintOK: true, HasTTY: true}
	f.procs[100] = &resources.Proc{PID: 100, PPID: 90, PGID: 100, SID: 90, UID: 501, Name: "2.1.318", Exe: claudeExe,
		Start: t0.Add(-30 * time.Minute), Footprint: 500 << 20, FootprintOK: true, HasTTY: true}
	shellStart := t0.Add(-10 * time.Second)
	f.procs[200] = &resources.Proc{PID: 200, PPID: 100, PGID: 200, SID: 200, UID: 501, Name: "bash", Exe: "/bin/bash",
		Start: shellStart, Footprint: 4 << 20, FootprintOK: true}
	f.procs[201] = &resources.Proc{PID: 201, PPID: 200, PGID: 200, SID: 200, UID: 501, Name: "python3", Exe: "/usr/bin/python3",
		Start: shellStart.Add(50 * time.Millisecond), Footprint: 1 << 30, FootprintOK: true}
	env := map[string]string{"CLAUDECODE": "1", "CLAUDE_PID": "100", "CLAUDE_CODE_SESSION_ID": "sess-1"}
	// The leader is a platform shell whose environment macOS hides: only
	// the python member's environment is readable.
	rd := annFake{fake: f, env: map[int]map[string]string{201: env},
		cwd: map[int]string{100: "/home/u/proj", 201: "/home/u/proj/sub", 90: "/home/u"}}

	walRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(walRoot, "sess-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"at":"` + shellStart.Add(-200*time.Millisecond).Format(time.RFC3339Nano) + `","event":"pretool","tool":"Bash","agent_id":"abc"}` + "\n"
	if err := os.WriteFile(filepath.Join(walRoot, "sess-1", "agent-abc.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	scan, _ := f.Procs()
	recs := []watcher.Record{{PID: 200, Start: shellStart, ClaudePID: 100, ClaudeStart: f.procs[100].Start,
		State: watcher.Classified, Exe: "/bin/bash", FirstSeen: t0}}
	e := &Elig{R: rd, SelfPID: 9999, UID: 501, Home: "/home/u",
		Labeler: &attrib.Labeler{FS: attrib.DirReader{Root: walRoot}}}
	cls := e.Classify(scan, recs, nil)
	if cls.Annotate == nil {
		t.Fatal("no annotator")
	}
	sys := resources.System{}
	rec := sampler.New(rd, 10).From(sys, scan, t0)
	cls.Annotate(rec.TopMem)

	var row *sampler.Row
	for i := range rec.TopMem {
		if rec.TopMem[i].PID == 201 {
			row = &rec.TopMem[i]
		}
	}
	if row == nil {
		t.Fatalf("allocator not in top_mem: %+v", rec.TopMem)
	}
	if row.OwnerApp != ClaudeOwner || row.AgentRoot != 100 || row.Session != "sess-1" ||
		row.Agent != "agent:abc" || row.Confidence != "high" || row.SID != 200 || row.UID != 501 || row.Cwd != "./sub" {
		t.Fatalf("row attribution: %+v", *row)
	}

	// Every Scope field is present in the JSON line, even when empty.
	b, err := rec.Line()
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		TopMem []map[string]json.RawMessage `json:"top_mem"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, r := range raw.TopMem {
		for _, k := range []string{"pid", "ppid", "pgid", "sid", "uid", "start", "name", "cmd", "cwd",
			"owner_app", "agent", "agent_root", "confidence", "session"} {
			if _, ok := r[k]; !ok {
				t.Errorf("row %s lacks %q", r["pid"], k)
			}
		}
	}

	// incident reads the same line back with the label (it parsed
	// confidence as a string while the sampler wrote a number).
	dir := t.TempDir()
	path := filepath.Join(dir, "resources.jsonl")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	ss, err := incident.ReadSamples(path, t0.Add(-time.Minute), t0.Add(time.Minute))
	if err != nil || len(ss) != 1 {
		t.Fatalf("incident read %d samples (%v)", len(ss), err)
	}
	found := false
	for _, p := range ss[0].Top {
		if p.PID == 201 && p.Agent == "agent:abc" && p.Confidence == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("incident lost the label: %+v", ss[0].Top)
	}
}

func TestRelCwd(t *testing.T) {
	for _, c := range []struct{ cwd, root, home, want string }{
		{"/h/p", "/h/p", "/h", "."},
		{"/h/p/x", "/h/p", "/h", "./x"},
		{"/h/px", "/h/p", "/h", "~/px"},
		{"/h", "", "/h", "~"},
		{"/tmp/a", "", "/h", "/tmp/a"},
		{"", "/h/p", "/h", ""},
		{"/x", "/", "/", "/x"},
	} {
		if got := relCwd(c.cwd, c.root, c.home); got != c.want {
			t.Errorf("relCwd(%q,%q,%q)=%q want %q", c.cwd, c.root, c.home, got, c.want)
		}
	}
}

// Growth alerts from guard groups carry the job, app and agent, and the
// classifier names a process's app and agent.
func TestAlertSeriesAndWhoNameTheJob(t *testing.T) {
	g := &guard.Group{PGID: 200, Cmd: "python3 job.py", Agent: "agent:abc"}
	ss := alertSeries([]guard.Term{{Key: "pg:200:1", Group: g}, {Key: "inel:Google Chrome"}, {Key: "unattributed"}})
	if len(ss) != 2 {
		t.Fatalf("series: %+v", ss)
	}
	for _, s := range ss {
		if s.Key == "pg:200:1" && (s.Name != "python3 job.py" || s.App != ClaudeOwner || s.Agent != "agent:abc") {
			t.Fatalf("group series: %+v", s)
		}
	}
	const claudeExe = "/home/u/.local/share/claude/versions/2.1.318"
	scan := []resources.Proc{
		{PID: 100, PPID: 1, PGID: 100, Exe: claudeExe, Name: "2.1.318"},
		{PID: 201, PPID: 100, PGID: 200, Exe: "/usr/bin/python3", Name: "python3"},
	}
	e := &Elig{resolver: attrib.NewResolver(16)}
	who := e.whoFunc(scan, map[int]groupLabel{200: {label: attrib.Label{Agent: "agent:abc", Confidence: 0.9}}})
	if app, agent := who(scan[1]); app != ClaudeOwner || agent != "agent:abc" {
		t.Fatalf("who: %q %q", app, agent)
	}
}

// A group whose session cannot be read is looked up on a bounded number
// of scans, then "unknown" is cached (code-inspection r4 F2).
func TestUnknownSessionIsNotReadEveryScan(t *testing.T) {
	const claudeExe = "/home/u/.local/share/claude/versions/2.1.318"
	f := newFake()
	f.procs[1] = &resources.Proc{PID: 1, Name: "launchd", Exe: "/sbin/launchd", Start: t0.Add(-time.Hour), FootprintOK: true}
	f.procs[100] = &resources.Proc{PID: 100, PPID: 1, PGID: 100, SID: 100, UID: 501, Exe: claudeExe, Start: t0.Add(-time.Hour), FootprintOK: true}
	f.procs[200] = &resources.Proc{PID: 200, PPID: 100, PGID: 200, SID: 200, UID: 501, Exe: "/bin/zsh", Start: t0.Add(-time.Minute), FootprintOK: true}
	f.procs[201] = &resources.Proc{PID: 201, PPID: 200, PGID: 200, SID: 200, UID: 501, Exe: "/bin/sleep", Start: t0.Add(-time.Minute), FootprintOK: true}
	n := 0
	rd := annFake{fake: f, env: map[int]map[string]string{}, reads: &n}
	scan, _ := f.Procs()
	recs := []watcher.Record{{PID: 200, Start: f.procs[200].Start, ClaudePID: 100, ClaudeStart: f.procs[100].Start,
		State: watcher.Classified, Exe: "/bin/zsh", FirstSeen: t0}}
	e := &Elig{R: rd, SelfPID: 9999, UID: 501, Labeler: &attrib.Labeler{FS: attrib.DirReader{Root: t.TempDir()}}}
	var perScan []int
	for i := 0; i < 6; i++ {
		before := n
		cls := e.Classify(scan, recs, nil)
		if i == 0 && len(cls.Groups) == 0 {
			t.Fatal("setup: no group")
		}
		perScan = append(perScan, n-before)
	}
	// Eligibility reads environments every scan; the session lookup adds
	// reads only on the first sessionTries scans.
	if perScan[0] <= perScan[5] || perScan[sessionTries] != perScan[5] {
		t.Fatalf("env reads per scan %v: the session lookup must stop after %d scans", perScan, sessionTries)
	}
}

// Red-team F5: a jetsam report is parsed once, not on every scan. The
// second scan finds it in the seen set (a parse error would be reported
// through Errs if the file were read again).
func TestJetsamReportParsedOnce(t *testing.T) {
	dir := t.TempDir()
	src := "../jetsam/testdata/incident/JetsamEvent-2026-11-04-161829.ips"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip("fixture not present")
	}
	p := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var errs []string
	l := &Loop{d: Deps{JetsamDir: dir, Now: func() time.Time { return t0 },
		Errs: func(w string, e error) { errs = append(errs, w) }}}
	l.checkJetsam()
	if len(l.jetsamSeen) != 1 {
		t.Fatalf("report not marked seen: %v", l.jetsamSeen)
	}
	// Same name, size and mtime, but unparseable content: only a re-read
	// would notice.
	fi, _ := os.Stat(p)
	junk := make([]byte, fi.Size())
	if err := os.WriteFile(p, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, fi.ModTime(), fi.ModTime())
	l.jetsamAt = time.Time{} // force the same Since as the first scan
	before := jetsam.Parses()
	l.checkJetsam()
	if n := jetsam.Parses() - before; n != 0 {
		t.Fatalf("seen report parsed again (%d parses)", n)
	}
	if l.d5 {
		t.Fatal("history must not raise D5")
	}
	if len(l.jetsamSeen) != 1 {
		t.Fatalf("seen set changed: %v", l.jetsamSeen)
	}
}
