package resmon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/attrib"
	"github.com/ericmacdougall/netwatch/internal/incident"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
	"github.com/ericmacdougall/netwatch/internal/watcher"
)

// annFake adds environments and working directories to the fake reader.
type annFake struct {
	*fake
	env map[int]map[string]string
	cwd map[int]string
}

func (a annFake) Env(pid int, keys ...string) map[string]string {
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
