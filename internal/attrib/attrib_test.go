package attrib

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

func TestClaudeFromExe(t *testing.T) {
	yes := map[string]string{
		"/home/user/.local/share/claude/versions/2.1.318":             "2.1.318",
		"/Users/user/.local/share/claude/versions/2.1.318/bin/claude": "2.1.318",
		"/opt/claude/versions/3.0.0-beta.1":                           "3.0.0-beta.1",
	}
	for exe, ver := range yes {
		if got, ok := ClaudeFromExe(exe); !ok || got != ver {
			t.Errorf("ClaudeFromExe(%q) = %q, %v", exe, got, ok)
		}
	}
	no := []string{
		"", "claude", "versions/2.1.318",
		"/tmp/evil/2.1.318",                                                       // version-shaped name, wrong directory
		"/usr/local/bin/claude",                                                   // name alone is not identity
		"/home/user/claude/versions/latest",                                       // not a version
		"/home/user/claude/versions/2.1",                                          // not semver
		"/home/user/claude/versions/2.1.318/../../x",                              // not a clean path
		"/home/user/claude/versions",                                              // no version segment
		"/home/user/notclaude/versions/2.1.318",                                   // segment must be exactly claude
		"/Users/user/Library/Application Support/Claude/claude-code/2.0.5/claude", // unverified layout
	}
	for _, exe := range no {
		if v, ok := ClaudeFromExe(exe); ok {
			t.Errorf("ClaudeFromExe(%q) = %q, want not Claude", exe, v)
		}
	}
}

// CR-9: a process whose comm is a version string but whose exe is elsewhere
// is not Claude. The naive variant (comm decides) classifies it as Claude.
func TestCR9CommLooksLikeVersionButExeElsewhere(t *testing.T) {
	r := NewResolver(16)
	fake := resources.Proc{PID: 500, Start: time.Unix(1000, 0), Name: "2.1.318", Exe: "/tmp/evil/2.1.318", PPID: 1}
	in := r.Classify(fake, map[int]resources.Proc{500: fake})
	if in.Claude {
		t.Fatal("process named 2.1.318 with a foreign exe was treated as Claude")
	}
	if !in.Hint {
		t.Fatal("the comm hint should still be reported")
	}
	real := resources.Proc{PID: 501, Start: time.Unix(1000, 0), Name: "2.1.318", Exe: "/home/user/.local/share/claude/versions/2.1.318", PPID: 1}
	if in := r.Classify(real, nil); !in.Claude || in.Version != "2.1.318" || in.ClaudePID != 501 {
		t.Fatalf("real claude: %+v", in)
	}
}

func chain() map[int]resources.Proc {
	mk := func(pid, ppid int, exe string) resources.Proc {
		return resources.Proc{PID: pid, PPID: ppid, Exe: exe, Name: filepath.Base(exe), Start: time.Unix(int64(pid), 0)}
	}
	ps := []resources.Proc{
		mk(1, 0, "/sbin/launchd"),
		mk(10, 1, "/Applications/Cursor.app/Contents/MacOS/Cursor"),
		mk(20, 10, "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper"),
		mk(30, 20, "/bin/zsh"),
		mk(40, 30, "/home/user/.local/share/claude/versions/2.1.318"),
		mk(50, 40, "/bin/bash"),
		mk(60, 50, "/usr/bin/sleep"),
		mk(70, 1, "/usr/bin/tmux"),
		mk(80, 70, "/bin/zsh"),
		mk(90, 80, "/usr/bin/python3"),
	}
	m := map[int]resources.Proc{}
	for _, p := range ps {
		m[p.PID] = p
	}
	return m
}

func TestOwnerAndClaudeAncestor(t *testing.T) {
	tbl := chain()
	r := NewResolver(16)
	in := r.Classify(tbl[60], tbl)
	if in.Owner != "Cursor" || in.ClaudePID != 40 || in.Claude {
		t.Fatalf("%+v", in)
	}
	// No bundle in the chain: owner is the top ancestor below pid 1.
	if in := r.Classify(tbl[90], tbl); in.Owner != "tmux" || in.ClaudePID != 0 {
		t.Fatalf("%+v", in)
	}
}

func TestWalkStopsAtInitAndCycles(t *testing.T) {
	a := resources.Proc{PID: 5, PPID: 6, Exe: "/x/a"}
	b := resources.Proc{PID: 6, PPID: 5, Exe: "/x/b"}
	tbl := map[int]resources.Proc{5: a, 6: b}
	done := make(chan Info, 1)
	go func() { done <- NewResolver(4).Classify(a, tbl) }()
	select {
	case in := <-done:
		if in.Owner != "b" {
			t.Fatalf("%+v", in)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent walk looped on a cycle")
	}
}

func TestLRUKeyedByPidAndStart(t *testing.T) {
	r := NewResolver(2)
	p := func(pid int, start int64, exe string) resources.Proc {
		return resources.Proc{PID: pid, Start: time.Unix(start, 0), Exe: exe}
	}
	old := p(7, 100, "/home/user/.local/share/claude/versions/1.0.0")
	if !r.Classify(old, nil).Claude {
		t.Fatal("setup")
	}
	// The same pid reused by a different process must not hit the old entry.
	reused := p(7, 200, "/bin/ls")
	if in := r.Classify(reused, nil); in.Claude {
		t.Fatal("pid reuse served a stale cache entry")
	}
	if r.Len() != 2 {
		t.Fatalf("len %d", r.Len())
	}
	// Capacity 2: a third entry evicts the least recently used one.
	r.Classify(old, nil) // touch old, so reused is now the oldest
	r.Classify(p(8, 300, "/bin/cat"), nil)
	if r.Len() != 2 {
		t.Fatalf("len after eviction %d", r.Len())
	}
	r.mu.Lock()
	_, hasOld := r.m[key{7, old.Start.UnixNano()}]
	_, hasReused := r.m[key{7, reused.Start.UnixNano()}]
	r.mu.Unlock()
	if !hasOld || hasReused {
		t.Fatalf("LRU evicted the wrong entry: old=%v reused=%v", hasOld, hasReused)
	}
}

func TestCommandLineRedactedAndTruncated(t *testing.T) {
	got := CommandLine([]string{"curl", "--token=abc123secret", "https://u:pw@example.com/x"}, 200)
	if strings.Contains(got, "abc123secret") || strings.Contains(got, ":pw@") {
		t.Fatalf("secret leaked: %q", got)
	}
	long := CommandLine([]string{strings.Repeat("a", 500)}, 40)
	if n := len([]rune(long)); n != 40 {
		t.Fatalf("len %d", n)
	}
	if got := CommandLine([]string{"a\x1b[2Jb"}, 50); strings.ContainsRune(got, 0x1b) {
		t.Fatal("control character kept")
	}
}

func walLine(at time.Time, agent string) string {
	a := "null"
	if agent != "" {
		a = fmt.Sprintf("%q", agent)
	}
	return fmt.Sprintf(`{"at":%q,"event":"pretool","agent_id":%s,"tool":"Bash","tool_use_id":"t","target_chars":5}`+"\n", at.Format(time.RFC3339Nano), a)
}

func writeWAL(t *testing.T, root, session, name string, lines ...string) {
	t.Helper()
	d := filepath.Join(root, session)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, name), []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLabelMatchesPretoolByStartTime(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	writeWAL(t, root, "sess-1", "main.jsonl",
		walLine(base, ""),
		walLine(base.Add(60*time.Second), ""),
		`{"at":"`+base.Add(30*time.Second).Format(time.RFC3339Nano)+`","event":"posttool","tool":"Bash"}`+"\n")
	writeWAL(t, root, "sess-1", "agent-abc.jsonl", walLine(base.Add(20*time.Second), "abc"))
	l := &Labeler{FS: DirReader{Root: root}}

	if got := l.Label("sess-1", base.Add(400*time.Millisecond)); got.Agent != "main" || got.Confidence < 0.8 {
		t.Fatalf("main: %+v", got)
	}
	if got := l.Label("sess-1", base.Add(20*time.Second+300*time.Millisecond)); got.Agent != "agent:abc" || got.Confidence < 0.8 {
		t.Fatalf("subagent: %+v", got)
	}
	// Nothing near this start time: no label, zero confidence.
	if got := l.Label("sess-1", base.Add(40*time.Second)); got.Agent != "" || got.Confidence != 0 {
		t.Fatalf("unmatched: %+v", got)
	}
	// Two agents ran a tool within the same window: low confidence.
	writeWAL(t, root, "sess-2", "main.jsonl", walLine(base, ""))
	writeWAL(t, root, "sess-2", "agent-x.jsonl", walLine(base.Add(100*time.Millisecond), "x"))
	if got := l.Label("sess-2", base.Add(500*time.Millisecond)); got.Agent == "" || got.Confidence >= 0.5 {
		t.Fatalf("ambiguous: %+v", got)
	}
}

func TestLabelRejectsHostileInput(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	l := &Labeler{FS: DirReader{Root: root}}
	for _, s := range []string{"", "..", "../x", "a/b", "/etc", strings.Repeat("a", 65), "a b"} {
		if got := l.Label(s, base); got != (Label{}) {
			t.Errorf("session %q produced %+v", s, got)
		}
	}
	// A symlinked WAL file is not followed.
	// (Windows has no O_NOFOLLOW; WAL labelling reads Claude Code hook logs
	// on macOS and Linux, so the symlink control is unix-only.)
	if runtime.GOOS != "windows" {
		writeWAL(t, root, "sess", "other.jsonl", walLine(base, "evil"))
		if err := os.Symlink(filepath.Join(root, "sess", "other.jsonl"), filepath.Join(root, "sess", "main.jsonl")); err != nil {
			t.Fatal(err)
		}
		if got := l.Label("sess", base.Add(time.Second)); got != (Label{}) {
			t.Fatalf("symlink followed: %+v", got)
		}
	}
	// An oversize line and garbage are skipped, not fatal.
	writeWAL(t, root, "sess2", "main.jsonl", strings.Repeat("x", 100000)+"\n", "not json\n", walLine(base, ""))
	if got := l.Label("sess2", base.Add(time.Second)); got.Agent != "main" {
		t.Fatalf("after junk: %+v", got)
	}
}

func TestDirReaderBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte(strings.Repeat("0123456789", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := DirReader{Root: root}.Tail("f", 25)
	if want := strings.Repeat("0123456789", 100)[975:]; err != nil || string(b) != want {
		t.Fatalf("tail %q %v", b, err)
	}
	if _, err := (DirReader{Root: root}).Tail("../f", 10); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := (DirReader{Root: root}).Tail(root, 10); err == nil {
		t.Fatal("absolute path accepted")
	}
}

// A busy session has hundreds of agent WAL files (598 in the live run that
// found this). The labeler must read the recently written ones, not the
// first 64 in directory order.
func TestLabelFindsRecentAgentAmongManyFiles(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	old := base.Add(-24 * time.Hour)
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf("agent-a%03d.jsonl", i)
		writeWAL(t, root, "busy", name, walLine(old, fmt.Sprintf("a%03d", i)))
		if err := os.Chtimes(filepath.Join(root, "busy", name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	// Sorts last by name, so directory order alone puts it past 64.
	writeWAL(t, root, "busy", "agent-zzz.jsonl", walLine(base, "zzz"))
	l := &Labeler{FS: DirReader{Root: root}}
	if got := l.Label("busy", base.Add(300*time.Millisecond)); got.Agent != "agent:zzz" {
		t.Fatalf("recent agent file not read: %+v", got)
	}
}

// An agent_id that is not an id is never copied into a label.
func TestLabelRejectsMalformedAgentID(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	writeWAL(t, root, "s", "main.jsonl", walLine(base, "bad id/../x"))
	l := &Labeler{FS: DirReader{Root: root}}
	if got := l.Label("s", base.Add(100*time.Millisecond)); got.Agent != "" {
		t.Fatalf("malformed agent id labelled: %+v", got)
	}
}
