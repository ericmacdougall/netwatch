//go:build !windows

package transcript

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	sess  = "11111111-2222-4333-8444-555555555555"
	sess2 = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	// Assembled so secret scanners do not flag the fixture.
	fakeToken = "abc123" + "def456ghi"
)

func line(ts, session, agent, name, cmd string) string {
	m := map[string]any{
		"timestamp": ts, "sessionId": session, "type": "assistant",
		"message": map[string]any{"content": []any{
			map[string]any{"type": "text", "text": "hello"},
			map[string]any{"type": "tool_use", "id": "toolu_01ABC", "name": name, "input": map[string]any{"command": cmd}},
		}},
	}
	if agent != "" {
		m["agentId"] = agent
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func put(t *testing.T, path string, mtime time.Time, lines ...string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, mtime, mtime)
}

func TestParseLine(t *testing.T) {
	cmd := "curl -H 'Authorization: Bearer " + fakeToken + "' https://example.com"
	cs := ParseLine([]byte(line("2026-11-04T16:06:32.197Z", sess, "aabbcc112233", "Bash", cmd)))
	if len(cs) != 1 {
		t.Fatalf("calls: %+v", cs)
	}
	c := cs[0]
	if !c.At.Equal(time.Date(2026, 11, 4, 16, 6, 32, 197000000, time.UTC)) || c.AgentID != "aabbcc112233" || c.SessionID != sess {
		t.Errorf("fields: %+v", c)
	}
	if c.SHA256 != Hash(cmd) || c.Len != len(cmd) {
		t.Errorf("hash/len: %+v", c)
	}
	if strings.Contains(c.Redacted, fakeToken) {
		t.Errorf("secret survived redaction: %q", c.Redacted)
	}
	js, _ := json.Marshal(c)
	if strings.Contains(string(js), fakeToken) {
		t.Errorf("raw command leaked into JSON: %s", js)
	}
	long := strings.Repeat("echo hello; ", 100)
	if r := []rune(ParseLine([]byte(line("2026-11-04T16:06:32Z", sess, "", "Bash", long)))[0].Redacted); len(r) > maxRedactedRunes+3 {
		t.Errorf("not truncated: %d", len(r))
	}
}

func TestParseLineRejects(t *testing.T) {
	cases := map[string]string{
		"not json":          "{nope",
		"other tool":        line("2026-11-04T16:06:32Z", sess, "", "Read", "x"),
		"empty command":     line("2026-11-04T16:06:32Z", sess, "", "Bash", ""),
		"bad session id":    line("2026-11-04T16:06:32Z", "../x", "", "Bash", "ls"),
		"bad timestamp":     line("yesterday", sess, "", "Bash", "ls"),
		"string content":    `{"timestamp":"2026-11-04T16:06:32Z","sessionId":"` + sess + `","message":{"content":"Bash"}}`,
		"null message":      `{"timestamp":"2026-11-04T16:06:32Z","sessionId":"` + sess + `","message":null}`,
		"content is object": `{"timestamp":"2026-11-04T16:06:32Z","sessionId":"` + sess + `","message":{"content":{"type":"tool_use"}}}`,
		"deep":              strings.Repeat("[", 100000),
	}
	for n, in := range cases {
		if cs := ParseLine([]byte(in)); len(cs) != 0 {
			t.Errorf("%s: accepted %+v", n, cs)
		}
	}
	// A bad agent id is dropped, the call kept.
	cs := ParseLine([]byte(line("2026-11-04T16:06:32Z", sess, "../etc", "Bash", "ls")))
	if len(cs) != 1 || cs[0].AgentID != "" {
		t.Errorf("bad agent id: %+v", cs)
	}
	// One odd content item does not hide a valid one.
	odd := `{"timestamp":"2026-11-04T16:06:32Z","sessionId":"` + sess + `","message":{"content":[{"type":"tool_use","name":5},{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}`
	if cs := ParseLine([]byte(odd)); len(cs) != 1 {
		t.Errorf("odd item hid the valid one: %+v", cs)
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add([]byte(line("2026-11-04T16:06:32Z", sess, "ab", "Bash", "ls")))
	f.Add([]byte(`{"message":{"content":[`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, c := range ParseLine(b) {
			if c.SHA256 == "" || c.SessionID == "" || c.At.IsZero() {
				t.Fatalf("incomplete call %+v", c)
			}
		}
	})
}

func TestScanLayoutAndBounds(t *testing.T) {
	root := filepath.Join(t.TempDir(), "projects")
	now := time.Date(2026, 11, 4, 17, 0, 0, 0, time.UTC)
	t0 := "2026-11-04T16:06:32Z"
	put(t, filepath.Join(root, "-proj-a", sess+".jsonl"), now, line(t0, sess, "", "Bash", "make test"), "garbage {", line("2026-11-04T16:06:40Z", sess, "", "Read", "x"))
	put(t, filepath.Join(root, "-proj-a", sess, "subagents", "agent-aabbcc.jsonl"), now.Add(-time.Minute), line(t0, sess, "aabbcc", "Bash", "make lint"))
	put(t, filepath.Join(root, "-proj-b", sess2+".jsonl"), now.Add(-48*time.Hour), line(t0, sess2, "", "Bash", "old file"))

	cs, st, err := Scan(Config{Root: root, WindowStart: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || st.FilesRead != 2 || st.FilesOld != 1 {
		t.Fatalf("calls=%d stats=%+v", len(cs), st)
	}
	var sub *Call
	for i := range cs {
		if cs[i].AgentID == "aabbcc" {
			sub = &cs[i]
		}
	}
	if sub == nil || sub.File != "agent-aabbcc.jsonl" {
		t.Errorf("subagent call missing: %+v", cs)
	}

	t.Run("file count cap keeps the newest", func(t *testing.T) {
		cs, st, _ := Scan(Config{Root: root, WindowStart: now.Add(-100 * time.Hour), MaxFiles: 1})
		if len(cs) != 1 || cs[0].Redacted != "make test" || st.FilesOverCap != 2 {
			t.Errorf("%+v %+v", cs, st)
		}
	})
	t.Run("byte cap reads only the tail", func(t *testing.T) {
		p := filepath.Join(root, "-proj-c", sess+".jsonl")
		put(t, p, now, line("2026-11-04T10:00:00Z", sess, "", "Bash", "early"), line("2026-11-04T16:00:00Z", sess, "", "Bash", "late"))
		cs, _, _ := Scan(Config{Root: filepath.Join(root, "..", "projects"), WindowStart: now.Add(-time.Hour), MaxFileBytes: int64(len(line("2026-11-04T16:00:00Z", sess, "", "Bash", "late")) + 5)})
		for _, c := range cs {
			if c.Redacted == "early" {
				t.Error("read past the byte cap")
			}
		}
	})
	t.Run("line cap", func(t *testing.T) {
		p := filepath.Join(root, "-proj-d", sess+".jsonl")
		put(t, p, now, line(t0, sess, "", "Bash", strings.Repeat("x", 5000)))
		cs, _, _ := Scan(Config{Root: filepath.Join(root, "-proj-d", ".."), WindowStart: now.Add(-time.Hour), MaxLine: 1000})
		for _, c := range cs {
			if c.Len == 5000 {
				t.Error("over-long line was parsed")
			}
		}
	})
}

func TestScanHostileEntries(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	good := filepath.Join(root, "-p", sess+".jsonl")
	put(t, good, now, line("2026-11-04T16:06:32Z", sess, "", "Bash", "ok"))
	if err := syscall.Mkfifo(filepath.Join(root, "-p", sess2+".jsonl"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Symlink(good, filepath.Join(root, "-p", "link.jsonl"))
	os.Symlink(filepath.Join(root, "-p"), filepath.Join(root, "-linkproj"))
	os.MkdirAll(filepath.Join(root, "-p", "not-a-uuid", "subagents"), 0o700)
	put(t, filepath.Join(root, "-p", "not-a-uuid", "subagents", "agent-x.jsonl"), now, line("2026-11-04T16:06:33Z", sess, "x", "Bash", "should not be read"))
	done := make(chan []Call)
	go func() {
		cs, _, _ := Scan(Config{Root: root, WindowStart: now.Add(-time.Hour)})
		done <- cs
	}()
	select {
	case cs := <-done:
		if len(cs) != 1 || cs[0].Redacted != "ok" {
			t.Errorf("calls: %+v", cs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Scan blocked")
	}
	if cs, _, err := Scan(Config{Root: filepath.Join(root, "missing")}); err != nil || len(cs) != 0 {
		t.Errorf("missing root: %v %v", cs, err)
	}
}

func TestDefaultRootUsesHome(t *testing.T) {
	t.Setenv("HOME", "/home/user")
	r, err := DefaultRoot()
	if err != nil || r != "/home/user/.claude/projects" {
		t.Errorf("%q %v", r, err)
	}
}

func TestManyFilesStayBounded(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	for i := 0; i < 30; i++ {
		put(t, filepath.Join(root, "-p", fmt.Sprintf("%08d-2222-4333-8444-555555555555.jsonl", i)), now.Add(time.Duration(i)*time.Second), line("2026-11-04T16:06:32Z", sess, "", "Bash", fmt.Sprint("c", i)))
	}
	cs, st, _ := Scan(Config{Root: root, WindowStart: now.Add(-time.Hour), MaxFiles: 5})
	if len(cs) != 5 || st.FilesRead != 5 {
		t.Errorf("%d %+v", len(cs), st)
	}
}

func TestPrograms(t *testing.T) {
	cases := map[string][]string{
		"python3.12 big.py --n 5":                             {"python", "big"},
		"python -m pkg.sub.mod arg":                           {"python", "pkg"},
		"cd /x && FOO=1 /usr/bin/Python3 run.py; ls | grep a": {"cd", "python", "run", "ls", "grep"},
		"sudo -u bob nohup node server.js &":                  {"node", "server"},
		"timeout 30 env A=b make test":                        {"make"},
		"bash -c 'python3 inner.py && rm x'":                  {"bash", "python", "inner", "rm"},
		"echo $(date) `uname`":                                {"echo", "date", "uname"},
		"if true; then ./scripts/Build-2.sh; fi":              {"true", "build-2.sh"},
		"ls \"a b\" 'c;d'":                                    {"ls"},
		"":                                                    nil,
	}
	for in, want := range cases {
		got := Programs(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
	if n := len(Programs(strings.Repeat("a1 ; b2 ; c; ", 100) + strings.Repeat("x;", 100))); n > 24 {
		t.Errorf("not bounded: %d", n)
	}
	cs := ParseLine([]byte(line("2026-11-04T16:06:32Z", sess, "", "Bash", "python3.12 job.py")))
	if len(cs) != 1 || strings.Join(cs[0].Programs, ",") != "python,job" {
		t.Errorf("ParseLine programs: %+v", cs)
	}
}

func FuzzPrograms(f *testing.F) {
	f.Add("python3 -m x; ls | cat && bash -c 'echo hi'")
	f.Add("'unterminated")
	f.Add(strings.Repeat("bash -c '", 50))
	f.Fuzz(func(t *testing.T, s string) {
		if n := len(Programs(s)); n > 24 {
			t.Fatalf("%d programs", n)
		}
	})
}

func TestArgNames(t *testing.T) {
	cases := map[string][]string{
		`perl -e 'alarm 150; exec @ARGV' python3 io.py`: {"python", "io.py"},
		"xargs python3":                     {"python"},
		"timeout 5 python3 job.py":          {"job.py"}, // python3 is the program (strong), not an argument
		`echo "python3 is great" 'python3'`: nil,
		"ls /usr/bin/Python3.12":            {"python"},
		"FOO=1 xargs -n1 -P4 python3.11 -u": {"python"},
		"bash -c 'xargs python3'":           {"python"},
		"cmd $HOME python3\\ x":             nil, // $-words and escaped-space words are not standalone names
	}
	for in, want := range cases {
		got := ArgNames(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
	if n := len(ArgNames(strings.Repeat("x a1 b2 c3 d4 e5 f6; ", 200))); n > 48 {
		t.Errorf("not bounded: %d", n)
	}
	cs := ParseLine([]byte(line("2026-11-04T16:06:32Z", sess, "", "Bash", "xargs python3")))
	if len(cs) != 1 || strings.Join(cs[0].ArgNames, ",") != "python" || strings.Join(cs[0].Programs, ",") != "xargs" {
		t.Errorf("ParseLine: %+v", cs)
	}
}
