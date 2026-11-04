//go:build !windows

package shapecheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

var base = time.Date(2026, 11, 4, 16, 0, 0, 0, time.UTC)

const hookCmd = "python3 /home/user/.claude/hooks/pre_tool.py --strict"

// wrap builds the argv of a Bash tool shell the way Claude Code does:
// the command is single-quoted into an eval inside a snapshot preamble.
func wrap(cmd string) []string {
	q := strings.ReplaceAll(cmd, "'", `'"'"'`)
	return []string{"/bin/zsh", "-c", "source /home/user/.claude/shell-snapshots/s.sh 2>/dev/null || true && eval '" + q + "' < /dev/null && pwd -P >| /tmp/cwd"}
}

func call(at time.Time, cmd string) transcript.Call {
	return transcript.Call{At: at, SessionID: "11111111-2222-4333-8444-555555555555", SHA256: transcript.Hash(cmd), Redacted: "x"}
}

var toolShape = Shape{Setsid: true, NoTTY: true}

// shells returns n confirmed tool shells and their transcript calls.
func shells(n int, shape Shape) ([]Child, []transcript.Call) {
	var cs []Child
	var calls []transcript.Call
	for i := 0; i < n; i++ {
		cmd := fmt.Sprintf("echo it's job %d && make", i) // contains a single quote
		at := base.Add(time.Duration(i) * time.Minute)
		calls = append(calls, call(at, cmd))
		cs = append(cs, Child{PID: 100 + i, Start: at.Add(900 * time.Millisecond), Argv: wrap(cmd), Shape: shape})
	}
	return cs, calls
}

func hookChild(i int, shape Shape) Child {
	return Child{PID: 500 + i, Start: base.Add(time.Duration(i) * time.Minute), Argv: []string{"/bin/sh", "-c", hookCmd}, Shape: shape}
}

func hookSettings() Settings { return Settings{HookCommands: []string{hookCmd}} }

func TestMatchingShapePasses(t *testing.T) {
	cs, calls := shells(3, toolShape)
	r := Check(Input{Version: "9.9.9", Children: cs, Calls: calls})
	if r.Verdict != Pass || r.Confirmed != 3 || r.ConfirmedShape != 3 {
		t.Fatalf("%+v", r)
	}
	// With hooks configured and observed without the shape, still a pass.
	cs = append(cs, hookChild(1, Shape{}))
	r = Check(Input{Children: cs, Calls: calls, Settings: hookSettings()})
	if r.Verdict != Pass || r.HookChildren != 1 {
		t.Fatalf("with a non-shaped hook child: %+v", r)
	}
}

func TestHookShapedMatchFails(t *testing.T) {
	cs, calls := shells(3, toolShape)
	cs = append(cs, hookChild(1, toolShape))
	r := Check(Input{Children: cs, Calls: calls, Settings: hookSettings()})
	if r.Verdict != Fail || r.HookWithShape != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestMCPShapedMatchFails(t *testing.T) {
	set := Settings{MCP: []MCPServer{{Name: "s", Command: "/usr/bin/node", Args: []string{"/home/user/mcp/server.js", "--stdio"}}}}
	cs, calls := shells(3, toolShape)
	mcp := Child{PID: 900, Start: base, Argv: []string{"/usr/bin/node", "/home/user/mcp/server.js", "--stdio"}, Shape: toolShape}
	if r := Check(Input{Children: append(cs, mcp), Calls: calls, Settings: set}); r.Verdict != Fail || r.MCPWithShape != 1 {
		t.Fatalf("%+v", r)
	}
	mcp.Shape = Shape{}
	if r := Check(Input{Children: append(cs, mcp), Calls: calls, Settings: set}); r.Verdict != Pass {
		t.Fatalf("unshaped mcp child: %+v", r)
	}
	if r := Check(Input{Children: cs, Calls: calls, Settings: set}); r.Verdict != Inconclusive {
		t.Fatalf("mcp configured, none observed: %+v", r)
	}
}

func TestNoObservationsIsInconclusive(t *testing.T) {
	r := Check(Input{Version: "9.9.9"})
	if r.Verdict != Inconclusive {
		t.Fatalf("%+v", r)
	}
	_, calls := shells(3, toolShape)
	if r := Check(Input{Calls: calls}); r.Verdict != Inconclusive {
		t.Fatalf("calls but no children: %+v", r)
	}
	cs, _ := shells(3, toolShape)
	if r := Check(Input{Children: cs}); r.Verdict != Inconclusive || r.Confirmed != 0 {
		t.Fatalf("children but no transcript ground truth: %+v", r)
	}
}

func TestHooksConfiguredButNoneObservedIsInconclusive(t *testing.T) {
	cs, calls := shells(5, toolShape)
	r := Check(Input{Children: cs, Calls: calls, Settings: hookSettings()})
	if r.Verdict != Inconclusive || !strings.Contains(r.Reason, "hooks are configured but none was observed") {
		t.Fatalf("%+v", r)
	}
}

func TestHookOnlyStartTimeMatchIsNotCounted(t *testing.T) {
	// Hooks run right when a tool call is issued, so their start times
	// match transcript timestamps. Three of them must not become three
	// confirmed tool shells.
	var cs []Child
	var calls []transcript.Call
	for i := 0; i < 3; i++ {
		cs = append(cs, hookChild(i, toolShape))
		calls = append(calls, call(base.Add(time.Duration(i)*time.Minute), fmt.Sprint("ls ", i)))
	}
	r := Check(Input{Children: cs, Calls: calls, Settings: hookSettings()})
	if r.Confirmed != 0 || r.Verdict == Pass {
		t.Fatalf("hook children counted: %+v", r)
	}
	// Even when a hook's command text equals a tool call's and the times
	// match, a hook-shaped child is never confirmed as a tool shell.
	same := hookChild(9, toolShape)
	if r := Check(Input{Children: []Child{same}, Calls: []transcript.Call{call(same.Start, hookCmd)}, Settings: hookSettings()}); r.Confirmed != 0 || r.HookChildren != 1 {
		t.Fatalf("hook child with a matching call confirmed: %+v", r)
	}
	// An unknown (not configured) child that merely starts at the right
	// time, with a different payload, is a start-only match: not confirmed.
	other := Child{PID: 7, Start: base.Add(100 * time.Millisecond), Argv: []string{"/bin/sh", "-c", "some other thing"}, Shape: toolShape}
	r = Check(Input{Children: []Child{other}, Calls: calls})
	if r.Confirmed != 0 || r.StartOnlyMatches != 1 {
		t.Fatalf("start-only match: %+v", r)
	}
}

func TestConfirmationNeedsPayloadAndTime(t *testing.T) {
	cs, calls := shells(3, toolShape)
	// Right command, but the call is 3s from the shell's start.
	late := append([]transcript.Call(nil), calls...)
	late[0].At = late[0].At.Add(-3 * time.Second)
	if r := Check(Input{Children: cs, Calls: late}); r.Confirmed != 2 || r.Verdict != Inconclusive {
		t.Fatalf("3s apart: %+v", r)
	}
	// Right time, but the payload differs by one character.
	cs2, calls2 := shells(3, toolShape)
	cs2[1].Argv = wrap("echo it's job 1 && make!")
	if r := Check(Input{Children: cs2, Calls: calls2}); r.Confirmed != 2 {
		t.Fatalf("payload differs: %+v", r)
	}
	// A direct -c payload (no eval wrapper) matches by whole payload.
	direct := Child{PID: 1, Start: base, Argv: []string{"/bin/bash", "-c", "make all"}, Shape: toolShape}
	if r := Check(Input{Children: []Child{direct}, Calls: []transcript.Call{call(base, "make all")}}); r.Confirmed != 1 {
		t.Fatalf("direct payload: %+v", r)
	}
}

func TestShapeRequirements(t *testing.T) {
	cs, calls := shells(3, Shape{Setsid: true, NoTTY: false})
	if r := Check(Input{Children: cs, Calls: calls}); r.Verdict != Fail {
		t.Errorf("confirmed shells without the shape: %+v", r)
	}
	cs, calls = shells(2, toolShape)
	if r := Check(Input{Children: cs, Calls: calls}); r.Verdict != Inconclusive {
		t.Errorf("two shells: %+v", r)
	}
}

func TestEvalArgument(t *testing.T) {
	cases := map[string]string{
		`x && eval 'ls -la' < /dev/null`:       "ls -la",
		`eval 'echo '"'"'hi'"'"'' < /dev/null`: "echo 'hi'",
		`eval "echo \"q\"" && true`:            `echo "q"`,
		`eval plain && true`:                   "plain",
		`eval 'unterminated`:                   "",
		`nothing here`:                         "",
	}
	for in, want := range cases {
		got, ok := evalArgument(in)
		if (want == "") == ok || got != want {
			t.Errorf("%q: got %q ok=%v want %q", in, got, ok, want)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSettings(t *testing.T) {
	d := t.TempDir()
	user := writeFile(t, d, "settings.json", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 /home/user/h1.py"}]}],"Stop":[{"command":"/home/user/h2.sh"}]},
	  "statusLine":{"type":"command","command":"/home/user/status.sh"}}`, 0o644)
	proj := writeFile(t, d, "proj/.mcp.json", `{"mcpServers":{"a":{"command":"npx","args":["-y","pkg"]}}}`, 0o644)
	s := LoadSettings([]string{user, proj, filepath.Join(d, "missing.json")})
	if len(s.HookCommands) != 3 || len(s.MCP) != 1 || len(s.Unreadable) != 0 {
		t.Fatalf("%+v", s)
	}
	for _, bad := range map[string]string{
		"dupkeys.json": `{"hooks":{},"hooks":{}}`,
		"types.json":   `{"hooks":"nope"}`,
		"junk.json":    `{`,
	} {
		p := writeFile(t, d, "bad-"+fmt.Sprint(len(bad))+".json", bad, 0o644)
		if s := LoadSettings([]string{p}); len(s.Unreadable) != 1 {
			t.Errorf("%q not flagged unreadable: %+v", bad, s)
		}
	}
	link := filepath.Join(d, "link.json")
	os.Symlink(user, link)
	if s := LoadSettings([]string{link}); len(s.Unreadable) != 1 {
		t.Error("symlinked settings were followed")
	}
	// Unreadable settings make a check inconclusive: hooks cannot be excluded.
	cs, calls := shells(3, toolShape)
	if r := Check(Input{Children: cs, Calls: calls, Settings: Settings{Unreadable: []string{"x"}}}); r.Verdict != Inconclusive {
		t.Errorf("%+v", r)
	}
}

type memEvents struct{ evs []record.Event }

func (m *memEvents) Append(r any) error { m.evs = append(m.evs, r.(record.Event)); return nil }

func TestRunAllowlistsOnPassOnly(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	cs, calls := shells(3, toolShape)
	ev := &memEvents{}
	cfg := Config{Version: "9.9.9", StateDir: state, Events: ev,
		Children: func() []Child { return cs },
		Calls:    func(_, _ time.Time) ([]transcript.Call, error) { return calls, nil }}
	now := base.Add(time.Hour)

	// Inconclusive (hook configured, none seen): nothing written.
	set := writeFile(t, t.TempDir(), "s.json", `{"hooks":{"Stop":[{"command":"`+hookCmd+`"}]}}`, 0o600)
	cfg.SettingsPaths = []string{set}
	res, err := Run(cfg, now)
	if err != nil || res.Verdict != Inconclusive || Allowed(state, "9.9.9") || len(ev.evs) != 0 {
		t.Fatalf("inconclusive run changed state: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(state, AllowlistFile)); err == nil {
		t.Fatal("allowlist written on an inconclusive check")
	}

	// Pass: allowlisted, 0600, one ALLOWLIST_CHANGE.
	cfg.SettingsPaths = nil
	res, err = Run(cfg, now)
	if err != nil || res.Verdict != Pass || !Allowed(state, "9.9.9") {
		t.Fatalf("%+v %v", res, err)
	}
	fi, _ := os.Stat(filepath.Join(state, AllowlistFile))
	di, _ := os.Stat(state)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Errorf("modes file=%v dir=%v", fi.Mode().Perm(), di.Mode().Perm())
	}
	if len(ev.evs) != 1 || ev.evs[0].Event != record.AllowlistChange || ev.evs[0].Version != "9.9.9" {
		t.Fatalf("events: %+v", ev.evs)
	}
	// A repeat pass does not log again.
	Run(cfg, now.Add(time.Hour))
	if len(ev.evs) != 1 {
		t.Errorf("duplicate ALLOWLIST_CHANGE: %d", len(ev.evs))
	}
	// A second version is added alongside.
	cfg.Version = "9.9.10"
	Run(cfg, now.Add(2*time.Hour))
	if !Allowed(state, "9.9.9") || !Allowed(state, "9.9.10") || Allowed(state, "1.0.0") {
		t.Error("allowlist contents wrong")
	}
}

func TestAllowedFailsClosed(t *testing.T) {
	state := t.TempDir()
	os.Chmod(state, 0o700)
	p := writeFile(t, state, AllowlistFile, `{"versions":["9.9.9"]}`, 0o644) // too open
	if Allowed(state, "9.9.9") {
		t.Error("world-readable allowlist honoured")
	}
	os.Chmod(p, 0o600)
	if !Allowed(state, "9.9.9") {
		t.Error("control: 0600 allowlist rejected")
	}
	os.WriteFile(p, []byte(`{"versions":["9.9.9"],"versions":[]}`), 0o600)
	if Allowed(state, "9.9.9") {
		t.Error("duplicate-key allowlist honoured")
	}
	if _, err := Allow(state, "", base); err == nil {
		t.Error("empty version accepted")
	}
}

func TestSchedule(t *testing.T) {
	var s Schedule
	now := base
	if !s.Due(now) {
		t.Fatal("first check is due immediately")
	}
	s.Record(now, Inconclusive)
	if s.Due(now.Add(59 * time.Minute)) {
		t.Error("retried before an hour")
	}
	n := 1
	for ; s.Due(now.Add(time.Duration(n) * time.Hour)); n++ {
		s.Record(now.Add(time.Duration(n)*time.Hour), Inconclusive)
	}
	if s.Attempts() != MaxAttempts || !s.Exhausted() {
		t.Errorf("attempts %d exhausted %v", s.Attempts(), s.Exhausted())
	}
	var p Schedule
	p.Record(now, Pass)
	if p.Due(now.Add(48 * time.Hour)) {
		t.Error("retried after a pass")
	}
	var f Schedule
	f.Record(now, Fail)
	if f.Due(now.Add(48 * time.Hour)) {
		t.Error("retried after a fail")
	}
}
