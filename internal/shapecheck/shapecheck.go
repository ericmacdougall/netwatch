package shapecheck

import (
	"fmt"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// MatchWindow is how close a transcript tool_use must be to a shell's
// start (A4).
const MatchWindow = 2 * time.Second

// MinConfirmed is the number of confirmed tool shells with the expected
// shape that a pass needs (A4).
const MinConfirmed = 3

// Shape is the observed shape of a child.
type Shape struct {
	Setsid bool // pgid == sid == pid after exec
	NoTTY  bool
}

// Expected reports whether the shape is the tool-shell shape the guard
// relies on.
func (s Shape) Expected() bool { return s.Setsid && s.NoTTY }

// Child is a child of a Claude Code process of the version under test, as
// the watcher recorded it.
type Child struct {
	PID   int
	Start time.Time
	Argv  []string // redaction is the caller's concern; argv is not retained here
	Shape Shape
}

// Verdict of a check.
type Verdict string

// Verdicts.
const (
	Pass         Verdict = "pass"
	Fail         Verdict = "fail"
	Inconclusive Verdict = "inconclusive"
)

// Input is everything one check looks at.
type Input struct {
	Version  string
	Children []Child
	Calls    []transcript.Call
	Settings Settings
}

// Result explains a verdict with counts, never command text.
type Result struct {
	Version          string  `json:"version"`
	Verdict          Verdict `json:"verdict"`
	Reason           string  `json:"reason"`
	Children         int     `json:"children"`
	Confirmed        int     `json:"confirmed_tool_shells"`
	ConfirmedShape   int     `json:"confirmed_with_shape"`
	HookChildren     int     `json:"hook_children"`
	MCPChildren      int     `json:"mcp_children"`
	HookWithShape    int     `json:"hook_children_with_shape"`
	MCPWithShape     int     `json:"mcp_children_with_shape"`
	StartOnlyMatches int     `json:"start_only_matches"`
	HooksConfigured  int     `json:"hooks_configured"`
	MCPConfigured    int     `json:"mcp_configured"`
}

// payload returns the -c argument of a shell argv, or "".
func payload(argv []string) string {
	for i, a := range argv {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// payloadHashes returns the SHA-256 candidates a payload can match: the
// whole payload, and the argument of Claude's `eval '...'` wrapper
// unquoted. Only hashes leave this function.
func payloadHashes(p string) []string {
	if p == "" {
		return nil
	}
	hs := []string{transcript.Hash(p), transcript.Hash(strings.TrimSpace(p))}
	if cmd, ok := evalArgument(p); ok {
		hs = append(hs, transcript.Hash(cmd))
	}
	return hs
}

// evalArgument extracts and unquotes the shell word after the first
// "eval " of a payload (single quotes, double quotes and adjacent pieces,
// as in 'a'"'"'b').
func evalArgument(p string) (string, bool) {
	i := strings.Index(p, "eval ")
	if i < 0 {
		return "", false
	}
	s := p[i+len("eval "):]
	var b strings.Builder
	for j := 0; j < len(s); {
		switch c := s[j]; c {
		case '\'':
			k := strings.IndexByte(s[j+1:], '\'')
			if k < 0 {
				return "", false
			}
			b.WriteString(s[j+1 : j+1+k])
			j += k + 2
		case '"':
			j++
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return "", false
			}
			j++
		case ' ', '\t', '\n':
			return b.String(), b.Len() > 0
		case '\\':
			if j+1 < len(s) {
				b.WriteByte(s[j+1])
			}
			j += 2
		default:
			b.WriteByte(c)
			j++
		}
	}
	return b.String(), b.Len() > 0
}

func within(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= MatchWindow
}

// Check applies A4 to the observations.
func Check(in Input) Result {
	r := Result{Version: in.Version, Children: len(in.Children), HooksConfigured: len(in.Settings.HookCommands), MCPConfigured: len(in.Settings.MCP)}
	callsByHash := map[string][]time.Time{}
	for _, c := range in.Calls {
		callsByHash[c.SHA256] = append(callsByHash[c.SHA256], c.At)
	}
	for _, ch := range in.Children {
		hook, mcp := in.Settings.hookShaped(ch.Argv), in.Settings.mcpShaped(ch.Argv)
		switch {
		case hook:
			r.HookChildren++
			if ch.Shape.Expected() {
				r.HookWithShape++
			}
			continue // never a tool shell, even when its start matches a call
		case mcp:
			r.MCPChildren++
			if ch.Shape.Expected() {
				r.MCPWithShape++
			}
			continue
		}
		confirmed := false
		for _, h := range payloadHashes(payload(ch.Argv)) {
			for _, at := range callsByHash[h] {
				if within(at, ch.Start) {
					confirmed = true
				}
			}
		}
		if !confirmed {
			for _, c := range in.Calls {
				if within(c.At, ch.Start) {
					r.StartOnlyMatches++
					break
				}
			}
			continue
		}
		r.Confirmed++
		if ch.Shape.Expected() {
			r.ConfirmedShape++
		}
	}
	r.Verdict, r.Reason = r.decide(in)
	return r
}

func (r *Result) decide(in Input) (Verdict, string) {
	if len(in.Settings.Unreadable) > 0 {
		return Inconclusive, fmt.Sprintf("%d settings source(s) exist but could not be read safely, so hook commands cannot be excluded", len(in.Settings.Unreadable))
	}
	if r.HookWithShape > 0 || r.MCPWithShape > 0 {
		return Fail, fmt.Sprintf("a hook or MCP child has the tool-shell shape (hook %d, mcp %d): the shape does not identify tool shells for this version", r.HookWithShape, r.MCPWithShape)
	}
	if r.Confirmed < MinConfirmed {
		return Inconclusive, fmt.Sprintf("only %d confirmed tool shell(s), need %d (start-only matches %d are not counted)", r.Confirmed, MinConfirmed, r.StartOnlyMatches)
	}
	if r.ConfirmedShape < MinConfirmed {
		return Fail, fmt.Sprintf("%d of %d confirmed tool shells have the expected shape, need %d", r.ConfirmedShape, r.Confirmed, MinConfirmed)
	}
	if r.HooksConfigured > 0 && r.HookChildren == 0 {
		return Inconclusive, "hooks are configured but none was observed, so a hook with the tool-shell shape cannot be ruled out"
	}
	if r.MCPConfigured > 0 && r.MCPChildren == 0 {
		return Inconclusive, "MCP servers are configured but none was observed, so an MCP child with the tool-shell shape cannot be ruled out"
	}
	return Pass, fmt.Sprintf("%d confirmed tool shells have the expected shape; no hook or MCP child has it", r.ConfirmedShape)
}
