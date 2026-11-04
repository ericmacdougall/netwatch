// Package shapecheck implements plan amendment A4: before a Claude Code
// version may be killed (not just paused), prove from observation that the
// "tool shell" shape (a Bash tool's shell calling setsid) identifies tool
// shells and not hooks or MCP servers of that version.
//
// Ground truth: a tool shell is confirmed when its -c payload carries the
// exact command of a transcript Bash tool_use whose timestamp is within 2s
// of the shell's start. Hook children are excluded first by the hook
// commands configured in every settings source, MCP children by their
// configured server commands. Without ground truth the result is
// inconclusive and the version is not allowlisted.
package shapecheck

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

const maxSettingsBytes = 2 << 20

// minHookMatchLen is the shortest configured command that may match by
// substring; a command like "true" would otherwise match everything.
const minHookMatchLen = 8

// Settings is what the exclusions need from every settings source.
type Settings struct {
	HookCommands []string
	MCP          []MCPServer
	// Unreadable lists sources that exist but could not be read safely or
	// parsed. A check cannot exclude hooks it cannot see, so any entry makes
	// the result inconclusive.
	Unreadable []string
}

// MCPServer is a configured MCP server command.
type MCPServer struct {
	Name    string
	Command string
	Args    []string
}

type hookEntry struct {
	Command string `json:"command"`
	Hooks   []struct {
		Command string `json:"command"`
	} `json:"hooks"`
}

type rawSettings struct {
	Hooks      map[string][]hookEntry `json:"hooks"`
	StatusLine *struct {
		Command string `json:"command"`
	} `json:"statusLine"`
	MCP map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	} `json:"mcpServers"`
}

// LoadSettings reads each path through safeio (owned by us, bounded, no
// symlink). The same parser serves settings.json, settings.local.json,
// project .claude/settings*.json, managed settings, plugin hooks.json and
// .mcp.json. A missing file is skipped; an unreadable one is recorded.
func LoadSettings(paths []string) Settings {
	var s Settings
	for _, p := range paths {
		var raw rawSettings
		err := safeio.ReadJSON(p, safeio.Opts{Max: maxSettingsBytes, RequireOwner: true}, &raw)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			s.Unreadable = append(s.Unreadable, filepath.Base(p))
			continue
		}
		for _, entries := range raw.Hooks {
			for _, e := range entries {
				if e.Command != "" {
					s.HookCommands = append(s.HookCommands, e.Command)
				}
				for _, h := range e.Hooks {
					if h.Command != "" {
						s.HookCommands = append(s.HookCommands, h.Command)
					}
				}
			}
		}
		if raw.StatusLine != nil && raw.StatusLine.Command != "" {
			s.HookCommands = append(s.HookCommands, raw.StatusLine.Command)
		}
		for n, m := range raw.MCP {
			if m.Command != "" {
				s.MCP = append(s.MCP, MCPServer{Name: n, Command: m.Command, Args: m.Args})
			}
		}
	}
	return s
}

// DefaultSettingsPaths lists the user and per-project settings files. home
// and projectDirs come from the caller; nothing is hard-coded.
func DefaultSettingsPaths(home string, projectDirs []string) []string {
	var ps []string
	ps = append(ps, filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude", "settings.local.json"))
	for _, d := range projectDirs {
		ps = append(ps, filepath.Join(d, ".claude", "settings.json"), filepath.Join(d, ".claude", "settings.local.json"), filepath.Join(d, ".mcp.json"))
	}
	return ps
}

func norm(s string) string { return strings.Join(strings.Fields(s), " ") }

// hookShaped reports whether the child looks like a configured hook or
// status line command.
func (s Settings) hookShaped(argv []string) bool {
	joined := norm(strings.Join(argv, " "))
	for _, h := range s.HookCommands {
		h = norm(h)
		if h == "" {
			continue
		}
		if joined == h || (len(h) >= minHookMatchLen && strings.Contains(joined, h)) {
			return true
		}
	}
	return false
}

// mcpShaped reports whether the child runs a configured MCP server.
func (s Settings) mcpShaped(argv []string) bool {
	for _, m := range s.MCP {
		if !hasWord(argv, m.Command) {
			continue
		}
		ok := true
		for _, a := range m.Args {
			if !hasWord(argv, a) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// hasWord matches an argv element exactly, or the command by base name in
// the first two positions (an interpreter then a script).
func hasWord(argv []string, w string) bool {
	for i, a := range argv {
		if a == w || (i < 2 && filepath.Base(a) == filepath.Base(w) && !strings.Contains(w, " ")) {
			return true
		}
	}
	return false
}
