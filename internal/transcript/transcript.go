// Package transcript is a bounded, read-only reader for Claude Code
// transcripts (JSONL). It extracts the Bash tool_use calls with their time,
// session and agent ids, so a process start time can be matched to the tool
// call that probably spawned it.
//
// Privacy: the raw command is never returned or kept. A Call carries a
// redacted, truncated form (internal/redact) and the SHA-256 of the exact
// command, which is enough to confirm a match against a process argv.
package transcript

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// Default bounds.
const (
	DefaultMaxFiles     = 200
	DefaultMaxFileBytes = 4 << 20
	DefaultMaxLine      = 1 << 20
	maxLinesPerFile     = 100000
	maxProjects         = 1000
	maxEntries          = 5000
	maxRedactedRunes    = 160
)

var (
	uuidRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	agentRE = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// Call is one Bash tool_use. It has no field for the raw command.
type Call struct {
	At        time.Time `json:"at"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id,omitempty"`
	ToolUseID string    `json:"tool_use_id,omitempty"`
	File      string    `json:"file"`    // base name of the transcript
	Redacted  string    `json:"command"` // redacted and truncated
	SHA256    string    `json:"sha256"`  // of the exact command
	Len       int       `json:"len"`     // bytes of the exact command
	// Programs are the normalized names of the executables the command
	// invokes (see programs.go); derived, not the command itself.
	Programs []string `json:"programs,omitempty"`
}

// Config bounds one scan.
type Config struct {
	Root         string    // projects root; "" means DefaultRoot()
	WindowStart  time.Time // only files modified at or after this are read
	MaxFiles     int
	MaxFileBytes int64
	MaxLine      int
}

// Stats says what a scan did, so callers can report limits honestly.
type Stats struct {
	FilesSeen, FilesRead, FilesOld, FilesOverCap int
	Lines                                        int
}

// DefaultRoot is ~/.claude/projects built from the user's home directory.
func DefaultRoot() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".claude", "projects"), nil
}

// Hash returns the SHA-256 hex of an exact command, the key used to match
// a process's -c payload.
func Hash(cmd string) string {
	s := sha256.Sum256([]byte(cmd))
	return hex.EncodeToString(s[:])
}

// Redact returns the single-line, redacted, truncated display form.
func Redact(cmd string) string {
	s := redact.String(strings.Join(strings.Fields(cmd), " "))
	if utf8.RuneCountInString(s) > maxRedactedRunes {
		r := []rune(s)
		s = string(r[:maxRedactedRunes]) + "..."
	}
	return s
}

type contentItem struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	ID    string `json:"id"`
	Input struct {
		Command string `json:"command"`
	} `json:"input"`
}

type lineShape struct {
	Timestamp string `json:"timestamp"`
	SessionID string `json:"sessionId"`
	AgentID   string `json:"agentId"`
	Message   struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

// ParseLine extracts the Bash tool_use calls of one transcript line. A
// malformed or unrelated line yields none; it never panics.
func ParseLine(line []byte) []Call {
	var l lineShape
	if json.Unmarshal(line, &l) != nil {
		return nil
	}
	c := strings.TrimSpace(string(l.Message.Content))
	if !strings.HasPrefix(c, "[") {
		return nil
	}
	at, err := time.Parse(time.RFC3339Nano, l.Timestamp)
	if err != nil || !uuidRE.MatchString(l.SessionID) {
		return nil
	}
	var items []contentItem
	if json.Unmarshal(l.Message.Content, &items) != nil {
		// One odd item must not hide the others: retry item by item.
		items = nil
		var raws []json.RawMessage
		if json.Unmarshal(l.Message.Content, &raws) != nil {
			return nil
		}
		for _, r := range raws {
			var it contentItem
			if json.Unmarshal(r, &it) == nil {
				items = append(items, it)
			}
		}
	}
	agent := l.AgentID
	if !agentRE.MatchString(agent) {
		agent = ""
	}
	var out []Call
	for _, it := range items {
		if it.Type != "tool_use" || it.Name != "Bash" || it.Input.Command == "" {
			continue
		}
		out = append(out, Call{At: at.UTC(), SessionID: strings.ToLower(l.SessionID), AgentID: agent, ToolUseID: safeID(it.ID),
			Redacted: Redact(it.Input.Command), SHA256: Hash(it.Input.Command), Len: len(it.Input.Command),
			Programs: Programs(it.Input.Command)})
	}
	return out
}

func safeID(s string) string {
	if len(s) > 64 || !agentRE.MatchString(strings.ReplaceAll(s, "_", "")) {
		return ""
	}
	return s
}

type fileRef struct {
	path  string
	mtime time.Time
}

// Scan reads the newest transcripts under the root within the bounds and
// returns their Bash calls sorted by time. A missing root is not an error.
func Scan(cfg Config) ([]Call, Stats, error) {
	var st Stats
	if cfg.Root == "" {
		r, err := DefaultRoot()
		if err != nil {
			return nil, st, err
		}
		cfg.Root = r
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = DefaultMaxFileBytes
	}
	if cfg.MaxLine <= 0 {
		cfg.MaxLine = DefaultMaxLine
	}
	files := discover(cfg, &st)
	sort.Slice(files, func(i, j int) bool { return files[i].mtime.After(files[j].mtime) })
	if len(files) > cfg.MaxFiles {
		st.FilesOverCap = len(files) - cfg.MaxFiles
		files = files[:cfg.MaxFiles]
	}
	var calls []Call
	for _, f := range files {
		lines, err := safeio.TailLines(f.path, maxLinesPerFile, cfg.MaxLine, safeio.Opts{Max: cfg.MaxFileBytes})
		if err != nil {
			continue
		}
		st.FilesRead++
		base := filepath.Base(f.path)
		for _, l := range lines {
			st.Lines++
			cs := ParseLine(l)
			if len(cs) == 0 {
				continue
			}
			for _, c := range cs {
				c.File = base
				calls = append(calls, c)
			}
		}
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].At.Before(calls[j].At) })
	return calls, st, nil
}

func names(dir string) []string {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	n, _ := d.Readdirnames(maxEntries)
	return n
}

func isRealDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

func consider(p string, cfg Config, st *Stats, out *[]fileRef) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	st.FilesSeen++
	if fi.ModTime().Before(cfg.WindowStart) {
		st.FilesOld++
		return
	}
	*out = append(*out, fileRef{p, fi.ModTime()})
}

func discover(cfg Config, st *Stats) []fileRef {
	var out []fileRef
	projects := names(cfg.Root)
	if len(projects) > maxProjects {
		projects = projects[:maxProjects]
	}
	for _, p := range projects {
		pdir := filepath.Join(cfg.Root, p)
		if !isRealDir(pdir) {
			continue
		}
		for _, n := range names(pdir) {
			full := filepath.Join(pdir, n)
			switch {
			case strings.HasSuffix(n, ".jsonl"):
				consider(full, cfg, st, &out)
			case uuidRE.MatchString(n) && isRealDir(full):
				sub := filepath.Join(full, "subagents")
				if !isRealDir(sub) {
					continue
				}
				for _, a := range names(sub) {
					if strings.HasPrefix(a, "agent-") && strings.HasSuffix(a, ".jsonl") {
						consider(filepath.Join(sub, a), cfg, st, &out)
					}
				}
			}
		}
	}
	return out
}
