package attrib

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FileReader is the narrow, read-only view of the harness WAL tree the
// labeler needs. The production reader is the shared hardened reader
// (internal/safeio) behind this interface; DirReader below is a minimal
// stand-in with the same guarantees for the parts that matter here.
type FileReader interface {
	// Tail returns at most max trailing bytes of the root-relative file.
	Tail(rel string, max int64) ([]byte, error)
	// List returns up to max entry names of the root-relative directory,
	// most recently modified first.
	List(rel string, max int) ([]string, error)
}

// DirReader reads files below Root. It refuses symlinks and non-regular
// files (O_NOFOLLOW|O_NONBLOCK plus fstat) and never reads more than the
// caller's cap, so a FIFO or a huge file cannot hang or exhaust us.
type DirReader struct{ Root string }

var errUnsafe = errors.New("attrib: unsafe path or file")

func (d DirReader) resolve(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", errUnsafe
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errUnsafe
		}
	}
	return filepath.Join(d.Root, rel), nil
}

// Tail implements FileReader.
func (d DirReader) Tail(rel string, max int64) ([]byte, error) {
	p, err := d.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := openNoFollow(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errUnsafe
	}
	off := st.Size() - max
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// List implements FileReader: the max most recently modified entries,
// newest first. It reads at most listScan entries; a session with more
// agent files than that is read partially (bounded work beats a label).
func (d DirReader) List(rel string, max int) ([]string, error) {
	p, err := d.resolve(rel)
	if err != nil {
		return nil, err
	}
	// Same open as Tail: os.Open would block forever on a FIFO left where
	// the directory should be.
	f, err := openNoFollow(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.IsDir() {
		return nil, errUnsafe
	}
	// Readdir lstats each entry, so a symlink reports its own time.
	infos, err := f.Readdir(listScan)
	if err == io.EOF {
		err = nil
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ModTime().After(infos[j].ModTime()) })
	if max >= 0 && len(infos) > max {
		infos = infos[:max]
	}
	names := make([]string, len(infos))
	for i, fi := range infos {
		names[i] = fi.Name()
	}
	return names, err
}

// listScan bounds how many directory entries List reads.
const listScan = 8192

// Label is the agent attribution of one tool shell.
type Label struct {
	Agent      string  // "main", "agent:<id>" or ""
	Confidence float64 // 0 when nothing matched
}

// Level names the confidence for records: high, medium, low, or "" when
// nothing matched.
func (l Label) Level() string {
	switch {
	case l.Agent == "" || l.Confidence <= 0:
		return ""
	case l.Confidence >= 0.85:
		return "high"
	case l.Confidence >= 0.5:
		return "medium"
	}
	return "low"
}

// Labeler matches a tool shell's start time to the pretool entries the
// harness hooks write into the session WAL.
type Labeler struct {
	FS FileReader
	// Window is how far after a pretool entry the shell may start.
	// Default 3s.
	Window time.Duration
	// TailBytes bounds the read of each WAL file. Default 64 KiB.
	TailBytes int64
}

var sessionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
var agentID = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
var agentFile = regexp.MustCompile(`^(main|agent-[A-Za-z0-9]{1,64})\.jsonl$`)

type walEntry struct {
	At      string  `json:"at"`
	Event   string  `json:"event"`
	Tool    string  `json:"tool"`
	AgentID *string `json:"agent_id"`
}

const (
	maxFiles   = 64
	maxLineLen = 4096
)

// Label finds the agent whose Bash pretool entry most closely precedes
// shellStart. The session id is validated before it becomes a path.
func (l *Labeler) Label(session string, shellStart time.Time) Label {
	if l == nil || l.FS == nil || !sessionID.MatchString(session) || shellStart.IsZero() {
		return Label{}
	}
	win := l.Window
	if win <= 0 {
		win = 3 * time.Second
	}
	tail := l.TailBytes
	if tail <= 0 {
		tail = 64 << 10
	}
	names, err := l.FS.List(session, maxFiles)
	if err != nil {
		return Label{}
	}
	type cand struct {
		agent string
		gap   time.Duration
	}
	var cands []cand
	for _, n := range names {
		if !agentFile.MatchString(n) {
			continue
		}
		b, err := l.FS.Tail(session+"/"+n, tail)
		if err != nil {
			continue
		}
		for len(b) > 0 {
			var line []byte
			if i := bytes.IndexByte(b, '\n'); i >= 0 {
				line, b = b[:i], b[i+1:]
			} else {
				line, b = b, nil
			}
			if len(line) == 0 || len(line) > maxLineLen {
				continue // also drops the partial first line of a tail
			}
			var e walEntry
			if json.Unmarshal(line, &e) != nil || e.Event != "pretool" || e.Tool != "Bash" {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, e.At)
			if err != nil {
				continue
			}
			gap := shellStart.Sub(at)
			if gap < -500*time.Millisecond || gap > win {
				continue // clock skew allowance, then the window
			}
			who := "main"
			if e.AgentID != nil && *e.AgentID != "" {
				if !agentID.MatchString(*e.AgentID) {
					continue // not an id: never copied into records or alerts
				}
				who = "agent:" + *e.AgentID
			}
			cands = append(cands, cand{who, gap.Abs()})
		}
	}
	if len(cands) == 0 {
		return Label{}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].gap < cands[j].gap })
	distinct := map[string]bool{}
	for _, c := range cands {
		distinct[c.agent] = true
	}
	conf := 0.9
	switch {
	case len(distinct) > 1:
		conf = 0.35 // two agents ran a tool at once: a guess
	case len(cands) > 1:
		conf = 0.8
	}
	return Label{Agent: cands[0].agent, Confidence: conf}
}
