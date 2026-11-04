package incident

import (
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// Candidate ranking (spec line 197, AC-6).
//
// Given a process start time T and the process name from the jetsam report,
// the Bash tool_use calls with a timestamp in [T-60s, T+2s] are candidates.
// They are ordered by, in turn:
//
//  1. name match: a call whose command invokes a program whose normalized
//     name equals the process name (case-insensitive, version suffix
//     stripped, so python3.12 matches Python; interpreter -m modules and
//     scripts count, see transcript.Programs) ranks above calls that do not;
//  2. adjusted distance |T - At|, plus 5s for a call after T. Tool_use
//     timestamps are written before execution, so a call at or before T is
//     the more plausible parent; calls up to 2s after T stay eligible for
//     clock skew;
//  3. input order (stable).
//
// Confidence: medium only when exactly one name-matching call falls in the
// window; low otherwise (none, or several). Only the first candidate can be
// medium. The label never decides eligibility. It is a content signal, not
// proof: the process name is the interpreter or binary, so a name match
// narrows the field only as far as the name is distinctive.
const (
	CandidateBefore = 60 * time.Second
	CandidateAfter  = 2 * time.Second
	afterPenalty    = 5 * time.Second
	maxCandidates   = 5
)

// Candidate is one ranked transcript call.
type Candidate struct {
	Rank       int           `json:"rank"`
	NameMatch  bool          `json:"name_match"`
	Confidence string        `json:"confidence"`
	At         time.Time     `json:"at"`
	Before     time.Duration `json:"before_start_ns"` // T - At; negative if the call is after T
	SessionID  string        `json:"session_id"`
	AgentID    string        `json:"agent_id,omitempty"`
	Command    string        `json:"command"` // redacted and truncated
	SHA256     string        `json:"sha256"`
}

// Label is a short agent label for output and replay attribution.
func (c Candidate) Label() string {
	s := c.SessionID
	if len(s) > 8 {
		s = s[:8]
	}
	if c.AgentID != "" {
		return "agent " + c.AgentID + " in session " + s
	}
	return "session " + s
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func nameMatches(c transcript.Call, want string) bool {
	if want == "" {
		return false
	}
	for _, p := range c.Programs {
		if p == want {
			return true
		}
	}
	return false
}

// RankCandidates implements the rule above for a process named process. It
// returns at most five candidates.
func RankCandidates(calls []transcript.Call, start time.Time, process string) []Candidate {
	want := transcript.NormalizeName(process)
	type scored struct {
		c     transcript.Call
		match bool
		dist  time.Duration
	}
	var in []scored
	matches := 0
	for _, c := range calls {
		d := start.Sub(c.At) // positive: the call came first
		if d < -CandidateAfter || d > CandidateBefore {
			continue
		}
		s := scored{c: c, match: nameMatches(c, want), dist: abs(d)}
		if d < 0 {
			s.dist += afterPenalty
		}
		if s.match {
			matches++
		}
		in = append(in, s)
	}
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].match != in[j].match {
			return in[i].match
		}
		return in[i].dist < in[j].dist
	})
	var out []Candidate
	for i, s := range in {
		if i == maxCandidates {
			break
		}
		conf := "low"
		if i == 0 && matches == 1 {
			conf = "medium"
		}
		out = append(out, Candidate{Rank: i + 1, NameMatch: s.match, Confidence: conf, At: s.c.At, Before: start.Sub(s.c.At),
			SessionID: s.c.SessionID, AgentID: s.c.AgentID, Command: s.c.Redacted, SHA256: s.c.SHA256})
	}
	return out
}
