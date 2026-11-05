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
//  1. name match, strong then weak then none. Strong: the command invokes a
//     program whose normalized name equals the process name
//     (case-insensitive, version suffix stripped, so python3.12 matches
//     Python; interpreter -m modules and scripts count, see
//     transcript.Programs). Weak: a standalone argument (unquoted, not a
//     flag) has that normalized base name, which covers exec-through
//     wrappers such as `perl -e '...exec @ARGV' python3` or `xargs python3`
//     without listing them, and also a file merely named like the process;
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
	MatchKind  string        `json:"match_kind"` // strong, weak or none
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

// Match tiers.
const (
	matchNone   = 0
	matchWeak   = 1
	matchStrong = 2
)

var matchKinds = [...]string{"none", "weak", "strong"}

// matchTier is strong when the command invokes the program, weak when a
// standalone argument has that name, none otherwise.
func matchTier(c transcript.Call, want string) int {
	if want == "" {
		return matchNone
	}
	for _, p := range c.Programs {
		if p == want {
			return matchStrong
		}
	}
	for _, a := range c.ArgNames {
		if a == want {
			return matchWeak
		}
	}
	return matchNone
}

func nameMatches(c transcript.Call, want string) bool { return matchTier(c, want) != matchNone }

// RankCandidates implements the rule above for a process named process. It
// returns at most five candidates.
func RankCandidates(calls []transcript.Call, start time.Time, process string) []Candidate {
	want := transcript.NormalizeName(process)
	type scored struct {
		c    transcript.Call
		tier int
		dist time.Duration
	}
	var in []scored
	matches := 0
	for _, c := range calls {
		d := start.Sub(c.At) // positive: the call came first
		if d < -CandidateAfter || d > CandidateBefore {
			continue
		}
		s := scored{c: c, tier: matchTier(c, want), dist: abs(d)}
		if d < 0 {
			s.dist += afterPenalty
		}
		if s.tier != matchNone {
			matches++
		}
		in = append(in, s)
	}
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].tier != in[j].tier {
			return in[i].tier > in[j].tier
		}
		return in[i].dist < in[j].dist
	})
	var out []Candidate
	for i, s := range in {
		if i == maxCandidates {
			break
		}
		conf := "low"
		if i == 0 && matches == 1 && s.tier != matchNone {
			conf = "medium"
		}
		out = append(out, Candidate{Rank: i + 1, NameMatch: s.tier != matchNone, MatchKind: matchKinds[s.tier], Confidence: conf, At: s.c.At, Before: start.Sub(s.c.At),
			SessionID: s.c.SessionID, AgentID: s.c.AgentID, Command: s.c.Redacted, SHA256: s.c.SHA256})
	}
	return out
}

// CountMatches is the number of calls in the window whose name matches
// strongly or weakly; RankCandidates returns at most five of them.
func CountMatches(calls []transcript.Call, start time.Time, process string) int {
	want := transcript.NormalizeName(process)
	n := 0
	for _, c := range calls {
		if d := start.Sub(c.At); d >= -CandidateAfter && d <= CandidateBefore && matchTier(c, want) != matchNone {
			n++
		}
	}
	return n
}
