package incident

import (
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// Candidate ranking (spec line 197, AC-6).
//
// Given a process start time T, the Bash tool_use calls with a timestamp in
// [T-60s, T+2s] are candidates, ranked by closeness to T. Confidence:
//
//	medium  exactly one call is within 15s of T and no other call is
//	        within 30s of T;
//	low     everything else (several close calls, or only distant ones).
//
// A transcript timestamp is when the model issued the call, so it precedes
// the process start by the approval and spawn latency; nothing here is
// proof, which is why the label never exceeds medium and never decides
// eligibility.
const (
	CandidateBefore = 60 * time.Second
	CandidateAfter  = 2 * time.Second
	mediumNear      = 15 * time.Second
	mediumQuiet     = 30 * time.Second
	maxCandidates   = 5
)

// Candidate is one ranked transcript call.
type Candidate struct {
	Rank       int           `json:"rank"`
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

// RankCandidates implements the rule above. It returns at most five.
func RankCandidates(calls []transcript.Call, start time.Time) []Candidate {
	var in []transcript.Call
	near, quiet := 0, 0
	for _, c := range calls {
		d := start.Sub(c.At)
		if d < -CandidateAfter || d > CandidateBefore {
			continue
		}
		in = append(in, c)
		if abs(d) <= mediumNear {
			near++
		}
		if abs(d) <= mediumQuiet {
			quiet++
		}
	}
	sort.SliceStable(in, func(i, j int) bool { return abs(start.Sub(in[i].At)) < abs(start.Sub(in[j].At)) })
	conf := "low"
	if near == 1 && quiet == 1 {
		conf = "medium"
	}
	var out []Candidate
	for i, c := range in {
		if i == maxCandidates {
			break
		}
		cc := "low"
		if i == 0 {
			cc = conf
		}
		out = append(out, Candidate{Rank: i + 1, Confidence: cc, At: c.At, Before: start.Sub(c.At), SessionID: c.SessionID,
			AgentID: c.AgentID, Command: c.Redacted, SHA256: c.SHA256})
	}
	return out
}
