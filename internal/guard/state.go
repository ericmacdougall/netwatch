package guard

import (
	"fmt"
	"sort"
	"time"
)

// StateVersion is the on-disk version this build writes and reads.
const StateVersion = 1

// Phase of a recorded group.
const (
	PhasePaused = "paused"
	PhaseTerm   = "terming" // SIGTERM sent, waiting to SIGKILL survivors
)

// RecMember is one member netwatch signalled (or is about to).
type RecMember struct {
	PID    int       `json:"pid"`
	Start  time.Time `json:"start"`
	Sig    bool      `json:"stopped,omitempty"` // SIGSTOP was delivered
	Termed bool      `json:"termed,omitempty"`  // SIGTERM was delivered
}

// PidStart identifies a process that was already stopped before netwatch
// acted, so the user's own Ctrl-Z is never undone.
type PidStart struct {
	PID   int       `json:"pid"`
	Start time.Time `json:"start"`
}

// Facts are recorded at pause time and re-verified before a kill: any
// change means no kill.
type Facts struct {
	Tier         Tier   `json:"tier"`
	EnvOK        bool   `json:"env_ok"`
	Allowlisted  bool   `json:"allowlisted"`
	ClaudeVer    string `json:"claude_ver,omitempty"`
	BudgetMax    uint64 `json:"budget_max,omitempty"`
	BudgetWithin bool   `json:"budget_within,omitempty"`
	ExclHash     string `json:"excl_hash"`
}

// PathA is the sustained-critical window counter for one paused group.
type PathA struct {
	Start time.Time `json:"start,omitempty"` // first critical poll of the current window
	Last  time.Time `json:"last,omitempty"`
	Pts   []PathAPt `json:"pts,omitempty"` // polls inside the trailing window
}

// PathAPt is one poll inside the path A window.
type PathAPt struct {
	At   time.Time `json:"at"`
	Crit bool      `json:"crit"`
}

// Record is one paused (or terminating) group.
type Record struct {
	PGID        int         `json:"pgid"`
	LeaderStart time.Time   `json:"leader_start"`
	Phase       string      `json:"phase"`
	PausedAt    time.Time   `json:"paused_at"`
	Sticky      bool        `json:"sticky,omitempty"`
	Members     []RecMember `json:"members"`
	Already     []PidStart  `json:"already_stopped,omitempty"`
	Facts       Facts       `json:"facts"`
	Cmd         string      `json:"cmd,omitempty"`
	Agent       string      `json:"agent,omitempty"`
	Signals     []string    `json:"signals,omitempty"`
	PathA       PathA       `json:"path_a"`
	TermAt      time.Time   `json:"term_at,omitempty"`
	FPAtTerm    uint64      `json:"fp_at_term,omitempty"`
	LastWarn    time.Time   `json:"last_warn,omitempty"`
	Unstable    int         `json:"unstable,omitempty"`
	Frozen      bool        `json:"frozen,omitempty"`
	Missing     int         `json:"-"` // consecutive polls the group was absent
}

// Key is the record's map key, the same format as Term.Key.
func (r *Record) Key() string { return keyOf(r.PGID, r.LeaderStart) }

func keyOf(pgid int, start time.Time) string {
	return fmt.Sprintf("pg:%d:%d", pgid, start.UnixNano())
}

// Episode is one danger episode.
type Episode struct {
	ID          string            `json:"id"`
	Since       time.Time         `json:"danger_since"`
	BaselineAt  time.Time         `json:"baseline_at"`
	Baselines   map[string]uint64 `json:"baselines"`
	DangerBase  map[string]uint64 `json:"danger_base"`
	D4          map[string]bool   `json:"d4"`
	P1          map[string]bool   `json:"p1"`
	Resumed     map[string]bool   `json:"resumed,omitempty"`
	Unprotected map[string]bool   `json:"unprotected,omitempty"`
	Pauses      int               `json:"pauses"`
	Cleared     bool              `json:"cleared,omitempty"`
}

// Tracker holds the poll-to-poll counters for path B and the fast path.
type Trackers struct {
	CondSince  time.Time `json:"cond_since,omitempty"` // path B condition holding since
	CondLast   time.Time `json:"cond_last,omitempty"`
	CompPolls  int       `json:"comp_polls"` // consecutive polls at the fast-path level
	CompLast   time.Time `json:"comp_last,omitempty"`
	LastPollAt time.Time `json:"last_poll,omitempty"`
}

// State is everything a restart needs. It is persisted fsynced, versioned.
type State struct {
	Version       int                  `json:"version"`
	Episode       *Episode             `json:"episode,omitempty"`
	Groups        map[string]*Record   `json:"groups"`
	LastResume    map[string]time.Time `json:"last_resume,omitempty"`
	CooldownUntil time.Time            `json:"cooldown_until,omitempty"`
	LastPauseAt   time.Time            `json:"last_pause_at,omitempty"`
	Trk           Trackers             `json:"trk"`

	// Unreadable is set by the store when the file is valid JSON with a
	// version this build cannot interpret; only Groups' minimal envelope
	// (pgid, start, members) is trusted then.
	Unreadable bool `json:"-"`
}

func newState() State {
	return State{Version: StateVersion, Groups: map[string]*Record{}, LastResume: map[string]time.Time{}}
}

func (s *State) init() {
	if s.Groups == nil {
		s.Groups = map[string]*Record{}
	}
	if s.LastResume == nil {
		s.LastResume = map[string]time.Time{}
	}
	if e := s.Episode; e != nil {
		if e.Baselines == nil {
			e.Baselines = map[string]uint64{}
		}
		if e.DangerBase == nil {
			e.DangerBase = map[string]uint64{}
		}
		if e.D4 == nil {
			e.D4 = map[string]bool{}
		}
		if e.P1 == nil {
			e.P1 = map[string]bool{}
		}
		if e.Resumed == nil {
			e.Resumed = map[string]bool{}
		}
		if e.Unprotected == nil {
			e.Unprotected = map[string]bool{}
		}
	}
}

// Clone returns a deep copy.
func (s State) Clone() State {
	c := s
	c.Groups = make(map[string]*Record, len(s.Groups))
	for k, r := range s.Groups {
		rc := *r
		rc.Members = append([]RecMember(nil), r.Members...)
		rc.PathA.Pts = append([]PathAPt(nil), r.PathA.Pts...)
		rc.Already = append([]PidStart(nil), r.Already...)
		rc.Signals = append([]string(nil), r.Signals...)
		c.Groups[k] = &rc
	}
	c.LastResume = make(map[string]time.Time, len(s.LastResume))
	for k, v := range s.LastResume {
		c.LastResume[k] = v
	}
	if s.Episode != nil {
		e := *s.Episode
		e.Baselines = cloneU(s.Episode.Baselines)
		e.DangerBase = cloneU(s.Episode.DangerBase)
		e.D4 = cloneB(s.Episode.D4)
		e.P1 = cloneB(s.Episode.P1)
		e.Resumed = cloneB(s.Episode.Resumed)
		e.Unprotected = cloneB(s.Episode.Unprotected)
		c.Episode = &e
	}
	return c
}

func cloneU(m map[string]uint64) map[string]uint64 {
	o := make(map[string]uint64, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

func cloneB(m map[string]bool) map[string]bool {
	o := make(map[string]bool, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// sortedRecords returns the records in key order for deterministic output.
func (s *State) sortedRecords() []*Record {
	out := make([]*Record, 0, len(s.Groups))
	for _, r := range s.Groups {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PGID < out[j].PGID })
	return out
}
