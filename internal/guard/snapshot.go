package guard

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Point is one footprint sample of a term.
type Point = danger.Point

// Term is one footprint series the tracker keeps: an agent group, an
// ineligible aggregate or "unattributed". Series is oldest first and
// covers at least the last 60s when available.
type Term struct {
	Key    string // "pg:<pgid>:<leader start unix ns>", "inel:<app>", "unattributed"
	Group  *Group // nil for aggregates
	Series []Point
}

// Snapshot is everything the state machine sees at one poll.
type Snapshot struct {
	At       time.Time
	Sys      resources.System
	Signals  danger.Signals
	Terms    []Term
	ScanAt   time.Time // time of the last full scan
	ScanOK   bool      // the last full scan succeeded
	SelfTest error     // non-nil disables pause and kill

	// Alive reports whether a process is still the same process (pid and
	// start). Optional: a nil Alive means "unknown", and the machine then
	// never drops a paused record on its own.
	Alive func(pid int, start time.Time) bool
}

// ActionKind is what the executor must do.
type ActionKind int

// Action kinds.
const (
	ActAlert ActionKind = iota
	ActPause
	ActResume
	ActTerm // SIGTERM while stopped, then SIGCONT
	ActKill // SIGKILL
	ActUnprotected
)

// Action is one decision. Reason is human-readable and names the rule.
type Action struct {
	Kind   ActionKind
	PGID   int
	Start  time.Time
	Reason string

	// Fields the executor and the event log need. Members is what to
	// signal: never includes excluded members.
	Members     []Member
	Signals     []string // danger signal names that justified the action
	DangerSince time.Time
	Prong       string // kill: the path and causation prong that passed
	Cmd, Agent  string // redacted, informational
	Footprint   uint64
}
