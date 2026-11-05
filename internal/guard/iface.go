// Package guard is the host-protection state machine: on host danger it
// alerts, pauses (SIGSTOP) the agent-owned process group that caused it,
// resumes when danger clears and, only in pause+kill mode and only under
// the kill gate, kills it. The rules follow the guard spec and its plan
// amendments A1-A8; every rule has a named test.
//
// The machine is pure: it takes a Snapshot and the time and returns
// Actions. An Executor applies actions through a Signaller, and a Store
// persists the episode so a crash restart can adopt paused groups.
package guard

import (
	"syscall"
	"time"
)

// Mode is the guard mode.
type Mode string

// Modes.
const (
	ModeOff       Mode = "off"
	ModeAlert     Mode = "alert"
	ModePause     Mode = "pause"
	ModePauseKill Mode = "pause+kill"
)

// Tier says what the guard may do to a group.
type Tier int

// Tiers, from most to least capable.
const (
	TierNone       Tier = iota // ineligible: alert only
	TierFallback               // CLAUDECODE + no tty: pause only
	TierUnverified             // pending child exited unseen: pause only
	TierTool                   // verified tool-shell group: pause and (gated) kill
)

// Member is one process in a group, identified by (PID, Start).
type Member struct {
	PID      int
	PPID     int // lets the executor signal top-down
	Start    time.Time
	Excluded bool // never signalled (exclusion rule or never-signal list)
	Stopped  bool // already in state T when observed
}

// Group is one agent-owned process group as the guard sees it.
type Group struct {
	PGID        int
	LeaderStart time.Time
	Tier        Tier
	Members     []Member
	Footprint   uint64 // bytes, members only (excluded subtrees not counted)
	Agent       string // attribution label, informational only
	Cmd         string // redacted, short
	ClaudeVer   string
	Allowlisted bool // ClaudeVer is in the kill allowlist
	EnvOK       bool // CLAUDECODE=1 and CLAUDE_PID matches the record
	Budget      *Budget
	FromWatcher bool
}

// Budget is a verified run_capped declaration.
type Budget struct {
	MaxBytes uint64 // already clamped to 50% of RAM
	MaxProcs int
}

// Signaller sends one signal to one process, but only if the process
// still has the given start time. Implementations re-read the start time
// immediately before kill(2).
type Signaller interface {
	Signal(pid int, start time.Time, sig syscall.Signal) error
}

// Notifier delivers a user-visible notification.
type Notifier interface {
	Notify(key, title, msg string) (bool, error)
}

// SigCONT is SIGCONT on every platform the package builds for (Windows has
// no syscall.SIGCONT), for callers that inspect a signal.
const SigCONT = sigCONT
