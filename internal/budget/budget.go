// Package budget reads run_capped sidecars
// (~/.agent-harness/state/run_capped/<wrapper-pid>.json) and decides
// whether a process group runs inside a verified declared budget. Every
// check in the spec's sidecar list must pass or the sidecar is ignored.
package budget

import "time"

// Sidecar is the on-disk schema written by run_capped.
type Sidecar struct {
	WrapperPID int     `json:"wrapper_pid"`
	PGID       int     `json:"pgid"`
	ChildPID   int     `json:"child_pid"`
	MaxRSSGB   float64 `json:"max_rss_gb"`
	MaxProcs   int     `json:"max_procs"`
	TimeoutS   float64 `json:"timeout_s"`
	StartedAt  float64 `json:"started_at"` // unix seconds
	Host       string  `json:"host"`
	Argv0      string  `json:"argv0"`
}

// Declared is a verified budget for one group.
type Declared struct {
	PGID     int
	MaxBytes uint64 // clamped to 50% of RAM; most restrictive sidecar wins
	MaxProcs int
	Wrapper  int
	Since    time.Time
}

// MaxSidecarBytes caps one sidecar read.
const MaxSidecarBytes = 64 << 10
