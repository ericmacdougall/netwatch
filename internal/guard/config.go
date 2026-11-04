package guard

import (
	"time"

	"github.com/ericmacdougall/netwatch/internal/danger"
)

// Config holds every guard threshold. The defaults are the spec values.
type Config struct {
	Mode Mode
	// NoKill forbids the kill stage whatever the mode. It is set on macOS,
	// where kill eligibility cannot be verified (the environment of system
	// binaries is not readable), so pause+kill acts as pause there.
	NoKill bool
	Danger danger.Config

	ScanInterval time.Duration // a scan older than 2x this is stale (10s)

	PauseGap     time.Duration // at most 1 new pause per this (10s)
	MaxPaused    int           // groups paused at once (3)
	StickyWindow time.Duration // re-pause within this of a resume is sticky (10m)
	MaxPause     time.Duration // conditional resume after this (30m)
	MaxPauseWarn time.Duration // repeat alert while still critical (10m)
	AbsCap       time.Duration // unconditional resume (2h)
	RestoreHold  time.Duration // clear is ignored this long after a restart (30s)
	PauseGrowth  uint64        // "grew this much since danger began" is causal (2 GB)
	MaxMembers   int           // a group larger than this stops being chased (4096)
	UnstableAt   int           // polls with new members before we stop chasing (3)
	BatchSize    int           // members signalled per fsync batch

	PathAWindow   time.Duration // 60s
	PathAMinPolls int           // 25
	PathAMinCrit  int           // 25
	PathAGap      time.Duration // 6s
	PathBFrac     float64       // 0.95
	PathBHold     time.Duration // 20s
	FastPolls     int           // A2 fast path: consecutive polls at PathBFrac (2)

	ShareMin      float64 // growth share needed (0.5)
	ShareDenomMin uint64  // denominator floor (1 GB)

	KillGrace       time.Duration // SIGKILL this long after SIGTERM (5s)
	KillEarlyGrowth uint64        // or when the group grows more than this (1 GB)
	Cooldown        time.Duration // no new kill for this long after one (120s)

	// Test switches; production leaves all false.
	DisablePathA, DisablePathB, DisableFast bool
}

// DefaultConfig returns the spec defaults for mode.
func DefaultConfig(mode Mode) Config {
	return Config{
		Mode:   mode,
		Danger: danger.Defaults(),

		ScanInterval: 10 * time.Second,
		PauseGap:     10 * time.Second,
		MaxPaused:    3,
		StickyWindow: 10 * time.Minute,
		MaxPause:     30 * time.Minute,
		MaxPauseWarn: 10 * time.Minute,
		AbsCap:       2 * time.Hour,
		RestoreHold:  30 * time.Second,
		PauseGrowth:  2 << 30,
		MaxMembers:   4096,
		UnstableAt:   3,
		BatchSize:    16,

		PathAWindow:   60 * time.Second,
		PathAMinPolls: 25,
		PathAMinCrit:  25,
		PathAGap:      6 * time.Second,
		PathBFrac:     0.95,
		PathBHold:     20 * time.Second,
		FastPolls:     2,

		ShareMin:      0.5,
		ShareDenomMin: 1 << 30,

		KillGrace:       5 * time.Second,
		KillEarlyGrowth: 1 << 30,
		Cooldown:        120 * time.Second,
	}
}

// ModeRank orders the modes; the guard may pause at pause or above.
func (m Mode) canPause() bool { return m == ModePause || m == ModePauseKill }
func (m Mode) canKill() bool  { return m == ModePauseKill }

// DefaultModeFor returns the platform default: darwin pause, linux alert,
// windows off, anything else off. macOS is pause-only: kill needs every
// group member's environment to confirm its Claude Code parent, and macOS
// hides the environment of system binaries (/bin/zsh, /bin/bash) that
// lead every tool-call job, so kill could never fire there.
func DefaultModeFor(goos string) Mode {
	switch goos {
	case "darwin":
		return ModePause
	case "linux":
		return ModeAlert
	}
	return ModeOff
}
