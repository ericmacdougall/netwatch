package shapecheck

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/safeio"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// AllowlistFile is the version allowlist inside the state directory.
const AllowlistFile = "allowlist.json"

type allowlist struct {
	Versions []string `json:"versions"`
	Updated  string   `json:"updated"`
}

func readAllowlist(dir string) (allowlist, error) {
	var a allowlist
	err := safeio.ReadJSON(filepath.Join(dir, AllowlistFile), safeio.Opts{Max: 64 << 10, RequireOwner: true, MaxPerm: 0o600}, &a)
	if errors.Is(err, fs.ErrNotExist) {
		return allowlist{}, nil
	}
	return a, err
}

// Allowed reports whether version is on the allowlist in dir. An unreadable
// or unsafe file means not allowed (fail closed).
func Allowed(dir, version string) bool {
	a, err := readAllowlist(dir)
	if err != nil {
		return false
	}
	for _, v := range a.Versions {
		if v == version {
			return true
		}
	}
	return false
}

// Allow adds version to the allowlist atomically (0600 file in a 0700 dir)
// and reports whether it was newly added.
func Allow(dir, version string, now time.Time) (bool, error) {
	if version == "" {
		return false, errors.New("shapecheck: empty version")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	a, err := readAllowlist(dir)
	if err != nil {
		return false, err
	}
	for _, v := range a.Versions {
		if v == version {
			return false, nil
		}
	}
	a.Versions = append(a.Versions, version)
	sort.Strings(a.Versions)
	a.Updated = now.Format(eventlog.TimeFormat)
	b, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	return true, safeio.WriteFileAtomic(dir, AllowlistFile, b)
}

// Appender is satisfied by *eventlog.Writer.
type Appender interface{ Append(rec any) error }

// Config wires one check to its sources and outputs.
type Config struct {
	Version       string
	StateDir      string
	SettingsPaths []string
	Children      func() []Child
	Calls         func(from, to time.Time) ([]transcript.Call, error)
	Events        Appender
	// Window is how far back observations are looked at; default 24h.
	Window time.Duration
}

// Run performs one check and, on a pass, allowlists the version and logs
// ALLOWLIST_CHANGE. An inconclusive or failed check changes nothing.
func Run(cfg Config, now time.Time) (Result, error) {
	if cfg.Window <= 0 {
		cfg.Window = 24 * time.Hour
	}
	in := Input{Version: cfg.Version, Settings: LoadSettings(cfg.SettingsPaths)}
	if cfg.Children != nil {
		in.Children = cfg.Children()
	}
	if cfg.Calls != nil {
		calls, err := cfg.Calls(now.Add(-cfg.Window), now)
		if err != nil {
			return Result{Version: cfg.Version, Verdict: Inconclusive, Reason: "transcripts unreadable"}, err
		}
		in.Calls = calls
	}
	res := Check(in)
	if res.Verdict != Pass {
		return res, nil
	}
	added, err := Allow(cfg.StateDir, cfg.Version, now)
	if err != nil {
		return res, err
	}
	if added && cfg.Events != nil {
		ev := record.Event{TS: now.Format(eventlog.TimeFormat), Event: record.AllowlistChange, Version: cfg.Version,
			Reason: "shape check passed: " + res.Reason}
		if err := cfg.Events.Append(ev); err != nil {
			return res, err
		}
	}
	return res, nil
}

// Retry limits for an inconclusive check (A4): hourly, at most 24 times.
const (
	RetryInterval = time.Hour
	MaxAttempts   = 24
)

// Schedule decides when a version's check should run again.
type Schedule struct {
	attempts int
	last     time.Time
	done     bool
}

// Due reports whether a check should run now.
func (s *Schedule) Due(now time.Time) bool {
	if s.done || s.attempts >= MaxAttempts {
		return false
	}
	return s.last.IsZero() || now.Sub(s.last) >= RetryInterval
}

// Record notes an attempt. Only an inconclusive result is retried: a pass
// or a fail is final for the version.
func (s *Schedule) Record(now time.Time, v Verdict) {
	s.attempts++
	s.last = now
	if v != Inconclusive {
		s.done = true
	}
}

// Attempts is how many checks have run.
func (s *Schedule) Attempts() int { return s.attempts }

// Exhausted reports that every retry was used without a verdict.
func (s *Schedule) Exhausted() bool { return !s.done && s.attempts >= MaxAttempts }
