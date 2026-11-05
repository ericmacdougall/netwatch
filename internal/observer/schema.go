// Package observer defines the resource observer document (schema 1) that
// netwatch emits under the "observer" key of `report --json`, and the rules
// the Python harness (deadman.py) relies on. The contract lives in
// agent-harness docs/observer.md (goodqa#14547); the golden sample under
// testdata is vendored from it and pinned by sha256.
package observer

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SchemaVersion is the contract version this package reads and writes.
const SchemaVersion = 1

// MaxArgv is the longest argv_masked value, in characters.
const MaxArgv = 512

// Attribution states.
const (
	StateAttributed   = "attributed"
	StateUnattributed = "unattributed"
	StateConflict     = "conflict"
	StateHookSSH      = "hook-ssh"
)

// Claim is one source's answer to "which task owns this process".
type Claim struct {
	Task    string `json:"task"`
	Agent   string `json:"agent"`
	Ticket  string `json:"ticket"`
	Session string `json:"session"`
	RunID   string `json:"run_id"`
}

// Attribution is the attribution object of a sample or writer. Only the
// fields of its state are set.
type Attribution struct {
	State string `json:"state"`
	Claim
	Via string `json:"via,omitempty"`
	// Detail is "env-only" when the only evidence is the process environment
	// (no verified or hook-ssh ancestry row), so readers can weight it.
	Detail   string `json:"detail,omitempty"`
	Env      *Claim `json:"env,omitempty"`
	Ancestry *Claim `json:"ancestry,omitempty"`
}

// MarshalJSON writes only the fields that belong to the state.
func (a Attribution) MarshalJSON() ([]byte, error) {
	switch a.State {
	case StateAttributed, StateHookSSH:
		type full struct {
			State string `json:"state"`
			Claim
			Via      string `json:"via"`
			Detail   string `json:"detail,omitempty"`
			Ancestry *Claim `json:"ancestry,omitempty"`
		}
		f := full{State: a.State, Claim: a.Claim, Via: a.Via, Detail: a.Detail}
		if a.State == StateHookSSH {
			f.Ancestry = a.Ancestry
		}
		return json.Marshal(f)
	case StateConflict:
		return json.Marshal(struct {
			State    string `json:"state"`
			Env      *Claim `json:"env"`
			Ancestry *Claim `json:"ancestry"`
		}{a.State, a.Env, a.Ancestry})
	}
	return json.Marshal(struct {
		State string `json:"state"`
	}{a.State})
}

// Sample is one process reading.
type Sample struct {
	Schema         int         `json:"schema"`
	Host           string      `json:"host"`
	At             string      `json:"at"`
	PID            int64       `json:"pid"`
	PPID           int64       `json:"ppid"`
	PGID           *int64      `json:"pgid"`
	Cgroup         *string     `json:"cgroup"`
	UID            int64       `json:"uid"`
	StartToken     string      `json:"start_token"`
	RSSBytes       int64       `json:"rss_bytes"`
	CPUSeconds     float64     `json:"cpu_seconds"`
	DiskWriteBytes *int64      `json:"disk_write_bytes"`
	DiskReadBytes  *int64      `json:"disk_read_bytes"`
	NetTxBytes     *int64      `json:"net_tx_bytes"`
	NetRxBytes     *int64      `json:"net_rx_bytes"`
	ArgvMasked     string      `json:"argv_masked"`
	Attribution    Attribution `json:"attribution"`
}

// Dir is a growing directory under a watched root.
type Dir struct {
	Path               string `json:"path"`
	GrowthBytesPerHour int64  `json:"growth_bytes_per_hour"`
}

// Volume is per-filesystem disk use, keyed by filesystem id, not mount name.
type Volume struct {
	FSID               string   `json:"fsid"`
	Mounts             []string `json:"mounts"`
	TotalBytes         int64    `json:"total_bytes"`
	FreeBytes          int64    `json:"free_bytes"`
	GrowthBytesPerHour int64    `json:"growth_bytes_per_hour"`
	TopGrowingDirs     []Dir    `json:"top_growing_dirs"`
}

// Writer is one of the top disk writers by delta.
type Writer struct {
	PID                 int64       `json:"pid"`
	DiskWriteBytesDelta int64       `json:"disk_write_bytes_delta"`
	Attribution         Attribution `json:"attribution"`
}

// Document is the schema-1 observer document.
type Document struct {
	Schema     int      `json:"schema"`
	Host       string   `json:"host"`
	At         string   `json:"at"`
	Volumes    []Volume `json:"volumes"`
	TopWriters []Writer `json:"top_writers"`
	Samples    []Sample `json:"samples"`
}

// Secret is the harness usage_guard.SECRET pattern, translated to RE2.
var Secret = regexp.MustCompile(`(?:ghp_|github_pat_|sk-ant-)[A-Za-z0-9_-]{16,}|-----BEGIN .*PRIVATE KEY-----|(?i:api[_-]?key|password|access[_-]?token|authorization)\s*[:=]\s*\S+`)

var (
	tokenRE = regexp.MustCompile(`^(proc|ps|win):.+$`)
	runIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fsidRE  = regexp.MustCompile(`^0x[0-9a-f]+$`)
)

// ParseTime accepts both RFC3339 forms (`Z` and `+00:00`).
func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func validClaim(c Claim) bool {
	return c.Task != "" && c.Agent != "" && c.Ticket != "" && c.Session != "" && runIDRE.MatchString(c.RunID)
}

// Validate enforces the contract rules on a decoded document.
func (d Document) Validate() error {
	if d.Schema != SchemaVersion {
		return fmt.Errorf("schema %d, want %d", d.Schema, SchemaVersion)
	}
	if d.Host == "" {
		return errors.New("empty host")
	}
	if _, err := ParseTime(d.At); err != nil {
		return fmt.Errorf("at: %w", err)
	}
	for _, v := range d.Volumes {
		if !fsidRE.MatchString(v.FSID) {
			return fmt.Errorf("volume fsid %q", v.FSID)
		}
		if len(v.TopGrowingDirs) > 5 {
			return fmt.Errorf("volume %s has %d growing dirs, max 5", v.FSID, len(v.TopGrowingDirs))
		}
		if v.TotalBytes < 0 || v.FreeBytes < 0 {
			return fmt.Errorf("volume %s negative size", v.FSID)
		}
	}
	if len(d.TopWriters) > 5 {
		return fmt.Errorf("%d top writers, max 5", len(d.TopWriters))
	}
	for _, w := range d.TopWriters {
		if err := w.Attribution.validate(); err != nil {
			return fmt.Errorf("writer %d: %w", w.PID, err)
		}
	}
	for _, s := range d.Samples {
		if err := s.validate(); err != nil {
			return fmt.Errorf("sample pid %d: %w", s.PID, err)
		}
	}
	return nil
}

func (s Sample) validate() error {
	if s.Schema != SchemaVersion {
		return fmt.Errorf("schema %d", s.Schema)
	}
	if _, err := ParseTime(s.At); err != nil {
		return fmt.Errorf("at: %w", err)
	}
	if !tokenRE.MatchString(s.StartToken) {
		return fmt.Errorf("start_token %q", s.StartToken)
	}
	if n := len([]rune(s.ArgvMasked)); n > MaxArgv {
		return fmt.Errorf("argv_masked is %d characters, max %d", n, MaxArgv)
	}
	if Secret.MatchString(s.ArgvMasked) {
		return errors.New("argv_masked holds an unmasked secret")
	}
	return s.Attribution.validate()
}

func (a Attribution) validate() error {
	switch a.State {
	case StateAttributed, StateHookSSH:
		if !validClaim(a.Claim) {
			return fmt.Errorf("%s needs task, agent, ticket, session and a 32-hex run_id", a.State)
		}
		switch a.Via {
		case "env", "ancestry", "both":
		default:
			return fmt.Errorf("via %q", a.Via)
		}
		if a.Detail != "" && (a.Detail != "env-only" || a.Via != "env") {
			return fmt.Errorf("detail %q is only valid as env-only with via env", a.Detail)
		}
		if a.State == StateAttributed && a.Ancestry != nil {
			return errors.New("attributed must not carry an ancestry object")
		}
	case StateConflict:
		if a.Env == nil || a.Ancestry == nil || !validClaim(*a.Env) || !validClaim(*a.Ancestry) {
			return errors.New("conflict needs complete env and ancestry claims")
		}
		if *a.Env == *a.Ancestry {
			return errors.New("conflict claims are equal; that is not a conflict")
		}
	case StateUnattributed:
		if a.Claim != (Claim{}) || a.Via != "" || a.Env != nil || a.Ancestry != nil {
			return errors.New("unattributed carries no fields")
		}
	default:
		return fmt.Errorf("unknown attribution state %q", a.State)
	}
	return nil
}

// extraSecret masks what Secret misses: the credential after an
// "Authorization: Bearer" prefix (Secret stops at the word Bearer) and the
// value of a secret-named command-line flag. It only ever redacts more.
var extraSecret = regexp.MustCompile(`(?i)\bbearer\s+\S+|(--?(?:token|password|passwd|secret|api[_-]?key|access[_-]?token)(?:\s+|=))\S+`)

// Mask applies the secret mask to argv and caps it at MaxArgv characters.
func Mask(argv string) string {
	out := argv
	out = extraSecret.ReplaceAllStringFunc(out, func(m string) string {
		if loc := extraSecret.FindStringSubmatch(m); loc[1] != "" {
			return loc[1] + "****"
		}
		return "****"
	})
	out = Secret.ReplaceAllString(out, "****") // after extraSecret: it would eat the word Bearer and keep the token
	if r := []rune(out); len(r) > MaxArgv {
		out = string(r[:MaxArgv])
	}
	return strings.ToValidUTF8(out, "")
}
