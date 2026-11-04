// Package record defines the JSON records netwatch writes to
// samples.jsonl and events.jsonl. Field names follow the original prototype
// so old logs remain readable.
package record

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/ericmacdougall/netwatch/internal/health"
)

// Event names.
const (
	Start         = "START"
	Stop          = "STOP"
	NewNetApp     = "NEW_NET_APP"
	Degraded      = "DEGRADED"
	Recovered     = "RECOVERED"
	Orphan        = "ORPHAN"
	Runaway       = "RUNAWAY"
	OrphansKilled = "ORPHANS_KILLED"

	// Resource and guard events (GoodQA work-tracker-automatic#35742).
	ResourceAlert         = "RESOURCE_ALERT"
	GuardPause            = "GUARD_PAUSE"
	GuardResume           = "GUARD_RESUME"
	GuardKill             = "GUARD_KILL"
	HostAtRiskUnprotected = "HOST_AT_RISK_UNPROTECTED"
	ModeChange            = "MODE_CHANGE"
	Incident              = "INCIDENT"
	AllowlistChange       = "ALLOWLIST_CHANGE"
	GuardTestTarget       = "GUARD_TEST_TARGET"
)

// FlexInt decodes a JSON number or numeric string; the prototype wrote
// some PIDs as strings.
type FlexInt int

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		v, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return err
		}
		n = int(v)
	}
	*f = FlexInt(n)
	return nil
}

// Talker is one entry of a top-talkers list. Rates are kilobytes per second.
type Talker struct {
	Proc    string  `json:"proc"`
	PID     FlexInt `json:"pid,omitempty"`
	InKBps  float64 `json:"in_kBps"`
	OutKBps float64 `json:"out_kBps"`
	Conns   int     `json:"conns,omitempty"`
}

// UnmarshalJSON also accepts the prototype's "name.pid" proc strings and
// its misnamed in_kbps/out_kbps keys (which were kB/s all along).
func (t *Talker) UnmarshalJSON(b []byte) error {
	type plain Talker
	var aux struct {
		plain
		LegacyIn  *float64 `json:"in_kbps"`
		LegacyOut *float64 `json:"out_kbps"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*t = Talker(aux.plain)
	if aux.LegacyIn != nil && t.InKBps == 0 {
		t.InKBps = *aux.LegacyIn
	}
	if aux.LegacyOut != nil && t.OutKBps == 0 {
		t.OutKBps = *aux.LegacyOut
	}
	if t.PID == 0 {
		if i := strings.LastIndexByte(t.Proc, '.'); i > 0 {
			if n, err := strconv.Atoi(t.Proc[i+1:]); err == nil {
				t.Proc, t.PID = t.Proc[:i], FlexInt(n)
			}
		}
	}
	return nil
}

// SelfUsage is netwatch's own resource use over the last interval,
// including the helper commands it runs.
type SelfUsage struct {
	CPUPct float64 `json:"cpu_pct"`
	RSSMB  float64 `json:"rss_mb"`
}

// Sample is one line of samples.jsonl.
type Sample struct {
	TS        string       `json:"ts"`
	Iface     string       `json:"iface,omitempty"`
	GW        *health.Ping `json:"gw"`
	Net       *health.Ping `json:"net"`
	InKBps    float64      `json:"in_kBps"`
	OutKBps   float64      `json:"out_kBps"`
	IfInKBps  *float64     `json:"if_in_kBps,omitempty"`
	IfOutKBps *float64     `json:"if_out_kBps,omitempty"`
	Top       []Talker     `json:"top"`
	Self      *SelfUsage   `json:"self,omitempty"`
}

// KillResult records what happened to one PID during orphans --kill.
type KillResult struct {
	PID    int    `json:"pid"`
	Result string `json:"result"`
}

// Event is one line of events.jsonl. Fields not used by an event type are
// omitted.
type Event struct {
	TS    string `json:"ts"`
	Event string `json:"event"`

	// START
	Version    string `json:"version,omitempty"`
	OS         string `json:"os,omitempty"`
	KnownProcs *int   `json:"known_procs,omitempty"`

	// NEW_NET_APP
	Proc          string   `json:"proc,omitempty"`
	FirstSeenName *bool    `json:"first_seen_name,omitempty"`
	Conns         *int     `json:"conns,omitempty"`
	InKBps        *float64 `json:"in_kBps,omitempty"`
	OutKBps       *float64 `json:"out_kBps,omitempty"`

	// DEGRADED / RECOVERED (and NEW_NET_APP's gw)
	Iface string       `json:"iface,omitempty"`
	GW    *health.Ping `json:"gw,omitempty"`
	Net   *health.Ping `json:"net,omitempty"`
	Top   []Talker     `json:"top,omitempty"`

	// ORPHAN / RUNAWAY
	Reason string   `json:"reason,omitempty"`
	PID    FlexInt  `json:"pid,omitempty"`
	PPID   FlexInt  `json:"ppid,omitempty"`
	AgeH   *float64 `json:"age_h,omitempty"`
	CPU    *float64 `json:"cpu,omitempty"`
	RSSMB  *int     `json:"rss_mb,omitempty"`
	Cmd    string   `json:"cmd,omitempty"`

	// ORPHANS_KILLED
	PIDs    []int        `json:"pids,omitempty"`
	Results []KillResult `json:"results,omitempty"`
}

// Ptr returns a pointer to v, for optional fields.
func Ptr[T any](v T) *T { return &v }
