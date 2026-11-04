package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/redact"
)

// Limits on the resources summary.
const (
	maxTopProcs   = 5
	maxGuardTail  = 5
	maxReportCmd  = 120
	maxReportText = 200
)

// ResRow is one process row of a resources.jsonl record, as far as the
// report reads it. Unknown fields are ignored so the sampler can grow.
type ResRow struct {
	PID       int    `json:"pid"`
	Start     string `json:"start"`
	Name      string `json:"name"`
	Footprint uint64 `json:"footprint"`
	Agent     string `json:"agent"`
	Cmd       string `json:"cmd"`
}

// ResRecord is one resources.jsonl line.
type ResRecord struct {
	TS            string  `json:"ts"`
	Pressure      string  `json:"pressure"`
	CompressorPct float64 `json:"compressor_pct"`
	SwapUsed      uint64  `json:"swap_used"`
	Sys           struct {
		Headroom *uint64 `json:"headroom_bytes"`
	} `json:"sys"`
	TopMem []ResRow `json:"top_mem"`
}

// TSOf is the timestamp accessor for eventlog.ReadSince.
func (r ResRecord) TSOf() string { return r.TS }

// flexText decodes any JSON scalar as text, so a field that one version
// writes as a string and another as a number never drops the whole line.
type flexText string

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexText) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexText(s)
		return nil
	}
	if len(b) > 0 && (b[0] == '{' || b[0] == '[') {
		*f = ""
		return nil
	}
	if string(b) == "null" {
		*f = ""
		return nil
	}
	*f = flexText(b)
	return nil
}

// GuardEvent is the part of an events.jsonl line the memory summary reads.
type GuardEvent struct {
	TS     string   `json:"ts"`
	Event  string   `json:"event"`
	PGID   flexText `json:"pgid"`
	Agent  flexText `json:"agent"`
	Reason flexText `json:"reason"`
}

// TSOf is the timestamp accessor for eventlog.ReadSince.
func (g GuardEvent) TSOf() string { return g.TS }

// ReadResources reads the window's records and guard events. Missing or
// unreadable files give empty results: the memory summary is best effort and
// must never make `report` fail.
func ReadResources(resPath, evPath string, from time.Time) ([]ResRecord, []GuardEvent) {
	recs, _ := eventlog.ReadSince(resPath, from, ResRecord.TSOf)
	evs, _ := eventlog.ReadSince(evPath, from, GuardEvent.TSOf)
	return recs, evs
}

// IsMemoryEvent reports events that belong to the memory summary.
func IsMemoryEvent(name string) bool {
	switch name {
	case record.ResourceAlert, record.GuardPause, record.GuardResume, record.GuardKill,
		record.HostAtRiskUnprotected, record.ModeChange:
		return true
	}
	return false
}

// TopProc is one process in the peak-footprint ranking.
type TopProc struct {
	Name      string `json:"name"`
	PID       int    `json:"pid"`
	PeakBytes uint64 `json:"peak_bytes"`
	Agent     string `json:"agent,omitempty"`
	Cmd       string `json:"cmd,omitempty"`
}

// GuardLine is one guard event in the tail.
type GuardLine struct {
	TS     string `json:"ts"`
	Event  string `json:"event"`
	PGID   int    `json:"pgid,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Resources is the memory summary of a window. With no samples it encodes
// as {"samples":0} (plus empty count maps for alerts and guard events when
// any exist).
type Resources struct {
	Samples          int            `json:"samples"`
	Pressure         map[string]int `json:"pressure,omitempty"`
	MaxCompressorPct *float64       `json:"max_compressor_pct,omitempty"`
	MaxSwapUsed      *uint64        `json:"max_swap_used,omitempty"`
	MinHeadroom      *uint64        `json:"min_headroom_bytes,omitempty"`
	TopProcs         []TopProc      `json:"top_procs,omitempty"`
	Alerts           map[string]int `json:"alerts,omitempty"`
	GuardActions     map[string]int `json:"guard_actions,omitempty"`
	LastGuardEvents  []GuardLine    `json:"last_guard_events,omitempty"`
}

// Summarize builds the memory summary. Every string from the logs is passed
// through the redactor: logs written by other versions or by hand are not
// trusted to be clean.
func Summarize(recs []ResRecord, evs []GuardEvent) Resources {
	r := Resources{Samples: len(recs)}
	type key struct {
		pid   int
		start string
	}
	peak := map[key]*TopProc{}
	for _, rec := range recs {
		if r.Pressure == nil {
			r.Pressure = map[string]int{}
		}
		lvl := strings.ToLower(redact.Display(rec.Pressure))
		if lvl == "" {
			lvl = "unknown"
		}
		r.Pressure[lvl]++
		if r.MaxCompressorPct == nil || rec.CompressorPct > *r.MaxCompressorPct {
			v := rec.CompressorPct
			r.MaxCompressorPct = &v
		}
		if r.MaxSwapUsed == nil || rec.SwapUsed > *r.MaxSwapUsed {
			v := rec.SwapUsed
			r.MaxSwapUsed = &v
		}
		if h := rec.Sys.Headroom; h != nil && (r.MinHeadroom == nil || *h < *r.MinHeadroom) {
			v := *h
			r.MinHeadroom = &v
		}
		for _, row := range rec.TopMem {
			k := key{row.PID, row.Start}
			p := peak[k]
			if p == nil {
				p = &TopProc{PID: row.PID}
				peak[k] = p
			}
			if row.Footprint >= p.PeakBytes {
				p.PeakBytes = row.Footprint
				p.Name = clip(redact.Display(row.Name), 60)
				p.Cmd = clip(redact.Display(row.Cmd), maxReportCmd)
				if row.Agent != "" {
					p.Agent = clip(redact.Display(row.Agent), 60)
				}
			}
		}
	}
	for _, p := range peak {
		r.TopProcs = append(r.TopProcs, *p)
	}
	sort.Slice(r.TopProcs, func(i, j int) bool {
		a, b := r.TopProcs[i], r.TopProcs[j]
		if a.PeakBytes != b.PeakBytes {
			return a.PeakBytes > b.PeakBytes
		}
		return a.PID < b.PID
	})
	if len(r.TopProcs) > maxTopProcs {
		r.TopProcs = r.TopProcs[:maxTopProcs]
	}

	var guardEvs []GuardLine
	for _, e := range evs {
		if !IsMemoryEvent(e.Event) {
			continue
		}
		if e.Event == record.ResourceAlert {
			if r.Alerts == nil {
				r.Alerts = map[string]int{}
			}
			r.Alerts[alertTrigger(string(e.Reason))]++
			continue
		}
		if r.GuardActions == nil {
			r.GuardActions = map[string]int{}
		}
		r.GuardActions[e.Event]++
		guardEvs = append(guardEvs, GuardLine{TS: e.TS, Event: e.Event, PGID: atoi(string(e.PGID)),
			Agent:  clip(redact.Display(string(e.Agent)), 60),
			Reason: clip(redact.Display(string(e.Reason)), maxReportText)})
	}
	if n := len(guardEvs); n > maxGuardTail {
		guardEvs = guardEvs[n-maxGuardTail:]
	}
	r.LastGuardEvents = guardEvs
	return r
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// alertTrigger extracts "growth_over_limit" from "growth_over_limit: ...".
func alertTrigger(reason string) string {
	if i := strings.IndexByte(reason, ':'); i > 0 {
		reason = reason[:i]
	}
	reason = strings.TrimSpace(redact.Display(reason))
	if reason == "" || len(reason) > 40 || strings.ContainsAny(reason, " \t") {
		return "other"
	}
	return reason
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func gb(b uint64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%d MB", b>>20)
}

// writeMemory appends the short "Memory" section. It prints nothing when
// the window holds no memory data, so reports from hosts without the
// resource sampler read exactly as before.
func (r Resources) writeMemory(b *strings.Builder) {
	if r.Samples == 0 && len(r.Alerts) == 0 && len(r.GuardActions) == 0 {
		return
	}
	b.WriteString("  Memory:\n")
	if r.Samples > 0 {
		fmt.Fprintf(b, "    %d samples; pressure %s", r.Samples, countList(r.Pressure))
		if r.MaxCompressorPct != nil {
			fmt.Fprintf(b, "; compressor max %.0f%%", *r.MaxCompressorPct)
		}
		if r.MaxSwapUsed != nil {
			fmt.Fprintf(b, "; swap max %s", gb(*r.MaxSwapUsed))
		}
		if r.MinHeadroom != nil {
			fmt.Fprintf(b, "; headroom min %s", gb(*r.MinHeadroom))
		}
		b.WriteString("\n")
	}
	for _, p := range r.TopProcs {
		fmt.Fprintf(b, "    %-10s %-24s pid %-7d", gb(p.PeakBytes), clip(p.Name, 24), p.PID)
		if p.Agent != "" {
			fmt.Fprintf(b, " [%s]", p.Agent)
		}
		if p.Cmd != "" {
			fmt.Fprintf(b, " %s", clip(p.Cmd, 70))
		}
		b.WriteString("\n")
	}
	if len(r.Alerts) > 0 {
		fmt.Fprintf(b, "    alerts: %s\n", countList(r.Alerts))
	}
	if len(r.GuardActions) > 0 {
		fmt.Fprintf(b, "    guard: %s\n", countList(r.GuardActions))
	}
	for _, g := range r.LastGuardEvents {
		fmt.Fprintf(b, "      %s %s", g.TS, g.Event)
		if g.PGID != 0 {
			fmt.Fprintf(b, " pgid %d", g.PGID)
		}
		if g.Agent != "" {
			fmt.Fprintf(b, " [%s]", g.Agent)
		}
		if g.Reason != "" {
			fmt.Fprintf(b, " %s", g.Reason)
		}
		b.WriteString("\n")
	}
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
