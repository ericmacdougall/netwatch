// Package alerts raises the five early-warning alerts: a process over 8 GB,
// a group or aggregate growing over 2 GB/min, memory pressure at warn or
// worse, swap over 10 GB and more than 60 Chrome helpers.
//
// Alerts only tell the user. This package must never be able to signal a
// process, and TestNoSignalCapability enforces that on its source and on
// every package it depends on. For that reason it takes its own plain
// input types rather than importing the guard package.
package alerts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

// Trigger names (also the first word of the event Reason).
const (
	TrigProcess  = "process_over_limit"
	TrigGrowth   = "growth_over_limit"
	TrigPressure = "memory_pressure"
	TrigSwap     = "swap_over_limit"
	TrigChrome   = "chrome_helpers"
)

// Thresholds. Every comparison is strict: a value exactly at the limit does
// not alert.
const (
	gib = 1 << 30

	DefaultProcBytes   = 8 * gib
	DefaultGrowthBytes = 2 * gib // per minute
	DefaultSwapBytes   = 10 * gib
	DefaultChrome      = 60

	// minGrowthSpan is the shortest history a growth rate is computed
	// over. Shorter spans give meaningless rates from one noisy pair.
	minGrowthSpan = 20 * time.Second
)

// Config sets the thresholds; zero fields take the defaults.
type Config struct {
	ProcBytes     uint64
	GrowthPerMin  uint64
	SwapBytes     uint64
	ChromeHelpers int
	Cooldown      time.Duration // default 10 minutes
}

// Point is one footprint sample.
type Point struct {
	At    time.Time
	Bytes uint64
}

// Series is the footprint history of one tracked term (an agent group or an
// ineligible owner aggregate). "unattributed" must not be passed: it has no
// owner to warn about.
type Series struct {
	Key    string  // identity for rate limiting ("pg:..", "inel:<app>", ..)
	Points []Point // oldest first
	// Display: the job's short redacted command, its owner app and the
	// agent label. Empty fields are left out of the message.
	Name, App, Agent string
}

// label is how a series is named in a message: the job with its pgid, app
// and agent, or an aggregate's readable key, never "pg:<pgid>:<ns>".
func (s Series) label() string {
	pgid := ""
	if strings.HasPrefix(s.Key, "pg:") {
		if f := strings.SplitN(s.Key, ":", 3); len(f) == 3 {
			pgid = f[1]
		}
	}
	name := s.Name
	if name == "" {
		switch {
		case pgid != "":
			name = "job"
		default:
			name = redact.DisplayKey(s.Key)
		}
	}
	var parts []string
	if pgid != "" {
		parts = append(parts, "pgid "+pgid)
	}
	parts = append(parts, who(s.App, s.Agent)...)
	if len(parts) == 0 {
		return name
	}
	return name + " (" + strings.Join(parts, ", ") + ")"
}

func who(app, agent string) []string {
	var parts []string
	if app != "" {
		parts = append(parts, "app "+app)
	}
	if agent != "" {
		parts = append(parts, "agent "+agent)
	}
	return parts
}

// Input is everything one evaluation sees.
type Input struct {
	At     time.Time
	Sys    resources.System
	Procs  []resources.Proc // the last full scan
	Series []Series
	// Who gives a process's owner app and agent label (optional).
	Who func(p resources.Proc) (app, agent string)
}

// Alert is one raised alert.
type Alert struct {
	Trigger   string
	Subject   string // pid, term key or "host"
	Message   string
	PID       int
	Footprint uint64
	Reason    string
}

// Sink receives events.
type Sink interface{ Emit(record.Event) }

// Engine evaluates the triggers and rate-limits them.
type Engine struct {
	cfg    Config
	notify *notify.Limiter // desktop notifications (may be disabled)
	dedupe *notify.Limiter // event de-duplication; always on, sends nothing
	sink   Sink
	// Describe returns a redacted, short command line for a pid, or "".
	Describe func(pid int) string
	// Now stamps events; defaults to time.Now.
	Now func() time.Time
}

// New returns an engine. n may be nil (no notifications); sink may be nil.
func New(cfg Config, n *notify.Limiter, sink Sink) *Engine {
	if cfg.ProcBytes == 0 {
		cfg.ProcBytes = DefaultProcBytes
	}
	if cfg.GrowthPerMin == 0 {
		cfg.GrowthPerMin = DefaultGrowthBytes
	}
	if cfg.SwapBytes == 0 {
		cfg.SwapBytes = DefaultSwapBytes
	}
	if cfg.ChromeHelpers == 0 {
		cfg.ChromeHelpers = DefaultChrome
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 10 * time.Minute
	}
	e := &Engine{cfg: cfg, notify: n, sink: sink, Now: time.Now}
	e.dedupe = notify.New(true, cfg.Cooldown, func(string, string) error { return nil })
	return e
}

func procWho(f func(resources.Proc) (string, string), p resources.Proc) []string {
	if f == nil {
		return nil
	}
	return who(f(p))
}

// Evaluate returns the alerts that hold for in, in a stable order, without
// any rate limiting.
func (e *Engine) Evaluate(in Input) []Alert {
	var out []Alert

	// 1. A single process over the limit.
	for _, p := range in.Procs {
		if p.FootprintOK && p.Footprint > e.cfg.ProcBytes {
			out = append(out, Alert{Trigger: TrigProcess, Subject: fmt.Sprintf("pid:%d", p.PID), PID: p.PID, Footprint: p.Footprint,
				Message: fmt.Sprintf("%s (%s) uses %s", p.Name, strings.Join(append([]string{fmt.Sprintf("pid %d", p.PID)}, procWho(in.Who, p)...), ", "), human(p.Footprint))})
		}
	}

	// 2. Growth over the limit per minute.
	for _, s := range in.Series {
		if rate, ok := growthPerMin(s.Points); ok && rate > float64(e.cfg.GrowthPerMin) {
			last := s.Points[len(s.Points)-1].Bytes
			out = append(out, Alert{Trigger: TrigGrowth, Subject: s.Key, Footprint: last,
				Message: fmt.Sprintf("%s is growing %s/min (now %s)", s.label(), human(uint64(rate)), human(last))})
		}
	}

	// 3. Pressure.
	if in.Sys.Pressure == resources.LevelWarn || in.Sys.Pressure == resources.LevelCritical {
		out = append(out, Alert{Trigger: TrigPressure, Subject: "host:" + in.Sys.Pressure.String(),
			Message: "memory pressure is " + in.Sys.Pressure.String()})
	}

	// 4. Swap.
	if in.Sys.SwapUsed > e.cfg.SwapBytes {
		out = append(out, Alert{Trigger: TrigSwap, Subject: "host", Footprint: in.Sys.SwapUsed,
			Message: fmt.Sprintf("swap in use is %s", human(in.Sys.SwapUsed))})
	}

	// 5. Chrome helpers.
	if n := CountChromeHelpers(in.Procs); n > e.cfg.ChromeHelpers {
		out = append(out, Alert{Trigger: TrigChrome, Subject: "host",
			Message: fmt.Sprintf("%d Chrome helper processes are running", n)})
	}

	for i := range out {
		out[i].Reason = out[i].Trigger + ": " + out[i].Message
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Trigger != out[j].Trigger {
			return out[i].Trigger < out[j].Trigger
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// Run evaluates in, then notifies and emits an event for each alert that
// is not within its cooldown. It returns the alerts that were emitted.
func (e *Engine) Run(in Input) []Alert {
	var fired []Alert
	for _, a := range e.Evaluate(in) {
		key := a.Trigger + "|" + a.Subject
		if ok, _ := e.dedupe.Notify(key, "", ""); !ok {
			continue
		}
		fired = append(fired, a)
		if e.notify != nil {
			e.notify.Notify(key, "netwatch: "+strings.ReplaceAll(a.Trigger, "_", " "), a.Message)
		}
		if e.sink != nil {
			ev := record.Event{TS: e.Now().UTC().Format(time.RFC3339), Event: record.ResourceAlert, Reason: notify.Clean(a.Reason, 240)}
			if a.PID != 0 {
				ev.PID = record.FlexInt(a.PID)
				if e.Describe != nil {
					ev.Cmd = notify.Clean(e.Describe(a.PID), 200)
				}
			}
			if a.Footprint != 0 {
				ev.RSSMB = record.Ptr(int(a.Footprint >> 20))
			}
			e.sink.Emit(ev)
		}
	}
	return fired
}

// growthPerMin returns bytes per minute over the whole series span, or
// false if the history is too short or empty.
func growthPerMin(pts []Point) (float64, bool) {
	if len(pts) < 2 {
		return 0, false
	}
	first, last := pts[0], pts[len(pts)-1]
	span := last.At.Sub(first.At)
	if span < minGrowthSpan || last.Bytes <= first.Bytes {
		return 0, false
	}
	return float64(last.Bytes-first.Bytes) / span.Minutes(), true
}

// CountChromeHelpers counts Chrome helper processes: a process whose name
// mentions chrome or chromium and that is either a "Helper" (macOS) or has a
// Chrome parent (Linux, where every process is just "chrome").
func CountChromeHelpers(procs []resources.Proc) int {
	isChrome := func(n string) bool {
		n = strings.ToLower(n)
		return strings.Contains(n, "chrome") || strings.Contains(n, "chromium")
	}
	byPID := make(map[int]*resources.Proc, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
	}
	n := 0
	for i := range procs {
		p := &procs[i]
		if !isChrome(p.Name) {
			continue
		}
		if strings.Contains(strings.ToLower(p.Name), "helper") {
			n++
			continue
		}
		if par, ok := byPID[p.PPID]; ok && par != p && isChrome(par.Name) {
			n++
		}
	}
	return n
}

func human(b uint64) string {
	switch {
	case b >= gib:
		return fmt.Sprintf("%.1f GB", float64(b)/gib)
	default:
		return fmt.Sprintf("%d MB", b>>20)
	}
}
