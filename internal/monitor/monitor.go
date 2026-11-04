// Package monitor is netwatch's sampling loop: it reads the collector,
// writes samples and events, and raises notifications.
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/procscan"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/redact"
	"github.com/ericmacdougall/netwatch/internal/selfusage"
)

// Deps are the monitor's collaborators.
type Deps struct {
	Cfg     *config.Config
	Col     collector.Collector
	Events  *eventlog.Writer
	Samples *eventlog.Writer
	Notify  *notify.Limiter
	Out     io.Writer // receives each event as a JSON line; may be nil
	Errs    io.Writer // collector errors, rate-limited
	Version string
	Self    int // our own PID, never reported or signalled
	Now     func() time.Time
	// OnceWait overrides the gap between readings in once mode (tests).
	OnceWait time.Duration
}

// pingCount is the number of echo requests per host per sample.
const pingCount = 5

// onceWait is the gap between the two network readings in `once` mode.
const onceWait = 3 * time.Second

// CmdLen bounds command lines stored in events.
const CmdLen = 300

type identity struct {
	pid   int
	start time.Time
}

type state struct {
	d        Deps
	prev     netrate.Snapshot
	havePrev bool
	det      *netrate.Detector
	health   health.Tracker
	runaway  *procscan.RunawayTracker
	orphans  map[identity]bool
	lastScan time.Time
	meter    *selfusage.Meter
	selfRSS  float64
	errSeen  map[string]time.Time
}

// Run samples until ctx is cancelled, or for a single cycle when once is
// set. It returns nil on cancellation.
func Run(ctx context.Context, d Deps, once bool) error {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &state{d: d, runaway: procscan.NewRunawayTracker(), orphans: map[identity]bool{},
		meter: selfusage.NewMeter(), errSeen: map[string]time.Time{}}

	if st, ok := d.Col.(collector.Streamer); ok && !once {
		st.StartNetStream(ctx, time.Duration(d.Cfg.Interval)*time.Second)
	}
	gw, err := d.Col.Gateway(ctx)
	s.logErr("gateway", err)
	snap, err := d.Col.Net(ctx, gw.Iface)
	s.logErr("net", err)
	if err == nil {
		s.prev, s.havePrev = snap, true
		// Processes already online at startup are not "new".
		s.det = netrate.NewDetector(snap)
	}
	s.emit(record.Event{Event: record.Start, Version: d.Version, OS: runtime.GOOS + "/" + runtime.GOARCH,
		KnownProcs: record.Ptr(len(snap.Procs))})

	wait := time.Duration(d.Cfg.Interval) * time.Second
	if once {
		wait = onceWait
		if d.OnceWait > 0 {
			wait = d.OnceWait
		}
	}
	for {
		select {
		case <-ctx.Done():
			s.emit(record.Event{Event: record.Stop})
			return nil
		case <-time.After(wait):
		}
		s.cycle(ctx, once)
		if once {
			return nil
		}
	}
}

func (s *state) cycle(ctx context.Context, once bool) {
	cfg, col := s.d.Cfg, s.d.Col
	gw, err := col.Gateway(ctx)
	s.logErr("gateway", err)

	var hGW, hNet *health.Ping
	var wg sync.WaitGroup
	if gw.Addr != "" {
		wg.Add(1)
		go func() { defer wg.Done(); hGW = col.Ping(ctx, gw.Addr, pingCount) }()
	}
	if cfg.InternetHost != "" {
		wg.Add(1)
		go func() { defer wg.Done(); hNet = col.Ping(ctx, cfg.InternetHost, pingCount) }()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	cur, err := col.Net(ctx, gw.Iface)
	s.logErr("net", err)
	var rates netrate.Rates
	if err == nil {
		if s.havePrev {
			rates = netrate.Compute(s.prev, cur)
		}
		s.prev, s.havePrev = cur, true
	}
	top := talkers(rates, cfg.TopN)
	inK, outK := math.Round(rates.InKBps), math.Round(rates.OutKBps)
	if !cur.HasBytes && rates.HasIf {
		// Without per-process bytes the interface is the only traffic measure.
		inK, outK = math.Round(rates.IfInKBps), math.Round(rates.IfOutKBps)
	}

	if once || s.d.Now().Sub(s.lastScan) >= time.Duration(cfg.OrphanEvery)*time.Second {
		s.lastScan = s.d.Now()
		s.scanProcesses(ctx)
	}

	sample := record.Sample{TS: s.ts(), Iface: gw.Iface, GW: hGW, Net: hNet, InKBps: inK, OutKBps: outK, Top: top,
		Self: &record.SelfUsage{CPUPct: math.Round(s.meter.Sample()*100) / 100, RSSMB: s.selfRSS}}
	if rates.HasIf {
		sample.IfInKBps = record.Ptr(math.Round(rates.IfInKBps))
		sample.IfOutKBps = record.Ptr(math.Round(rates.IfOutKBps))
	}
	s.logErr("samples log", s.d.Samples.Append(sample))

	if err == nil && s.det == nil {
		// The first reading arrived late (e.g. nettop starting slowly):
		// seed from it so a restart does not report every app as new.
		s.det = netrate.NewDetector(cur)
	} else if err == nil {
		for _, a := range s.det.Observe(cur, rates, cfg.NewAppMinKbps) {
			ev := record.Event{Event: record.NewNetApp, Proc: a.Name, PID: record.FlexInt(a.PID),
				InKBps: record.Ptr(math.Round(a.InKBps)), OutKBps: record.Ptr(math.Round(a.OutKBps)),
				FirstSeenName: record.Ptr(a.FirstName), GW: hGW}
			if !cur.HasBytes {
				ev.Conns = record.Ptr(a.Conns)
			}
			s.emit(ev)
			if a.FirstName {
				msg := fmt.Sprintf("%s (%d) %.0f↓/%.0f↑ kB/s", a.Name, a.PID, a.InKBps, a.OutKBps)
				if !cur.HasBytes {
					msg = fmt.Sprintf("%s (%d) %d connections", a.Name, a.PID, a.Conns)
				}
				s.notify("new:"+a.Name, "new app online", msg)
			}
		}
	}

	th := health.Thresholds{GatewayMs: cfg.DegradedGwMs, LossPct: cfg.DegradedLossPct}
	switch s.health.Update(hGW, hNet, th) {
	case health.BecameDegraded:
		s.emit(record.Event{Event: record.Degraded, Iface: gw.Iface, GW: hGW, Net: hNet,
			InKBps: record.Ptr(inK), OutKBps: record.Ptr(outK), Top: top})
		culprit := "?"
		if len(top) > 0 {
			culprit = top[0].Proc
		}
		s.notify("degraded", "network degraded",
			fmt.Sprintf("gw %s · top: %s · out %.0f kB/s", pingText(hGW), culprit, outK))
	case health.BecameRecovered:
		s.emit(record.Event{Event: record.Recovered, GW: hGW, Net: hNet})
	}
}

func (s *state) scanProcesses(ctx context.Context) {
	cfg, col := s.d.Cfg, s.d.Col
	procs, err := col.Processes(ctx)
	s.logErr("processes", err)
	if err != nil {
		return
	}
	live := map[identity]bool{}
	for _, p := range procs {
		live[identity{p.PID, p.Start}] = true
		if p.PID == s.d.Self {
			s.selfRSS = float64(p.RSSMB)
		}
	}
	var fresh []procscan.Process
	for _, p := range procscan.Orphans(cfg, procs, col.OrphanRule(), s.d.Self) {
		id := identity{p.PID, p.Start}
		if s.orphans[id] {
			continue
		}
		s.orphans[id] = true
		fresh = append(fresh, p)
		s.emit(record.Event{Event: record.Orphan, PID: record.FlexInt(p.PID), PPID: record.FlexInt(p.PPID),
			AgeH: record.Ptr(hours(p.Age)), CPU: record.Ptr(p.CPU), RSSMB: record.Ptr(p.RSSMB), Cmd: CleanCmd(p.Cmd)})
	}
	for id := range s.orphans {
		if !live[id] {
			delete(s.orphans, id)
		}
	}
	if len(fresh) > 0 {
		var names []string
		for i, p := range fresh {
			if i == 4 {
				break
			}
			names = append(names, procscan.Short(procscan.BaseName(p), 30))
		}
		s.notify("orphan", fmt.Sprintf("%d orphaned process(es)", len(fresh)),
			strings.Join(names, "; ")+" — run: netwatch orphans")
	}
	for _, r := range s.runaway.Scan(cfg, procs, s.d.Self) {
		s.emit(record.Event{Event: record.Runaway, Reason: r.Reason, PID: record.FlexInt(r.PID), PPID: record.FlexInt(r.PPID),
			CPU: record.Ptr(r.CPU), RSSMB: record.Ptr(r.RSSMB), AgeH: record.Ptr(hours(r.Age)), Cmd: CleanCmd(r.Cmd)})
		s.notify(fmt.Sprintf("run:%d", r.PID), "runaway process",
			fmt.Sprintf("%s pid %d cpu %.0f%% rss %dMB", procscan.Short(procscan.BaseName(r.Process), 40), r.PID, r.CPU, r.RSSMB))
	}
}

// CleanCmd redacts and truncates a command line for logs and output.
func CleanCmd(cmd string) string { return procscan.Short(redact.String(cmd), CmdLen) }

func hours(d time.Duration) float64 { return math.Round(d.Hours()*10) / 10 }

func talkers(r netrate.Rates, n int) []record.Talker {
	out := []record.Talker{}
	for i, p := range r.Procs {
		if i == n {
			break
		}
		t := record.Talker{Proc: p.Name, PID: record.FlexInt(p.PID), InKBps: math.Round(p.InKBps), OutKBps: math.Round(p.OutKBps)}
		if p.Conns > 0 {
			t.Conns = p.Conns
		}
		out = append(out, t)
	}
	return out
}

func pingText(p *health.Ping) string {
	if p == nil {
		return "n/a"
	}
	if p.Avg == nil {
		return fmt.Sprintf("no reply (%g%% loss)", p.Loss)
	}
	return fmt.Sprintf("%gms loss %g%%", *p.Avg, p.Loss)
}

func (s *state) ts() string { return s.d.Now().Format(eventlog.TimeFormat) }

func (s *state) emit(ev record.Event) {
	ev.TS = s.ts()
	s.logErr("events log", s.d.Events.Append(ev))
	if s.d.Out != nil {
		if b, err := json.Marshal(ev); err == nil {
			fmt.Fprintln(s.d.Out, string(b))
		}
	}
}

func (s *state) notify(key, title, msg string) {
	if _, err := s.d.Notify.Notify(key, title, msg); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		s.logErr("notify", err)
	}
}

// errRepeat is how often an unchanged error is repeated on stderr, so a
// persistent failure (no network, missing tool) does not grow the log.
const errRepeat = time.Hour

func (s *state) logErr(what string, err error) {
	if err == nil || s.d.Errs == nil {
		return
	}
	key := what + ": " + err.Error()
	if t, ok := s.errSeen[key]; ok && s.d.Now().Sub(t) < errRepeat {
		return
	}
	if len(s.errSeen) > 200 {
		s.errSeen = map[string]time.Time{}
	}
	s.errSeen[key] = s.d.Now()
	fmt.Fprintf(s.d.Errs, "%s netwatch: %s\n", s.ts(), key)
}
