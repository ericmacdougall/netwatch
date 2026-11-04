// Package report summarises the sample and event logs over a time window,
// as text for people and JSON for scripts and agents.
package report

import (
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/procscan"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/redact"
)

var sinceRe = regexp.MustCompile(`^(\d+)([smhd])$`)

// ParseSince parses a window such as "90s", "30m", "2h" or "7d".
func ParseSince(s string) (time.Duration, error) {
	m := sinceRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("bad --since %q: want a number followed by s, m, h or d (e.g. 2h)", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 || n > 3650*24 {
		return 0, errors.New("--since out of range")
	}
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

// GatewayStats summarises gateway round-trip times in milliseconds.
type GatewayStats struct {
	Median float64 `json:"median_ms"`
	P95    float64 `json:"p95_ms"`
	Max    float64 `json:"max_ms"`
}

// TalkerAvg is a process's average contribution while it was a top talker.
type TalkerAvg struct {
	Proc    string  `json:"proc"`
	InKBps  float64 `json:"in_kBps"`
	OutKBps float64 `json:"out_kBps"`
}

// SelfStats summarises netwatch's own resource use.
type SelfStats struct {
	AvgCPUPct float64 `json:"avg_cpu_pct"`
	MaxCPUPct float64 `json:"max_cpu_pct"`
	MaxRSSMB  float64 `json:"max_rss_mb"`
}

// Report is the summary of one window.
type Report struct {
	Since       string         `json:"since"`
	From        string         `json:"from"`
	Samples     int            `json:"samples"`
	EventCount  int            `json:"event_count"`
	Gateway     *GatewayStats  `json:"gateway,omitempty"`
	GatewayLoss *float64       `json:"gateway_loss_avg_pct,omitempty"`
	AvgInKBps   float64        `json:"avg_in_kBps"`
	AvgOutKBps  float64        `json:"avg_out_kBps"`
	TopTalkers  []TalkerAvg    `json:"top_talkers"`
	Self        *SelfStats     `json:"self,omitempty"`
	Counts      map[string]int `json:"counts"`
	Events      []record.Event `json:"events"`
	// Resources is the memory summary. It is always present; with no
	// resources.jsonl data it is {"samples": 0}.
	Resources Resources `json:"resources"`
}

// WithResources adds the memory summary to r.
func (r Report) WithResources(recs []ResRecord, evs []GuardEvent) Report {
	r.Resources = Summarize(recs, evs)
	return r
}

// maxTalkers is how many talkers a report lists.
const maxTalkers = 8

// Build summarises samples and events.
func Build(since string, from time.Time, samples []record.Sample, events []record.Event) Report {
	r := Report{Since: since, From: from.Format(time.RFC3339), Samples: len(samples),
		Counts: map[string]int{}, TopTalkers: []TalkerAvg{}, Events: []record.Event{}}
	var gws []float64
	var lossSum float64
	var lossN int
	talk := map[string]*TalkerAvg{}
	var selfN int
	var self SelfStats
	for _, s := range samples {
		if s.GW != nil {
			if s.GW.Avg != nil {
				gws = append(gws, *s.GW.Avg)
			}
			lossSum += s.GW.Loss
			lossN++
		}
		r.AvgInKBps += s.InKBps
		r.AvgOutKBps += s.OutKBps
		for _, t := range s.Top {
			name := redact.Display(t.Proc)
			a := talk[name]
			if a == nil {
				a = &TalkerAvg{Proc: name}
				talk[name] = a
			}
			a.InKBps += t.InKBps
			a.OutKBps += t.OutKBps
		}
		if s.Self != nil {
			selfN++
			self.AvgCPUPct += s.Self.CPUPct
			self.MaxCPUPct = math.Max(self.MaxCPUPct, s.Self.CPUPct)
			self.MaxRSSMB = math.Max(self.MaxRSSMB, s.Self.RSSMB)
		}
	}
	if n := float64(len(samples)); n > 0 {
		r.AvgInKBps = math.Round(r.AvgInKBps / n)
		r.AvgOutKBps = math.Round(r.AvgOutKBps / n)
		for _, a := range talk {
			a.InKBps = math.Round(a.InKBps / n)
			a.OutKBps = math.Round(a.OutKBps / n)
			r.TopTalkers = append(r.TopTalkers, *a)
		}
		sort.Slice(r.TopTalkers, func(i, j int) bool {
			a, b := r.TopTalkers[i], r.TopTalkers[j]
			if a.InKBps+a.OutKBps != b.InKBps+b.OutKBps {
				return a.InKBps+a.OutKBps > b.InKBps+b.OutKBps
			}
			return a.Proc < b.Proc
		})
		if len(r.TopTalkers) > maxTalkers {
			r.TopTalkers = r.TopTalkers[:maxTalkers]
		}
	}
	if len(gws) > 0 {
		sort.Float64s(gws)
		r.Gateway = &GatewayStats{Median: round1(gws[len(gws)/2]), P95: round1(gws[nearestRank(len(gws), 0.95)]), Max: round1(gws[len(gws)-1])}
	}
	if lossN > 0 {
		v := math.Round(lossSum/float64(lossN)*10) / 10
		r.GatewayLoss = &v
	}
	if selfN > 0 {
		self.AvgCPUPct = math.Round(self.AvgCPUPct/float64(selfN)*100) / 100
		r.Self = &self
	}
	for _, e := range events {
		if e.Event == record.Start || e.Event == record.Stop {
			continue
		}
		// Memory and guard events are summarised under Resources; the
		// network event list renders only the events it understands.
		if IsMemoryEvent(e.Event) {
			continue
		}
		r.Counts[e.Event]++
		// Logs written by older versions (or the Python prototype) may hold
		// unredacted command lines; never print them as stored.
		e.Cmd = redact.Display(e.Cmd)
		e.Proc = redact.Display(e.Proc)
		r.Events = append(r.Events, e)
	}
	r.EventCount = len(r.Events)
	return r
}

func nearestRank(n int, q float64) int {
	i := int(math.Ceil(q*float64(n))) - 1
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

func fmtPing(p *health.Ping) string {
	if p == nil {
		return "-"
	}
	if p.Avg == nil {
		return fmt.Sprintf("no reply (%g%% loss)", p.Loss)
	}
	return fmt.Sprintf("%gms/%gms max, %g%% loss", *p.Avg, *p.Max, p.Loss)
}

func fnum(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func inum(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// WriteText renders the report for a terminal.
func (r Report) WriteText(w io.Writer) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "netwatch report, last %s: %d samples, %d events\n", r.Since, r.Samples, r.EventCount)
	if g := r.Gateway; g != nil {
		fmt.Fprintf(b, "  gateway ms: median %g  p95 %g  max %g", g.Median, g.P95, g.Max)
		if r.GatewayLoss != nil {
			fmt.Fprintf(b, "  avg loss %g%%", *r.GatewayLoss)
		}
		b.WriteString("\n")
	}
	if r.Samples > 0 {
		fmt.Fprintf(b, "  avg traffic: in %g kB/s, out %g kB/s\n", r.AvgInKBps, r.AvgOutKBps)
	}
	if s := r.Self; s != nil {
		fmt.Fprintf(b, "  netwatch itself: cpu avg %.2f%% (max %.1f%%), rss max %.0f MB\n", s.AvgCPUPct, s.MaxCPUPct, s.MaxRSSMB)
	}
	if len(r.TopTalkers) > 0 {
		b.WriteString("  top talkers (avg kB/s in / out while in the top list):\n")
		for _, t := range r.TopTalkers {
			fmt.Fprintf(b, "    %-38s %7g / %7g\n", procscan.Short(t.Proc, 38), t.InKBps, t.OutKBps)
		}
	}
	r.Resources.writeMemory(b)
	for _, e := range r.Events {
		fmt.Fprintf(b, "  %s %-12s", e.TS, e.Event)
		switch e.Event {
		case record.NewNetApp:
			fmt.Fprintf(b, " %s (%d) %g↓/%g↑ kB/s", e.Proc, e.PID, fnum(e.InKBps), fnum(e.OutKBps))
			if e.Conns != nil {
				fmt.Fprintf(b, " %d conns", *e.Conns)
			}
		case record.Degraded, record.Recovered:
			fmt.Fprintf(b, " gw=%s net=%s", fmtPing(e.GW), fmtPing(e.Net))
			if len(e.Top) > 0 {
				var parts []string
				for i, t := range e.Top {
					if i == 3 {
						break
					}
					parts = append(parts, fmt.Sprintf("%s(%g↑)", t.Proc, t.OutKBps))
				}
				b.WriteString(" top=" + strings.Join(parts, ", "))
			}
		case record.OrphansKilled:
			fmt.Fprintf(b, " pids %v", e.PIDs)
		default:
			if e.Reason != "" {
				fmt.Fprintf(b, " [%s]", e.Reason)
			}
			fmt.Fprintf(b, " pid %d cpu %g rss %dMB %s", e.PID, fnum(e.CPU), inum(e.RSSMB), procscan.Short(e.Cmd, 90))
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
