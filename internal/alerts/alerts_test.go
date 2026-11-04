package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/resources"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type sinkRec struct{ evs []record.Event }

func (s *sinkRec) Emit(e record.Event) { s.evs = append(s.evs, e) }

func triggers(as []Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Trigger)
	}
	return out
}

func has(as []Alert, trig string) bool {
	for _, a := range as {
		if a.Trigger == trig {
			return true
		}
	}
	return false
}

func growing(key string, perMin uint64, over time.Duration) Series {
	start := uint64(1 << 30)
	end := start + uint64(float64(perMin)*over.Minutes())
	return Series{Key: key, Points: []Point{{t0, start}, {t0.Add(over), end}}}
}

// CR-7: each of the five triggers has a just-under control that must stay
// quiet, next to a case just over that must fire. A variant that fires at
// or below the limit fails the control.
func TestCR7EachTriggerJustUnderIsQuiet(t *testing.T) {
	e := New(Config{}, nil, nil)
	chrome := func(n int) []resources.Proc {
		ps := []resources.Proc{{PID: 1, Name: "Google Chrome", PPID: 0}}
		for i := 0; i < n; i++ {
			ps = append(ps, resources.Proc{PID: 100 + i, PPID: 1, Name: "Google Chrome Helper (Renderer)"})
		}
		return ps
	}
	cases := []struct {
		name        string
		trig        string
		under, over Input
		equal       *Input
	}{
		{"process", TrigProcess,
			Input{Procs: []resources.Proc{{PID: 5, Name: "x", Footprint: DefaultProcBytes - 1, FootprintOK: true}}},
			Input{Procs: []resources.Proc{{PID: 5, Name: "x", Footprint: DefaultProcBytes + 1, FootprintOK: true}}},
			&Input{Procs: []resources.Proc{{PID: 5, Name: "x", Footprint: DefaultProcBytes, FootprintOK: true}}}},
		{"growth", TrigGrowth,
			Input{Series: []Series{growing("pg:1:1", DefaultGrowthBytes-(DefaultGrowthBytes/100), time.Minute)}},
			Input{Series: []Series{growing("pg:1:1", DefaultGrowthBytes+(DefaultGrowthBytes/100), time.Minute)}},
			&Input{Series: []Series{growing("pg:1:1", DefaultGrowthBytes, time.Minute)}}},
		{"pressure", TrigPressure,
			Input{Sys: resources.System{Pressure: resources.LevelNormal}},
			Input{Sys: resources.System{Pressure: resources.LevelWarn}}, nil},
		{"swap", TrigSwap,
			Input{Sys: resources.System{SwapUsed: DefaultSwapBytes - 1}},
			Input{Sys: resources.System{SwapUsed: DefaultSwapBytes + 1}},
			&Input{Sys: resources.System{SwapUsed: DefaultSwapBytes}}},
		{"chrome", TrigChrome,
			Input{Procs: chrome(60)}, Input{Procs: chrome(61)}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := e.Evaluate(c.under); has(got, c.trig) {
				t.Fatalf("just under the limit fired: %v", triggers(got))
			}
			if c.equal != nil {
				if got := e.Evaluate(*c.equal); has(got, c.trig) {
					t.Fatalf("exactly at the limit fired: %v", triggers(got))
				}
			}
			if got := e.Evaluate(c.over); !has(got, c.trig) {
				t.Fatalf("over the limit did not fire: %v", triggers(got))
			}
		})
	}
}

func TestPressureCriticalAndUnknown(t *testing.T) {
	e := New(Config{}, nil, nil)
	if !has(e.Evaluate(Input{Sys: resources.System{Pressure: resources.LevelCritical}}), TrigPressure) {
		t.Fatal("critical did not alert")
	}
	if has(e.Evaluate(Input{Sys: resources.System{Pressure: resources.LevelUnknown}}), TrigPressure) {
		t.Fatal("unknown pressure alerted")
	}
}

func TestGrowthNeedsEnoughHistoryAndRealGrowth(t *testing.T) {
	e := New(Config{}, nil, nil)
	// 1 GB in 5 s is 12 GB/min but one noisy pair is not a trend.
	short := Series{Key: "k", Points: []Point{{t0, 0}, {t0.Add(5 * time.Second), 1 << 30}}}
	if has(e.Evaluate(Input{Series: []Series{short}}), TrigGrowth) {
		t.Fatal("alerted on a 5s span")
	}
	// A shrinking or flat series, and an empty one, never alert.
	shrink := Series{Key: "k", Points: []Point{{t0, 9 << 30}, {t0.Add(time.Minute), 1 << 30}}}
	if has(e.Evaluate(Input{Series: []Series{shrink, {Key: "e"}}}), TrigGrowth) {
		t.Fatal("alerted on shrinkage")
	}
}

func TestUnreadableProcessIsNotOver(t *testing.T) {
	e := New(Config{}, nil, nil)
	in := Input{Procs: []resources.Proc{{PID: 9, Footprint: 99 << 30, FootprintOK: false}}}
	if has(e.Evaluate(in), TrigProcess) {
		t.Fatal("a process we cannot read has no footprint to compare")
	}
}

func TestRateLimitedPerKeyThroughLimiter(t *testing.T) {
	now := t0
	sink := &sinkRec{}
	var sent []string
	lim := notify.New(true, time.Hour, func(title, msg string) error { sent = append(sent, title+"|"+msg); return nil })
	lim.Now = func() time.Time { return now }
	e := New(Config{Cooldown: time.Hour}, lim, sink)
	e.dedupe.Now = func() time.Time { return now }
	e.Now = func() time.Time { return now }
	in := Input{Sys: resources.System{SwapUsed: 11 << 30, Pressure: resources.LevelWarn}}

	if got := e.Run(in); len(got) != 2 || len(sink.evs) != 2 || len(sent) != 2 {
		t.Fatalf("first run: %d alerts %d events %d notifications", len(got), len(sink.evs), len(sent))
	}
	now = now.Add(30 * time.Minute)
	if got := e.Run(in); len(got) != 0 || len(sink.evs) != 2 || len(sent) != 2 {
		t.Fatalf("within cooldown: %d alerts %d events %d notifications", len(got), len(sink.evs), len(sent))
	}
	// A different subject is a different key.
	in2 := Input{Sys: resources.System{Pressure: resources.LevelCritical}}
	if got := e.Run(in2); len(got) != 1 {
		t.Fatalf("critical after warn should be a new key, got %d", len(got))
	}
	now = now.Add(2 * time.Hour)
	if got := e.Run(in); len(got) != 2 {
		t.Fatalf("after cooldown: %d", len(got))
	}
	for _, ev := range sink.evs {
		if ev.Event != record.ResourceAlert || ev.Reason == "" || ev.TS == "" {
			t.Fatalf("bad event %+v", ev)
		}
	}
}

func TestEventsEmittedEvenWhenNotificationsDisabled(t *testing.T) {
	sink := &sinkRec{}
	off := notify.New(false, time.Hour, func(string, string) error { t.Fatal("sent while disabled"); return nil })
	e := New(Config{}, off, sink)
	e.Run(Input{Sys: resources.System{SwapUsed: 20 << 30}})
	if len(sink.evs) != 1 {
		t.Fatalf("events %d", len(sink.evs))
	}
}

func TestEventCarriesRedactedCommand(t *testing.T) {
	sink := &sinkRec{}
	e := New(Config{}, nil, sink)
	e.Describe = func(pid int) string { return "python train.py --api-key=sk-secret-value-123456" }
	e.Run(Input{Procs: []resources.Proc{{PID: 42, Name: "python", Footprint: 9 << 30, FootprintOK: true}}})
	if len(sink.evs) != 1 || sink.evs[0].PID != 42 || sink.evs[0].RSSMB == nil || *sink.evs[0].RSSMB != 9<<10 {
		t.Fatalf("%+v", sink.evs)
	}
	if strings.Contains(sink.evs[0].Cmd, "sk-secret") {
		t.Fatalf("secret in event: %q", sink.evs[0].Cmd)
	}
}

// NEG-1 shape (CR-7): a Codex-shaped hog is not an agent group. It must
// produce alerts, and the engine has no way to act on it.
func TestCodexShapedHogAlertsOnly(t *testing.T) {
	sink := &sinkRec{}
	e := New(Config{}, nil, sink)
	hog := resources.Proc{PID: 777, PPID: 1, Name: "codex", Footprint: 12 << 30, FootprintOK: true}
	series := growing("inel:Codex", 5<<30, time.Minute)
	fired := e.Run(Input{Procs: []resources.Proc{hog}, Series: []Series{series}, Sys: resources.System{Pressure: resources.LevelCritical}})
	if !has(fired, TrigProcess) || !has(fired, TrigGrowth) || !has(fired, TrigPressure) {
		t.Fatalf("expected alerts, got %v", triggers(fired))
	}
	for _, ev := range sink.evs {
		if ev.Event != record.ResourceAlert {
			t.Fatalf("an alert produced a %s event", ev.Event)
		}
	}
}

func TestCountChromeHelpers(t *testing.T) {
	ps := []resources.Proc{
		{PID: 1, PPID: 0, Name: "chrome"}, // the browser itself
		{PID: 2, PPID: 1, Name: "chrome"}, // linux style child
		{PID: 3, PPID: 1, Name: "chrome_crashpad"},
		{PID: 4, PPID: 1, Name: "Google Chrome Helper"},
		{PID: 5, PPID: 99, Name: "firefox"},
		{PID: 6, PPID: 5, Name: "Web Content"},
	}
	if n := CountChromeHelpers(ps); n != 3 {
		t.Fatalf("helpers %d, want 3", n)
	}
}

// Alerts name the process or job, its owner app and the agent, never the
// internal group key (the AC-3 live run showed "pg:61859:1793...").
func TestAlertsNameAppAndAgent(t *testing.T) {
	e := New(Config{}, nil, nil)
	s := growing("pg:61859:1793822848342331000", 5<<30, time.Minute)
	s.Name, s.App, s.Agent = "python3 job.py", "Claude Code", "agent:abc"
	p := resources.Proc{PID: 61999, PGID: 61859, Name: "Python", Footprint: 9 << 30, FootprintOK: true}
	who := func(q resources.Proc) (string, string) {
		if q.PID == 61999 {
			return "Claude Code", "agent:abc"
		}
		return "", ""
	}
	as := e.Evaluate(Input{Series: []Series{s}, Procs: []resources.Proc{p}, Who: who})
	var growth, proc string
	for _, a := range as {
		switch a.Trigger {
		case TrigGrowth:
			growth = a.Message
			if a.Subject != s.Key {
				t.Errorf("rate-limit subject changed: %q", a.Subject)
			}
		case TrigProcess:
			proc = a.Message
		}
	}
	for name, m := range map[string]string{"growth": growth, "process": proc} {
		if strings.Contains(m, "pg:") || !strings.Contains(m, "app Claude Code") || !strings.Contains(m, "agent agent:abc") {
			t.Errorf("%s alert: %q", name, m)
		}
	}
	if !strings.HasPrefix(growth, "python3 job.py (pgid 61859, ") {
		t.Errorf("growth alert lacks the job: %q", growth)
	}
	// An aggregate keeps its readable key; nothing unknown is invented.
	agg := growing("inel:Google Chrome", 5<<30, time.Minute)
	as = e.Evaluate(Input{Series: []Series{agg}})
	if len(as) != 1 || as[0].Message != "Google Chrome is growing 5.0 GB/min (now 6.0 GB)" {
		t.Errorf("aggregate alert: %+v", as)
	}
}

// Red-team F6: an aggregate keyed by an absolute exe path is named by
// its base name only.
func TestAggregateExeKeyShowsNoPath(t *testing.T) {
	e := New(Config{}, nil, nil)
	as := e.Evaluate(Input{Series: []Series{growing("inel:exe:/home/someone/bin/tool", 5<<30, time.Minute)}})
	if len(as) != 1 || strings.Contains(as[0].Message, "/home/") || !strings.HasPrefix(as[0].Message, "tool is growing") {
		t.Fatalf("aggregate alert: %+v", as)
	}
}
