package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/record"
)

func TestParseSince(t *testing.T) {
	ok := map[string]time.Duration{"90s": 90 * time.Second, "30m": 30 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour}
	for in, want := range ok {
		if got, err := ParseSince(in); err != nil || got != want {
			t.Errorf("ParseSince(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "2", "h", "2w", "-1h", "0h", "1.5h", "99999999d"} {
		if _, err := ParseSince(bad); err == nil {
			t.Errorf("ParseSince(%q) should fail", bad)
		}
	}
}

func ping(avg float64, loss float64) *health.Ping {
	return &health.Ping{Avg: &avg, Max: &avg, Loss: loss}
}

func TestBuildAndText(t *testing.T) {
	samples := []record.Sample{
		{TS: "t1", GW: ping(2, 0), InKBps: 100, OutKBps: 10, Top: []record.Talker{{Proc: "browser", InKBps: 90, OutKBps: 5}, {Proc: "sync", InKBps: 10, OutKBps: 5}},
			Self: &record.SelfUsage{CPUPct: 0.2, RSSMB: 12}},
		{TS: "t2", GW: ping(4, 0), InKBps: 0, OutKBps: 300, Top: []record.Talker{{Proc: "sync", OutKBps: 300}},
			Self: &record.SelfUsage{CPUPct: 0.4, RSSMB: 14}},
		{TS: "t3", GW: ping(80, 20), InKBps: 2, OutKBps: 2},
		{TS: "t4", GW: &health.Ping{Loss: 100}},
	}
	events := []record.Event{
		{TS: "t0", Event: record.Start},
		{TS: "t1", Event: record.NewNetApp, Proc: "sync", PID: 42, InKBps: record.Ptr(1.0), OutKBps: record.Ptr(80.0)},
		{TS: "t3", Event: record.Degraded, GW: ping(80, 20), Net: ping(30, 0), Top: []record.Talker{{Proc: "sync", OutKBps: 300}}},
		{TS: "t4", Event: record.Recovered, GW: ping(3, 0)},
		{TS: "t5", Event: record.Orphan, PID: 7, CPU: record.Ptr(0.0), RSSMB: record.Ptr(50), Cmd: "node dev.js"},
		{TS: "t6", Event: record.Runaway, Reason: "cpu", PID: 8, CPU: record.Ptr(99.0), RSSMB: record.Ptr(10), Cmd: "node spin.js"},
	}
	r := Build("2h", time.Unix(0, 0), samples, events)
	if r.Samples != 4 || r.EventCount != 5 {
		t.Fatalf("counts: %+v", r)
	}
	if r.Gateway == nil || r.Gateway.Median != 4 || r.Gateway.Max != 80 || r.Gateway.P95 != 80 {
		t.Fatalf("gateway stats: %+v", r.Gateway)
	}
	if *r.GatewayLoss != 30 {
		t.Fatalf("avg loss: %v", *r.GatewayLoss)
	}
	if r.AvgInKBps != 26 || r.AvgOutKBps != 78 {
		t.Fatalf("avg traffic: %v %v", r.AvgInKBps, r.AvgOutKBps)
	}
	if len(r.TopTalkers) != 2 || r.TopTalkers[0].Proc != "sync" || r.TopTalkers[0].OutKBps != 76 {
		t.Fatalf("talkers: %+v", r.TopTalkers)
	}
	if r.Self == nil || r.Self.AvgCPUPct != 0.3 || r.Self.MaxRSSMB != 14 {
		t.Fatalf("self: %+v", r.Self)
	}
	if r.Counts[record.Orphan] != 1 || r.Counts[record.Start] != 0 {
		t.Fatalf("event counts: %v", r.Counts)
	}

	var sb strings.Builder
	if err := r.WriteText(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"netwatch report, last 2h: 4 samples, 5 events",
		"gateway ms: median 4  p95 80  max 80",
		"avg traffic: in 26 kB/s, out 78 kB/s",
		"NEW_NET_APP  sync (42) 1↓/80↑ kB/s",
		"DEGRADED     gw=80ms/80ms max, 20% loss net=30ms/30ms max, 0% loss top=sync(300↑)",
		"RUNAWAY      [cpu] pid 8 cpu 99 rss 10MB node spin.js",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"since", "samples", "gateway", "top_talkers", "events", "counts"} {
		if _, ok := back[k]; !ok {
			t.Errorf("json report missing %q", k)
		}
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build("1h", time.Unix(0, 0), nil, nil)
	var sb strings.Builder
	_ = r.WriteText(&sb)
	if !strings.Contains(sb.String(), "0 samples, 0 events") || r.Gateway != nil {
		t.Fatalf("empty report wrong: %q", sb.String())
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"top_talkers":[]`) || !strings.Contains(string(b), `"events":[]`) {
		t.Fatalf("empty lists should encode as [] for scripts: %s", b)
	}
}

func TestBuildRedactsLegacyRecords(t *testing.T) {
	events := []record.Event{{TS: "2026-01-01T00:00:00Z", Event: record.Orphan, Cmd: "node a.js --token=abc123secret\x1b[2J"}}
	r := Build("1h", time.Time{}, nil, events)
	if got := r.Events[0].Cmd; strings.Contains(got, "abc123secret") || strings.Contains(got, "\x1b") {
		t.Fatalf("report kept a secret or control character: %q", got)
	}
}

// A window holding only daemon restarts must say so, not just "0 events".
func TestReportShowsDaemonLifecycle(t *testing.T) {
	evs := []record.Event{
		{TS: "2026-11-04T13:57:06-07:00", Event: record.Start},
		{TS: "2026-11-04T13:57:18-07:00", Event: record.Stop},
		{TS: "2026-11-04T13:57:26-07:00", Event: record.Start},
	}
	r := Build("1h", time.Now(), nil, evs)
	if r.Starts != 2 || r.Stops != 1 || r.EventCount != 0 {
		t.Fatalf("starts %d stops %d events %d", r.Starts, r.Stops, r.EventCount)
	}
	var sb strings.Builder
	if err := r.WriteText(&sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "daemon: 2 starts, 1 stops") {
		t.Fatalf("text lacks the lifecycle line:\n%s", sb.String())
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"daemon_starts":2`) {
		t.Fatalf("json lacks daemon_starts: %s", b)
	}
}
