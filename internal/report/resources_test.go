package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/record"
)

const resFixture = `{"ts":"2026-11-04T12:00:00Z","pressure":"normal","compressor_pct":4.5,"swap_used":1000,"sys":{"headroom_bytes":9000000000},"top_mem":[{"pid":10,"start":"s1","name":"Python","footprint":2147483648,"agent":"main","cmd":"python train.py"},{"pid":11,"start":"s2","name":"node","footprint":100,"cmd":"node a.js"}]}
{"ts":"2026-11-04T12:00:10Z","pressure":"warn","compressor_pct":40,"swap_used":5000,"sys":{"headroom_bytes":3000000000},"top_mem":[{"pid":10,"start":"s1","name":"Python","footprint":9663676416,"agent":"main","cmd":"python train.py --api-key=sk-canary-secret-123456"},{"pid":12,"start":"s3","name":"a","footprint":5,"cmd":""},{"pid":13,"start":"s4","name":"b","footprint":6},{"pid":14,"start":"s5","name":"c","footprint":7},{"pid":15,"start":"s6","name":"d","footprint":8},{"pid":16,"start":"s7","name":"e","footprint":9}]}
not json at all
{"ts":"2026-11-04T12:00:20Z","pressure":"critical","compressor_pct":12,"swap_used":3000,"sys":{"headroom_bytes":4000000000},"top_mem":[]}
{"ts":"2026-11-04T12:00:30Z","pressure":"warn","compressor_pct":1,"swap_used":0,"top_mem":[]}
`

const evFixture = `{"ts":"2026-11-04T12:00:01Z","event":"START","version":"x"}
{"ts":"2026-11-04T12:00:02Z","event":"RESOURCE_ALERT","reason":"swap_over_limit: swap in use is 11.0 GB"}
{"ts":"2026-11-04T12:00:03Z","event":"RESOURCE_ALERT","reason":"memory_pressure: memory pressure is warn"}
{"ts":"2026-11-04T12:00:04Z","event":"RESOURCE_ALERT","reason":"swap_over_limit: swap in use is 12.0 GB"}
{"ts":"2026-11-04T12:00:05Z","event":"GUARD_PAUSE","pgid":200,"agent":"main","reason":"D4 token=abc123secretvalue"}
{"ts":"2026-11-04T12:00:06Z","event":"GUARD_RESUME","pgid":200,"agent":"main","reason":"clear"}
{"ts":"2026-11-04T12:00:07Z","event":"HOST_AT_RISK_UNPROTECTED","reason":"codex hog","pgid":"x"}
{"ts":"2026-11-04T12:00:08Z","event":"MODE_CHANGE","from":"pause+kill","to":"alert","agent":7,"reason":"user"}
{"ts":"2026-11-04T12:00:09Z","event":"GUARD_PAUSE","pgid":201,"agent":"agent:abc","reason":"p1"}
{"ts":"2026-11-04T12:00:10Z","event":"GUARD_KILL","pgid":201,"agent":"agent:abc","reason":"path A"}
{"ts":"2026-11-04T12:00:11Z","event":"GUARD_RESUME","pgid":202,"agent":"main","reason":"clear"}
{"ts":"2026-11-04T12:00:12Z","event":"ORPHAN","pid":5,"cmd":"node x.js"}
`

func writeFixture(t *testing.T) (res, ev string) {
	t.Helper()
	d := t.TempDir()
	res, ev = filepath.Join(d, "resources.jsonl"), filepath.Join(d, "events.jsonl")
	if err := os.WriteFile(res, []byte(resFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ev, []byte(evFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func TestResourcesSummaryFromFixture(t *testing.T) {
	res, ev := writeFixture(t)
	recs, evs := ReadResources(res, ev, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if len(recs) != 4 {
		t.Fatalf("read %d records (the torn line must be skipped)", len(recs))
	}
	s := Summarize(recs, evs)
	if s.Samples != 4 || s.Pressure["normal"] != 1 || s.Pressure["warn"] != 2 || s.Pressure["critical"] != 1 {
		t.Fatalf("%+v", s)
	}
	if *s.MaxCompressorPct != 40 || *s.MaxSwapUsed != 5000 || *s.MinHeadroom != 3000000000 {
		t.Fatalf("max/min: %v %v %v", *s.MaxCompressorPct, *s.MaxSwapUsed, *s.MinHeadroom)
	}
	if len(s.TopProcs) != 5 || s.TopProcs[0].PID != 10 || s.TopProcs[0].PeakBytes != 9663676416 || s.TopProcs[0].Agent != "main" || s.TopProcs[0].Name != "Python" {
		t.Fatalf("top procs %+v", s.TopProcs)
	}
	if s.TopProcs[1].PID != 11 || s.TopProcs[2].PID != 16 || s.TopProcs[4].PID != 14 {
		t.Fatalf("ranking %+v", s.TopProcs)
	}
	if s.Alerts["swap_over_limit"] != 2 || s.Alerts["memory_pressure"] != 1 || len(s.Alerts) != 2 {
		t.Fatalf("alerts %v", s.Alerts)
	}
	want := map[string]int{"GUARD_PAUSE": 2, "GUARD_RESUME": 2, "GUARD_KILL": 1, "HOST_AT_RISK_UNPROTECTED": 1, "MODE_CHANGE": 1}
	for k, v := range want {
		if s.GuardActions[k] != v {
			t.Errorf("%s = %d, want %d", k, s.GuardActions[k], v)
		}
	}
	if len(s.LastGuardEvents) != 5 {
		t.Fatalf("tail %d", len(s.LastGuardEvents))
	}
	last := s.LastGuardEvents[4]
	if last.Event != record.GuardResume || last.PGID != 202 || last.Agent != "main" || last.TS == "" || last.Reason != "clear" {
		t.Fatalf("last %+v", last)
	}
	// A numeric agent and a string pgid must not drop the event.
	if s.LastGuardEvents[0].Event != record.HostAtRiskUnprotected || s.LastGuardEvents[0].PGID != 0 ||
		s.LastGuardEvents[1].Event != record.ModeChange || s.LastGuardEvents[1].Agent != "7" {
		t.Fatalf("tail %+v", s.LastGuardEvents)
	}
}

func TestResourcesWindowCutoff(t *testing.T) {
	res, ev := writeFixture(t)
	recs, evs := ReadResources(res, ev, time.Date(2026, 11, 4, 12, 0, 15, 0, time.UTC))
	if s := Summarize(recs, evs); s.Samples != 2 || len(s.Alerts) != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestResourcesEmptyAndMissing(t *testing.T) {
	d := t.TempDir()
	recs, evs := ReadResources(filepath.Join(d, "nope.jsonl"), filepath.Join(d, "nope2.jsonl"), time.Unix(0, 0))
	r := Build("1h", time.Unix(0, 0), nil, nil).WithResources(recs, evs)
	b, err := json.Marshal(r.Resources)
	if err != nil || string(b) != `{"samples":0}` {
		t.Fatalf("%s %v", b, err)
	}
	var sb strings.Builder
	if err := r.WriteText(&sb); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb.String(), "Memory") {
		t.Fatalf("empty window printed a Memory section:\n%s", sb.String())
	}
	// An empty (zero byte) file is the same.
	os.WriteFile(filepath.Join(d, "resources.jsonl"), nil, 0o600)
	recs, _ = ReadResources(filepath.Join(d, "resources.jsonl"), filepath.Join(d, "nope2.jsonl"), time.Unix(0, 0))
	if s := Summarize(recs, nil); s.Samples != 0 {
		t.Fatalf("%+v", s)
	}
}

// The redaction canary: a secret in a logged command, agent or reason must
// not reach text or JSON output.
func TestResourcesRedactionCanary(t *testing.T) {
	res, ev := writeFixture(t)
	recs, evs := ReadResources(res, ev, time.Unix(0, 0))
	r := Build("1h", time.Unix(0, 0), nil, nil).WithResources(recs, evs)
	b, _ := json.Marshal(r)
	var sb strings.Builder
	r.WriteText(&sb)
	for _, out := range []string{string(b), sb.String()} {
		for _, secret := range []string{"sk-canary-secret-123456", "abc123secretvalue"} {
			if strings.Contains(out, secret) {
				t.Fatalf("secret %q leaked:\n%s", secret, out)
			}
		}
	}
	if !strings.Contains(string(b), "python train.py") {
		t.Fatal("the redacted command should still be present")
	}
}

func TestExistingReportUnchangedByMemoryEvents(t *testing.T) {
	events := []record.Event{
		{TS: "t1", Event: record.Orphan, PID: 7, Cmd: "node dev.js"},
		{TS: "t2", Event: record.GuardPause},
		{TS: "t3", Event: record.ResourceAlert, Reason: "swap_over_limit: x"},
	}
	r := Build("2h", time.Unix(0, 0), nil, events)
	if r.EventCount != 1 || r.Counts[record.Orphan] != 1 || len(r.Counts) != 1 {
		t.Fatalf("memory events leaked into the network event list: %+v", r)
	}
	var sb strings.Builder
	r.WriteText(&sb)
	if strings.Contains(sb.String(), "GUARD_PAUSE") {
		t.Fatal("guard event rendered as an orphan line")
	}
}

func TestMemorySectionText(t *testing.T) {
	res, ev := writeFixture(t)
	recs, evs := ReadResources(res, ev, time.Unix(0, 0))
	r := Build("1h", time.Unix(0, 0), nil, nil).WithResources(recs, evs)
	var sb strings.Builder
	r.WriteText(&sb)
	out := sb.String()
	for _, want := range []string{"Memory:", "4 samples", "critical 1", "compressor max 40%", "swap max", "headroom min 2.8 GB", "9.0 GB", "[main]", "alerts: memory_pressure 1, swap_over_limit 2", "GUARD_KILL"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
