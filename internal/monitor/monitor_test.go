package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/procscan"
	"github.com/ericmacdougall/netwatch/internal/record"
)

type fakeCollector struct {
	mu    sync.Mutex
	nets  []netrate.Snapshot
	procs []procscan.Process
	gwRTT *float64
}

func (f *fakeCollector) Processes(context.Context) ([]procscan.Process, error) { return f.procs, nil }
func (f *fakeCollector) Net(context.Context, string) (netrate.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.nets[0]
	if len(f.nets) > 1 {
		f.nets = f.nets[1:]
	}
	return s, nil
}
func (f *fakeCollector) Gateway(context.Context) (collector.Gateway, error) {
	return collector.Gateway{Addr: "192.0.2.1", Iface: "eth0"}, nil
}
func (f *fakeCollector) Ping(_ context.Context, host string, _ int) *health.Ping {
	if host == "192.0.2.1" && f.gwRTT != nil {
		return &health.Ping{Avg: f.gwRTT, Max: f.gwRTT}
	}
	v := 5.0
	return &health.Ping{Avg: &v, Max: &v}
}
func (f *fakeCollector) OrphanRule() procscan.OrphanRule        { return procscan.InitParent }
func (f *fakeCollector) Terminate(procscan.Process, bool) error { return nil }
func (f *fakeCollector) Notify(string, string) error            { return nil }

func TestOnceEmitsExpectedEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Compile()
	slow := 120.0
	t0 := time.Now()
	k := netrate.Key{Name: "uploader", PID: 77}
	fc := &fakeCollector{
		nets: []netrate.Snapshot{
			{At: t0, HasBytes: true, Procs: map[netrate.Key]netrate.Counter{}},
			{At: t0.Add(time.Second), HasBytes: true, Procs: map[netrate.Key]netrate.Counter{k: {Out: 200 * 1024}}},
		},
		procs: []procscan.Process{
			{PID: 1, PPID: 0, Cmd: "/sbin/launchd", Start: t0.Add(-time.Hour)},
			{PID: 50, PPID: 1, Own: true, Age: 2 * time.Hour, Start: t0.Add(-2 * time.Hour), CPU: 1, RSSMB: 40,
				Cmd: "node /srv/dev.js --api-key=topsecretvalue"},
			{PID: 99, PPID: 1, Own: true, Age: time.Hour, Start: t0.Add(-time.Hour), RSSMB: 12, Cmd: "netwatch run"},
		},
		gwRTT: &slow,
	}
	var out, errs bytes.Buffer
	var notes []string
	lim := notify.New(true, time.Minute, func(title, msg string) error { notes = append(notes, title+": "+msg); return nil })
	d := Deps{Cfg: &cfg, Col: fc,
		Events:  eventlog.NewWriter(filepath.Join(dir, "events.jsonl"), 1<<20),
		Samples: eventlog.NewWriter(filepath.Join(dir, "samples.jsonl"), 1<<20),
		Notify:  lim, Out: &out, Errs: &errs, Version: "test", Self: 99, OnceWait: time.Millisecond}
	if err := Run(context.Background(), d, true); err != nil {
		t.Fatal(err)
	}
	evs, err := eventlog.ReadSince(filepath.Join(dir, "events.jsonl"), time.Time{}, func(e record.Event) string { return e.TS })
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range evs {
		names = append(names, e.Event)
	}
	got := strings.Join(names, ",")
	if got != "START,ORPHAN,NEW_NET_APP,DEGRADED" {
		t.Fatalf("events = %s\nstderr: %s", got, errs.String())
	}
	if evs[1].PID != 50 || strings.Contains(evs[1].Cmd, "topsecretvalue") {
		t.Fatalf("orphan event wrong or unredacted: %+v", evs[1])
	}
	if evs[2].Proc != "uploader" || *evs[2].OutKBps != 200 || !*evs[2].FirstSeenName {
		t.Fatalf("new app event wrong: %+v", evs[2])
	}
	if len(evs[3].Top) != 1 || evs[3].Top[0].Proc != "uploader" {
		t.Fatalf("degraded should carry top talkers: %+v", evs[3])
	}
	samples, _ := eventlog.ReadSince(filepath.Join(dir, "samples.jsonl"), time.Time{}, func(s record.Sample) string { return s.TS })
	if len(samples) != 1 || samples[0].OutKBps != 200 || samples[0].Self == nil || samples[0].Self.RSSMB != 12 {
		t.Fatalf("sample wrong: %+v", samples)
	}
	if len(notes) != 3 {
		t.Fatalf("want orphan, new app and degraded notifications, got %v", notes)
	}
	for _, n := range notes {
		if strings.Contains(n, "topsecretvalue") {
			t.Fatalf("secret in notification: %s", n)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !json.Valid([]byte(lines[0])) {
		t.Fatalf("stdout should echo 4 JSON events, got %q", out.String())
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Compile()
	fc := &fakeCollector{nets: []netrate.Snapshot{{At: time.Now(), Procs: map[netrate.Key]netrate.Counter{}}}}
	ctx, cancel := context.WithCancel(context.Background())
	d := Deps{Cfg: &cfg, Col: fc,
		Events:  eventlog.NewWriter(filepath.Join(dir, "events.jsonl"), 1<<20),
		Samples: eventlog.NewWriter(filepath.Join(dir, "samples.jsonl"), 1<<20)}
	done := make(chan error)
	go func() { done <- Run(ctx, d, false) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	evs, _ := eventlog.ReadSince(filepath.Join(dir, "events.jsonl"), time.Time{}, func(e record.Event) string { return e.TS })
	if len(evs) != 2 || evs[1].Event != record.Stop {
		t.Fatalf("want START,STOP got %+v", evs)
	}
}

// A collector whose first network reading fails must not report every
// process as new once readings start (nettop can take a while to start).
type lateNet struct {
	fakeCollector
	calls int
}

func (l *lateNet) Net(ctx context.Context, iface string) (netrate.Snapshot, error) {
	l.calls++
	if l.calls == 1 {
		return netrate.Snapshot{}, context.DeadlineExceeded
	}
	return l.fakeCollector.Net(ctx, iface)
}

func TestLateFirstReadingSeedsDetector(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Compile()
	t0 := time.Now()
	busy := map[netrate.Key]netrate.Counter{{Name: "browser", PID: 5}: {In: 1 << 30}}
	lc := &lateNet{fakeCollector: fakeCollector{nets: []netrate.Snapshot{{At: t0, HasBytes: true, Procs: busy}}}}
	d := Deps{Cfg: &cfg, Col: lc,
		Events:  eventlog.NewWriter(filepath.Join(dir, "events.jsonl"), 1<<20),
		Samples: eventlog.NewWriter(filepath.Join(dir, "samples.jsonl"), 1<<20), OnceWait: time.Millisecond}
	if err := Run(context.Background(), d, true); err != nil {
		t.Fatal(err)
	}
	evs, _ := eventlog.ReadSince(filepath.Join(dir, "events.jsonl"), time.Time{}, func(e record.Event) string { return e.TS })
	for _, e := range evs {
		if e.Event == record.NewNetApp {
			t.Fatalf("seeding failed, got %+v", e)
		}
	}
}
