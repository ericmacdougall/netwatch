//go:build !windows

package incident

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/record"
)

type memAppender struct{ recs []Record }

func (m *memAppender) Append(r any) error {
	m.recs = append(m.recs, r.(Record))
	return nil
}

// fileAppender appends to a real events.jsonl so a second Detect sees the
// first INCIDENT.
type fileAppender struct{ w *eventlog.Writer }

func (f fileAppender) Append(r any) error { return f.w.Append(r) }

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ev(ts, name string) string {
	b, _ := json.Marshal(map[string]string{"ts": ts, "event": name})
	return string(b)
}

type udir struct {
	dir, events, res, diags string
}

func newDirs(t *testing.T) udir {
	t.Helper()
	d := t.TempDir()
	u := udir{dir: d, events: filepath.Join(d, "events.jsonl"), res: filepath.Join(d, "resources.jsonl"), diags: filepath.Join(d, "diag")}
	if err := os.Mkdir(u.diags, 0o700); err != nil {
		t.Fatal(err)
	}
	return u
}

func (u udir) cfg(now string, t *testing.T) DetectConfig {
	return DetectConfig{EventsPath: u.events, ActivityPaths: []string{u.res}, DiagDirs: []string{u.diags}, Now: mt(t, now)}
}

const resetDiag = `{"bug_type":"115","timestamp":"2026-11-04 16:35:09.00 +0000","name":"Reset count"}
Date: 2026-11-04 16:35:09.86 +0000
Reset count: 1
`

func TestDetectCleanShutdownWritesNothing(t *testing.T) {
	u := newDirs(t)
	writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start), ev("2026-11-04T16:00:00Z", record.Stop))
	w := &memAppender{}
	det, wrote, err := CheckAndRecord(u.cfg("2026-11-04T17:00:00Z", t), w, nil)
	if err != nil || wrote || det.Unclean || len(w.recs) != 0 {
		t.Fatalf("clean STOP produced an incident: %+v %v %v", det, wrote, err)
	}
}

func TestDetectUncleanWritesExactlyOneIncident(t *testing.T) {
	u := newDirs(t)
	writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start), ev("2026-11-04T16:06:50Z", record.NewNetApp))
	cfg := u.cfg("2026-11-04T16:40:00Z", t)
	ea := fileAppender{eventlog.NewWriter(u.events, 1<<20)}

	det, wrote, err := CheckAndRecord(cfg, ea, nil)
	if err != nil || !wrote || !det.Unclean || det.Kind != KindUncleanShutdown || !det.NoStop {
		t.Fatalf("first start: %+v wrote=%v err=%v", det, wrote, err)
	}
	if det.Gap < 30*time.Minute {
		t.Errorf("gap %s", det.Gap)
	}
	// A second start over the same gap (before any new START) must not
	// write another INCIDENT.
	cfg.Now = cfg.Now.Add(30 * time.Second)
	det2, wrote2, err := CheckAndRecord(cfg, ea, nil)
	if err != nil || wrote2 || !det2.Duplicate {
		t.Fatalf("second start duplicated: %+v wrote=%v err=%v", det2, wrote2, err)
	}
	n := 0
	evs, _ := readEvents(u.events)
	for _, e := range evs {
		if e.Event == record.Incident {
			n++
		}
	}
	if n != 1 {
		t.Errorf("INCIDENT events: %d", n)
	}
	// After a new START and another crash, a new incident is legitimate.
	ea.Append(map[string]string{"ts": "2026-11-04T16:41:00Z", "event": record.Start})
	ea.Append(map[string]string{"ts": "2026-11-04T16:45:00Z", "event": "NEW_NET_APP"})
	cfg.Now = mt(t, "2026-11-04T17:30:00Z")
	if _, wrote3, _ := CheckAndRecord(cfg, ea, nil); !wrote3 {
		t.Error("a later crash must be recorded")
	}
}

func TestDetectQuickRestartIsNotAnIncident(t *testing.T) {
	u := newDirs(t)
	writeLines(t, u.events, ev("2026-11-04T16:06:50Z", record.Start))
	det, wrote, _ := CheckAndRecord(u.cfg("2026-11-04T16:06:58Z", t), &memAppender{}, nil)
	if wrote || det.Unclean {
		t.Fatalf("8s restart flagged: %+v", det)
	}
}

func TestDetectResourceActivityExtendsLastSeen(t *testing.T) {
	u := newDirs(t)
	writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start))
	writeLines(t, u.res, `{"ts":"2026-11-04T16:06:50Z","pressure":"normal"}`, `{"ts":"2026-11-04T16:06:5`)
	det, _ := Detect(u.cfg("2026-11-04T16:40:00Z", t))
	if !det.PrevLast.Equal(mt(t, "2026-11-04T16:06:50Z")) {
		t.Errorf("prev last %s (torn tail must be skipped, resources counted)", det.PrevLast)
	}
}

func TestDetectResetDiag(t *testing.T) {
	u := newDirs(t)
	// A clean STOP, then a reset report newer than it: still an incident.
	writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start), ev("2026-11-04T16:00:00Z", record.Stop))
	os.WriteFile(filepath.Join(u.diags, "ResetCounter-2026-11-04-163509.diag"), []byte(resetDiag), 0o644)
	w := &memAppender{}
	det, wrote, err := CheckAndRecord(u.cfg("2026-11-04T17:00:00Z", t), w, nil)
	if err != nil || !wrote || det.Kind != KindHostReset || len(w.recs[0].Diags) != 1 {
		t.Fatalf("%+v %v %v", det, wrote, err)
	}
	t.Run("an older diag is not new", func(t *testing.T) {
		u := newDirs(t)
		writeLines(t, u.events, ev("2026-11-04T17:00:00Z", record.Start), ev("2026-11-04T17:30:00Z", record.Stop))
		os.WriteFile(filepath.Join(u.diags, "ResetCounter-2026-11-04-163509.diag"), []byte(resetDiag), 0o644)
		if det, _ := Detect(u.cfg("2026-11-04T18:00:00Z", t)); det.Unclean {
			t.Errorf("old diag counted: %+v", det)
		}
	})
	t.Run("panic report counts", func(t *testing.T) {
		u := newDirs(t)
		writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start), ev("2026-11-04T16:00:00Z", record.Stop))
		os.WriteFile(filepath.Join(u.diags, "Kernel-panic-2026-11-04.diag"), []byte(`{"timestamp":"2026-11-04 16:30:00.00 +0000"}`+"\nx\n"), 0o644)
		if det, _ := Detect(u.cfg("2026-11-04T17:00:00Z", t)); det.Kind != KindHostReset {
			t.Errorf("%+v", det)
		}
	})
	t.Run("a diag with no readable time is ignored", func(t *testing.T) {
		u := newDirs(t)
		writeLines(t, u.events, ev("2026-11-04T15:00:00Z", record.Start), ev("2026-11-04T16:00:00Z", record.Stop))
		os.WriteFile(filepath.Join(u.diags, "ResetCounter-junk.diag"), []byte("junk"), 0o644)
		if det, _ := Detect(u.cfg("2026-11-04T17:00:00Z", t)); det.Unclean {
			t.Error("junk diag counted")
		}
	})
}

func TestDetectNoPreviousRunAndHostileFiles(t *testing.T) {
	u := newDirs(t)
	if det, err := Detect(u.cfg("2026-11-04T17:00:00Z", t)); err != nil || det.Unclean {
		t.Fatalf("no log: %+v %v", det, err)
	}
	// events.jsonl is a FIFO: must not block, must not be read.
	if err := syscall.Mkfifo(u.events, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		det, err := Detect(u.cfg("2026-11-04T17:00:00Z", t))
		if err == nil && det.Unclean {
			t.Error("FIFO treated as a log")
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Detect blocked on a FIFO")
	}
	// A symlinked events file is refused too.
	os.Remove(u.events)
	real := filepath.Join(u.dir, "real")
	writeLines(t, real, ev("2026-11-04T15:00:00Z", record.Start))
	os.Symlink(real, u.events)
	if det, err := Detect(u.cfg("2026-11-04T17:00:00Z", t)); err == nil && det.Unclean {
		t.Error("symlinked events file was followed")
	}
}

func TestCollectJoinsEvidence(t *testing.T) {
	rep := collectFixture(t)
	e := rep.Estimate
	if e == nil || e.PID != 10934 {
		t.Fatalf("estimate %+v", e)
	}
	within := e.Start.Sub(mt(t, "2026-11-04T16:06:43Z"))
	if within < -500*time.Millisecond || within > 500*time.Millisecond {
		t.Errorf("start %s", e.Start)
	}
	if e.Attribution == nil || e.Attribution.Agent != "agent-fixture" || e.Attribution.Confidence != "medium" {
		t.Errorf("attribution %+v", e.Attribution)
	}
	if e.FirstSample == nil || !e.FirstSample.Equal(mt(t, "2026-11-04T16:06:44Z")) {
		t.Errorf("first sample %v", e.FirstSample)
	}
	if len(rep.Resets) != 1 || rep.Resets[0].Kind != DiagReset {
		t.Errorf("resets %+v", rep.Resets)
	}
	var out bytes.Buffer
	rep.Render(&out)
	for _, want := range []string{"jetsam report", "pressure critical", "estimated start", "Attribution from samples: agent-fixture"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("render lacks %q:\n%s", want, out.String())
		}
	}
	for i := 1; i < len(rep.Entries); i++ {
		if rep.Entries[i].At.Before(rep.Entries[i-1].At) {
			t.Fatal("timeline not sorted")
		}
	}
	if js, err := rep.JSON(); err != nil || !json.Valid(js) {
		t.Errorf("json: %v", err)
	}
}

func TestCollectWithoutSamplesHasNoAttribution(t *testing.T) {
	rep, err := Collect(Options{JetsamDir: jetsamFixture, LogDir: t.TempDir(), Now: mt(t, "2026-11-04T17:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Estimate == nil || rep.Estimate.Attribution != nil || rep.Estimate.Note == "" {
		t.Errorf("estimate %+v", rep.Estimate)
	}
	if !strings.Contains(strings.Join(rep.Notes, "|"), "no resource samples") {
		t.Errorf("notes %v", rep.Notes)
	}
	r := ReplayGuard(ReplayInputFrom(rep, ModePauseKill))
	if r.Verified || !strings.Contains(strings.Join(r.Notes, "|"), "attribution unknown, not eligible") {
		t.Errorf("replay without attribution: verified=%v notes=%v", r.Verified, r.Notes)
	}
}

func TestCollectMissingEvidenceIsNotVerified(t *testing.T) {
	rep, err := Collect(Options{JetsamDir: filepath.Join(t.TempDir(), "none"), LogDir: t.TempDir(), Now: mt(t, "2026-11-04T17:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Estimate != nil || !strings.Contains(strings.Join(rep.Notes, "|"), "not verified") {
		t.Errorf("%+v", rep)
	}
	if r := ReplayGuard(ReplayInputFrom(rep, ModePauseKill)); r.Verified || r.Checks[0].Status != "not verified" {
		t.Errorf("replay: %+v", r.Checks)
	}
}

func TestLastClusterOnly(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"JetsamEvent-2026-11-04-160707.ips", "JetsamEvent-2026-11-04-160732.ips", "JetsamEvent-2026-11-04-161829.ips"} {
		b, _ := os.ReadFile(filepath.Join(jetsamFixture, f))
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	// An older, unrelated incident two hours earlier.
	old, _ := os.ReadFile(filepath.Join(jetsamFixture, "JetsamEvent-2026-11-04-160707.ips"))
	old = bytes.ReplaceAll(old, []byte("16:07:07"), []byte("12:07:07"))
	os.WriteFile(filepath.Join(dir, "JetsamEvent-2026-11-04-120707.ips"), old, 0o600)
	all, _ := Collect(Options{JetsamDir: dir, Now: mt(t, "2026-11-04T17:00:00Z")})
	last, _ := Collect(Options{JetsamDir: dir, Last: true, Now: mt(t, "2026-11-04T17:00:00Z")})
	if len(all.Reports) != 4 || len(last.Reports) != 3 {
		t.Fatalf("all=%d last=%d", len(all.Reports), len(last.Reports))
	}
}
