//go:build !windows

package incident

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/transcript"
)

const (
	tsess = "11111111-2222-4333-8444-555555555555"
	// Assembled so secret scanners do not flag the fixture.
	fixtureSecret = "hunter2" + "hunter2pw"
)

var T0 = time.Date(2026, 11, 4, 16, 6, 43, 0, time.UTC)

func call(offset time.Duration, agent string) transcript.Call {
	return transcript.Call{At: T0.Add(-offset), SessionID: tsess, AgentID: agent, Redacted: "cmd", SHA256: strings.Repeat("ab", 32)}
}

func TestRankCandidatesConfidenceRule(t *testing.T) {
	s := time.Second
	// medium: exactly one within 15s and nothing else within 30s. Calls at
	// 31s and 50s are outside the quiet radius.
	got := RankCandidates([]transcript.Call{call(10*s, "a1"), call(31*s, "a2"), call(50*s, "a3")}, T0)
	if len(got) != 3 || got[0].Confidence != "medium" || got[0].AgentID != "a1" || got[1].Confidence != "low" {
		t.Fatalf("medium case: %+v", got)
	}
	// low: a second call inside 30s (the real incident had calls 10.7s and
	// 16.5s away).
	got = RankCandidates([]transcript.Call{call(10700*time.Millisecond, "a1"), call(16500*time.Millisecond, "a2")}, T0)
	if got[0].Confidence != "low" {
		t.Errorf("second call within 30s must make it low: %+v", got)
	}
	// low: two within 15s.
	if got = RankCandidates([]transcript.Call{call(5*s, "a1"), call(9*s, "a2")}, T0); got[0].Confidence != "low" {
		t.Errorf("two near calls: %+v", got)
	}
	// low: a single call, but farther than 15s.
	if got = RankCandidates([]transcript.Call{call(20*s, "a1")}, T0); len(got) != 1 || got[0].Confidence != "low" {
		t.Errorf("single distant call: %+v", got)
	}
}

func TestRankCandidatesWindowAndOrder(t *testing.T) {
	s := time.Second
	calls := []transcript.Call{
		call(61*s, "toofar"), call(60*s, "edge-early"), call(20*s, "mid"), call(-1500*time.Millisecond, "just-after"),
		call(-3*s, "after-window"), call(8*s, "close"),
	}
	got := RankCandidates(calls, T0)
	var ids []string
	for _, c := range got {
		ids = append(ids, c.AgentID)
	}
	if strings.Join(ids, ",") != "just-after,close,mid,edge-early" {
		t.Fatalf("order/window: %v", ids)
	}
	if got[0].Before >= 0 || got[0].Rank != 1 || got[3].Rank != 4 {
		t.Errorf("fields: %+v", got)
	}
	if RankCandidates(nil, T0) != nil || RankCandidates([]transcript.Call{call(90*s, "x")}, T0) != nil {
		t.Error("no candidate expected")
	}
	var many []transcript.Call
	for i := 1; i <= 20; i++ {
		many = append(many, call(time.Duration(i)*s, fmt.Sprint("a", i)))
	}
	if len(RankCandidates(many, T0)) != 5 {
		t.Error("candidates not capped at 5")
	}
}

func writeTranscript(t *testing.T, root string, calls ...string) {
	t.Helper()
	p := filepath.Join(root, "-proj", tsess+".jsonl")
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(strings.Join(calls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func tline(ts, agent, cmd string) string {
	m := map[string]any{"timestamp": ts, "sessionId": tsess, "agentId": agent, "message": map[string]any{"content": []any{
		map[string]any{"type": "tool_use", "name": "Bash", "id": "toolu_1", "input": map[string]any{"command": cmd}}}}}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestCollectRanksTranscriptCandidates(t *testing.T) {
	root := t.TempDir()
	// Fixture culprit starts at 16:06:42.99; one call 10.8s earlier.
	writeTranscript(t, root,
		tline("2026-11-04T16:06:32.200Z", "aaaa1111", "python3 big.py --password="+fixtureSecret),
		tline("2026-11-04T15:00:00Z", "bbbb2222", "ls"))
	now := time.Now() // files are fresh, so the mtime window keeps them
	rep, err := Collect(Options{JetsamDir: jetsamFixture, TranscriptRoot: root, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Candidates) != 1 || rep.Candidates[0].AgentID != "aaaa1111" || rep.Candidates[0].Confidence != "medium" {
		t.Fatalf("candidates: %+v", rep.Candidates)
	}
	var b strings.Builder
	rep.Render(&b)
	js, _ := rep.JSON()
	for _, out := range []string{b.String(), string(js)} {
		if strings.Contains(out, fixtureSecret) {
			t.Errorf("raw secret in output")
		}
		if !strings.Contains(out, "aaaa1111") {
			t.Errorf("candidate missing from output")
		}
	}
	if !strings.Contains(b.String(), "Candidate 1 (medium)") {
		t.Errorf("text output: %s", b.String())
	}
	// With no samples the candidate becomes the replay's attribution.
	in := ReplayInputFrom(rep, ModePauseKill)
	if !strings.Contains(in.AgentLabel, "aaaa1111") {
		t.Errorf("replay label %q", in.AgentLabel)
	}
	if r := ReplayGuard(in); !r.Verified {
		t.Errorf("replay with transcript attribution not verified: %+v", r.Checks)
	}
}

func TestCollectTranscriptControls(t *testing.T) {
	now := time.Now()
	t.Run("empty transcript dir is attribution unknown", func(t *testing.T) {
		rep, _ := Collect(Options{JetsamDir: jetsamFixture, TranscriptRoot: t.TempDir(), Now: now})
		if len(rep.Candidates) != 0 || !strings.Contains(strings.Join(rep.Notes, "|"), "attribution unknown") {
			t.Errorf("%+v %v", rep.Candidates, rep.Notes)
		}
		if r := ReplayGuard(ReplayInputFrom(rep, ModePauseKill)); r.Verified || !strings.Contains(strings.Join(r.Notes, "|"), "attribution unknown, not eligible") {
			t.Errorf("replay: %v %v", r.Verified, r.Notes)
		}
	})
	t.Run("no root configured", func(t *testing.T) {
		rep, _ := Collect(Options{JetsamDir: jetsamFixture, Now: now})
		if !strings.Contains(strings.Join(rep.Notes, "|"), "no transcript root") {
			t.Errorf("%v", rep.Notes)
		}
	})
	t.Run("calls outside the window are not candidates", func(t *testing.T) {
		root := t.TempDir()
		writeTranscript(t, root, tline("2026-11-04T16:06:46Z", "late", "ls"), tline("2026-11-04T16:05:00Z", "early", "ls"))
		rep, _ := Collect(Options{JetsamDir: jetsamFixture, TranscriptRoot: root, Now: now})
		if len(rep.Candidates) != 0 {
			t.Errorf("%+v", rep.Candidates)
		}
	})
}

// Optional, Mac only: the real evidence and real transcripts. Never
// committed; set JETSAM_EVIDENCE_DIR and TRANSCRIPT_ROOT.
func TestRealTranscriptCandidateIfPresent(t *testing.T) {
	ev, root := os.Getenv("JETSAM_EVIDENCE_DIR"), os.Getenv("TRANSCRIPT_ROOT")
	if ev == "" || root == "" {
		t.Skip("JETSAM_EVIDENCE_DIR and TRANSCRIPT_ROOT not set")
	}
	rep, err := Collect(Options{JetsamDir: ev, DiagDirs: []string{ev}, TranscriptRoot: root, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Candidates {
		t.Logf("candidate %d %s %s agent=%s session=%.8s before=%s", c.Rank, c.Confidence, c.At.Format("15:04:05.000Z"), c.AgentID, c.SessionID, c.Before)
	}
	t.Logf("notes: %v", rep.Notes)
	if len(rep.Candidates) == 0 {
		t.Fatal("no candidate found")
	}
}
