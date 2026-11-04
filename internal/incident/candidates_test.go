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

func call(offset time.Duration, agent string, programs ...string) transcript.Call {
	return transcript.Call{At: T0.Add(-offset), SessionID: tsess, AgentID: agent, Redacted: "cmd", SHA256: strings.Repeat("ab", 32), Programs: programs}
}

func ids(cs []Candidate) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.AgentID)
	}
	return strings.Join(s, ",")
}

func TestNameMatchRanksFirstAndSetsConfidence(t *testing.T) {
	s := time.Second
	// A name-matching call ranks above nearer non-matching calls, and
	// being the only match makes it medium.
	got := RankCandidates([]transcript.Call{
		call(2*s, "near-ls", "ls"), call(30*s, "the-python", "python"), call(5*s, "near-git", "git"),
	}, T0, "Python")
	if ids(got) != "the-python,near-ls,near-git" || !got[0].NameMatch || got[0].Confidence != "medium" || got[1].Confidence != "low" || got[1].NameMatch {
		t.Fatalf("one match: %+v", got)
	}
	// Two name-matching calls: low, closeness orders them.
	got = RankCandidates([]transcript.Call{call(30*s, "far", "python"), call(12*s, "close", "python"), call(1*s, "other", "ls")}, T0, "Python")
	if ids(got) != "close,far,other" || got[0].Confidence != "low" {
		t.Fatalf("two matches: %+v", got)
	}
	// No name match: ordered by closeness, low.
	got = RankCandidates([]transcript.Call{call(20*s, "b", "git"), call(3*s, "a", "ls")}, T0, "Python")
	if ids(got) != "a,b" || got[0].Confidence != "low" || got[0].NameMatch {
		t.Fatalf("no match: %+v", got)
	}
	// An empty process name never matches.
	if got = RankCandidates([]transcript.Call{call(3*s, "a", "")}, T0, ""); got[0].NameMatch || got[0].Confidence != "low" {
		t.Fatalf("empty name: %+v", got)
	}
	// A match outside the window does not count toward "exactly one".
	got = RankCandidates([]transcript.Call{call(10*s, "in", "python"), call(90*s, "out", "python")}, T0, "python")
	if len(got) != 1 || got[0].Confidence != "medium" {
		t.Fatalf("outside-window match: %+v", got)
	}
}

func TestVersionAndCaseInsensitiveMatch(t *testing.T) {
	for _, proc := range []string{"Python", "python3", "python3.12", "PYTHON"} {
		got := RankCandidates([]transcript.Call{call(10*time.Second, "a", transcript.Programs("python3.12 big.py")...)}, T0, proc)
		if !got[0].NameMatch {
			t.Errorf("process %q did not match python3.12", proc)
		}
	}
	if got := RankCandidates([]transcript.Call{call(10*time.Second, "a", "pythonista")}, T0, "Python"); got[0].NameMatch {
		t.Error("prefix match must not count")
	}
}

func TestBeforePreferredToAfter(t *testing.T) {
	s := time.Second
	// 1s before T beats 1s after T; 1s after T still beats 8s before T
	// only if the penalty (5s) says so: 1+5=6 < 8.
	got := RankCandidates([]transcript.Call{call(-1*s, "after1", "ls"), call(1*s, "before1", "ls"), call(8*s, "before8", "ls")}, T0, "x")
	if ids(got) != "before1,after1,before8" {
		t.Fatalf("order %s", ids(got))
	}
	// The after-call is still eligible inside +2s and excluded past it.
	got = RankCandidates([]transcript.Call{call(-1900*time.Millisecond, "in", "ls"), call(-2100*time.Millisecond, "out", "ls")}, T0, "x")
	if ids(got) != "in" {
		t.Fatalf("skew allowance: %s", ids(got))
	}
	// Name match still dominates the before/after preference.
	got = RankCandidates([]transcript.Call{call(1*s, "before-ls", "ls"), call(-1*s, "after-py", "python")}, T0, "python")
	if ids(got) != "after-py,before-ls" {
		t.Fatalf("name match vs side: %s", ids(got))
	}
}

func TestRankWindowAndCap(t *testing.T) {
	s := time.Second
	got := RankCandidates([]transcript.Call{call(61*s, "toofar"), call(60*s, "edge"), call(-3*s, "late")}, T0, "x")
	if ids(got) != "edge" {
		t.Fatalf("window: %s", ids(got))
	}
	if RankCandidates(nil, T0, "x") != nil {
		t.Error("nil expected")
	}
	var many []transcript.Call
	for i := 1; i <= 20; i++ {
		many = append(many, call(time.Duration(i)*s, fmt.Sprint("a", i)))
	}
	if len(RankCandidates(many, T0, "x")) != 5 {
		t.Error("not capped at 5")
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
	if !strings.Contains(b.String(), "Candidate 1 (medium, name match true)") {
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
	// Every name-matching call in the window, ranked or not.
	if rep.Estimate != nil {
		calls, _, _ := transcript.Scan(transcript.Config{Root: root, WindowStart: rep.Estimate.Start.Add(-CandidateBefore)})
		want := transcript.NormalizeName(rep.Estimate.Process)
		for _, c := range calls {
			d := rep.Estimate.Start.Sub(c.At)
			if d >= -CandidateAfter && d <= CandidateBefore && nameMatches(c, want) {
				t.Logf("name-matching call: agent=%s at=%s before=%s cmd=%s", c.AgentID, c.At.Format("15:04:05.000Z"), d, c.Redacted)
			}
		}
	}
	if len(rep.Candidates) == 0 {
		t.Fatal("no candidate found")
	}
}

func TestCollectNameMatchAmongManyCalls(t *testing.T) {
	root := t.TempDir()
	// Fixture culprit (Python) starts at 16:06:42.99. Several agents ran
	// Bash calls around it; only one invoked python.
	writeTranscript(t, root,
		tline("2026-11-04T16:06:42.500Z", "nearest00", "ls -la"),
		tline("2026-11-04T16:06:36.000Z", "other0001", "git status"),
		tline("2026-11-04T16:06:32.200Z", "pyagent01", "cd /home/user/proj && python3.12 -m bigjob --n 5"),
	)
	rep, _ := Collect(Options{JetsamDir: jetsamFixture, TranscriptRoot: root, Now: time.Now()})
	if len(rep.Candidates) != 3 || rep.Candidates[0].AgentID != "pyagent01" || rep.Candidates[0].Confidence != "medium" || !rep.Candidates[0].NameMatch {
		t.Fatalf("%+v", rep.Candidates)
	}
	if rep.Candidates[1].AgentID != "nearest00" || rep.Candidates[1].Confidence != "low" {
		t.Errorf("rest ordered by closeness: %+v", rep.Candidates[1:])
	}
}

func TestCollectNoNameMatchIsLow(t *testing.T) {
	root := t.TempDir()
	writeTranscript(t, root, tline("2026-11-04T16:06:42.500Z", "nearest00", "ls -la"))
	rep, _ := Collect(Options{JetsamDir: jetsamFixture, TranscriptRoot: root, Now: time.Now()})
	if len(rep.Candidates) != 1 || rep.Candidates[0].Confidence != "low" || rep.Candidates[0].NameMatch {
		t.Fatalf("%+v", rep.Candidates)
	}
}
