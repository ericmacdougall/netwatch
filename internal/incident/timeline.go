package incident

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/jetsam"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/transcript"
)

// Attribution is the agent label for the culprit taken from the samples
// recorded before the crash.
type Attribution struct {
	Agent      string    `json:"agent"`
	Confidence string    `json:"confidence,omitempty"`
	SampleAt   time.Time `json:"sample_at"`
}

// Estimate is the best guess of what caused the incident and when it
// started, derived from the jetsam reports and corroborated by samples.
type Estimate struct {
	Process     string       `json:"process"`
	PID         int          `json:"pid"`
	Start       time.Time    `json:"start"`
	StartSource string       `json:"start_source"`
	GiB         float64      `json:"gib_at_first_report"`
	FirstSample *time.Time   `json:"first_sample,omitempty"`
	Attribution *Attribution `json:"attribution,omitempty"`
	Note        string       `json:"note,omitempty"`
}

// BuildEstimate picks the largest process of the first report with a
// non-idle kill (or the first report), dates it as snapshot - age/24e6 and
// joins the samples. It returns nil without reports.
func BuildEstimate(reports []*jetsam.Report, samples []Sample) *Estimate {
	if len(reports) == 0 {
		return nil
	}
	rep := firstNonIdle(reports)
	if rep == nil {
		rep = reports[0]
	}
	top := rep.Top()
	if top == nil {
		return nil
	}
	e := &Estimate{Process: top.Name, PID: top.PID, Start: top.Start, StartSource: "jetsam: snapshot - age/24e6",
		GiB: float64(top.Bytes) / (1 << 30)}
	for _, s := range samples {
		for _, p := range s.Top {
			if p.PID != top.PID || p.Name != top.Name {
				continue
			}
			if e.FirstSample == nil {
				t := s.At
				e.FirstSample = &t
			}
			// Keep the last labelled sample at or before the first report.
			if p.Agent != "" && !s.At.After(rep.Written) {
				e.Attribution = &Attribution{Agent: p.Agent, Confidence: p.Confidence, SampleAt: s.At}
			}
		}
	}
	if e.Attribution == nil {
		e.Note = "attribution unknown: no labelled sample of this process before the crash"
	}
	return e
}

// Entry is one line of the incident timeline.
type Entry struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
	Text   string    `json:"text"`
}

// Report is the joined incident view.
type Report struct {
	Generated time.Time        `json:"generated"`
	Entries   []Entry          `json:"timeline"`
	Estimate  *Estimate        `json:"estimate,omitempty"`
	Resets    []DiagInfo       `json:"resets,omitempty"`
	Skipped   []jetsam.Skip    `json:"skipped,omitempty"`
	Notes     []string         `json:"notes,omitempty"`
	Reports   []*jetsam.Report `json:"-"`
	// Candidates are the transcript Bash calls that may have started the
	// culprit, best first (see candidates.go for the rule).
	Candidates []Candidate `json:"candidates,omitempty"`
}

// Options says where to look.
type Options struct {
	LogDir    string // holds events.jsonl and resources.jsonl
	JetsamDir string
	DiagDirs  []string
	// TranscriptRoot is the projects root to rank candidates from; empty
	// means no transcript attribution.
	TranscriptRoot string
	Since          time.Time // zero: everything the bounds allow
	Last           bool      // only the most recent cluster of reports
	Now            time.Time
}

// clusterGap separates two incidents: reports closer than this belong to
// one.
const clusterGap = 30 * time.Minute

// Collect reads the evidence directories and joins them. Missing sources
// become notes, not errors.
func Collect(o Options) (*Report, error) {
	rep := &Report{Generated: o.Now}
	var reports []*jetsam.Report
	if o.JetsamDir != "" {
		res, err := jetsam.ScanDir(o.JetsamDir, jetsam.ScanLimits{Since: o.Since})
		if err != nil {
			rep.Notes = append(rep.Notes, "jetsam directory unreadable: "+err.Error())
		} else {
			reports, rep.Skipped = res.Reports, res.Skipped
		}
	}
	if o.Last {
		reports = lastCluster(reports)
	}
	rep.Reports = reports
	if len(reports) == 0 {
		rep.Notes = append(rep.Notes, "not verified: no jetsam reports found")
	}

	from, to := o.Since, o.Now
	if len(reports) > 0 {
		from = reports[0].Snapshot.Add(-10 * time.Minute)
		to = reports[len(reports)-1].Written.Add(time.Minute)
	}
	var samples []Sample
	if o.LogDir != "" {
		s, _ := ReadSamples(filepath.Join(o.LogDir, "resources.jsonl"), from, to)
		samples = s
		if len(samples) == 0 {
			rep.Notes = append(rep.Notes, "no resource samples in the window: the estimate has no sample corroboration and no attribution")
		}
		rep.Entries = append(rep.Entries, eventEntries(filepath.Join(o.LogDir, "events.jsonl"), from, to)...)
	}
	rep.Estimate = BuildEstimate(reports, samples)
	rep.rankTranscripts(o)
	rep.Resets = ScanDiags(o.DiagDirs, from, to.Add(2*time.Hour))
	rep.Entries = append(rep.Entries, reportEntries(reports)...)
	rep.Entries = append(rep.Entries, sampleEntries(samples)...)
	for _, d := range rep.Resets {
		rep.Entries = append(rep.Entries, Entry{d.At, "diag", fmt.Sprintf("%s report %s", d.Kind, filepath.Base(d.Path))})
	}
	for _, c := range rep.Candidates[:min(len(rep.Candidates), 1)] {
		rep.Entries = append(rep.Entries, Entry{c.At, "transcript", "candidate Bash call (" + c.Confidence + "): " + c.Label()})
	}
	if rep.Estimate != nil {
		rep.Entries = append(rep.Entries, Entry{rep.Estimate.Start, "estimate",
			fmt.Sprintf("estimated start of %s pid %d (%s)", rep.Estimate.Process, rep.Estimate.PID, rep.Estimate.StartSource)})
	}
	sort.SliceStable(rep.Entries, func(i, j int) bool { return rep.Entries[i].At.Before(rep.Entries[j].At) })
	return rep, nil
}

func lastCluster(rs []*jetsam.Report) []*jetsam.Report {
	if len(rs) == 0 {
		return rs
	}
	i := len(rs) - 1
	for i > 0 && rs[i].Snapshot.Sub(rs[i-1].Written) <= clusterGap {
		i--
	}
	return rs[i:]
}

func reportEntries(rs []*jetsam.Report) []Entry {
	var out []Entry
	for _, r := range rs {
		kills := 0
		for _, p := range r.Procs {
			if p.Reason != "" && !p.Idle {
				kills++
			}
		}
		text := fmt.Sprintf("jetsam report %s: %d non-idle kills, snapshot %s", filepath.Base(r.Path), kills, r.Snapshot.UTC().Format("15:04:05.0Z"))
		if t := r.Top(); t != nil {
			text += fmt.Sprintf(", largest %s pid %d %.1f GiB", t.Name, t.PID, float64(t.Bytes)/(1<<30))
		}
		out = append(out, Entry{r.Written, "jetsam", text})
		if r.NonIdleKill {
			out = append(out, Entry{r.Snapshot, "jetsam", "snapshot of " + filepath.Base(r.Path) + " (non-idle kills)"})
		}
	}
	return out
}

// sampleEntries keeps pressure transitions only, so a long window stays
// readable.
func sampleEntries(ss []Sample) []Entry {
	var out []Entry
	last := resources.LevelUnknown
	for _, s := range ss {
		if s.Pressure == last {
			continue
		}
		last = s.Pressure
		text := fmt.Sprintf("pressure %s, compressor %.0f%%", s.Pressure, s.CompressorPct)
		if len(s.Top) > 0 {
			text += fmt.Sprintf(", top %s pid %d %.1f GiB", s.Top[0].Name, s.Top[0].PID, float64(s.Top[0].Footprint)/(1<<30))
			if s.Top[0].Agent != "" {
				text += " (" + s.Top[0].Agent + ")"
			}
		}
		out = append(out, Entry{s.At, "sample", text})
	}
	return out
}

func eventEntries(path string, from, to time.Time) []Entry {
	evs, _ := readEvents(path)
	var out []Entry
	for _, e := range evs {
		if e.At.Before(from) || e.At.After(to) {
			continue
		}
		switch e.Event {
		case "START", "STOP", "INCIDENT", "GUARD_PAUSE", "GUARD_RESUME", "GUARD_KILL", "RESOURCE_ALERT", "HOST_AT_RISK_UNPROTECTED", "MODE_CHANGE":
			out = append(out, Entry{e.At, "event", e.Event})
		}
	}
	return out
}

// Render writes the human-readable timeline.
func (r *Report) Render(w io.Writer) {
	fmt.Fprintf(w, "Incident timeline (%d entries)\n", len(r.Entries))
	for _, e := range r.Entries {
		fmt.Fprintf(w, "  %s  %-8s %s\n", e.At.UTC().Format("2006-01-02 15:04:05.0Z"), e.Source, e.Text)
	}
	if r.Estimate != nil {
		e := r.Estimate
		fmt.Fprintf(w, "\nEstimated culprit: %s pid %d, %.2f GiB at the first report, started %s (%s)\n",
			e.Process, e.PID, e.GiB, e.Start.UTC().Format("15:04:05.0Z"), e.StartSource)
		if e.Attribution != nil {
			fmt.Fprintf(w, "Attribution from samples: %s (confidence %s, sample %s)\n", e.Attribution.Agent, orDash(e.Attribution.Confidence), e.Attribution.SampleAt.UTC().Format("15:04:05Z"))
		} else {
			fmt.Fprintf(w, "Attribution: unknown\n")
		}
	}
	for _, c := range r.Candidates {
		fmt.Fprintf(w, "Candidate %d (%s, name match %v): %s at %s, %s before the start, %s\n    %s\n", c.Rank, c.Confidence, c.NameMatch, c.Label(),
			c.At.UTC().Format("15:04:05.0Z"), c.Before.Round(100*time.Millisecond), "sha256 "+c.SHA256[:12], c.Command)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(w, "skipped %s: %s\n", filepath.Base(s.Path), s.Err)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// JSON encodes the report.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Render writes the replay as text.
func (r *ReplayReport) Render(w io.Writer) {
	fmt.Fprintln(w, "Guard replay (simulation, not a measurement)")
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	if r.Culprit != nil {
		c := r.Culprit
		fmt.Fprintf(w, "Culprit: %s pid %d, started %s, %.2f GiB at the first non-idle report; D1 onset %s\n",
			c.Name, c.PID, ts(c.Start), c.GiB, ts(r.Onset))
	}
	fmt.Fprintln(w, "Assumptions:")
	for _, a := range r.Assumptions {
		fmt.Fprintf(w, "  - %s\n", a)
	}
	if r.Inputs != nil {
		keys := make([]string, 0, len(r.Inputs))
		for k := range r.Inputs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprint(w, "Inputs:")
		for _, k := range keys {
			fmt.Fprintf(w, " %s=%v;", k, r.Inputs[k])
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Simulated actions (min..max over poll phases):")
	for _, rg := range r.Ranges {
		fmt.Fprintf(w, "  %-38s | %-34s | pause %s..%s | SIGTERM %s..%s (%s)\n", rg.Ramp, rg.Variant, ts0(rg.PauseMin), ts0(rg.PauseMax), ts0(rg.TermMin), ts0(rg.TermMax), orDash(rg.KillPath))
	}
	for _, res := range r.Results {
		if res.Variant == VariantFast.Name {
			fmt.Fprintf(w, "  pause before headroom ran out (phase 0, %s): %v\n", res.Ramp, res.PauseBeforeHeadroomGone)
		}
	}
	fmt.Fprintln(w, "Checks:")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  [%s] %s: %s\n", c.Status, c.Name, c.Detail)
	}
	fmt.Fprintln(w, "Controls:")
	for _, c := range r.Controls {
		fmt.Fprintf(w, "  [%s] %s: %s\n", c.Status, c.Name, c.Detail)
	}
	fmt.Fprintln(w, "Margins (printed, not asserted; negative means the event came first):")
	for _, m := range r.Margins {
		fmt.Fprintf(w, "  %s vs %s: %s\n", m.Label, m.Action, m.Text)
	}
	fmt.Fprintf(w, "Verified: %v\n%s\n", r.Verified, r.Limitation)
}

func ts0(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return ts(t)
}

// JSON encodes the replay report.
func (r *ReplayReport) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// rankTranscripts adds the transcript candidates for the estimated start.
func (r *Report) rankTranscripts(o Options) {
	if r.Estimate == nil {
		return
	}
	if o.TranscriptRoot == "" {
		r.Notes = append(r.Notes, "no transcript root given: no transcript attribution")
		return
	}
	calls, st, err := transcript.Scan(transcript.Config{Root: o.TranscriptRoot, WindowStart: r.Estimate.Start.Add(-CandidateBefore)})
	if err != nil {
		r.Notes = append(r.Notes, "transcripts unreadable: "+err.Error())
		return
	}
	r.Candidates = RankCandidates(calls, r.Estimate.Start, r.Estimate.Process)
	if len(r.Candidates) == 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("no Bash tool call within [-60s, +2s] of the start (%d transcript files read): attribution unknown", st.FilesRead))
	}
}
