package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// Reading bounds for log tails.
const (
	tailWindow  = 8 << 20 // bytes examined at the end of a log
	tailLine    = 1 << 20 // longest line kept
	tailRecords = 20000
)

// eventLine is the part of an events.jsonl record the forensics need.
type eventLine struct {
	TS         string `json:"ts"`
	Event      string `json:"event"`
	PrevLastTS string `json:"prev_last_ts"`
	At         time.Time
}

// tail reads the last records of a JSONL log, also looking at the rotated
// ".1" generation when the current file is empty or missing. Torn or
// hostile lines are skipped; a missing log is not an error.
func tailJSONL(path string) ([][]byte, error) {
	var out [][]byte
	for _, p := range []string{path + ".1", path} {
		lines, err := safeio.TailLines(p, tailRecords, tailLine, safeio.Opts{Max: tailWindow})
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		out = append(out, lines...)
	}
	return out, nil
}

func readEvents(path string) ([]eventLine, error) {
	lines, err := tailJSONL(path)
	var out []eventLine
	for _, l := range lines {
		var e eventLine
		if json.Unmarshal(l, &e) != nil {
			continue
		}
		t, ok := eventlog.ParseTime(e.TS)
		if !ok {
			continue
		}
		e.At = t
		out = append(out, e)
	}
	return out, err
}

// lastRecordTime returns the time of the newest parseable record in a JSONL
// log, or the zero time.
func lastRecordTime(path string) time.Time {
	lines, _ := tailJSONL(path)
	for i := len(lines) - 1; i >= 0; i-- {
		var e struct {
			TS string `json:"ts"`
		}
		if json.Unmarshal(bytes.TrimSpace(lines[i]), &e) != nil {
			continue
		}
		if t, ok := eventlog.ParseTime(e.TS); ok {
			return t
		}
	}
	return time.Time{}
}

// Appender is satisfied by *eventlog.Writer.
type Appender interface{ Append(rec any) error }

// DetectConfig describes where the previous run left its traces.
type DetectConfig struct {
	EventsPath    string
	ActivityPaths []string // other logs whose newest record counts as activity (resources.jsonl)
	DiagDirs      []string // where ResetCounter and panic reports land
	Now           time.Time
	MinGap        time.Duration // quiet time that makes a missing STOP an incident; default 60s
}

// Incident kinds.
const (
	KindHostReset       = "host_reset"
	KindUncleanShutdown = "unclean_shutdown"
	defaultMinGap       = 60 * time.Second
	diagSlack           = 0 * time.Second
)

// Detection is the verdict of Detect.
type Detection struct {
	Unclean   bool          `json:"unclean"`
	Duplicate bool          `json:"duplicate,omitempty"` // an INCIDENT for this gap already exists
	Kind      string        `json:"kind,omitempty"`
	PrevLast  time.Time     `json:"prev_last,omitempty"`
	Gap       time.Duration `json:"gap_ns,omitempty"`
	NoStop    bool          `json:"no_stop"`
	Diags     []DiagInfo    `json:"diags,omitempty"`
}

// Detect decides, at start-up and before the new START is written, whether
// the previous run ended uncleanly: no STOP event followed by a quiet gap,
// or a ResetCounter or panic report newer than the last activity.
func Detect(cfg DetectConfig) (*Detection, error) {
	if cfg.MinGap <= 0 {
		cfg.MinGap = defaultMinGap
	}
	evs, err := readEvents(cfg.EventsPath)
	if err != nil {
		return nil, err
	}
	det := &Detection{}
	var lifecycle *eventLine
	var prevLast time.Time
	for i := range evs {
		// INCIDENT records are written by the next run about this gap, so
		// they are not activity of the run that ended.
		if evs[i].Event != record.Incident && evs[i].At.After(prevLast) {
			prevLast = evs[i].At
		}
		if evs[i].Event == record.Start || evs[i].Event == record.Stop {
			lifecycle = &evs[i]
		}
	}
	if lifecycle == nil {
		return det, nil // no previous run recorded
	}
	for _, p := range cfg.ActivityPaths {
		if t := lastRecordTime(p); t.After(prevLast) {
			prevLast = t
		}
	}
	det.PrevLast = prevLast
	det.NoStop = lifecycle.Event == record.Start
	det.Gap = cfg.Now.Sub(prevLast)
	det.Diags = ScanDiags(cfg.DiagDirs, prevLast.Add(-diagSlack), cfg.Now.Add(time.Minute))

	switch {
	case len(det.Diags) > 0:
		det.Unclean, det.Kind = true, KindHostReset
	case det.NoStop && det.Gap >= cfg.MinGap:
		det.Unclean, det.Kind = true, KindUncleanShutdown
	}
	if det.Unclean {
		for _, e := range evs {
			if e.Event == record.Incident && e.PrevLastTS == prevLast.Format(time.RFC3339Nano) {
				det.Duplicate = true
			}
		}
	}
	return det, nil
}

// Record is the INCIDENT event written to events.jsonl.
type Record struct {
	TS         string    `json:"ts"`
	Event      string    `json:"event"`
	Kind       string    `json:"kind"`
	PrevLastTS string    `json:"prev_last_ts"`
	GapS       float64   `json:"gap_s"`
	NoStop     bool      `json:"no_stop"`
	Diags      []string  `json:"diags,omitempty"`
	Estimate   *Estimate `json:"estimate,omitempty"`
}

// NewRecord builds the INCIDENT event for a detection; est may be nil.
func NewRecord(d *Detection, now time.Time, est *Estimate) Record {
	r := Record{TS: now.Format(eventlog.TimeFormat), Event: record.Incident, Kind: d.Kind,
		PrevLastTS: d.PrevLast.Format(time.RFC3339Nano), GapS: d.Gap.Seconds(), NoStop: d.NoStop, Estimate: est}
	for _, dg := range d.Diags {
		r.Diags = append(r.Diags, baseName(dg.Path))
	}
	return r
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// CheckAndRecord runs Detect and appends exactly one INCIDENT event for an
// unclean end of the previous run. A repeat start over the same gap writes
// nothing. It returns the detection and whether an event was written.
func CheckAndRecord(cfg DetectConfig, w Appender, enrich func(*Detection) *Estimate) (*Detection, bool, error) {
	det, err := Detect(cfg)
	if err != nil || !det.Unclean || det.Duplicate {
		return det, false, err
	}
	var est *Estimate
	if enrich != nil {
		est = enrich(det)
	}
	if err := w.Append(NewRecord(det, cfg.Now, est)); err != nil {
		return det, false, err
	}
	return det, true, nil
}
