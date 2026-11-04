package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ericmacdougall/netwatch/internal/incident"
	"github.com/ericmacdougall/netwatch/internal/report"
	"github.com/ericmacdougall/netwatch/internal/resources"
	"github.com/ericmacdougall/netwatch/internal/sampler"
)

// diagDir is where macOS writes JetsamEvent and ResetCounter reports.
// Other platforms have no equivalent, so incident reads only netwatch's
// own logs there.
func diagDir() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Logs/DiagnosticReports"
	}
	return ""
}

// transcriptRoot is Claude Code's projects directory, read only by
// `incident` to rank candidate tool calls.
func transcriptRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "projects")
}

func (a *app) cmdTop(args []string) error {
	fs := a.flags("top")
	byMem := fs.Bool("mem", false, "rank by memory footprint (default)")
	byCPU := fs.Bool("cpu", false, "rank by CPU over a 1s interval")
	n := fs.Int("n", 15, "rows")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *byMem && *byCPU {
		return usageError{fmt.Errorf("--mem and --cpu are exclusive")}
	}
	if *n < 1 || *n > 500 {
		return usageError{fmt.Errorf("-n must be 1-500")}
	}
	mode := sampler.ByMem
	if *byCPU {
		mode = sampler.ByCPU
	}
	r := resources.New()
	rows, unread, err := sampler.Top(r, mode, *n, time.Second, time.Now, time.Sleep)
	if err != nil {
		return err
	}
	return sampler.Write(a.stdout, mode, rows, unread, *asJSON)
}

func (a *app) cmdIncident(args []string) error {
	fs := a.flags("incident")
	last := fs.Bool("last", false, "only the most recent incident")
	asJSON := fs.Bool("json", false, "JSON output")
	since := fs.String("since", "", "only reports newer than this (e.g. 24h, 7d)")
	dir := fs.String("dir", diagDir(), "directory holding JetsamEvent and ResetCounter reports")
	replay := fs.Bool("replay-guard", false, "replay the guard against the incident timeline")
	if err := parse(fs, args); err != nil {
		return err
	}
	now := time.Now()
	o := incident.Options{LogDir: a.logDir, JetsamDir: *dir, TranscriptRoot: transcriptRoot(),
		Last: *last, Now: now}
	if *dir != "" {
		o.DiagDirs = []string{*dir}
	}
	if *since != "" {
		d, err := report.ParseSince(*since)
		if err != nil {
			return usageError{err}
		}
		o.Since = now.Add(-d)
	}
	rep, err := incident.Collect(o)
	if err != nil {
		return err
	}
	if *replay {
		rr := incident.ReplayGuard(incident.ReplayInputFrom(rep, incident.ModePauseKill))
		if *asJSON {
			b, err := rr.JSON()
			if err != nil {
				return err
			}
			_, err = a.stdout.Write(append(b, '\n'))
			return err
		}
		rr.Render(a.stdout)
		return nil
	}
	if *asJSON {
		b, err := rep.JSON()
		if err != nil {
			return err
		}
		_, err = a.stdout.Write(append(b, '\n'))
		return err
	}
	rep.Render(a.stdout)
	return nil
}
