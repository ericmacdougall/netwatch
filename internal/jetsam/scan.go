package jetsam

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Scan limits. Reports are 0.5-2.5 MiB each in the field, and a busy
// DiagnosticReports directory can hold thousands.
const (
	DefaultMaxFiles = 64
	DefaultMaxBytes = 128 << 20
	maxDirEntries   = 50000
)

// ScanLimits bound one directory scan. Zero values mean the defaults.
type ScanLimits struct {
	MaxFiles int       // newest N reports are parsed
	MaxBytes int64     // total bytes of reports parsed
	Since    time.Time // skip reports written before this (zero: all)
	// MaxReport caps one report (0: MaxReportBytes). The daemon uses a
	// lower cap than the incident command.
	MaxReport int64
	// Seen, when set, skips a file the caller already parsed (same name,
	// size and modification time) without reading it again.
	Seen func(name string, size int64, mod time.Time) bool
}

// sinceSlack allows for a report file written a little before the time
// inside it.
const sinceSlack = time.Minute

// Skip records one file that was not parsed and why.
type Skip struct {
	Path string
	Err  string
}

// ScanResult is the outcome of ScanDir.
type ScanResult struct {
	Reports []*Report // oldest snapshot first
	Skipped []Skip
}

// ScanDir parses JetsamEvent-*.ips files in dir, newest file names first
// until a limit is reached, and returns them oldest first. A bad file is
// skipped with a note; it never aborts the scan. Symlinks and non-regular
// files are skipped (safeio and the Lstat check).
func ScanDir(dir string, lim ScanLimits) (*ScanResult, error) {
	if lim.MaxFiles <= 0 {
		lim.MaxFiles = DefaultMaxFiles
	}
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = DefaultMaxBytes
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(maxDirEntries)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) && len(names) == 0 {
		return nil, err
	}
	var cand []string
	for _, n := range names {
		if strings.HasPrefix(n, "JetsamEvent-") && strings.HasSuffix(n, ".ips") {
			cand = append(cand, n)
		}
	}
	// The file name embeds the local timestamp, so a reverse sort is
	// newest first without touching the files.
	sort.Sort(sort.Reverse(sort.StringSlice(cand)))

	res := &ScanResult{}
	var total int64
	for _, n := range cand {
		if len(res.Reports) >= lim.MaxFiles {
			res.Skipped = append(res.Skipped, Skip{filepath.Join(dir, n), "file count limit"})
			continue
		}
		p := filepath.Join(dir, n)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			res.Skipped = append(res.Skipped, Skip{p, "not a regular file"})
			continue
		}
		maxReport := lim.MaxReport
		if maxReport <= 0 || maxReport > MaxReportBytes {
			maxReport = MaxReportBytes
		}
		if fi.Size() > maxReport {
			res.Skipped = append(res.Skipped, Skip{p, fmt.Sprintf("over the %d MiB report limit", maxReport>>20)})
			continue
		}
		// Cheap filters first: parsing a large report costs far more than
		// a stat, and the daemon scans every few seconds.
		if !lim.Since.IsZero() && fi.ModTime().Before(lim.Since.Add(-sinceSlack)) {
			continue
		}
		if lim.Seen != nil && lim.Seen(n, fi.Size(), fi.ModTime()) {
			continue
		}
		if total+fi.Size() > lim.MaxBytes {
			res.Skipped = append(res.Skipped, Skip{p, "total byte limit"})
			continue
		}
		r, err := ParseFile(p)
		if err != nil {
			res.Skipped = append(res.Skipped, Skip{p, err.Error()})
			continue
		}
		if !lim.Since.IsZero() && r.Written.Before(lim.Since) {
			continue
		}
		total += fi.Size()
		res.Reports = append(res.Reports, r)
	}
	sort.SliceStable(res.Reports, func(i, j int) bool {
		a, b := res.Reports[i], res.Reports[j]
		if !a.Snapshot.Equal(b.Snapshot) {
			return a.Snapshot.Before(b.Snapshot)
		}
		return a.Path < b.Path
	})
	return res, nil
}
