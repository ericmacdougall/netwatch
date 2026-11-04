package incident

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// maxDiagBytes caps one .diag or panic report read. These files are small.
const maxDiagBytes = 256 << 10

// maxDirEntries bounds a directory listing.
const maxDirEntries = 20000

const diagTimeLayout = "2006-01-02 15:04:05.999 -0700"

// Diag kinds.
const (
	DiagReset = "reset_counter"
	DiagPanic = "panic"
)

// DiagInfo is one ResetCounter or panic report.
type DiagInfo struct {
	Path string    `json:"path"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// diagKind classifies a file name, or returns "".
func diagKind(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "ResetCounter-") && strings.HasSuffix(name, ".diag"):
		return DiagReset
	case strings.Contains(l, "panic") && (strings.HasSuffix(l, ".diag") || strings.HasSuffix(l, ".panic") || strings.HasSuffix(l, ".ips")):
		return DiagPanic
	}
	return ""
}

// ParseDiag reads a report through safeio and extracts its time from the
// JSON header ("timestamp") or a "Date:" line. It returns ok=false when the
// file has no usable time.
func ParseDiag(path string) (DiagInfo, bool) {
	name := filepath.Base(path)
	kind := diagKind(name)
	if kind == "" {
		return DiagInfo{}, false
	}
	b, err := safeio.ReadFile(path, safeio.Opts{Max: maxDiagBytes})
	if err != nil {
		return DiagInfo{}, false
	}
	line, rest, _ := bytes.Cut(b, []byte("\n"))
	var h struct {
		Timestamp string `json:"timestamp"`
	}
	if safeio.DecodeJSON(line, &h) == nil {
		if t, err := time.Parse(diagTimeLayout, h.Timestamp); err == nil {
			return DiagInfo{Path: path, Kind: kind, At: t.UTC()}, true
		}
	}
	for _, l := range bytes.Split(rest, []byte("\n")) {
		if v, ok := strings.CutPrefix(string(l), "Date:"); ok {
			if t, err := time.Parse(diagTimeLayout, strings.TrimSpace(v)); err == nil {
				return DiagInfo{Path: path, Kind: kind, At: t.UTC()}, true
			}
		}
	}
	return DiagInfo{}, false
}

// ScanDiags lists reset and panic reports in dirs whose time is in
// [after, until]. Unreadable or hostile files are skipped.
func ScanDiags(dirs []string, after, until time.Time) []DiagInfo {
	var out []DiagInfo
	for _, dir := range dirs {
		d, err := os.Open(dir)
		if err != nil {
			continue
		}
		names, _ := d.Readdirnames(maxDirEntries)
		d.Close()
		for _, n := range names {
			if diagKind(n) == "" {
				continue
			}
			fi, err := os.Lstat(filepath.Join(dir, n))
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if info, ok := ParseDiag(filepath.Join(dir, n)); ok && !info.At.Before(after) && !info.At.After(until) {
				out = append(out, info)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}
