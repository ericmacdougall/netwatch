package jetsam

import (
	"os"
	"testing"
	"time"
)

// JETSAM_EVIDENCE_DIR points at a local copy of real reports. The files are
// never committed; without the variable the test is skipped.
func TestRealEvidenceIfPresent(t *testing.T) {
	dir := os.Getenv("JETSAM_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("JETSAM_EVIDENCE_DIR not set")
	}
	res, err := ScanDir(dir, ScanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Reports) == 0 {
		t.Fatalf("no reports parsed; skipped: %v", res.Skipped)
	}
	r := res.Reports[0]
	within(t, r.Snapshot, mustTime(t, "2026-11-04T16:06:53.6Z"), 100*time.Millisecond, "snapshot")
	within(t, r.Top().Start, mustTime(t, "2026-11-04T16:06:43Z"), 500*time.Millisecond, "python start")
	t.Logf("parsed %d reports, skipped %d", len(res.Reports), len(res.Skipped))
}
