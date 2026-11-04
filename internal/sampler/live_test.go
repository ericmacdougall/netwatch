package sampler

import (
	"os"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// TestLiveTopFindsSelf runs the real reader: this process must be listed
// with a footprint, a start time and a non-empty command.
func TestLiveTopFindsSelf(t *testing.T) {
	r := resources.New()
	rows, _, err := Top(r, ByMem, 100000, 0, nil, nil)
	if err != nil {
		t.Skipf("reader unavailable: %v", err)
	}
	for _, row := range rows {
		if row.PID == os.Getpid() {
			if row.Footprint == 0 || row.Start == "" || row.Cmd == "" {
				t.Fatalf("self row %+v", row)
			}
			return
		}
	}
	t.Fatalf("own pid %d not in %d rows", os.Getpid(), len(rows))
}

func TestLiveSampleRecord(t *testing.T) {
	r := resources.New()
	s := New(r, 5)
	rec, err := s.Sample()
	if err != nil {
		t.Skipf("reader unavailable: %v", err)
	}
	if rec.Sys.RAM == 0 || len(rec.TopMem) == 0 || rec.TS == "" {
		t.Fatalf("%+v", rec)
	}
	time.Sleep(10 * time.Millisecond)
}
