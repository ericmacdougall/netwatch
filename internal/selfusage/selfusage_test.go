package selfusage

import (
	"testing"
	"time"
)

func TestMeterMeasuresBusyLoop(t *testing.T) {
	m := NewMeter()
	deadline := time.Now().Add(200 * time.Millisecond)
	x := 0
	for time.Now().Before(deadline) {
		x++
	}
	_ = x
	if pct := m.Sample(); pct < 20 || pct > 400 {
		t.Fatalf("busy loop measured %.1f%% of a core", pct)
	}
}
