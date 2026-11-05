//go:build !windows

package resmon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type memLog struct{ recs []map[string]any }

func (m *memLog) Append(rec any) error {
	b, _ := json.Marshal(rec)
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	m.recs = append(m.recs, v)
	return nil
}

// guard-events.jsonl carries no command text, only the exe basename, the
// agent label and a fingerprint; events.jsonl keeps the redacted command.
func TestGuardEventsFileHasNoCommandText(t *testing.T) {
	ev, gl := &memLog{}, &memLog{}
	s := &Sink{Events: ev, Guard: gl, Now: func() time.Time { return t0 }}
	cmd := "/usr/bin/python3 io.py --input /dev/zero"
	s.Event("GUARD_PAUSE", map[string]any{"pgid": 4242, "agent": "agent:abc", "cmd": cmd, "signals": []string{"D1"}})
	s.Event("RESOURCE_ALERT", map[string]any{"cmd": cmd}) // not a guard event

	if len(ev.recs) != 2 || ev.recs[0]["cmd"] != cmd {
		t.Fatalf("events.jsonl records: %v", ev.recs)
	}
	if len(gl.recs) != 1 {
		t.Fatalf("guard-events.jsonl got %d records, want 1: %v", len(gl.recs), gl.recs)
	}
	g := gl.recs[0]
	b, _ := json.Marshal(g)
	for _, leak := range []string{"io.py", "/dev/zero", "--input", "/usr/bin"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("guard-events.jsonl leaks %q: %s", leak, b)
		}
	}
	if g["exe"] != "python3" || g["agent"] != "agent:abc" || g["fingerprint"] == nil || g["event"] != "GUARD_PAUSE" {
		t.Errorf("guard-events record = %s", b)
	}
}
