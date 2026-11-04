package resmon

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/eventlog"
)

// Appender is the events.jsonl writer.
type Appender interface{ Append(rec any) error }

// LineWriter receives one JSON line at a time (guard-events.jsonl).
type LineWriter interface{ Append(rec any) error }

// Sink writes guard events to two places:
//
//   - events.jsonl: the full event, with the redacted short command, like
//     every other netwatch event;
//   - guard-events.jsonl: an agent-readable copy for harness hooks. It
//     carries no command text at all, only the executable's basename, the
//     agent label, the event and a fingerprint of the redacted command, so
//     a hook can warn an agent that is about to retry a paused or killed
//     command without netwatch handing argv to another program.
type Sink struct {
	Events Appender
	Guard  LineWriter // optional
	Now    func() time.Time

	mu sync.Mutex
}

// Event implements guard.EventSink.
func (s *Sink) Event(name string, fields map[string]any) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ts := now().Format(eventlog.TimeFormat)
	full := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		full[k] = v
	}
	full["ts"], full["event"] = ts, name

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Events != nil {
		_ = s.Events.Append(full)
	}
	if s.Guard != nil && agentEvent(name) {
		_ = s.Guard.Append(agentView(ts, name, fields))
	}
}

// agentEvent reports whether an event belongs in guard-events.jsonl.
func agentEvent(name string) bool {
	return strings.HasPrefix(name, "GUARD_") || name == "HOST_AT_RISK_UNPROTECTED" || name == "MODE_CHANGE"
}

// agentFields are the only fields copied to guard-events.jsonl besides the
// derived exe and fingerprint.
var agentFields = []string{"pgid", "agent", "reason", "signals", "stage", "prong", "danger_since", "signalled_at", "from", "to"}

func agentView(ts, name string, fields map[string]any) map[string]any {
	out := map[string]any{"ts": ts, "event": name}
	for _, k := range agentFields {
		if v, ok := fields[k]; ok {
			out[k] = v
		}
	}
	if cmd, ok := fields["cmd"].(string); ok && cmd != "" {
		out["exe"] = exeBase(cmd)
		sum := sha256.Sum256([]byte(cmd))
		out["fingerprint"] = hex.EncodeToString(sum[:8])
	}
	return out
}

// exeBase is the basename of the first word of a redacted command line.
func exeBase(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return path.Base(f[0])
}
