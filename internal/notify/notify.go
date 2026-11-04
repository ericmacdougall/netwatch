// Package notify rate-limits desktop notifications. Delivery itself is
// platform-specific and injected as a Sender.
package notify

import (
	"strings"
	"sync"
	"time"

	"github.com/ericmacdougall/netwatch/internal/redact"
)

// Sender delivers one notification.
type Sender func(title, msg string) error

// MaxLen bounds message length; notification centres truncate anyway.
const MaxLen = 220

// Limiter suppresses repeats of the same key within a cooldown so a flapping
// network or a busy orphan does not flood the desktop.
type Limiter struct {
	Enabled  bool
	Cooldown time.Duration
	Send     Sender
	Now      func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

// New returns a Limiter.
func New(enabled bool, cooldown time.Duration, send Sender) *Limiter {
	return &Limiter{Enabled: enabled, Cooldown: cooldown, Send: send, Now: time.Now}
}

// Notify sends unless disabled or the key fired within the cooldown. It
// reports whether a notification was attempted. Text is redacted and
// stripped of control characters before it leaves the process.
func (l *Limiter) Notify(key, title, msg string) (bool, error) {
	if l == nil || !l.Enabled || l.Send == nil {
		return false, nil
	}
	l.mu.Lock()
	now := l.Now()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if t, ok := l.last[key]; ok && now.Sub(t) < l.Cooldown {
		l.mu.Unlock()
		return false, nil
	}
	l.last[key] = now
	// Bound the map: forget keys whose cooldown has long passed.
	if len(l.last) > 1000 {
		for k, t := range l.last {
			if now.Sub(t) >= l.Cooldown {
				delete(l.last, k)
			}
		}
	}
	l.mu.Unlock()
	return true, l.Send(Clean(title, 80), Clean(msg, MaxLen))
}

// Clean redacts secrets, removes control characters and truncates.
func Clean(s string, n int) string {
	s = redact.String(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	r := []rune(s)
	if len(r) > n {
		s = string(r[:n-1]) + "…"
	}
	return s
}
