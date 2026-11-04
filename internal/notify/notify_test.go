package notify

import (
	"strings"
	"testing"
	"time"
)

func TestLimiterCooldownPerKeyAndRedaction(t *testing.T) {
	now := time.Unix(1000, 0)
	var sent []string
	l := New(true, 10*time.Minute, func(title, msg string) error {
		sent = append(sent, title+"|"+msg)
		return nil
	})
	l.Now = func() time.Time { return now }

	if ok, _ := l.Notify("a", "t", "node --token=abcdef123 x"); !ok {
		t.Fatal("first notification should send")
	}
	if ok, _ := l.Notify("a", "t", "again"); ok {
		t.Fatal("same key inside cooldown should be suppressed")
	}
	if ok, _ := l.Notify("b", "t", "other key"); !ok {
		t.Fatal("different key should send")
	}
	now = now.Add(10 * time.Minute)
	if ok, _ := l.Notify("a", "t", "after cooldown"); !ok {
		t.Fatal("key should send again after cooldown")
	}
	if len(sent) != 3 {
		t.Fatalf("sent %d: %v", len(sent), sent)
	}
	if strings.Contains(sent[0], "abcdef123") {
		t.Fatalf("secret reached notification: %q", sent[0])
	}
}

func TestLimiterDisabled(t *testing.T) {
	called := false
	l := New(false, 0, func(string, string) error { called = true; return nil })
	if ok, _ := l.Notify("a", "t", "m"); ok || called {
		t.Fatal("disabled limiter must not send")
	}
	var nilL *Limiter
	if ok, _ := nilL.Notify("a", "t", "m"); ok {
		t.Fatal("nil limiter must not send")
	}
}

func TestClean(t *testing.T) {
	got := Clean("line1\nline2\x07"+strings.Repeat("é", 300), 50)
	if strings.ContainsAny(got, "\n\x07") {
		t.Fatalf("control chars kept: %q", got)
	}
	if n := len([]rune(got)); n != 50 {
		t.Fatalf("length %d, want 50", n)
	}
}
