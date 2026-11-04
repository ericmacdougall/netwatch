package redact

import (
	"strings"
	"testing"
)

func TestStringRedactsSecrets(t *testing.T) {
	cases := []struct {
		in     string
		secret string
		keep   string
	}{
		{"node server.js --token=abc123def456", "abc123def456", "--token="},
		{"tool --api-key s3cr3tvalue --verbose", "s3cr3tvalue", "--verbose"},
		{"cli -password=hunter2hunter", "hunter2hunter", "cli"},
		{`curl -H "Authorization: Bearer eyabcdefghijklmnop" https://example.com`, "eyabcdefghijklmnop", "https://example.com"},
		{"curl -H Authorization:Basic dXNlcjpwYXNz https://x", "dXNlcjpwYXNz", "https://x"},
		{"env GITHUB_TOKEN=zzzyyyxxx node a.js", "zzzyyyxxx", "node a.js"},
		{"wget https://example.com/x?user=a&password=pw123456&y=1", "pw123456", "&y=1"},
		{"git clone https://alice:pa55word@example.com/r.git", "pa55word", "example.com/r.git"},
		{"run ghp_abcdefghijklmnopqrstuvwxyz0123", "ghp_abcdefghijklmnopqrstuvwxyz0123", "run"},
		{"call sk-ABCDEFGHIJKLMNOPQRSTUVWX", "sk-ABCDEFGHIJKLMNOPQRSTUVWX", "call"},
		{"x eyJhbGciOiJIUzI1.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4", "x "},
		{"app --client-secret 'quoted value'", "quoted value", "app"},
		{"rclone serve --pass=abc --session-key=k123456", "k123456", "rclone serve"},
	}
	for _, c := range cases {
		got := String(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("secret leaked:\n in: %s\nout: %s", c.in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Errorf("no mask in output for %q: %q", c.in, got)
		}
		if !strings.Contains(got, c.keep) {
			t.Errorf("over-redacted %q: %q (wanted to keep %q)", c.in, got, c.keep)
		}
	}
}

func TestStringLeavesOrdinaryCommandsAlone(t *testing.T) {
	for _, in := range []string{
		"/usr/local/bin/node /srv/app/server.js --port 3000",
		"/opt/google/chrome/chrome --type=renderer --headless --lang=en-US",
		"python3 -m http.server 8000",
		"",
	} {
		if got := String(in); got != in {
			t.Errorf("changed benign command:\n in: %s\nout: %s", in, got)
		}
	}
}

func TestStringIsIdempotent(t *testing.T) {
	in := "x --token=abc123 Authorization: Bearer abcdefghijkl"
	once := String(in)
	if twice := String(once); twice != once {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
}
