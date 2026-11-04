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
		{"run ghp" + "_abcdefghijklmnopqrstuvwxyz0123", "ghp_abcdefghijklmnopqrstuvwxyz0123", "run"},
		{"call sk" + "-ABCDEFGHIJKLMNOPQRSTUVWX", "sk-ABCDEFGHIJKLMNOPQRSTUVWX", "call"},
		{"x eyJhbGciOiJIUzI1.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4", "x "},
		{"app --client-secret 'quoted value'", "quoted value", "app"},
		{"rclone serve --pass=abc --session-key=k123456", "k123456", "rclone serve"},
		// Shapes found in review; written unquoted, the way ps shows them.
		// Fake tokens are split with + so secret scanners do not flag them.
		{"wrangler dev --var API_TOKEN:s3cretWr4ngler", "s3cretWr4ngler", "--var API_TOKEN:"},
		{"mysql -u root -pHunter2pw db", "Hunter2pw", "-u root"},
		{"sshpass -p Hunter2pw ssh host", "Hunter2pw", "ssh host"},
		{"redis-cli -a Hunter2pw", "Hunter2pw", "redis-cli -a"},
		{"curl -u alice:Hunter2pw https://x", "Hunter2pw", "alice:"},
		{"curl -H X-Api-Key: Hunter2pw https://x", "Hunter2pw", "https://x"},
		{"curl -H Cookie: session=Hunter2pw https://x", "Hunter2pw", "https://x"},
		{"curl -H PRIVATE-TOKEN: Hunter2pw https://x", "Hunter2pw", "https://x"},
		{`curl -d {"password":"Hunter2pw"} https://x`, "Hunter2pw", "https://x"},
		{`curl -d {"api_key": "Hunter2pw", "n": 1}`, "Hunter2pw", `"n": 1`},
		{"stripe sk_" + "live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxXX", "sk_live_51H", "stripe"},
		{"git push https://glpat" + "-AbCdEfGhIjKlMnOpQrSt@gitlab.com/r", "glpat-", "gitlab.com/r"},
		{"x npm" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "npm_ABC", "x "},
		{"x hf" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "hf_ABC", "x "},
		{"x ya29" + ".a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "a0AfH6", "x "},
		{"curl https://hooks.slack.com/services/T0000/B0000/XXXXXXXXXXXXXXXX", "XXXXXXXXXXXXXXXX", "hooks.slack.com"},
		{"x ASIAABCDEFGHIJKLMNOP", "ASIAABCDEFGHIJKLMNOP", "x "},
		{"psql postgres://user:p@ss@db.example.com/x", "ss@db", "db.example.com/x"},
		{"git clone https://ghtoken123456@example.com/r", "ghtoken123456", "example.com/r"},
		{"node app.js --password=abc&def", "def", "app.js"},
		{"x SG" + ".abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123", "abcdefghijklmnopqrstuv", "x "},
		{"x AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "wJalrXUtnFEMI", "AWS_SECRET_ACCESS_KEY="},
		{"x --pass:Hunter2pw", "Hunter2pw", "--pass:"},
		{`curl.exe -H "Cookie: session=Hunter2pw" https://x`, "Hunter2pw", "https://x"},
		{`curl.exe -H "X-Api-Key: Hunter2pw" https://x`, "Hunter2pw", "https://x"},
		{"x --accessToken Hunter2pw --port 1", "Hunter2pw", "--port 1"},
		{`app.exe --client-secret "two words" --v`, "words", "--v"},
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
		"chrome --password-store=basic --type=renderer",
		"node --no-auth server.js --port 3000",
		"python tokenizer.py --tokenizer-path /models/x",
		"git --password-file /etc/x push",
		`C:\Program Files\nodejs\node.exe C:\src\app.js`,
		"ssh -p 2222 host",
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

func TestDisplayStripsControlCharacters(t *testing.T) {
	got := Display("node \x1b[2Jevil\r\nx --token=abc")
	if strings.ContainsAny(got, "\x1b\r\n") || strings.Contains(got, "abc") {
		t.Fatalf("Display left control characters or a secret: %q", got)
	}
}
