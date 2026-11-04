package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/procscan"
)

func TestOrphanFilter(t *testing.T) {
	f, err := orphanFilter("10, 20", "vite")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		p    procscan.Process
		want bool
	}{
		{procscan.Process{PID: 10, Cmd: "node vite"}, true},
		{procscan.Process{PID: 20, Cmd: "node server"}, false},
		{procscan.Process{PID: 30, Cmd: "node vite"}, false},
	}
	for _, c := range cases {
		if got := f(c.p); got != c.want {
			t.Errorf("filter(%+v) = %v", c.p, got)
		}
	}
	all, _ := orphanFilter("", "")
	if !all(procscan.Process{PID: 1}) {
		t.Fatal("empty filter should match everything")
	}
	for _, bad := range [][2]string{{"x", ""}, {"-3", ""}, {"", "("}} {
		if _, err := orphanFilter(bad[0], bad[1]); err == nil {
			t.Errorf("orphanFilter(%q, %q) should fail", bad[0], bad[1])
		}
	}
}

func TestCLIUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"orphans", "--force"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--force requires --kill") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"report", "--since", "2w"}, &out, &errb); code != 2 {
		t.Fatalf("bad --since should be a usage error, got %d %q", code, errb.String())
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command should exit 2, got %d", code)
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "netwatch ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestReportJSONFromEmptyLogDir(t *testing.T) {
	var out, errb bytes.Buffer
	dir := t.TempDir()
	if code := run([]string{"--log-dir", dir, "--config", dir + "/none.json", "report", "--json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"samples": 0`) {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestSanitizeLineRedactsLegacyRecords(t *testing.T) {
	got := string(sanitizeLine([]byte(`{"ts":"x","event":"ORPHAN","cmd":"node --token=abc123secret \u001b[2J"}` + "\n")))
	if strings.Contains(got, "abc123secret") || strings.Contains(got, "\x1b") || strings.Contains(got, `\u001b`) {
		t.Fatalf("tail kept a secret or control character: %q", got)
	}
	if got := string(sanitizeLine([]byte("plain --password=hunter22\n"))); strings.Contains(got, "hunter22") {
		t.Fatalf("non-JSON line not redacted: %q", got)
	}
}

func TestKillNeedsExplicitTargets(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"orphans", "--kill"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--kill needs --pid, --match or --all") {
		t.Fatalf("bare --kill: code %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"orphans", "--all"}, &out, &errb); code != 2 {
		t.Fatalf("--all without --kill: code %d", code)
	}
}

func TestMatchUsesRedactedCommand(t *testing.T) {
	f, _ := orphanFilter("", "hunter22")
	if f(procscan.Process{PID: 5, Cmd: "node --password=hunter22"}) {
		t.Fatal("--match selected a process by its secret")
	}
}

func TestServiceRejectsBadLabel(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"status", "--label", "../x"}, &out, &errb); code != 2 {
		t.Fatalf("bad label accepted: code %d %q", code, errb.String())
	}
}
