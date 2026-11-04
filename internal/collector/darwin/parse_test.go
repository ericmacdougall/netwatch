package darwin

import (
	"strings"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
)

func TestParsePS(t *testing.T) {
	out := `    1     0     0   1.0  12688 21:24 Tue Nov  3 21:46:14 2026     /sbin/launchd
  404     1   501  12.5  22560 1-02:03:04 Mon Nov  2 19:43:10 2026     /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=utility  --x
  bogus line
  405   404   501   0.0   2048 00:05 Tue Nov  3 22:00:00 2026
`
	procs := ParsePS(out, 501, time.UTC)
	if len(procs) != 2 {
		t.Fatalf("want 2 procs, got %d: %+v", len(procs), procs)
	}
	p := procs[1]
	if p.PID != 404 || p.PPID != 1 || !p.Own || p.CPU != 12.5 || p.RSSMB != 22 {
		t.Fatalf("bad fields: %+v", p)
	}
	if p.Age != 26*time.Hour+3*time.Minute+4*time.Second {
		t.Fatalf("bad age %v", p.Age)
	}
	if !p.Start.Equal(time.Date(2026, 11, 2, 19, 43, 10, 0, time.UTC)) {
		t.Fatalf("bad start %v", p.Start)
	}
	if p.Cmd != "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper --type=utility  --x" {
		t.Fatalf("command spacing not preserved: %q", p.Cmd)
	}
	if procs[0].Own {
		t.Fatal("root process marked as own")
	}
}

func TestParseNettop(t *testing.T) {
	out := ",bytes_in,bytes_out,\nlaunchd.1,0,0,\napsd.142,5512,29709,\ncom.apple.Web.900,10,,\nbad,1,2,\nx.y,1,2,\n"
	got := ParseNettop(out)
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %v", got)
	}
	if c := got[netrate.Key{Name: "apsd", PID: 142}]; c.In != 5512 || c.Out != 29709 {
		t.Fatalf("apsd: %+v", c)
	}
	if c := got[netrate.Key{Name: "com.apple.Web", PID: 900}]; c.In != 10 || c.Out != 0 {
		t.Fatalf("dotted name: %+v", c)
	}
}

func TestParseRoute(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.0.2.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n"
	g := ParseRoute(out)
	if g.Addr != "192.0.2.1" || g.Iface != "en0" {
		t.Fatalf("got %+v", g)
	}
	if g := ParseRoute("route: writing to routing socket: not in table\n"); g.Addr != "" {
		t.Fatalf("no route should be empty: %+v", g)
	}
}

func TestRenderPlistEscapes(t *testing.T) {
	s := RenderPlist(platform.ServiceOptions{Exe: "/Users/a b/bin/netwatch", Args: []string{"--config", "/x/<&>.json"},
		LogDir: "/Users/a b/Library/Logs/netwatch", Label: "com.example.netwatch"})
	for _, want := range []string{
		"<string>/Users/a b/bin/netwatch</string><string>--config</string><string>/x/&lt;&amp;&gt;.json</string><string>run</string>",
		"<key>Label</key><string>com.example.netwatch</string>",
		"/Users/a b/Library/Logs/netwatch/stderr.log",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist missing %q:\n%s", want, s)
		}
	}
}
