package linux

import (
	"strings"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
)

func TestParseStatHandlesParensInComm(t *testing.T) {
	line := "4242 (node (dev) x) S 1 4242 4242 0 -1 4194560 1000 0 0 0 150 50 0 0 20 0 11 0 987654 1234567 2048 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
	st, err := ParseStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != 4242 || st.Comm != "node (dev) x" || st.PPID != 1 || st.UTime != 150 || st.STime != 50 ||
		st.StartTime != 987654 || st.RSSPages != 2048 {
		t.Fatalf("bad parse: %+v", st)
	}
	for _, bad := range []string{"", "12 node S 1", "x (a) S 1 2 3"} {
		if _, err := ParseStat(bad); err == nil {
			t.Errorf("ParseStat(%q) should fail", bad)
		}
	}
}

func TestParseCmdlineAndBootTime(t *testing.T) {
	if got := ParseCmdline([]byte("node\x00server.js\x00--port\x003000\x00")); got != "node server.js --port 3000" {
		t.Fatalf("cmdline = %q", got)
	}
	if got := ParseCmdline(nil); got != "" {
		t.Fatalf("kernel thread cmdline = %q", got)
	}
	bt, err := ParseBootTime("cpu  1 2 3\nintr 5\nbtime 1767225600\nprocesses 9\n")
	if err != nil || bt != 1767225600 {
		t.Fatalf("btime = %d, %v", bt, err)
	}
}

func TestParseRoutePicksLowestMetricDefault(t *testing.T) {
	route := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0102000A	0003	0	0	600	00000000	0	0	0
eth0	00000000	010200C0	0003	0	0	100	00000000	0	0	0
eth0	000200C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
tun0	00000000	00000000	0001	0	0	50	00000000	0	0	0
`
	g := ParseRoute(route)
	if g != (platform.Gateway{Addr: "192.0.2.1", Iface: "eth0"}) {
		t.Fatalf("got %+v", g)
	}
	if g := ParseRoute("Iface\tDestination\n"); g.Addr != "" {
		t.Fatalf("no default route should be empty: %+v", g)
	}
}

func TestParseNetDev(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 123456 100 0 0 0 0 0 0 654321 90 0 0 0 0 0 0
`
	rx, tx, ok := ParseNetDev(dev, "eth0")
	if !ok || rx != 123456 || tx != 654321 {
		t.Fatalf("got %d %d %v", rx, tx, ok)
	}
	if _, _, ok := ParseNetDev(dev, "wlan0"); ok {
		t.Fatal("missing iface should not be ok")
	}
}

func TestParseSS(t *testing.T) {
	out := `ESTAB 0      0      192.0.2.5:51234   198.51.100.7:443   users:(("node",pid=4242,fd=21))
	 cubic wscale:7,7 rto:204 rtt:3.1/1.2 bytes_sent:1500 bytes_acked:1400 bytes_received:9000 segs_out:10
ESTAB 0      0      192.0.2.5:51240   198.51.100.7:443   users:(("node",pid=4242,fd=22))
	 cubic bytes_acked:100 bytes_received:1000
ESTAB 0      0      127.0.0.1:5000    127.0.0.1:41000    users:(("vite",pid=77,fd=3))
	 cubic bytes_acked:50 bytes_received:60
ESTAB 0      0      192.0.2.5:22      198.51.100.9:60000
	 cubic bytes_acked:999999 bytes_received:999999
LISTEN 0     511    *:3000            *:*                users:(("node",pid=4242,fd=19),("node",pid=4243,fd=19))
	 cubic rto:1000
ESTAB 0      0      [2001:db8::5]:4000 [::1]:5000       users:(("we\"ird",pid=88,fd=4))
	 bytes_acked:5 bytes_received:6
`
	got := ParseSS(out)
	node := got[netrate.Key{Name: "node", PID: 4242}]
	if node.Out != 1500 || node.In != 10000 || node.Conns != 2 {
		t.Fatalf("node: %+v", node)
	}
	vite := got[netrate.Key{Name: "vite", PID: 77}]
	if vite.Out != 50 || vite.Conns != 0 {
		t.Fatalf("loopback should count bytes but not connections: %+v", vite)
	}
	if w := got[netrate.Key{Name: `we\"ird`, PID: 88}]; w.In != 6 || w.Conns != 0 {
		t.Fatalf("ipv6 loopback / escaped name: %+v (all: %v)", w, got)
	}
	if len(got) != 3 {
		t.Fatalf("unowned socket must be skipped, got %v", got)
	}
}

func TestRenderUnitQuotes(t *testing.T) {
	u := RenderUnit(platform.ServiceOptions{Exe: "/home/u/my bin/netwatch", Args: []string{"--config", "/x/100%$HOME.json"}})
	want := `ExecStart="/home/u/my bin/netwatch" "--config" "/x/100%%$$HOME.json" "run"`
	if !strings.Contains(u, want) {
		t.Fatalf("unit missing %q:\n%s", want, u)
	}
}
