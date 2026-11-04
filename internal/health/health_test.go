package health

import "testing"

func f(v float64) *float64 { return &v }

func TestParsePingOutputBSDAndIputils(t *testing.T) {
	bsd := `PING 192.0.2.1 (192.0.2.1): 56 data bytes
64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=2.512 ms
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=3.100 ms
64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=3.100 ms (DUP!)
Request timeout for icmp_seq 2
64 bytes from 192.0.2.1: icmp_seq=3 ttl=64 time=9.9 ms

--- 192.0.2.1 ping statistics ---
5 packets transmitted, 3 packets received, 40.0% packet loss
round-trip min/avg/max/stddev = 2.512/5.171/9.900/3.3 ms`
	p := ParsePingOutput(bsd, 5)
	if p.Avg == nil || *p.Avg != 5.2 || *p.Max != 9.9 || p.Loss != 40 {
		t.Fatalf("bsd parse: avg %v max %v loss %v", deref(p.Avg), deref(p.Max), p.Loss)
	}
	linux := "64 bytes from 198.51.100.1: icmp_seq=1 ttl=57 time=11.2 ms\n64 bytes from 198.51.100.1: icmp_seq=2 ttl=57 time=12.8 ms\n"
	p = ParsePingOutput(linux, 2)
	if p.Avg == nil || *p.Avg != 12 || p.Loss != 0 {
		t.Fatalf("linux parse: %+v", p)
	}
}

func TestParsePingOutputNoReplies(t *testing.T) {
	p := ParsePingOutput("ping: sendto: No route to host\n", 5)
	if p.Avg != nil || p.Max != nil || p.Loss != 100 {
		t.Fatalf("want 100%% loss and nil times, got %+v", p)
	}
	if p := Summarize([]float64{1, 2, 3}, 0); p.Loss != 100 {
		t.Fatalf("zero sent should be total loss: %+v", p)
	}
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestBad(t *testing.T) {
	th := Thresholds{GatewayMs: 40, LossPct: 10}
	good := &Ping{Avg: f(3), Max: f(5), Loss: 0}
	cases := []struct {
		name    string
		gw, net *Ping
		want    bool
	}{
		{"healthy", good, good, false},
		{"slow gateway", &Ping{Avg: f(41), Max: f(90)}, good, true},
		{"exactly at threshold is fine", &Ping{Avg: f(40), Max: f(40)}, good, false},
		{"gateway loss", &Ping{Avg: f(2), Max: f(2), Loss: 20}, good, true},
		{"gateway silent", &Ping{Loss: 100}, good, true},
		{"internet loss", good, &Ping{Avg: f(30), Max: f(30), Loss: 10}, true},
		{"slow internet alone is fine", good, &Ping{Avg: f(400), Max: f(900)}, false},
		{"no gateway but internet ok", nil, good, false},
		{"no gateway and internet down", nil, &Ping{Loss: 100}, true},
		{"nothing measured", nil, nil, false},
	}
	for _, c := range cases {
		if got := Bad(c.gw, c.net, th); got != c.want {
			t.Errorf("%s: Bad = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTrackerEmitsOnlyOnChange(t *testing.T) {
	th := Thresholds{GatewayMs: 40, LossPct: 10}
	good := &Ping{Avg: f(3), Max: f(3)}
	bad := &Ping{Loss: 100}
	var tr Tracker
	seq := []struct {
		gw   *Ping
		want Transition
	}{
		{good, Steady}, {bad, BecameDegraded}, {bad, Steady}, {bad, Steady},
		{good, BecameRecovered}, {good, Steady}, {bad, BecameDegraded}, {good, BecameRecovered},
	}
	for i, s := range seq {
		if got := tr.Update(s.gw, good, th); got != s.want {
			t.Fatalf("step %d: got %v want %v", i, got, s.want)
		}
	}
}
