// Package linux collects processes from /proc, per-process TCP byte counts
// from `ss`, the default route from /proc/net/route, and installs a
// systemd --user unit. Nothing here needs root.
//
// Per-process network limits: `ss -tinp` reports byte counters only for TCP
// sockets, and only shows the owning process for sockets of the current
// user. UDP/QUIC traffic and other users' processes are invisible, and bytes
// moved by a socket that opened and closed between two samples are missed.
//
// The parsers in this file are OS-independent so they are tested everywhere.
package linux

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
)

// Stat holds the fields netwatch uses from /proc/<pid>/stat.
type Stat struct {
	PID, PPID    int
	Comm         string
	UTime, STime uint64 // clock ticks
	StartTime    uint64 // clock ticks after boot
	RSSPages     int64
}

// ParseStat parses /proc/<pid>/stat. The comm field is parenthesised and
// may itself contain spaces and parentheses, so fields are counted from the
// last ')'.
func ParseStat(s string) (Stat, error) {
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return Stat{}, errors.New("stat: no comm")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return Stat{}, fmt.Errorf("stat: pid: %w", err)
	}
	f := strings.Fields(s[end+1:])
	// f[0] is field 3 (state); field N is f[N-3].
	if len(f) < 22 {
		return Stat{}, errors.New("stat: too few fields")
	}
	st := Stat{PID: pid, Comm: s[open+1 : end]}
	var errs [5]error
	st.PPID, errs[0] = strconv.Atoi(f[1])
	st.UTime, errs[1] = strconv.ParseUint(f[11], 10, 64)
	st.STime, errs[2] = strconv.ParseUint(f[12], 10, 64)
	st.StartTime, errs[3] = strconv.ParseUint(f[19], 10, 64)
	st.RSSPages, errs[4] = strconv.ParseInt(f[21], 10, 64)
	if err := errors.Join(errs[:]...); err != nil {
		return Stat{}, fmt.Errorf("stat: %w", err)
	}
	return st, nil
}

// ParseCmdline turns NUL-separated /proc/<pid>/cmdline into a command line.
func ParseCmdline(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	return strings.ReplaceAll(s, "\x00", " ")
}

// ParseBootTime reads "btime" (seconds since the epoch) from /proc/stat.
func ParseBootTime(s string) (int64, error) {
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, errors.New("/proc/stat: no btime")
}

// ParseRoute picks the default route with the lowest metric from
// /proc/net/route, whose addresses are little-endian hex.
func ParseRoute(s string) platform.Gateway {
	var best platform.Gateway
	bestMetric := -1
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 || flags&0x2 == 0 { // RTF_UP and RTF_GATEWAY
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if bestMetric >= 0 && metric >= bestMetric {
			continue
		}
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], binary.LittleEndian.Uint32(raw))
		best = platform.Gateway{Addr: net.IP(ip[:]).String(), Iface: f[0]}
		bestMetric = metric
	}
	return best
}

// ParseNetDev returns cumulative receive and transmit bytes for iface from
// /proc/net/dev.
func ParseNetDev(s, iface string) (rx, tx uint64, ok bool) {
	for _, line := range strings.Split(s, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			return 0, 0, false
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		return r, t, err1 == nil && err2 == nil
	}
	return 0, 0, false
}

// SSArgs list all TCP sockets with internals and owning processes, no header.
var SSArgs = []string{"-tinpH"}

var (
	usersRe = regexp.MustCompile(`\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=\d+\)`)
	ackedRe = regexp.MustCompile(`\bbytes_acked:(\d+)`)
	recvRe  = regexp.MustCompile(`\bbytes_received:(\d+)`)
)

func loopbackPeer(sockLine string) bool {
	f := strings.Fields(sockLine)
	if len(f) < 5 {
		return false
	}
	peer := f[4]
	if i := strings.LastIndexByte(peer, ':'); i > 0 {
		peer = peer[:i]
	}
	peer = strings.Trim(peer, "[]")
	if i := strings.IndexByte(peer, '%'); i >= 0 {
		peer = peer[:i]
	}
	ip := net.ParseIP(peer)
	return ip != nil && ip.IsLoopback()
}

// ParseSS sums bytes per owning process from `ss -tinpH`. Each socket is a
// line followed by an indented line of TCP internals. Sockets without a
// visible owner (other users') are skipped. Loopback connections are not
// counted as connections but their bytes are, as nettop does on macOS.
func ParseSS(out string) map[netrate.Key]netrate.Counter {
	res := map[netrate.Key]netrate.Counter{}
	var owner *netrate.Key
	var estab bool
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			owner = nil
			m := usersRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			pid, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			k := netrate.Key{Name: m[1], PID: pid}
			owner = &k
			estab = strings.HasPrefix(line, "ESTAB") && !loopbackPeer(line)
			c := res[k]
			if estab {
				c.Conns++
			}
			res[k] = c
			continue
		}
		if owner == nil {
			continue
		}
		c := res[*owner]
		if m := ackedRe.FindStringSubmatch(line); m != nil {
			v, _ := strconv.ParseUint(m[1], 10, 64)
			c.Out += v
		}
		if m := recvRe.FindStringSubmatch(line); m != nil {
			v, _ := strconv.ParseUint(m[1], 10, 64)
			c.In += v
		}
		res[*owner] = c
		owner = nil
	}
	return res
}

// systemdQuote quotes one ExecStart argument: systemd expands % specifiers
// and $ variables, so both are escaped.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

// RenderUnit builds the systemd --user unit. Output goes to the journal
// only for errors; events are already in events.jsonl.
func RenderUnit(o platform.ServiceOptions) string {
	var args []string
	for _, a := range append(append([]string{o.Exe}, o.Args...), "run") {
		args = append(args, systemdQuote(a))
	}
	return `[Unit]
Description=netwatch network health and orphaned process monitor
Documentation=https://github.com/ericmacdougall/netwatch

[Service]
Type=simple
ExecStart=` + strings.Join(args, " ") + `
Restart=on-failure
RestartSec=30
Nice=10
IOSchedulingClass=idle
StandardOutput=null
StandardError=journal

[Install]
WantedBy=default.target
`
}
