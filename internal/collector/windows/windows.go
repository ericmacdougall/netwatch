//go:build windows

package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ericmacdougall/netwatch/internal/execx"
	"github.com/ericmacdougall/netwatch/internal/health"
	"github.com/ericmacdougall/netwatch/internal/netrate"
	"github.com/ericmacdougall/netwatch/internal/platform"
	"github.com/ericmacdougall/netwatch/internal/procscan"
)

var (
	iphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	procIcmpCreateFile       = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho         = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle      = iphlpapi.NewProc("IcmpCloseHandle")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
)

// Collector implements the collector and service interfaces for Windows.
type Collector struct {
	mu      sync.Mutex
	prevCPU map[int]cpuMark
	self    *windows.SID

	// ifIndex remembers the default-route interface found by Gateway.
	// net.InterfaceByName/ByIndex call GetAdaptersAddresses, which took
	// several seconds per call on a machine with many virtual adapters.
	ifMu    sync.Mutex
	ifAlias string
	ifIndex uint32
}

type cpuMark struct {
	created time.Time
	cpu     time.Duration
	at      time.Time
}

// New returns a Collector.
func New() *Collector {
	c := &Collector{prevCPU: map[int]cpuMark{}}
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		c.self, _ = tu.User.Sid.Copy()
	}
	return c
}

// DefaultLogDir is %LOCALAPPDATA%\netwatch\logs.
func DefaultLogDir() string {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "netwatch", "logs")
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "netwatch", "logs")
	}
	return "netwatch-logs"
}

func filetime(f windows.Filetime) time.Time { return time.Unix(0, f.Nanoseconds()) }

func duration(f windows.Filetime) time.Duration {
	return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100
}

type entry struct {
	pid, ppid int
	exe       string
}

// snapshot lists PIDs, parent PIDs and image names. It needs no handles,
// so it sees every process including protected ones.
func snapshot() ([]entry, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(h)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []entry
	for err = windows.Process32First(h, &pe); err == nil; err = windows.Process32Next(h, &pe) {
		out = append(out, entry{int(pe.ProcessID), int(pe.ParentProcessID), windows.UTF16ToString(pe.ExeFile[:])})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return out, fmt.Errorf("Process32Next: %w", err)
	}
	return out, nil
}

// commandLine reads a process's command line (Windows 8.1+).
func commandLine(h windows.Handle) string {
	var need uint32
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &need)
	if need == 0 || need > 1<<20 {
		return ""
	}
	// []uint64 keeps the UNICODE_STRING header pointer-aligned.
	buf := make([]uint64, (need+7)/8)
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buf[0]), uint32(len(buf)*8), &need); err != nil {
		return ""
	}
	return (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
}

func imagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

type memCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

func workingSetMB(h windows.Handle) int {
	var m memCounters
	m.cb = uint32(unsafe.Sizeof(m))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.cb)); r == 0 {
		return 0
	}
	return int(m.workingSetSize >> 20)
}

func (c *Collector) owned(h windows.Handle) bool {
	if c.self == nil {
		return false
	}
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return false
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	return err == nil && tu.User.Sid.Equals(c.self)
}

// Processes combines the snapshot with per-process details. Processes that
// cannot be opened (other users, protected) keep only PID, parent and name;
// their start time is zero, which the orphan rule treats as "cannot prove
// the parent is gone".
func (c *Collector) Processes(ctx context.Context) ([]procscan.Process, error) {
	entries, err := snapshot()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[int]cpuMark, len(entries))
	procs := make([]procscan.Process, 0, len(entries))
	for _, e := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p := procscan.Process{PID: e.pid, PPID: e.ppid, Name: e.exe, Cmd: e.exe}
		if e.pid > 4 {
			c.fill(&p, now, next)
		}
		if p.Match == "" {
			p.Match = NormalizeCmd("", p.Cmd)
		}
		procs = append(procs, p)
	}
	c.prevCPU = next
	return procs, nil
}

func (c *Collector) fill(p *procscan.Process, now time.Time, next map[int]cpuMark) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		p.Start = filetime(created)
		p.Age = now.Sub(p.Start)
		cpu := duration(kernel) + duration(user)
		if prev, ok := c.prevCPU[p.PID]; ok && prev.created.Equal(p.Start) && now.After(prev.at) && cpu >= prev.cpu {
			p.CPU = float64(cpu-prev.cpu) / float64(now.Sub(prev.at)) * 100
		} else if p.Age > 0 {
			p.CPU = float64(cpu) / float64(p.Age) * 100
		}
		p.CPU = math.Round(p.CPU*10) / 10
		next[p.PID] = cpuMark{created: p.Start, cpu: cpu, at: now}
	}
	img := imagePath(h)
	if cl := commandLine(h); cl != "" {
		p.Cmd = cl
	} else if img != "" {
		p.Cmd = img
	}
	p.Match = NormalizeCmd(img, p.Cmd)
	p.RSSMB = workingSetMB(h)
	p.Own = c.owned(h)
}

const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPIDAll = 5
	mibTCPStateEstab    = 5
)

// tcpTable calls GetExtendedTcpTable, growing the buffer as needed.
func tcpTable(family uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), tcpTableOwnerPIDAll, 0)
		switch windows.Errno(r) {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 4096
			continue
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
	}
	return nil, errors.New("GetExtendedTcpTable: table keeps growing")
}

// connections counts established, non-loopback TCP connections per PID.
func connections() (map[int]int, error) {
	counts := map[int]int{}
	if buf, err := tcpTable(afInet); err == nil {
		n := binary.LittleEndian.Uint32(buf)
		for i := uint32(0); i < n; i++ {
			row := buf[4+i*24 : 4+(i+1)*24] // MIB_TCPROW_OWNER_PID: 6 DWORDs
			state := binary.LittleEndian.Uint32(row[0:])
			remote := row[12:16]
			pid := int(binary.LittleEndian.Uint32(row[20:]))
			if state == mibTCPStateEstab && remote[0] != 127 {
				counts[pid]++
			}
		}
	} else {
		return counts, err
	}
	if buf, err := tcpTable(afInet6); err == nil {
		n := binary.LittleEndian.Uint32(buf)
		for i := uint32(0); i < n; i++ {
			// MIB_TCP6ROW_OWNER_PID: local addr[16], scope, port, remote addr[16], scope, port, state, pid.
			row := buf[4+i*56 : 4+(i+1)*56]
			remote := net.IP(row[24:40])
			state := binary.LittleEndian.Uint32(row[48:])
			pid := int(binary.LittleEndian.Uint32(row[52:]))
			if state == mibTCPStateEstab && !remote.IsLoopback() {
				counts[pid]++
			}
		}
	}
	return counts, nil
}

// Net reports per-process connection counts (no bytes without admin) and
// byte totals of the default-route interface.
func (c *Collector) Net(_ context.Context, iface string) (netrate.Snapshot, error) {
	snap := netrate.Snapshot{At: time.Now(), Procs: map[netrate.Key]netrate.Counter{}}
	c.ifMu.Lock()
	alias, index := c.ifAlias, c.ifIndex
	c.ifMu.Unlock()
	if iface != "" && iface == alias {
		if row, err := ifRow(index); err == nil {
			snap.HasIf, snap.IfIn, snap.IfOut = true, row.InOctets, row.OutOctets
		}
	}
	counts, err := connections()
	if err != nil {
		return snap, err
	}
	entries, err := snapshot()
	if err != nil {
		return snap, err
	}
	names := make(map[int]string, len(entries))
	for _, e := range entries {
		names[e.pid] = e.exe
	}
	for pid, n := range counts {
		if pid <= 4 {
			continue
		}
		name := names[pid]
		if name == "" {
			name = "pid" + strconv.Itoa(pid)
		}
		snap.Procs[netrate.Key{Name: name, PID: pid}] = netrate.Counter{Conns: n}
	}
	return snap, nil
}

// Gateway picks the IPv4 default route with the lowest metric.
func (c *Collector) Gateway(context.Context) (platform.Gateway, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(afInet, &table); err != nil {
		return platform.Gateway{}, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var best platform.Gateway
	var bestIndex uint32
	bestMetric := ^uint32(0)
	for _, r := range table.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.NextHop.Family != afInet {
			continue
		}
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r.NextHop))
		if v4.Addr == [4]byte{} || r.Metric >= bestMetric {
			continue // on-link default (VPN) has no next hop to ping
		}
		bestMetric = r.Metric
		best = platform.Gateway{Addr: net.IP(v4.Addr[:]).String()}
		bestIndex = r.InterfaceIndex
	}
	if best.Addr != "" {
		best.Iface = "if" + strconv.Itoa(int(bestIndex))
		if row, err := ifRow(bestIndex); err == nil {
			if a := windows.UTF16ToString(row.Alias[:]); a != "" {
				best.Iface = a
			}
		}
		c.ifMu.Lock()
		c.ifAlias, c.ifIndex = best.Iface, bestIndex
		c.ifMu.Unlock()
	}
	return best, nil
}

// ifRow reads one interface's details and counters.
func ifRow(index uint32) (*windows.MibIfRow2, error) {
	row := &windows.MibIfRow2{InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, row); err != nil {
		return nil, err
	}
	return row, nil
}

// icmpEchoReply is the start of ICMP_ECHO_REPLY; only these fields are read.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
}

// Ping sends echo requests with IcmpSendEcho, which needs no privileges.
func (c *Collector) Ping(ctx context.Context, host string, count int) *health.Ping {
	fail := &health.Ping{Loss: 100}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(addrs) == 0 {
			return fail
		}
		ip = addrs[0].To4()
	}
	h, _, _ := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return fail
	}
	defer procIcmpCloseHandle.Call(h)
	payload := []byte("netwatch-ping-payload-32-bytes!!")
	reply := make([]byte, 256)
	dest := binary.LittleEndian.Uint32(ip) // in_addr is network byte order in memory
	var rtts []float64
	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return fail
			case <-time.After(200 * time.Millisecond):
			}
		}
		n, _, _ := procIcmpSendEcho.Call(h, uintptr(dest), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 2000)
		if n == 0 {
			continue
		}
		r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		if r.Status == 0 {
			rtts = append(rtts, float64(r.RoundTripTime))
		}
	}
	p := health.Summarize(rtts, count)
	return &p
}

// OrphanRule: Windows never reparents; see procscan.MissingParent.
func (c *Collector) OrphanRule() procscan.OrphanRule { return procscan.MissingParent }

// Terminate opens the process first and checks its creation time. Holding
// the handle keeps Windows from reusing the PID, so the check cannot race.
// Without force it asks politely via taskkill (which closes windowed apps
// but not console programs such as node); with force it calls
// TerminateProcess, which gives the process no chance to clean up.
func (c *Collector) Terminate(p procscan.Process, force bool) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return err
	}
	if !filetime(created).Equal(p.Start) {
		return procscan.ErrChanged
	}
	if force {
		return windows.TerminateProcess(h, 1)
	}
	if _, err := execx.Output(context.Background(), 15*time.Second, "taskkill", "/PID", strconv.Itoa(p.PID)); err != nil {
		return fmt.Errorf("%w (console programs ignore a polite close; add --force)", err)
	}
	return nil
}

const toastScript = `$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $t.GetElementsByTagName('text')
$n.Item(0).AppendChild($t.CreateTextNode($env:NETWATCH_TOAST_TITLE)) | Out-Null
$n.Item(1).AppendChild($t.CreateTextNode($env:NETWATCH_TOAST_MSG)) | Out-Null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))`

// Notify shows a toast through Windows PowerShell. The text travels in
// environment variables, never in the script, so it cannot inject code.
func (c *Collector) Notify(title, msg string) error {
	u := utf16.Encode([]rune(toastScript))
	b := make([]byte, 0, 2*len(u))
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	_, err := execx.OutputEnv(context.Background(), 20*time.Second,
		[]string{"NETWATCH_TOAST_TITLE=netwatch: " + title, "NETWATCH_TOAST_MSG=" + msg},
		"powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	return err
}
