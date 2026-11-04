// Package windows collects processes through a Toolhelp32 snapshot,
// per-process TCP connection counts through GetExtendedTcpTable, interface
// totals through GetIfEntry2Ex, the default route through
// GetIpForwardTable2 and pings through IcmpSendEcho, and installs a
// per-user logon Scheduled Task. Nothing here needs administrator rights.
//
// Per-process network limits: Windows exposes per-connection byte counters
// (GetPerTcpConnectionEStats) only after an administrator enables them with
// SetPerTcpConnectionEStats. Without admin, netwatch ranks processes by
// established connection count and reports interface totals instead, so
// "top talkers" on Windows means "most connected", not "most bytes".
//
// The helpers in this file are OS-independent so they are tested everywhere.
package windows

import (
	"bytes"
	"encoding/xml"
	"strings"
	"unicode/utf16"

	"github.com/ericmacdougall/netwatch/internal/platform"
)

// SplitCommandLine separates the program from its arguments using the
// Windows convention: a leading quoted token may contain spaces.
func SplitCommandLine(cmdline string) (prog, args string) {
	s := strings.TrimLeft(cmdline, " \t")
	if strings.HasPrefix(s, `"`) {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : end+1], strings.TrimLeft(s[end+2:], " \t")
		}
		return strings.Trim(s, `"`), ""
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimLeft(s[i:], " \t")
	}
	return s, ""
}

// NormalizeCmd builds the pattern-matching text for a process: the image
// path with forward slashes and no ".exe", then the arguments. This lets
// the same patterns (e.g. `(^|/)node( |$)`) match on every OS.
func NormalizeCmd(imagePath, cmdline string) string {
	prog, args := SplitCommandLine(cmdline)
	if imagePath == "" {
		imagePath = prog
	}
	p := strings.ReplaceAll(imagePath, `\`, "/")
	if strings.HasSuffix(strings.ToLower(p), ".exe") {
		p = p[:len(p)-4]
	}
	if args == "" {
		return p
	}
	return p + " " + args
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// quoteArg quotes one argument for CreateProcess when needed.
func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat(`\`, slashes*2))
	b.WriteByte('"')
	return b.String()
}

// JoinArgs builds a command-line argument string.
func JoinArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quoteArg(a)
	}
	return strings.Join(q, " ")
}

// RenderTaskXML builds a Task Scheduler definition that starts netwatch at
// logon of user, runs it with the user's normal (limited) rights, restarts
// it if it fails and never stops it for running too long or on battery.
func RenderTaskXML(o platform.ServiceOptions, user string) string {
	args := JoinArgs(append(append([]string{}, o.Args...), "run"))
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>netwatch: network health and orphaned process monitor</Description>
    <URI>\` + xmlEscape(o.Label) + `</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(user) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(user) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>10</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(o.Exe) + `</Command>
      <Arguments>` + xmlEscape(args) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// UTF16File encodes s as UTF-16LE with a byte-order mark, the encoding
// schtasks expects for /XML files.
func UTF16File(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2, 2+2*len(u))
	b[0], b[1] = 0xFF, 0xFE
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}
