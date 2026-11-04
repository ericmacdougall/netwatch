package darwin

import (
	"bytes"
	"encoding/xml"
	"path"
	"strings"

	"github.com/ericmacdougall/netwatch/internal/platform"
)

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// RenderPlist builds the LaunchAgent property list. stdout goes to
// /dev/null because every event is already in events.jsonl; stderr keeps
// collector errors in the log directory.
func RenderPlist(o platform.ServiceOptions) string {
	var args strings.Builder
	for _, a := range append(append([]string{o.Exe}, o.Args...), "run") {
		args.WriteString("<string>" + xmlEscape(a) + "</string>")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + xmlEscape(o.Label) + `</string>
<key>ProgramArguments</key><array>` + args.String() + `</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>30</integer>
<key>ProcessType</key><string>Background</string>
<key>LowPriorityIO</key><true/>
<key>Nice</key><integer>10</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>` + xmlEscape(path.Join(o.LogDir, "stderr.log")) + `</string>
</dict></plist>
`
}
