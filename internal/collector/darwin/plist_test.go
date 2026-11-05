package darwin

import (
	"strings"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/platform"
)

// The guard must keep polling under memory pressure, so the agent is not
// a throttled background job: Interactive, no Nice, no low-priority IO,
// and a short restart throttle (plan: Service).
func TestPlistGuardScheduling(t *testing.T) {
	p := RenderPlist(platform.ServiceOptions{Label: "com.example.netwatch", Exe: "/usr/local/bin/netwatch", LogDir: "/Users/user/Library/Logs/netwatch"})
	want := []string{
		"<key>ProcessType</key><string>Interactive</string>",
		"<key>KeepAlive</key><true/>",
		"<key>ThrottleInterval</key><integer>5</integer>",
	}
	for _, w := range want {
		if !strings.Contains(p, w) {
			t.Errorf("plist lacks %q", w)
		}
	}
	for _, bad := range []string{"<key>Nice</key>", "<key>LowPriorityIO</key>", "Background"} {
		if strings.Contains(p, bad) {
			t.Errorf("plist still has %q", bad)
		}
	}
}
