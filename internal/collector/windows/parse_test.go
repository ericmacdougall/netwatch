package windows

import (
	"strings"
	"testing"

	"github.com/ericmacdougall/netwatch/internal/platform"
)

func TestSplitAndNormalize(t *testing.T) {
	cases := []struct{ image, cmdline, want string }{
		{`C:\Program Files\nodejs\node.exe`, `"C:\Program Files\nodejs\node.exe" -e "setInterval(()=>{},1e6)"`,
			`C:/Program Files/nodejs/node -e "setInterval(()=>{},1e6)"`},
		{`C:\nvm4w\nodejs\node.exe`, `node  server.js`, `C:/nvm4w/nodejs/node server.js`},
		{``, `C:\Tools\chrome.EXE --type=renderer`, `C:/Tools/chrome --type=renderer`},
		{`C:\Windows\System32\notepad.exe`, ``, `C:/Windows/System32/notepad`},
		{``, `"unterminated path`, `unterminated path`},
	}
	for _, c := range cases {
		if got := NormalizeCmd(c.image, c.cmdline); got != c.want {
			t.Errorf("NormalizeCmd(%q, %q) = %q, want %q", c.image, c.cmdline, got, c.want)
		}
	}
}

func TestJoinArgsQuoting(t *testing.T) {
	got := JoinArgs([]string{"--config", `C:\Users\A B\cfg.json`, `say "hi"`, `trail\`, "run"})
	want := `--config "C:\Users\A B\cfg.json" "say \"hi\"" trail\ run`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if got := JoinArgs([]string{`C:\a b\`}); got != `"C:\a b\\"` {
		t.Fatalf("trailing backslash before quote must double: %s", got)
	}
}

func TestRenderTaskXML(t *testing.T) {
	x := RenderTaskXML(platform.ServiceOptions{Exe: `C:\Users\A&B\netwatch.exe`, Args: []string{"--config", `C:\c d.json`}, Label: "netwatch"}, `HOST\user`)
	for _, want := range []string{
		`<Command>C:\Users\A&amp;B\netwatch.exe</Command>`,
		`<Arguments>--config &#34;C:\c d.json&#34; run</Arguments>`,
		`<UserId>HOST\user</UserId>`,
		`<RunLevel>LeastPrivilege</RunLevel>`,
		`<LogonTrigger>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("task xml missing %q:\n%s", want, x)
		}
	}
	b := UTF16File("A\u00e9")
	if len(b) != 6 || b[0] != 0xFF || b[1] != 0xFE || b[2] != 'A' || b[4] != 0xE9 {
		t.Fatalf("utf16 encoding wrong: % x", b)
	}
}
