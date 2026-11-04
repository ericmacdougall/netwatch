package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportJSONIncludesResources(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	res := `{"ts":"` + ts(-time.Minute) + `","pressure":"warn","compressor_pct":50,"swap_used":123,"sys":{"headroom_bytes":777},"top_mem":[{"pid":9,"start":"s","name":"Python","footprint":4096,"cmd":"python x --token=cmdcanarysecret1"}]}` + "\n"
	ev := `{"ts":"` + ts(-time.Minute) + `","event":"GUARD_PAUSE","pgid":9,"agent":"main","reason":"d4"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "resources.jsonl"), []byte(res), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ev), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--log-dir", dir, "--config", dir + "/none.json", "report", "--json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got struct {
		Samples   int `json:"samples"`
		Resources struct {
			Samples      int            `json:"samples"`
			Pressure     map[string]int `json:"pressure"`
			GuardActions map[string]int `json:"guard_actions"`
			TopProcs     []struct {
				PID int `json:"pid"`
			} `json:"top_procs"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if got.Resources.Samples != 1 || got.Resources.Pressure["warn"] != 1 || got.Resources.GuardActions["GUARD_PAUSE"] != 1 ||
		len(got.Resources.TopProcs) != 1 || got.Resources.TopProcs[0].PID != 9 {
		t.Fatalf("%s", out.String())
	}
	if strings.Contains(out.String(), "cmdcanarysecret1") {
		t.Fatal("secret leaked through the CLI")
	}
}

func TestReportTextWithoutResourceLogsHasNoMemorySection(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"--log-dir", dir, "--config", dir + "/none.json", "report"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Contains(out.String(), "Memory") {
		t.Fatalf("%s", out.String())
	}
}

// `orphans --json` must stay byte-compatible with v0.1.2. The command's
// source from the orphanJSON type through printOrphans is identical to the
// v0.1.2 tag (checked when this test was written); this pins the encoding
// of that shape against the v0.1.2 output for a fixture.
func TestOrphansJSONShapeMatchesV012(t *testing.T) {
	out := struct {
		Orphans []orphanJSON `json:"orphans"`
	}{Orphans: []orphanJSON{{PID: 4242, PPID: 1, AgeS: 3600, CPU: 0.5, RSSMB: 120, Name: "node", Cmd: "node /home/user/app/server.js"}}}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		t.Fatal(err)
	}
	const want = `{
  "orphans": [
    {
      "pid": 4242,
      "ppid": 1,
      "age_s": 3600,
      "cpu": 0.5,
      "rss_mb": 120,
      "name": "node",
      "cmd": "node /home/user/app/server.js"
    }
  ]
}
`
	if buf.String() != want {
		t.Fatalf("orphans JSON changed:\n%s", buf.String())
	}
}
