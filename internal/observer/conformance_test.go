package observer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// pinnedSHA256 is the golden sample hash pinned in agent-harness
// (docs/observer-sample.sha256, commit 4e6b67a0). Changing the sample needs a
// schema bump in both repositories.
const pinnedSHA256 = "aefcb5a6983e8bfd75fa75b6297d8c0416228dd4fa3a642f1680b039e559de83"

func loadSample(t *testing.T) ([]byte, Document) {
	t.Helper()
	raw, err := os.ReadFile("testdata/observer-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return raw, d
}

func TestPinnedSHAMatchesSample(t *testing.T) {
	raw, _ := loadSample(t)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pinnedSHA256 {
		t.Fatalf("sample sha256 %s, pinned %s", got, pinnedSHA256)
	}
	file, err := os.ReadFile("testdata/observer-sample.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(file), pinnedSHA256) {
		t.Fatalf("vendored sha file does not name the pinned hash: %q", file)
	}
}

func TestGoldenSampleConforms(t *testing.T) {
	_, d := loadSample(t)
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	states := map[string]bool{}
	for _, s := range d.Samples {
		states[s.Attribution.State] = true
	}
	for _, want := range []string{StateAttributed, StateUnattributed, StateConflict, StateHookSSH} {
		if !states[want] {
			t.Errorf("golden sample lacks state %q, so it would not be tested", want)
		}
	}
	if len(d.Samples) == 0 || len(d.Volumes) == 0 || len(d.TopWriters) == 0 {
		t.Fatal("golden sample is empty; the test would pass vacuously")
	}
}

func TestMarshalRoundTripKeepsStateFields(t *testing.T) {
	_, d := loadSample(t)
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round trip broke the contract: %v", err)
	}
	var un map[string]any
	for _, s := range d.Samples {
		if s.Attribution.State == StateUnattributed {
			b, _ := json.Marshal(s.Attribution)
			_ = json.Unmarshal(b, &un)
		}
	}
	if len(un) != 1 {
		t.Fatalf("unattributed must marshal to exactly {state}, got %v", un)
	}
}

func TestTimeAcceptsBothRFC3339Forms(t *testing.T) {
	for _, s := range []string{"2026-11-05T04:00:00+00:00", "2026-11-05T04:00:00Z", "2026-11-05T04:00:00.123456789Z"} {
		if _, err := ParseTime(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// Failing controls: each mutation breaks one rule and must be rejected, so a
// validator that accepts everything cannot pass.
func TestValidateRejectsBrokenDocuments(t *testing.T) {
	mut := map[string]func(d *Document){
		"schema 2":    func(d *Document) { d.Schema = 2 },
		"bad at":      func(d *Document) { d.At = "yesterday" },
		"bad fsid":    func(d *Document) { d.Volumes[0].FSID = "sda1" },
		"six writers": func(d *Document) { d.TopWriters = append(d.TopWriters, make([]Writer, 5)...) },
		"six dirs": func(d *Document) {
			d.Volumes[0].TopGrowingDirs = append(d.Volumes[0].TopGrowingDirs, make([]Dir, 4)...)
		},
		"bad token":          func(d *Document) { d.Samples[0].StartToken = "12345" },
		"long argv":          func(d *Document) { d.Samples[0].ArgvMasked = strings.Repeat("a", MaxArgv+1) },
		"unmasked secret":    func(d *Document) { d.Samples[0].ArgvMasked = "tool password=hunter2" },
		"unknown state":      func(d *Document) { d.Samples[0].Attribution.State = "guess" },
		"bad via":            func(d *Document) { d.Samples[0].Attribution.Via = "cwd" },
		"bad run id":         func(d *Document) { d.Samples[0].Attribution.RunID = "xyz" },
		"conflict equal":     func(d *Document) { setConflictEqual(d) },
		"unattributed extra": func(d *Document) { setUnattributedExtra(d) },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			_, d := loadSample(t)
			f(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("broken document accepted")
			}
		})
	}
}

func setConflictEqual(d *Document) {
	for i := range d.Samples {
		if a := &d.Samples[i].Attribution; a.State == StateConflict {
			c := *a.Env
			a.Ancestry = &c
		}
	}
}

func setUnattributedExtra(d *Document) {
	for i := range d.Samples {
		if a := &d.Samples[i].Attribution; a.State == StateUnattributed {
			a.Task = "sneaky"
		}
	}
}

func TestMaskCoversBearerAndSecretFlags(t *testing.T) {
	for in, leak := range map[string]string{
		"curl -H Authorization: Bearer abc123SECRET": "abc123SECRET",
		"srv --token s3cr3tvalue --port 80":          "s3cr3tvalue",
		"srv --password=hunter22":                    "hunter22",
		"srv -api-key kkkk1111":                      "kkkk1111",
	} {
		if got := Mask(in); strings.Contains(got, leak) {
			t.Errorf("Mask(%q) = %q leaks %q", in, got, leak)
		}
	}
	if got := Mask("srv --token t0k --port 80"); got != "srv --token **** --port 80" {
		t.Errorf("flag masking should keep the flag and later args: %q", got)
	}
}

func TestMaskHidesSecretsAndCaps(t *testing.T) {
	got := Mask("curl -H Authorization: Bearer abc password=hunter2 ghp_" + strings.Repeat("a", 20))
	for _, bad := range []string{"hunter2", "ghp_aaaa"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q leaked in %q", bad, got)
		}
	}
	if n := len([]rune(Mask(strings.Repeat("é", 2000)))); n != MaxArgv {
		t.Fatalf("cap = %d, want %d", n, MaxArgv)
	}
}
