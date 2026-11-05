package observer

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	runA = "0f0e0d0c0b0a09080706050403020100"
	runB = "a0f2762de96f28a2ec7a539f18188b91"
)

func row(run, task string) LedgerRow {
	return LedgerRow{RunID: run, Task: task, Agent: "main", Ticket: "none", Session: "s", PID: 100, StartToken: "proc:1"}
}

func envFor(run, task string) map[string]string {
	return map[string]string{"AGENT_HARNESS_TASK": task, "AGENT_ID": "main", "AGENT_HARNESS_TICKET": "none",
		"AGENT_HARNESS_SESSION": "s", "AGENT_HARNESS_RUN_ID": run}
}

var tree = map[int64]Proc{
	100: {100, 1, "proc:1"},
	200: {200, 100, "proc:2"},
	300: {300, 200, "proc:3"},
}

func TestAttributeStates(t *testing.T) {
	l := &Ledger{byRun: map[string]LedgerRow{}, byPID: map[ptKey]LedgerRow{}}
	l.Add(row(runA, "t-a"))
	cases := []struct {
		name  string
		p     Proc
		env   map[string]string
		state string
		via   string
	}{
		{"ancestry only", tree[300], nil, StateAttributed, "ancestry"},
		{"env only", Proc{999, 1, "proc:9"}, envFor(runB, "t-b"), StateAttributed, "env"},
		{"both agree", tree[300], envFor(runA, "t-a"), StateAttributed, "both"},
		{"disagree is conflict", tree[300], envFor(runB, "t-b"), StateConflict, ""},
		{"nothing", Proc{999, 1, "proc:9"}, nil, StateUnattributed, ""},
		{"pid reuse: token differs", Proc{300, 200, "proc:3"}, nil, StateAttributed, "ancestry"},
	}
	for _, c := range cases {
		a := l.Attribute(c.p, c.env, tree)
		if a.State != c.state || a.Via != c.via {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, a.State, a.Via, c.state, c.via)
		}
		if err := a.validate(); err != nil {
			t.Errorf("%s: invalid result: %v", c.name, err)
		}
	}
	reused := map[int64]Proc{100: {100, 1, "proc:777"}, 300: {300, 100, "proc:3"}}
	if a := l.Attribute(reused[300], nil, reused); a.State != StateUnattributed {
		t.Errorf("ancestor with a different start token must not match, got %s", a.State)
	}
}

func TestAttributeIgnoresMalformedEnvAndNeverPicksOnConflict(t *testing.T) {
	l := &Ledger{byRun: map[string]LedgerRow{}, byPID: map[ptKey]LedgerRow{}}
	e := envFor("not-a-run-id", "x")
	if a := l.Attribute(Proc{9, 1, "proc:9"}, e, nil); a.State != StateUnattributed {
		t.Fatalf("bad run id must not attribute, got %s", a.State)
	}
	l.Add(row(runA, "t-a"))
	a := l.Attribute(tree[300], envFor(runB, "t-b"), tree)
	if a.Task != "" || a.Env == nil || a.Ancestry == nil {
		t.Fatalf("conflict must carry both claims and no chosen task: %+v", a)
	}
}

func TestHookSSHNeverConflicts(t *testing.T) {
	l := &Ledger{byRun: map[string]LedgerRow{}, byPID: map[ptKey]LedgerRow{}}
	r := row(runA, "t-a")
	r.Via = "hook-ssh"
	l.Add(r)
	a := l.Attribute(tree[300], envFor(runB, "t-b"), tree)
	if a.State != StateHookSSH || a.Ancestry == nil || a.Task != "t-b" {
		t.Fatalf("want hook-ssh with claimed fields and an ancestry object, got %+v", a)
	}
	if err := a.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAncestryTerminatesOnCycle(t *testing.T) {
	l := &Ledger{byRun: map[string]LedgerRow{}, byPID: map[ptKey]LedgerRow{}}
	cyc := map[int64]Proc{5: {5, 6, "proc:5"}, 6: {6, 5, "proc:6"}}
	if a := l.Attribute(cyc[5], nil, cyc); a.State != StateUnattributed {
		t.Fatal("cycle should end unattributed")
	}
}

func TestLoadLedger(t *testing.T) {
	dir := t.TempDir()
	good := `{"run_id":"` + runA + `","task":"t","agent":"main","ticket":"none","session":"s","pid":100,"start_token":"proc:1"}`
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(runA+".json", good)
	write(runB+".json", good) // name disagrees with run_id: skipped
	write("garbage.json", "{")
	write("0f0e0d0c0b0a09080706050403020199.json", "{not json")
	l, err := LoadLedger(dir)
	if err != nil || len(l.byRun) != 1 {
		t.Fatalf("rows=%d err=%v, want exactly the one honest row", len(l.byRun), err)
	}
	if a := l.Attribute(Proc{100, 1, "proc:1"}, nil, nil); a.State != StateAttributed {
		t.Fatalf("loaded row did not attribute: %+v", a)
	}
	if empty, err := LoadLedger(filepath.Join(dir, "missing")); err != nil || len(empty.byRun) != 0 {
		t.Fatal("missing ledger dir must be an empty ledger")
	}
}
