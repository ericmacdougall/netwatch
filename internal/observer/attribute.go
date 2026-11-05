package observer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

// EnvKeys are the only environment variables the observer ever reads from a
// process. Nothing else is read, kept or logged.
var EnvKeys = []string{"AGENT_HARNESS_TASK", "AGENT_ID", "AGENT_HARNESS_TICKET", "AGENT_HARNESS_SESSION", "AGENT_HARNESS_RUN_ID"}

// LedgerRow is the part of an ah-run ledger row the observer uses. The
// ledger never holds commands or environments. ASSUMPTION: field names follow
// the contract prose (observer.md); confirm against a real row.
type LedgerRow struct {
	RunID      string  `json:"run_id"`
	Task       string  `json:"task"`
	Agent      string  `json:"agent"`
	Ticket     string  `json:"ticket"`
	Session    string  `json:"session"`
	Host       string  `json:"host"`
	PID        int64   `json:"pid"`
	StartToken string  `json:"start_token"`
	End        *string `json:"end"`
	Via        string  `json:"via"` // "hook-ssh" when the line was built by the hook
}

// Claim returns the row's attribution claim.
func (r LedgerRow) Claim() Claim {
	return Claim{Task: r.Task, Agent: r.Agent, Ticket: r.Ticket, Session: r.Session, RunID: r.RunID}
}

// Ledger indexes rows by run id and by pid and start token.
type Ledger struct {
	byRun map[string]LedgerRow
	byPID map[ptKey]LedgerRow
}

type ptKey struct {
	pid   int64
	token string
}

var runFileRE = regexp.MustCompile(`^[0-9a-f]{32}\.json$`)

// LoadLedger reads every <run_id>.json row in dir. A missing directory is an
// empty ledger (netwatch must work without the harness). Malformed rows and
// rows whose file name disagrees with their run_id are skipped, never trusted.
func LoadLedger(dir string) (*Ledger, error) {
	l := &Ledger{byRun: map[string]LedgerRow{}, byPID: map[ptKey]LedgerRow{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return l, err
	}
	for _, e := range ents {
		if !e.Type().IsRegular() || !runFileRE.MatchString(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(raw) > 1<<20 {
			continue
		}
		var row LedgerRow
		if json.Unmarshal(raw, &row) != nil || row.RunID+".json" != e.Name() {
			continue
		}
		l.Add(row)
	}
	return l, nil
}

// Add indexes a row.
func (l *Ledger) Add(r LedgerRow) {
	l.byRun[r.RunID] = r
	if r.PID != 0 && r.StartToken != "" {
		l.byPID[ptKey{r.PID, r.StartToken}] = r
	}
}

// Proc is what attribution needs to know about a process.
type Proc struct {
	PID, PPID  int64
	StartToken string
}

// Attribute decides one process's attribution from its environment (the five
// variables, already filtered by the caller) and its ancestry. Ancestry walks
// ppid up to a pid whose pid and start token match a ledger row; an ancestor
// whose token differs (pid reuse) is not a match. Disagreement is a conflict,
// never resolved by picking a side.
func (l *Ledger) Attribute(p Proc, env map[string]string, procs map[int64]Proc) Attribution {
	var envClaim *Claim
	if id := env["AGENT_HARNESS_RUN_ID"]; runIDRE.MatchString(id) {
		c := Claim{Task: env["AGENT_HARNESS_TASK"], Agent: env["AGENT_ID"], Ticket: env["AGENT_HARNESS_TICKET"],
			Session: env["AGENT_HARNESS_SESSION"], RunID: id}
		if validClaim(c) {
			envClaim = &c
		}
	}
	var anc *Claim
	var ancRow LedgerRow
	seen := map[int64]bool{}
	for cur, depth := p, 0; depth < 64; depth++ {
		if row, ok := l.byPID[ptKey{cur.PID, cur.StartToken}]; ok {
			c := row.Claim()
			if validClaim(c) {
				anc, ancRow = &c, row
			}
			break
		}
		next, ok := procs[cur.PPID]
		if !ok || seen[cur.PID] || cur.PPID <= 1 {
			break
		}
		seen[cur.PID] = true
		cur = next
	}
	switch {
	case envClaim != nil && anc != nil && *envClaim != *anc:
		if ancRow.Via == "hook-ssh" {
			return Attribution{State: StateHookSSH, Claim: *envClaim, Via: "env", Ancestry: anc}
		}
		return Attribution{State: StateConflict, Env: envClaim, Ancestry: anc}
	case envClaim != nil && anc != nil:
		return Attribution{State: StateAttributed, Claim: *envClaim, Via: "both"}
	case envClaim != nil:
		if row, ok := l.byRun[envClaim.RunID]; ok && row.Via == "hook-ssh" {
			return Attribution{State: StateHookSSH, Claim: *envClaim, Via: "env"}
		}
		return Attribution{State: StateAttributed, Claim: *envClaim, Via: "env"}
	case anc != nil:
		if ancRow.Via == "hook-ssh" {
			return Attribution{State: StateHookSSH, Claim: *anc, Via: "ancestry"}
		}
		return Attribution{State: StateAttributed, Claim: *anc, Via: "ancestry"}
	}
	return Attribution{State: StateUnattributed}
}
