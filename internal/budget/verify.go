package budget

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/ericmacdougall/netwatch/internal/safeio"
)

// Facts is the live process information the checks need. Tests use fakes;
// production wraps resources.Reader (see ReaderFacts).
type Facts interface {
	// Start returns the process start time; ok is false if it is not alive.
	Start(pid int) (t time.Time, ok bool)
	// Argv returns the process arguments, or nil.
	Argv(pid int) []string
	// Parent returns the parent pid of a live process.
	Parent(pid int) (ppid int, ok bool)
	// PGID returns the process group of a live process.
	PGID(pid int) (pgid int, ok bool)
	// GroupSize counts live members of a process group.
	GroupSize(pgid int) int
}

// Config controls verification.
type Config struct {
	Dir            string   // sidecar directory
	RunCappedPaths []string // configured run_capped script paths
	RAM            uint64   // physical memory; the budget is clamped to 50%
	OwnerUID       *int     // expected sidecar owner; nil means our uid
	StartSlack     time.Duration
	// Realpath resolves symlinks; nil means filepath.EvalSymlinks.
	Realpath func(string) (string, error)
}

const (
	defaultStartSlack = 5 * time.Second
	maxEntries        = 4096
	maxAncestorDepth  = 64
	maxRSSGBLimit     = 1 << 20 // sanity bound, 1 PiB
	maxProcsLimit     = 1 << 20
	gib               = 1 << 30
)

var digitsOnly = regexp.MustCompile(`^[0-9]{1,10}\.json$`)

// Rejection explains why one sidecar was ignored.
type Rejection struct {
	File   string
	Reason string
}

// Result is the outcome of verifying a directory of sidecars.
type Result struct {
	Budgets  map[int]Declared // by pgid
	Rejected []Rejection
}

// Load verifies every sidecar in cfg.Dir. A missing directory yields an
// empty result: no sidecars means no declared budgets.
func Load(cfg Config, f Facts) (*Result, error) {
	if cfg.StartSlack <= 0 {
		cfg.StartSlack = defaultStartSlack
	}
	if cfg.Realpath == nil {
		cfg.Realpath = filepath.EvalSymlinks
	}
	res := &Result{Budgets: map[int]Declared{}}
	d, err := os.Open(cfg.Dir)
	if os.IsNotExist(err) {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	names, _ := d.Readdirnames(maxEntries)
	d.Close()
	sort.Strings(names)

	allowed := map[string]bool{}
	for _, p := range cfg.RunCappedPaths {
		if rp, err := cfg.Realpath(p); err == nil {
			allowed[rp] = true
		}
	}
	for _, n := range names {
		sc, why := verifyOne(cfg, f, allowed, n)
		if why != "" {
			res.Rejected = append(res.Rejected, Rejection{File: n, Reason: why})
			continue
		}
		res.merge(cfg, sc)
	}
	return res, nil
}

// merge adds a verified sidecar. When several claim one group the most
// restrictive limits win, so a forged generous sidecar cannot loosen a
// genuine tight one.
func (r *Result) merge(cfg Config, sc *Sidecar) {
	bytes := budgetBytes(cfg.RAM, sc.MaxRSSGB)
	since := time.Unix(0, int64(sc.StartedAt*1e9))
	cur, ok := r.Budgets[sc.PGID]
	if !ok {
		r.Budgets[sc.PGID] = Declared{PGID: sc.PGID, MaxBytes: bytes, MaxProcs: sc.MaxProcs, Wrapper: sc.WrapperPID, Since: since}
		return
	}
	if bytes < cur.MaxBytes {
		cur.MaxBytes, cur.Wrapper, cur.Since = bytes, sc.WrapperPID, since
	}
	if sc.MaxProcs < cur.MaxProcs {
		cur.MaxProcs = sc.MaxProcs
	}
	r.Budgets[sc.PGID] = cur
}

// budgetBytes converts the declared GB figure and clamps it to half of RAM.
func budgetBytes(ram uint64, gb float64) uint64 {
	b := gb * gib
	if ram > 0 && b > float64(ram)/2 {
		return ram / 2
	}
	if b >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(b)
}

// Within reports whether a group is inside a verified declared budget. A
// group over its byte or process budget counts as undeclared, so a declared
// but runaway job is treated like any other.
func (r *Result) Within(pgid int, footprint uint64, procs int) (Declared, bool) {
	d, ok := r.Budgets[pgid]
	if !ok {
		return Declared{}, false
	}
	if footprint > d.MaxBytes || procs > d.MaxProcs {
		return d, false
	}
	return d, true
}

// verifyOne returns the verified sidecar or a non-empty rejection reason.
func verifyOne(cfg Config, f Facts, allowed map[string]bool, name string) (*Sidecar, string) {
	if !digitsOnly.MatchString(name) {
		return nil, "file name is not digits.json"
	}
	path := filepath.Join(cfg.Dir, name)
	var sc Sidecar
	// uid == self, mode <= 0600, regular file, no symlink, <= 64 KiB.
	err := safeio.ReadJSON(path, safeio.Opts{Max: MaxSidecarBytes, RequireOwner: true, OwnerUID: cfg.OwnerUID, MaxPerm: 0o600}, &sc)
	if err != nil {
		return nil, "unreadable or unsafe file: " + err.Error()
	}
	if why := checkSchema(&sc, name); why != "" {
		return nil, why
	}
	if why := checkWrapperAlive(cfg, f, &sc); why != "" {
		return nil, why
	}
	if why := checkWrapperScript(cfg, f, allowed, &sc); why != "" {
		return nil, why
	}
	if why := checkAncestor(f, &sc); why != "" {
		return nil, why
	}
	if why := checkChild(f, &sc); why != "" {
		return nil, why
	}
	if why := checkGroupSize(f, &sc); why != "" {
		return nil, why
	}
	return &sc, ""
}

func checkSchema(sc *Sidecar, name string) string {
	switch {
	case sc.WrapperPID <= 0 || sc.PGID <= 0 || sc.ChildPID <= 0:
		return "schema: pids must be positive"
	case fmt.Sprintf("%d.json", sc.WrapperPID) != name:
		return "schema: file name does not match wrapper_pid"
	case bad(sc.MaxRSSGB) || sc.MaxRSSGB <= 0 || sc.MaxRSSGB > maxRSSGBLimit:
		return "schema: max_rss_gb out of range"
	case sc.MaxProcs <= 0 || sc.MaxProcs > maxProcsLimit:
		return "schema: max_procs out of range"
	case bad(sc.TimeoutS) || sc.TimeoutS < 0:
		return "schema: timeout_s out of range"
	case bad(sc.StartedAt) || sc.StartedAt <= 0 || sc.StartedAt > 1e11:
		return "schema: started_at out of range"
	}
	return ""
}

func bad(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

func checkWrapperAlive(cfg Config, f Facts, sc *Sidecar) string {
	st, ok := f.Start(sc.WrapperPID)
	if !ok {
		return "wrapper is not alive"
	}
	want := time.Unix(0, int64(sc.StartedAt*1e9))
	d := st.Sub(want)
	if d < 0 {
		d = -d
	}
	if d > cfg.StartSlack {
		return "wrapper start does not match started_at"
	}
	return ""
}

// checkWrapperScript requires an absolute argv[0] or argv[1] (the script
// when the wrapper runs under an interpreter) whose realpath is one of the
// configured run_capped paths. A process that is merely named run_capped,
// or a relative path we cannot resolve, does not qualify.
func checkWrapperScript(cfg Config, f Facts, allowed map[string]bool, sc *Sidecar) string {
	argv := f.Argv(sc.WrapperPID)
	for i := 0; i < len(argv) && i < 2; i++ {
		if !filepath.IsAbs(argv[i]) {
			continue
		}
		if rp, err := cfg.Realpath(argv[i]); err == nil && allowed[rp] {
			return ""
		}
	}
	return "wrapper script is not a configured run_capped"
}

// checkAncestor requires the wrapper to be a proper ancestor of the group
// leader (or, if the leader has gone, of the declared child).
func checkAncestor(f Facts, sc *Sidecar) string {
	leader := sc.PGID
	if _, ok := f.Start(leader); !ok {
		leader = sc.ChildPID
	}
	cur := leader
	for i := 0; i < maxAncestorDepth; i++ {
		pp, ok := f.Parent(cur)
		if !ok || pp <= 1 {
			break
		}
		if pp == sc.WrapperPID {
			return ""
		}
		cur = pp
	}
	return "wrapper is not an ancestor of the group leader"
}

func checkChild(f Facts, sc *Sidecar) string {
	if _, ok := f.Start(sc.ChildPID); !ok {
		return "child is not alive"
	}
	if pp, ok := f.Parent(sc.ChildPID); !ok || pp != sc.WrapperPID {
		return "child is not a child of the wrapper"
	}
	if pg, ok := f.PGID(sc.ChildPID); !ok || pg != sc.PGID {
		return "child is not in the stated process group"
	}
	return ""
}

func checkGroupSize(f Facts, sc *Sidecar) string {
	if n := f.GroupSize(sc.PGID); n > sc.MaxProcs {
		return fmt.Sprintf("group has %d processes, over max_procs %d", n, sc.MaxProcs)
	}
	return ""
}
