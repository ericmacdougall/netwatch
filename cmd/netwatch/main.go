// Command netwatch watches network health and per-process traffic, and
// flags orphaned or runaway developer processes. See README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ericmacdougall/netwatch/internal/collector"
	"github.com/ericmacdougall/netwatch/internal/config"
	"github.com/ericmacdougall/netwatch/internal/eventlog"
	"github.com/ericmacdougall/netwatch/internal/monitor"
	"github.com/ericmacdougall/netwatch/internal/notify"
	"github.com/ericmacdougall/netwatch/internal/procscan"
	"github.com/ericmacdougall/netwatch/internal/record"
	"github.com/ericmacdougall/netwatch/internal/report"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `netwatch: network health, per-process traffic and orphaned dev process watcher

Usage:
  netwatch [--config FILE] [--log-dir DIR] <command> [flags]

Commands:
  run                      sample forever (what the background service runs)
  once                     take one sample and one process scan, then exit
  report [--since 2h] [--json]
                           summarise the logs for a window (s, m, h or d)
  orphans [--kill] [--force] [--json]
                           list orphaned watched processes; --kill asks them to
                           exit (SIGTERM on macOS/Linux; on Windows a polite
                           close, or TerminateProcess with --force)
  tail [-n N] [--no-follow]
                           print recent events and follow new ones
  install [--label NAME]   register the per-user background service
  uninstall [--label NAME] remove it
  status [--label NAME]    show service and log status
  config                   print the effective configuration
  version                  print the version

Environment:
  NETWATCH_CONFIG   config file (default: ` + "%s" + `)
  NETWATCH_LOG_DIR  log directory (default: ` + "%s" + `)
`

type app struct {
	configPath    string
	configFlagSet bool
	logDir        string
	logDirFlagSet bool
	stdout        io.Writer
	stderr        io.Writer
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr}
	a.configPath = os.Getenv(config.EnvConfig)
	if a.configPath == "" {
		a.configPath = config.DefaultPath()
	}
	a.logDir = os.Getenv(config.EnvLogDir)
	if a.logDir == "" {
		a.logDir = collector.DefaultLogDir()
	}
	// Global flags come before the command.
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, val, hasVal := strings.Cut(strings.TrimLeft(args[0], "-"), "=")
		if name == "h" || name == "help" {
			a.printUsage()
			return 0
		}
		if name != "config" && name != "log-dir" {
			fmt.Fprintf(stderr, "netwatch: unknown global flag %s\n", args[0])
			return 2
		}
		args = args[1:]
		if !hasVal {
			if len(args) == 0 {
				fmt.Fprintf(stderr, "netwatch: --%s needs a value\n", name)
				return 2
			}
			val, args = args[0], args[1:]
		}
		if name == "config" {
			a.configPath, a.configFlagSet = val, true
		} else {
			a.logDir, a.logDirFlagSet = val, true
		}
	}
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = a.cmdRun(args, false)
	case "once":
		err = a.cmdRun(args, true)
	case "report":
		err = a.cmdReport(args)
	case "orphans":
		err = a.cmdOrphans(args)
	case "tail":
		err = a.cmdTail(args)
	case "install", "uninstall", "status":
		err = a.cmdService(cmd, args)
	case "config":
		err = a.cmdConfig(args)
	case "version", "--version":
		fmt.Fprintln(stdout, "netwatch", version)
	case "help":
		a.printUsage()
	default:
		fmt.Fprintf(stderr, "netwatch: unknown command %q\n\n", cmd)
		a.printUsage()
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(stderr, "netwatch:", err)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "netwatch:", err)
		return 1
	}
	return 0
}

type usageError struct{ error }

func (a *app) printUsage() {
	fmt.Fprintf(a.stdout, usage, config.DefaultPath(), collector.DefaultLogDir())
}

func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("netwatch "+name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	return nil
}

// loadConfig never fails: a broken config falls back to defaults with a
// warning so the background service keeps running.
func (a *app) loadConfig() *config.Config {
	cfg, warnings, err := config.Load(a.configPath)
	for _, w := range warnings {
		fmt.Fprintln(a.stderr, "netwatch:", w)
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "netwatch: %v (%s); using defaults\n", err, a.configPath)
	}
	return &cfg
}

func (a *app) paths() (events, samples string) {
	return filepath.Join(a.logDir, "events.jsonl"), filepath.Join(a.logDir, "samples.jsonl")
}

func (a *app) writers(cfg *config.Config) (*eventlog.Writer, *eventlog.Writer) {
	ev, sm := a.paths()
	max := int64(cfg.MaxLogMB * 1024 * 1024)
	return eventlog.NewWriter(ev, max), eventlog.NewWriter(sm, max)
}

func (a *app) cmdRun(args []string, once bool) error {
	name := "run"
	if once {
		name = "once"
	}
	if err := parse(a.flags(name), args); err != nil {
		return err
	}
	cfg := a.loadConfig()
	if !once {
		// One monitor per log directory: two would double every event.
		unlock, err := lockRun(filepath.Join(a.logDir, "run.lock"))
		if err != nil {
			return err
		}
		defer unlock()
		background()
	}
	col, _ := collector.New()
	events, samples := a.writers(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := monitor.Deps{Cfg: cfg, Col: col, Events: events, Samples: samples,
		Notify: notify.New(cfg.Notify, time.Duration(cfg.NotifyCooldownS)*time.Second, col.Notify),
		Out:    a.stdout, Errs: a.stderr, Version: version, Self: os.Getpid()}
	return monitor.Run(ctx, d, once)
}

func (a *app) cmdReport(args []string) error {
	fs := a.flags("report")
	since := fs.String("since", "1h", "window to summarise, e.g. 30m, 2h, 7d")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	window, err := report.ParseSince(*since)
	if err != nil {
		return usageError{err}
	}
	from := time.Now().Add(-window)
	evPath, smPath := a.paths()
	samples, err := eventlog.ReadSince(smPath, from, func(s record.Sample) string { return s.TS })
	if err != nil {
		return err
	}
	events, err := eventlog.ReadSince(evPath, from, func(e record.Event) string { return e.TS })
	if err != nil {
		return err
	}
	r := report.Build(*since, from, samples, events)
	if *asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return r.WriteText(a.stdout)
}

// orphanJSON is the stable shape of `orphans --json`.
type orphanJSON struct {
	PID   int     `json:"pid"`
	PPID  int     `json:"ppid"`
	AgeS  int64   `json:"age_s"`
	CPU   float64 `json:"cpu"`
	RSSMB int     `json:"rss_mb"`
	Name  string  `json:"name"`
	Cmd   string  `json:"cmd"`
}

func (a *app) cmdOrphans(args []string) error {
	fs := a.flags("orphans")
	kill := fs.Bool("kill", false, "ask the listed orphans to exit")
	force := fs.Bool("force", false, "Windows only: TerminateProcess processes that ignore a polite close")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *force && !*kill {
		return usageError{errors.New("--force requires --kill")}
	}
	cfg := a.loadConfig()
	col, _ := collector.New()
	ctx := context.Background()
	self := os.Getpid()
	procs, err := col.Processes(ctx)
	if err != nil {
		return err
	}
	orphans := procscan.Orphans(cfg, procs, col.OrphanRule(), self)

	if !*asJSON {
		if len(orphans) == 0 {
			fmt.Fprintln(a.stdout, "no orphaned watched processes")
		}
		a.printOrphans(orphans)
	}
	var results []record.KillResult
	if *kill && len(orphans) > 0 {
		results = a.kill(ctx, cfg, col, orphans, *force, !*asJSON)
	}
	if *asJSON {
		out := struct {
			Orphans []orphanJSON        `json:"orphans"`
			Results []record.KillResult `json:"results,omitempty"`
		}{Orphans: []orphanJSON{}, Results: results}
		for _, p := range orphans {
			out.Orphans = append(out.Orphans, orphanJSON{PID: p.PID, PPID: p.PPID, AgeS: int64(p.Age.Seconds()),
				CPU: p.CPU, RSSMB: p.RSSMB, Name: procscan.BaseName(p), Cmd: monitor.CleanCmd(p.Cmd)})
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	return nil
}

func (a *app) kill(ctx context.Context, cfg *config.Config, col collector.Collector, orphans []procscan.Process, force, text bool) []record.KillResult {
	// Re-read the table just before signalling so a PID that exited and
	// was reused since the listing is never hit.
	fresh, err := col.Processes(ctx)
	var results []record.KillResult
	var killed []int
	for _, p := range orphans {
		res := "signalled"
		switch {
		case err != nil:
			res = "skipped: " + err.Error()
		default:
			if verr := procscan.VerifyForKill(cfg, p, fresh, col.OrphanRule(), os.Getpid()); verr != nil {
				res = "skipped: " + verr.Error()
			} else if terr := col.Terminate(p, force); terr != nil {
				res = "failed: " + terr.Error()
			} else {
				killed = append(killed, p.PID)
			}
		}
		results = append(results, record.KillResult{PID: p.PID, Result: res})
		if text {
			fmt.Fprintf(a.stdout, "%7d %s\n", p.PID, res)
		}
	}
	events, _ := a.writers(cfg)
	ev := record.Event{TS: time.Now().Format(eventlog.TimeFormat), Event: record.OrphansKilled, PIDs: killed, Results: results}
	if err := events.Append(ev); err != nil {
		fmt.Fprintln(a.stderr, "netwatch: events log:", err)
	}
	return results
}

func (a *app) printOrphans(orphans []procscan.Process) {
	for _, p := range orphans {
		fmt.Fprintf(a.stdout, "%7d age %6.1fh cpu %5.1f%% rss %6dMB  %s\n",
			p.PID, p.Age.Hours(), p.CPU, p.RSSMB, procscan.Short(monitor.CleanCmd(p.Cmd), 120))
	}
}

func (a *app) cmdConfig(args []string) error {
	if err := parse(a.flags("config"), args); err != nil {
		return err
	}
	cfg := a.loadConfig()
	fmt.Fprintf(a.stdout, "# config file: %s\n# log dir: %s\n", a.configPath, a.logDir)
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

func (a *app) cmdService(cmd string, args []string) error {
	fs := a.flags(cmd)
	label := fs.String("label", "", "service name (default: platform-specific)")
	if err := parse(fs, args); err != nil {
		return err
	}
	_, svc := collector.New()
	var msg string
	var err error
	switch cmd {
	case "install":
		exe, eerr := os.Executable()
		if eerr != nil {
			return eerr
		}
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		var gargs []string
		if a.configFlagSet || os.Getenv(config.EnvConfig) != "" {
			p, _ := filepath.Abs(a.configPath)
			gargs = append(gargs, "--config", p)
		}
		logDir, _ := filepath.Abs(a.logDir)
		if a.logDirFlagSet || os.Getenv(config.EnvLogDir) != "" {
			gargs = append(gargs, "--log-dir", logDir)
		}
		msg, err = svc.Install(collector.ServiceOptions{Exe: exe, Args: gargs, LogDir: logDir, Label: *label})
	case "uninstall":
		msg, err = svc.Uninstall(*label)
	case "status":
		msg, err = svc.Status(*label)
		if err == nil {
			msg = "service: " + msg + "\n" + a.logStatus()
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, msg)
	return nil
}

func (a *app) logStatus() string {
	ev, sm := a.paths()
	var b strings.Builder
	fmt.Fprintf(&b, "logs: %s\n", a.logDir)
	for _, p := range []string{ev, sm} {
		st, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "  %s: missing\n", filepath.Base(p))
			continue
		}
		fmt.Fprintf(&b, "  %s: %d KB, updated %s ago\n", filepath.Base(p), st.Size()/1024,
			time.Since(st.ModTime()).Round(time.Second))
	}
	return strings.TrimRight(b.String(), "\n")
}
