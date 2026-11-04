# netwatch

netwatch is a small background monitor for developer machines. It answers two questions:

1. **Why is the network bad right now?** Every 10 seconds it pings the gateway and an internet host and records per-process traffic. When latency or loss gets bad it logs a `DEGRADED` event with the top talkers at that moment, so you can see what was saturating the link. It also notes each app that starts moving real traffic for the first time (`NEW_NET_APP`).
2. **What is still running that should not be?** Every minute it looks for developer processes that were left behind: `node`, `vite`, `esbuild`, `wrangler`/`workerd`, Chrome helpers and headless Chrome, `chromedriver`, Playwright, Puppeteer, Electron, `Xvfb`, `crashpad_handler`, `rclone` and similar. A process is reported as an `ORPHAN` when it has lost the parent that started it and is older than a minimum age. It is reported as a `RUNAWAY` when it stays hot on CPU for several scans or passes a memory ceiling.

3. **What is eating memory, and which agent started it?** Every 10 seconds (every 2 seconds while memory is tight) it records memory pressure, the compressor, swap and the largest processes, with the app and, for Claude Code tool calls, the agent that launched them. It warns early: a process over 8 GB, growth over 2 GB a minute, memory pressure, swap over 10 GB, or more than 60 Chrome helpers. After a crash, `netwatch incident` joins macOS jetsam and reset reports with those samples.

The orphan scanner never kills anything on its own. `netwatch orphans --kill` is opt-in, re-checks every process just before signalling it, and on macOS and Linux only sends `SIGTERM`. The one exception is the [memory guard](#memory-guard): on macOS, when the host itself is about to run out of memory, it pauses the Claude Code tool-call job that is causing it, and kills that job only as a last resort. Turn it down to alerts with `netwatch guard alert`.

It runs on macOS, Linux and Windows as a single static binary with one dependency, [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) (BSD-3-Clause, from the Go project). On a laptop it averages about 1% of one CPU core, including the helper commands it runs, and about 13 MB of memory; see [Resource use](#resource-use).

## Install

Download the archive for your platform from the [releases page](https://github.com/ericmacdougall/netwatch/releases). Check it against `SHA256SUMS`, put `netwatch` somewhere on your `PATH`, then register the background service:

```sh
netwatch install     # per-user service; no root or administrator rights needed
netwatch status      # service state and log freshness
netwatch uninstall   # remove the service
```

Or build from source with Go 1.26 or newer:

```sh
go install github.com/ericmacdougall/netwatch/cmd/netwatch@latest
```

`install` registers the binary at its current path. If you move or upgrade the binary, run `netwatch install` again.

### macOS

```sh
curl -LO https://github.com/ericmacdougall/netwatch/releases/download/v0.1.0/netwatch_v0.1.0_darwin_arm64.tar.gz
curl -LO https://github.com/ericmacdougall/netwatch/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf netwatch_v0.1.0_darwin_arm64.tar.gz
install -m 755 netwatch_v0.1.0_darwin_arm64/netwatch ~/.local/bin/netwatch
~/.local/bin/netwatch install
```

`install` writes the LaunchAgent `~/Library/LaunchAgents/com.ericmacdougall.netwatch.plist` and loads it with `launchctl bootstrap`. It replaces any agent with the same label. Logs go to `~/Library/Logs/netwatch/`. If the binary was downloaded with a browser, clear the quarantine flag first with `xattr -d com.apple.quarantine netwatch`.

### Linux

```sh
tar xzf netwatch_v0.1.0_linux_amd64.tar.gz
install -m 755 netwatch_v0.1.0_linux_amd64/netwatch ~/.local/bin/netwatch
~/.local/bin/netwatch install
```

`install` writes the systemd user unit `~/.config/systemd/user/netwatch.service`, then enables and starts it. A user unit runs only while you are logged in unless lingering is enabled (`loginctl enable-linger $USER`, which may need an administrator). Logs go to `$XDG_STATE_HOME/netwatch/`, by default `~/.local/state/netwatch/`.

### Windows

```powershell
Expand-Archive netwatch_v0.1.0_windows_amd64.zip -DestinationPath $env:LOCALAPPDATA\netwatch
& "$env:LOCALAPPDATA\netwatch\netwatch_v0.1.0_windows_amd64\netwatch.exe" install
```

`install` creates a per-user Scheduled Task named `netwatch` that starts at logon with your normal, non-elevated rights, and starts it immediately. If local policy forbids a standard user from creating logon tasks, netwatch falls back to a `HKCU\...\CurrentVersion\Run` entry. Logs go to `%LOCALAPPDATA%\netwatch\logs\`.

## Usage

```text
netwatch [--config FILE] [--log-dir DIR] <command>

  run                       sample forever (what the service runs)
  once                      one sample and one process scan, then exit
  report [--since 2h] [--json]
  orphans [--pid N,..] [--match RE] [--kill [--all]] [--force] [--json]
  tail [-n N] [--no-follow]
  top [--mem|--cpu] [-n N] [--json]
  incident [--last] [--json] [--since D] [--dir DIR] [--replay-guard]
  guard off|alert|pause|pause+kill|status|verify-shape
  resume PGID|--all
  install | uninstall | status [--label NAME]
  config                    print the effective configuration
  version
```

Run `netwatch orphans` to see which watched processes are orphaned. Some orphans are deliberate, such as a dev server you started with `nohup`, so `--kill` needs explicit targets: `--pid 123,456`, `--match REGEX` (matched against the redacted command line you see in the listing), or `--all` for everything listed. `--kill` refuses to run as root. On Windows, which has no `SIGTERM`, `--kill` asks politely through `taskkill`. Console programs such as `node` ignore that request, so `--kill --force` is needed, which calls `TerminateProcess`. `--json` prints machine-readable output for scripts and agents:

```json
{
  "orphans": [
    {"pid": 7311, "ppid": 1, "age_s": 8640, "cpu": 0.1, "rss_mb": 96,
     "name": "node", "cmd": "node /Users/me/src/app/node_modules/.bin/vite --port 5173"}
  ],
  "results": [{"pid": 7311, "result": "signalled"}]
}
```

`results` appears only with `--kill`. A process that changed between the listing and the signal, for example because its PID was reused, is reported as `skipped: ...` and left alone.

### Example report

```text
$ netwatch report --since 2h
netwatch report, last 2h: 119 samples, 5 events
  gateway ms: median 3.9  p95 4.7  max 62  avg loss 0.7%
  avg traffic: in 161 kB/s, out 181 kB/s
  netwatch itself: cpu avg 0.30% (max 0.3%), rss max 14 MB
  top talkers (avg kB/s in / out while in the top list):
    rsync                                        2 /     161
    Safari                                     134 /      12
    node                                        25 /       8
  2026-11-03T21:02:31-07:00 NEW_NET_APP  rsync (4410) 1↓/1900↑ kB/s
  2026-11-03T21:05:31-07:00 DEGRADED     gw=62ms/111.6ms max, 20% loss net=120ms/216ms max, 0% loss top=rsync(2400↑), Safari(12↑)
  2026-11-03T21:09:31-07:00 RECOVERED    gw=3.4ms/6.1ms max, 0% loss net=14.2ms/25.6ms max, 0% loss
  2026-11-03T21:44:31-07:00 ORPHAN       pid 7311 cpu 0.1 rss 96MB node /Users/me/src/app/node_modules/.bin/vite --port 5173
  2026-11-03T22:13:31-07:00 RUNAWAY      [cpu] pid 9055 cpu 101.2 rss 410MB /Users/me/Library/Caches/ms-playwright/chromium-1200/chrome-mac/headless_shell --headless …
```

In this example, a backup upload (`rsync`) saturated the uplink. Gateway latency went from about 4 ms to 62 ms with 20% loss, and `DEGRADED` named `rsync` as the top talker. `report --json` prints the same summary as a JSON object with `gateway`, `top_talkers`, `counts` and `events` fields.

## Events

Events are appended to `events.jsonl` and echoed to stdout. Samples go to `samples.jsonl`.

| Event | Meaning |
| --- | --- |
| `START` / `STOP` | monitor started or stopped cleanly |
| `NEW_NET_APP` | an app moved at least `new_app_min_kbps` for the first time (on Windows: opened its first external TCP connection). An app is its executable path when netwatch can read it (your own processes), otherwise its name. Interpreters and shells (python, node, java, ruby, bash and similar) run many different programs from one path, so they are told apart by the script or module they run (`node server.js`, `python3 -m http.server`); when the command line cannot be read, as on Windows, each of their processes is reported on its own. A script given by a relative name (`python3 main.py`) is keyed by that name, so the same name run from another directory within the hour is not reported again. Another process of the same app, such as the next `git` or `curl` run, is not reported again until the app has been offline for about an hour (360 samples). Paths and command lines are used only in memory and never logged. `first_seen_name` is true the first time that program name is seen; only then is a notification shown |
| `DEGRADED` | gateway average RTT above `degraded_gw_ms`, gateway loss at or above `degraded_loss_pct`, no gateway replies, or internet loss at or above `degraded_loss_pct`. Includes the interface, both pings, total traffic and the top talkers |
| `RECOVERED` | health is back to normal |
| `ORPHAN` | a watched process lost its parent (see below) and is older than `orphan_min_age_min` |
| `RUNAWAY` | a watched process was at or above `runaway_cpu_pct` for `runaway_scans` consecutive scans (`reason: cpu`), or at or above `runaway_rss_mb` (`reason: rss`). Reported once per reason until it cools down or exits |
| `ORPHANS_KILLED` | `orphans --kill` ran. `pids` lists the signalled processes and `results` gives each outcome |
| `RESOURCE_ALERT` | an early-warning trigger fired: a process over 8 GB, growth over 2 GB/min, memory pressure warn or critical, swap over 10 GB, or more than 60 Chrome helpers. Rate-limited per condition |
| `GUARD_PAUSE` / `GUARD_RESUME` / `GUARD_KILL` | the memory guard paused, resumed or killed an agent job; the event names the danger signals, the group and the agent |
| `HOST_AT_RISK_UNPROTECTED` | memory is in danger but the cause is something the guard may not touch (another app, another user, an excluded process); it alerts and signals nothing |
| `MODE_CHANGE` | `netwatch guard MODE` changed the guard mode; the event says who changed it |
| `INCIDENT` | at start, netwatch found that the previous run ended without a clean `STOP` and the host reset or the service died |
| `ALLOWLIST_CHANGE` | the shape check verified a new Claude Code version for kill eligibility |

All rates are kilobytes per second (`kB/s`). Every sample also has a `self` field with netwatch's own CPU percentage, which includes the helper commands it runs, and its memory use.

What "lost its parent" means depends on the platform:

- **macOS:** the process was reparented to `launchd` (PID 1).
- **Linux:** the process was reparented to PID 1, or to a `systemd --user` session manager, which adopts orphans of a login session.
- **Windows:** Windows never reparents. A process counts as orphaned when its recorded parent PID no longer exists, or when that PID now belongs to a process that started after it. Windows reuses PIDs quickly, so a process like that cannot be the original parent.

Only processes owned by the user running netwatch are considered orphans.

## Configuration

netwatch reads a JSON file from the first of these that is set:

1. `--config FILE`
2. `NETWATCH_CONFIG`
3. the default path: `~/Library/Application Support/netwatch/config.json` on macOS, `~/.config/netwatch/config.json` on Linux, or `%APPDATA%\netwatch\config.json` on Windows

The file only needs the keys you change. A missing file means all defaults. Unknown keys, invalid regular expressions and out-of-range values produce warnings and fall back to the defaults. A file that is not valid JSON is reported and ignored. `netwatch config` prints the effective configuration.

```json
{
  "interval": 10,
  "orphan_every": 60,
  "net_every": 30,
  "internet_host": "1.1.1.1",
  "degraded_gw_ms": 40,
  "degraded_loss_pct": 10,
  "new_app_min_kbps": 50,
  "top_n": 6,
  "orphan_min_age_min": 30,
  "runaway_cpu_pct": 80,
  "runaway_scans": 3,
  "runaway_rss_mb": 3000,
  "notify": true,
  "notify_cooldown_s": 600,
  "max_log_mb": 20,
  "watch_patterns_extra": ["(^|/)my-dev-daemon( |$)"],
  "orphan_ignore_extra": ["/opt/my-app/helper"]
}
```

- `watch_patterns` and `orphan_ignore` are regular expressions ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)) matched against the full command line. On Windows, the program path is matched with forward slashes and without `.exe`, so `(^|/)node( |$)` matches `C:/Program Files/nodejs/node`.
- Setting either list replaces the built-in defaults. Use `watch_patterns_extra` and `orphan_ignore_extra` to add patterns instead.
- `net_every` is how often per-process traffic is sampled while the network is healthy. It is the main CPU cost on macOS; lower it for faster `NEW_NET_APP` detection.
- `--log-dir DIR` or `NETWATCH_LOG_DIR` changes where logs go.
- `netwatch install` records `--config` and `--log-dir` in the service definition when you pass them, or when the matching environment variables are set.

Each log file is rotated to `<name>.1` when it passes `max_log_mb`, and only one old generation is kept.

## Memory guard

The guard protects the host, not individual jobs. It has no per-job size or growth caps: a large job on a healthy machine is never touched. It acts only when the machine itself is in danger, and then escalates in three steps:

1. **Alert.** A `RESOURCE_ALERT` or `HOST_AT_RISK_UNPROTECTED` event and a notification name the process, its app and the agent that launched it.
2. **Pause.** The agent job that is causing the danger is stopped with `SIGSTOP`. A paused job keeps all its memory and work. It is resumed with `SIGCONT` once memory pressure has been normal for 30 seconds, after at most 30 minutes if pressure is no longer critical, or after 2 hours regardless. Resume it yourself with `netwatch resume PGID` or `netwatch resume --all`.
3. **Kill**, only as a last resort, only in `pause+kill` mode, and only when the paused job is the proven cause: critical pressure for a full minute after the pause, or the memory compressor at 95% or more. The job gets `SIGTERM`, then `SIGKILL` 5 seconds later.

**Danger** means one of: critical memory pressure; the compressor at 85% of its limit or more; swap at 85% of swap plus free disk; one agent group at 75% of RAM and growing over 1 GB a minute; or a group whose growth would use the remaining memory within 15 seconds, confirmed by one of the other signals.

**Modes.** `netwatch guard off|alert|pause|pause+kill` takes effect within one poll, logs `MODE_CHANGE` with who changed it, and sends a notification. Switching to `off` or `alert` resumes everything the guard paused. The defaults are `pause+kill` on macOS, `alert` on Linux and `off` on Windows. `netwatch guard status` prints the mode and thresholds. To turn the guard down to alerts only:

```sh
netwatch guard alert
```

**What it may touch.** Only Claude Code tool-call jobs: the process group of a shell that Claude Code started for a Bash tool call, including jobs backgrounded with `&` or `nohup`. Kill also requires that the job's own environment confirms its Claude Code parent and that the Claude Code version has passed the shape check (`netwatch guard verify-shape`). Jobs that only look like agent jobs (`CLAUDECODE` set, no terminal), and the leftovers of a short-lived Claude Code child that exited before netwatch could classify it, can be paused but never killed.

**What it never touches:** Claude Code itself and its MCP servers; anything in a terminal, `tmux` or `screen`; other apps (Chrome, editors, …); other users' processes and system processes; virtual machines, containers and databases (`qemu`, `limactl`, `colima`, `vfkit`, `docker`, `VirtualBox`, `postgres`, `mysqld`, `redis-server`, `mongod`; the list is configurable). When one of these is the cause, the guard only alerts.

**Codex and other agent harnesses get alerts only.** They move to guarded once their process shape has been verified live.

**Declared budgets.** A job started through the harness `run_capped` wrapper with a declared memory budget is paused last and never killed while it stays within that budget.

**Wall-clock timer warning.** Pausing a job does not pause the clock of whatever is waiting for it. A foreground Bash tool call has its own timeout, so Claude Code may kill a paused job when that timeout expires, and the agent may retry the same command. Guard events are also written to `guard-events.jsonl` in netwatch's state directory, without command text, so harness hooks can warn the agent.

**Limits.** The guard polls; it cannot outrun an allocation of several GB per second. On 2026-11-04 a Python process grew to 65 GB in about 11 seconds on a 16 GB Mac. Replayed against that incident, the guard would have paused it within about 2 seconds of the first danger signal and killed it within a minute, well before the host reset 27 minutes later, but after macOS had already started killing other apps. So the guard prevents the host reset; it does not prevent the first jetsam kills on very fast allocations. Validating input (never point a reader at an endless stream) is the first line of defence.

**Rollback.** To turn the guard off and return to the previous version:

```sh
netwatch resume --all     # resume anything the guard paused
netwatch guard alert      # stop pausing and killing
# then reinstall the previous release binary and run: netwatch install
```

`netwatch uninstall` also resumes every paused group before removing the service.

## Privacy

- **Everything stays on your machine.** netwatch has no telemetry and makes no network connections except the ICMP pings to your gateway and to `internet_host`.
- **Logs contain process names, PIDs and command lines.** Logs are readable only by your user (mode `0600` in a `0700` directory on macOS and Linux) and are never sent anywhere. netwatch tightens the modes of an existing log directory too, for example one left by an older version.
- **Only your own processes are logged as `ORPHAN` or `RUNAWAY`.** Other users' command lines are not recorded.
- **Secrets in command lines are masked as `[REDACTED]`.** This covers command lines in logs, terminal output, `report` and `tail` (including records written by older versions), `--json` output and notifications. Control characters are removed too. netwatch recognises common shapes:
  - options and assignments whose name contains a secret word: `--token=…`, `--password …`, `--api-key …`, `--var API_TOKEN:…`, `GITHUB_TOKEN=…`, `?password=…`, `{"password":"…"}`;
  - headers such as `Authorization:`, `Cookie:`, `X-Api-Key:` and `Bearer …`;
  - credentials in URLs (`https://user:pass@host`, `https://TOKEN@host`);
  - `mysql -p…`, `sshpass -p …`, `redis-cli -a …` and `curl -u user:…`;
  - well-known token formats: GitHub, GitLab, Slack (tokens and webhooks), AWS, Google, Stripe, npm, Hugging Face, SendGrid, OpenAI-style and JWTs.
- **Masking is best effort.** A secret passed as a bare positional argument cannot be recognised. Because `ps` and `/proc` drop quotes, only the first word of a multi-word secret value is masked. Treat the logs as you would your shell history.
- **Upgrading from the Python prototype:** its `stdout.log` copy of the events was written without redaction. netwatch no longer writes it and `install` tells you when it is still there; delete it when you no longer need it.
- **Notifications go to the local notification system:** `osascript` on macOS, `notify-send` on Linux, or a PowerShell toast on Windows. Their text is passed as data, never as script.

## Limitations by platform

### macOS

- Per-process bytes come from one `nettop -n` sample every `net_every` seconds (30 by default) while the network is healthy, and every interval while pings look bad, so `DEGRADED` names the current top talkers. Samples in between repeat the last traffic figures. `-n` (no reverse DNS) matters: without it `nettop` took 30 seconds per sample on a machine with slow DNS. `nettop` truncates process names to about 15 characters, and that is the name `NEW_NET_APP` and the talkers list show.
- An installed browser's `chrome_crashpad_handler` always detaches to `launchd`, so it is ignored by default. Handlers from Playwright or Puppeteer browser caches are still reported.
- Processes are read with `ps`. `ps` CPU is a decaying average, not an exact per-interval figure.
- Only IPv4 default routes are used to find the gateway.

### Linux

- Per-process traffic comes from `ss -tinp`. It covers TCP only: UDP, including QUIC/HTTP3, is not counted.
- Without root, `ss` shows the owning process only for your own sockets, so other users' traffic is invisible.
- Bytes moved by a connection that opened and closed between two samples are missed.
- Interface totals from `/proc/net/dev` are recorded as `if_in_kBps` and `if_out_kBps`.
- `ping` must work without root. Most distributions give it a file capability, or allow it through `net.ipv4.ping_group_range`.
- `notify-send` is used only when a desktop session is present. Otherwise notifications are skipped.
- The session subreaper is recognised by its process name, `systemd`. Other subreapers are not detected.

### Windows

- Windows only gives per-connection byte counters to administrators (`SetPerTcpConnectionEStats`). netwatch runs without admin, so it records each process's count of established, non-loopback TCP connections, plus byte totals for the default-route interface.
  - "Top talkers" on Windows means the processes with the most connections.
  - `NEW_NET_APP` fires when a process opens its first external TCP connection.
  - Sample `in_kBps` and `out_kBps` are the interface totals.
- Processes that cannot be opened, such as other users' or protected processes, have no command line, start time or memory figure. They are never reported as orphans.
- `--kill` without `--force` uses `taskkill`, which only closes windowed programs. Console programs need `--force`, which calls `TerminateProcess` and gives them no chance to clean up.
- Notifications use a PowerShell toast, which briefly starts `powershell.exe`, at most once per cooldown.
- Release binaries are not code-signed. During testing, Microsoft Defender's cloud heuristics once flagged an unsigned development build after it registered its Scheduled Task (`Trojan:Win32/Bearfoos.A!ml`, a generic machine-learning verdict). Later builds were not flagged. If it happens to you, check the binary against `SHA256SUMS` from the release and [report a false positive](https://www.microsoft.com/wdsi/filesubmission) rather than turning Defender off.
- If Task Scheduler is unavailable, `install` falls back to an `HKCU\…\Run` entry. Reinstalling in that mode does not stop an already running old instance; sign out and back in, or end it in Task Manager.
- Only IPv4 default routes are used.

## Resource use

netwatch runs at normal priority on macOS (the memory guard must keep polling while the host is under memory pressure, so the LaunchAgent is `Interactive` and restarts within 5 seconds), with lowered CPU and I/O priority on Linux, and at normal priority on Windows (a below-normal monitor was starved for tens of seconds on a busy machine). Each sample's `self` field records what it costs, including the helper commands it starts, and `netwatch report` summarises it.

Measured on an Apple M5 laptop (10 cores, macOS 26), with the installed LaunchAgent at default settings for 30 minutes, about 800 processes, and 1–4 MB/s of traffic:

| | v0.1.1 (`net_every` 30 s) | v0.1.0 (traffic every cycle) |
|---|---|---|
| netwatch process CPU (`ps` time), average | 0.22% of one core | 0.28% of one core |
| netwatch plus helpers (`self.cpu_pct`), average | 0.61% of one core (156 samples) | 1.16% of one core (155 samples) |
| netwatch plus helpers, peak sample | 3.0% (a sample with a process scan) | 3.7% |
| Resident memory, peak | 12 MB | 13 MB |

Most of the helper cost is `nettop` (about 18 ms of CPU per call). Since v0.1.1 it runs every `net_every` seconds (default 30) while the link is healthy, and on every cycle while pings fail or the link is degraded, so a problem still gets per-app traffic at full resolution. `ps` costs about 60 ms once a minute, and the two pings and `route` a few milliseconds each. On Windows the service's working set was about 15 MB. Run `netwatch report --since 1h` to see the figures for your machine.

## Development

```sh
go test ./...                              # unit tests plus collector tests for this OS
go vet ./... && staticcheck ./...
GOOS=windows go vet ./... && GOOS=linux go vet ./...
scripts/build-release.sh v0.0.0-dev dist   # cross-build all release archives
```

Tests for the classification logic, rate deltas, the degraded/recovered state machine, parsers, configuration, log rotation and redaction run on every OS. Collector tests that read the live system (`*_darwin_test.go`, `*_linux_test.go`, `*_windows_test.go`) run only on their platform. CI runs all of them on macOS, Linux and Windows.

### Changes from the Python prototype

netwatch began as a single Python script for macOS. The Go version keeps its event names, CLI and configuration keys, with these deliberate changes:

- **Timestamps** are RFC 3339 with a UTC offset. Old offset-less logs are still read as local time.
- **`pid`** is always a number.
- **Talker field names:** talker entries use `in_kBps` and `out_kBps`. The old `in_kbps` and `out_kbps` names were kB/s despite their names, and are still read from old logs.
- **Ownership:** only processes owned by the current user can be orphans or runaways. Others could not be signalled anyway, and their command lines are not ours to log.
- **Kill re-check:** `orphans --kill` re-reads the process table and checks each process's start time and command line before signalling it, and the platform layer checks the start time again through a kernel handle (Linux pidfd, Windows process handle) or `sysctl` (macOS) immediately before the signal.
- **Kill targets:** `orphans --kill` needs `--pid`, `--match` or `--all`; the prototype killed everything listed.
- **Installed browsers' crash reporters** are no longer reported as orphans.
- **Redaction:** secrets in command lines are redacted everywhere.
- **Service output:** the service no longer writes every event to `stdout.log`. Only errors go to `stderr.log` or the journal, and repeated errors are logged at most once an hour.
- **Single instance:** a lock file stops two monitors from writing to the same log directory.
- **`STOP` event:** a clean shutdown writes `STOP`.
- **Config location:** the default config path moved to the platform config directory.
- **New config keys:** `watch_patterns_extra` and `orphan_ignore_extra` were added.
- **`report --since`:** an invalid value is now an error instead of silently meaning one hour, and the window also accepts `s` (seconds).
- **New flags:** `report --json`, `orphans --json`, `orphans --force` (Windows) and `tail -n` / `--no-follow` were added. The new commands are `install`, `uninstall`, `status`, `config` and `version`.

## License

MIT. See [LICENSE](LICENSE).
