# Status and roadmap

Status as of 2026-11-08, checked against the code at `main` (34e91e3), the GitHub releases page, and the README.

## Shipped

Latest release: v0.1.4 (2026-11-05), with archives for macOS (arm64, amd64), Linux (amd64, arm64) and Windows (amd64) and a `SHA256SUMS` file. Releases v0.1.0 to v0.1.4 were published between 2026-11-04 and 2026-11-05.

| Capability | Where it lives | Evidence |
| --- | --- | --- |
| Gateway and internet ping, `DEGRADED` / `RECOVERED` with top talkers | `internal/monitor`, `internal/health`, `internal/netrate` | `internal/monitor/monitor_test.go`, `internal/health/health_test.go` |
| `NEW_NET_APP` detection | `internal/netrate` | `internal/netrate` tests |
| Orphan and runaway scan; `orphans --kill` with re-check before signalling | `internal/procscan`, `cmd/netwatch/main.go` | `internal/procscan` tests, `cmd/netwatch/main_test.go` |
| Secret redaction in logs, output and notifications | `internal/redact` | `internal/redact` tests |
| Per-user service install on macOS (LaunchAgent), Linux (systemd user unit), Windows (Scheduled Task, with a Run-key fallback) | `cmd/netwatch` `install` | `cmd/netwatch/daemon_test.go`; README Install |
| Memory and process sampling, early-warning alerts, `netwatch top` | `internal/resmon`, `internal/sampler`, `internal/alerts` | `internal/resmon/resmon_test.go`, `cmd/netwatch/resources_test.go` |
| Crash forensics: `netwatch incident` joins jetsam and reset reports with samples (macOS) | `internal/incident`, `internal/jetsam` | `internal/jetsam/` tests; README Events |
| Memory guard: alert, pause (macOS default), kill on Linux only under `pause+kill`; `resume`; mode switching | `internal/guard`, `internal/danger`, `internal/eligibility`, `internal/guardmode` | `cmd/netwatch/guard_test.go`, `internal/config/guard_test.go`, `cmd/netwatch/readme_test.go` (guard docs gate) |
| Single static binary, one dependency (`golang.org/x/sys`) | `go.mod` | `go.mod` |

CI is defined in `.github/workflows/ci.yml` (gofmt, vet, staticcheck, `go test -race` on Linux, macOS and Windows, cross-build, smoke run). The most recent hosted runs on GitHub, on the `fix/ci-lint-windows-tests` branch before PR #2 merged, were failures and one cancelled run; a hosted run on the merged `main` commit has not been confirmed. Treat the hosted CI status as unverified until a green run on `main` exists.

## Known limits (not shipped)

These are stated limits in the README and are not scheduled work:

- The guard never kills on macOS, because the environment of system binaries is not readable there.
- Linux per-process traffic is TCP only (`ss -tinp`); Windows reports connection counts rather than bytes per process without administrator rights.
- Gateway discovery uses IPv4 default routes only.
- Windows release binaries are not code-signed.
- The guard polls and cannot outrun an allocation of several GB per second; it prevents the host reset, not the first jetsam kills.

## In progress

No open issues or pull requests are recorded in the GitHub repository at the time of writing (PRs #1 and #2 are merged), so nothing is listed here.

## Next (planned, not committed)

- Move Codex and other agent harnesses from alert-only to guarded, once their process shape has been verified live (README, Memory guard).
- Get a green hosted CI run on `main` and keep it green.

Planned items have no ship date.
