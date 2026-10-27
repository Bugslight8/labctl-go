---
slug: v02a-hub
title: labctl v0.2a - the hub on the Mac mini (state, events, wake, access control, launchd)
status: building
tier: sensitive
created: 2026-10-26
depends: v01-foundation
---
# Plan: labctl v0.2a - the hub on the Mac mini (state, events, wake, access control, launchd)

## Goal
`labctl hub` runs all the time on the Mac mini. It watches every host (up / asleep / unreachable, with history),
serves that state and the hosts list over the tailnet to the user's own devices only, wakes hosts itself (it is on the
LAN, so no ssh hop), and logs every wake to an audit file. `labctl hub install` makes it a launchd login service.

## Finish line
`go test ./internal/hub/... -run TestHubEndToEnd -v` prints `--- PASS: TestHubEndToEnd` (a real hub on a loopback
port with fake tailscale status, fake whois and a fake dialer: an allowed caller reads hosts, gets live events, wakes a
host; a stranger gets 403), and `cmos check --quick` prints `CHECK: OK`.

## Design
- Decisions (human, 2026-10-26): use the mini's own Tailscale (no tsnet, no auth key); only the owner's Tailscale
  login may use the hub; the hub holds the one hosts file; launchd LaunchAgent with auto-login.
- Config: the hub's hosts.toml gains a `[hub]` table: `allow = ["<tailscale login>"]` (required, non-empty), `port`
  (default 7300). `inventory.Parse` validates it; clients never see it.
- Poller (`internal/hub/state.go`): every 5 s, `tailscale status --json` plus a TCP dial to port 22 (2 s timeout) of each
  host the tailnet calls online. State per host: `up` (tailnet online + port 22 answers), `unreachable` (tailnet online,
  port 22 silent: likely asleep with a stale tailnet entry), `asleep` (tailnet offline), `not-on-tailnet`. Each change
  appends an event `{seq, time, host, from, to}` to an in-memory ring (last 1000).
- API (`internal/hub/api.go`), JSON over plain HTTP: Tailscale already encrypts and authenticates the path (WireGuard).
  - `GET /v1/hosts` -> hosts (name, tailnet, user, os, tmux, wakeable, state, since) + the relay/hub name.
  - `GET /v1/events?since=<seq>` -> events after seq; waits up to 25 s for a new one (long poll, live updates).
  - `POST /v1/wake/<name>` -> sends the magic packet from the hub (`wol.Send`), 1 per host per 10 s, then 202.
- Access: listen only on this machine's Tailscale addresses (`tailscale ip`), never 0.0.0.0. Each request: caller =
  `tailscale whois --json <RemoteAddr>` (cached 60 s per address) -> `UserProfile.LoginName` must be in `allow`;
  tagged devices are refused. Identity comes from RemoteAddr only, never from a header.
- Audit: every wake (allowed or refused) and every refused request -> one JSON line in
  `~/.local/state/labctl/audit.jsonl` (mode 0600): time, login, device, remote addr, action, host, result.
- `labctl hub` serves; `labctl hub install` writes `~/Library/LaunchAgents/com.labctl.hub.plist` (RunAtLoad,
  KeepAlive, logs to `~/.local/state/labctl/hub.log`) and runs `launchctl bootstrap gui/<uid>`; `labctl hub uninstall`
  reverses it. Linux/systemd: v0.3.
- v0.1 carry-overs fixed here: peers that share a first label resolve to the one in this tailnet (`MagicDNSSuffix`),
  then by full name, never by map order; the relay-asleep warning names the real reason; the e2e test checks stdout and
  stderr separately.

## Threats
| id | boundary | threat | mitigation | check |
|---|---|---|---|---|
| T1 | tailnet device -> hub API | another user's device, a shared-in node or a tagged server reads the lab or wakes hosts | whois on every request; login must be in `allow`; tagged devices refused; empty `allow` refuses to start | `go test ./internal/hub -run TestAccess` |
| T2 | LAN / internet -> hub | the hub listens on the LAN or 0.0.0.0, where whois cannot vouch for anyone | bind only to the addresses `tailscale ip` returns, each checked to be in 100.64.0.0/10 or fd7a:115c:a1e0::/48 | `go test ./internal/hub -run TestListenAddrs` |
| T3 | request -> identity | a client spoofs identity with X-Forwarded-For or similar | identity from `RemoteAddr` only; headers ignored | `go test ./internal/hub -run TestIdentityIgnoresHeaders` |
| T4 | browser on an allowed device -> hub | a web page in the owner's browser POSTs /v1/wake (CSRF) | POST requires `X-Labctl: 1`, rejects any `Origin` header, sends no CORS headers | `go test ./internal/hub -run TestCSRF` |
| T5 | request path -> WoL / argv | a crafted host name reaches wol or a command | `/v1/wake/<name>` resolves only through `inventory.Find`; the MAC is the validated inventory one; no exec on this path | `go test ./internal/hub -run TestWakeUnknownHost` |
| T6 | allowed caller -> LAN | wake spam floods the LAN | 1 wake per host per 10 s, else 429 | `go test ./internal/hub -run TestWakeRateLimit` |
| T7 | hub -> disk | audit log readable by other users, or written outside the state dir | dir 0700, file 0600, path fixed under the state dir | `go test ./internal/hub -run TestAuditFile` |
| T8 | whois -> exec | RemoteAddr reaches the `tailscale whois` argv as an option | pass `net.SplitHostPort` + `netip.ParseAddr` output only, after `--` | `go test ./internal/hub -run TestWhoisArgv` |

## Unknowns
- Whether `launchctl bootstrap gui/<uid>` works over an ssh session on the mini without a GUI login: UNKNOWN. The
  install step prints the manual fallback (`launchctl load`). Blocks: manual try after M4, not the build.
- How shared-in nodes appear in `tailscale status --json`: ASSUMED their DNSName has the sharer's suffix, so a suffix
  match prefers this tailnet's node. Blocks: nothing (M1 tests both orders).
- The mini is not on the tailnet yet (2026-10-26). Blocks: the manual try only.

## Milestones

### M1: v0.1 carry-overs
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 1 | done | `internal/tailnet/status.go`, `internal/tailnet/status_test.go` | `go test ./internal/tailnet -run 'TestLookupSameLabel'` passes (both map orders, 200 runs) |
| 2 | done | `internal/cli/wake.go`, `internal/cli/wake_test.go`, `cmd/labctl/e2e_test.go` | `go test ./internal/cli -run TestAutoWake ./cmd/labctl -run TestEndToEnd` passes with stdout checked on its own |

### M2: inventory [hub] table, poller and events
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 3 | todo | `internal/inventory/inventory.go`, `internal/inventory/inventory_test.go` | `go test ./internal/inventory -run 'TestHubTable'` passes |
| 4 | todo | NEW `internal/hub/state.go`, NEW `internal/hub/state_test.go` | `go test ./internal/hub -run 'TestPoll|TestEvents'` passes |

### M3: API, access control, audit
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 5 | todo | NEW `internal/hub/auth.go`, NEW `internal/hub/auth_test.go` | `go test ./internal/hub -run 'TestAccess|TestIdentityIgnoresHeaders|TestWhoisArgv|TestListenAddrs'` passes |
| 6 | todo | NEW `internal/hub/api.go`, NEW `internal/hub/api_test.go`, NEW `internal/hub/audit.go` | `go test ./internal/hub -run 'TestHostsAPI|TestEventsAPI|TestCSRF|TestWakeUnknownHost|TestWakeRateLimit|TestAuditFile'` passes |

### M4: `labctl hub`, launchd install, end-to-end
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 7 | todo | NEW `internal/hub/serve.go`, NEW `internal/hub/launchd.go`, NEW `internal/hub/launchd_test.go`, `internal/cli/cli.go`, `cmd/labctl/main.go` | `go test ./internal/hub -run 'TestLaunchd' ./internal/cli -run 'TestHubCmd'` passes |
| 8 | todo | NEW `internal/hub/e2e_test.go`, `README.md` | `go test ./internal/hub/... -run TestHubEndToEnd -v` prints `--- PASS: TestHubEndToEnd` |

## Out of scope
- Clients using the hub: `labctl ls/wake/watch` over the hub, inventory cache, direct-mode fallback (v02b-hub-client).
- Nodes on each host, VM control, gRPC stream (v0.3). Agents (v0.4). Dashboards (v0.5).
- HTTPS certificates: the path is already WireGuard-encrypted; `tailscale serve` TLS can come with the phone dashboard.

## Risks
- A stale tailnet "online" for a sleeping host: the port-22 probe turns it into `unreachable`; TestPoll covers it.
- whois latency on every request: cached 60 s per address; TestAccess checks one whois per address per minute.
- The hub dies or the mini reboots: launchd KeepAlive + RunAtLoad; checked by TestLaunchd on the plist content.
