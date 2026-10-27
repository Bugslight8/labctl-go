---
slug: v02b-hub-client
title: labctl v0.2b - every device uses the hub (ls, wake, watch), with a cached direct-mode fallback
status: building
tier: sensitive
created: 2026-10-26
depends: v02a-hub
---
# Plan: labctl v0.2b - every device uses the hub (ls, wake, watch), with a cached direct-mode fallback

## Goal
On the MacBook, a client hosts file with only `hub_host = "<mini>"` is enough: `labctl ls` shows the hub's live state and
history, `labctl wake` asks the hub, `labctl watch` streams events live, and `labctl <host>` uses the hub's hosts list.
When the hub is down, labctl says so once and works in direct mode from its cached copy.

## Finish line
`go test ./cmd/labctl -run 'TestEndToEndHub' -v` prints `--- PASS: TestEndToEndHub` (main's real App wiring, with
only the network dialer swapped, against an in-process hub with fake whois and status: ls, wake, watch, and fallback
after the hub stops; the binary itself cannot reach a test hub without an address override that would bypass T2), and
`cmos check --quick` prints `CHECK: OK`.

## Design
- Client hosts file: `hub_host = "<host>"` (and optional `hub_port`, default 7300); hosts may be left out. (Not `hub`:
  the hub's own file has a `[hub]` table, and TOML cannot hold both.) With a hub, the hub's list wins, and local
  entries are only the fallback.
- `internal/hubclient`: GET /v1/hosts, GET /v1/events (long poll), POST /v1/wake with `X-Labctl: 1`; 3 s timeout
  except the long poll. Cache: the last /v1/hosts answer in `~/.cache/labctl/hosts.json` (0600), used when the hub is
  unreachable, with a one-line notice naming the hub and how old the cache is.
- The cached copy is validated with `inventory` rules on load, so a hub or a cache file cannot inject unsafe names.
- `labctl ls` adds a SINCE column; `labctl watch` prints events as they come (`12:04:10 korg up -> asleep`) until Ctrl-C.
- Wake through the hub; the v0.1 relay path stays as the fallback when the hub is down.

## Threats
| id | boundary | threat | mitigation | check |
|---|---|---|---|---|
| T1 | hub / cache -> ssh argv | a hub answer or an edited cache file holds `-oProxyCommand=...` names | the same `inventory` validation on every hub answer and every cache load | `go test ./internal/hubclient -run TestRejectsUnsafeHostList` |
| T2 | impostor -> client | another tailnet device answers as the hub | the hub address is the configured host's MagicDNS name; only Tailscale addresses accepted for it | `go test ./internal/hubclient -run TestHubAddress` |
| T3 | hub stream -> terminal | event text carries escape sequences | `printable` on every field `watch` prints | `go test ./internal/cli -run TestWatchStripsControlChars` |

## Unknowns
- None that block the build; the real try needs the mini on the tailnet with v02a installed.

## Milestones

### M1: hub client and cache
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 1 | done | NEW `internal/hubclient/client.go`, NEW `internal/hubclient/client_test.go`, `internal/inventory/inventory.go` | `go test ./internal/hubclient` passes, including TestRejectsUnsafeHostList and TestHubAddress |

### M2: ls, wake and <host> through the hub, with fallback
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 2 | done | `internal/cli/cli.go`, `internal/cli/wake.go`, NEW `internal/cli/hub_test.go` | `go test ./internal/cli -run 'TestHubLs|TestHubWake|TestHubFallback'` passes |

### M3: watch, end-to-end
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 3 | done | NEW `internal/cli/watch.go`, `internal/cli/hub_test.go`, NEW `cmd/labctl/e2e_hub_test.go`, `README.md` | `go test ./cmd/labctl -run TestEndToEndHub -v` prints `--- PASS: TestEndToEndHub`; `go test ./internal/cli -run TestWatch` passes |

## Out of scope
- Phone dashboard (v0.5). Nodes and VMs (v0.3).

## Risks
- Hub and client versions drift: /v1 paths are versioned; an unknown field is ignored, a missing one is an error.
