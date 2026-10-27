---
slug: v01-foundation
title: labctl v0.1 - hosts inventory, ls, wake, run and shell on any host (direct mode)
status: building
tier: sensitive
created: 2026-10-26
depends:
---
# Plan: labctl v0.1 - hosts inventory, ls, wake, run and shell on any host (direct mode)

## Goal
From the MacBook, anywhere on the tailnet, a user lists every home machine with its awake/asleep state
(`labctl ls`), wakes a sleeping one through the Mac mini (`labctl wake <host>`), and opens a tmux shell or runs a
command on it (`labctl <host> [cmd...]`, waking it first when needed). No hub yet: the MacBook talks to hosts directly.

## Finish line
`go test ./cmd/labctl -run TestEndToEnd -v` prints `--- PASS: TestEndToEnd` (builds the real binary, puts fake
`tailscale` and `ssh` programs on PATH, and checks `hosts init`, `ls`, `wake`, `<host> cmd` and auto-wake end to end),
and `cmos check --quick` prints `CHECK: OK`.

## Design
- One binary, `cmd/labctl`. Packages under `internal/`: `inventory` (hosts file), `tailnet` (parse
  `tailscale status --json`), `sshx` (build ssh argv, quote remote commands), `wol` (magic packet), `cli` (commands).
- Hosts file: TOML at `$LABCTL_HOSTS`, else `~/.config/labctl/hosts.toml` (library: github.com/BurntSushi/toml).
  Per host: `name`, `tailnet` (MagicDNS host name), `user`, `os`, `mac` (optional), `tmux` (session name, default
  `main`, empty = plain login shell). Top level: `relay` = the host name that sends wake packets (the Mac mini).
- Online state comes from `tailscale status --json` on the MacBook (fields `Peer[].HostName`, `DNSName`, `Online`,
  `LastSeen`, `OS`, `TailscaleIPs`, seen 2026-10-26): `ls` needs no SSH and answers at once.
- SSH: exec the system `ssh` (works with Tailscale SSH on macOS/Linux and OpenSSH Server on Windows, and handles the
  TTY for tmux). Shared connection per host: `ControlMaster=auto`, `ControlPersist=10m`,
  `ControlPath=~/.cache/labctl/cm-%C` (dir mode 0700), `ServerAliveInterval=5`, `ServerAliveCountMax=2`,
  `ConnectTimeout=10`. Same options as the bash version (../fabric/tools/mac/common.sh).
- Remote command: one argument = a shell string as given; several = each POSIX single-quoted.
- Wake: `labctl wake <host>` runs `ssh <relay> labctl wol <mac>`; on the relay, `labctl wol` sends the 102-byte magic
  packet to UDP 255.255.255.255:9. Then poll tailscale status every 2 s until Online, timeout 120 s.

## Commands
| Command | Result |
|---|---|
| `labctl hosts init` | writes the hosts file from tailscale status (refuses to overwrite an existing file) |
| `labctl ls` | table: name, state (up / asleep / not-on-tailnet), OS, Tailscale IP, last seen |
| `labctl wake <host> [--no-wait]` | wake through the relay, wait until online |
| `labctl wol <mac>` | send a magic packet from this machine (runs on the relay) |
| `labctl <host>` | interactive shell: attach or create the host's tmux session (auto-wake if asleep and `mac` is set) |
| `labctl <host> <cmd...>` | run a command there; exit code passes through (auto-wake as above) |
| `labctl off [host]` | close shared SSH connections |
| `labctl version` | prints the version |

## Threats
| id | boundary | threat | mitigation | check |
|---|---|---|---|---|
| T1 | hosts file -> local ssh argv | a host or user field like `-oProxyCommand=...` becomes an ssh option and runs a local command | validate `name`, `tailnet`, `user` against `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`; exec argv directly, never `sh -c` locally | `go test ./internal/inventory -run TestRejectsUnsafeFields` |
| T2 | MacBook -> remote shell | arguments with spaces, `;`, `$`, quotes are re-split or executed by the remote shell | POSIX single-quote each argument | `go test ./internal/sshx -run TestQuoteRoundTrip` (quoted output run through `/bin/sh -c` gives back the same argv) |
| T3 | MacBook -> relay | a bad `mac` value injects a command into `ssh <relay> labctl wol <mac>` | parse with `net.ParseMAC`, require 6 bytes, pass the canonical form | `go test ./internal/inventory -run TestRejectsBadMAC` |
| T4 | local socket dir | another local user hijacks the ControlMaster socket | create `~/.cache/labctl` with mode 0700; refuse to use it if owned by someone else or group/world-writable | `go test ./internal/sshx -run TestControlDirPerms` |
| T5 | tests -> real network | a test reaches a real host or the real tailnet | all tests use fakes; the end-to-end test puts fake `ssh`/`tailscale` first on PATH and fails if a real one would run | `go test ./cmd/labctl -run TestEndToEnd` |

## Unknowns
- MAC addresses of the hosts that should wake: needed for real wakes, not for the build (tests use fake MACs). Blocks: manual try after M3.
- Windows host: Tailscale SSH has no server on Windows, so it needs OpenSSH Server and a key, and its default shell
  (cmd.exe) does not understand POSIX quoting. v0.1 targets a POSIX shell on Windows (WSL bash or Git Bash as the
  OpenSSH DefaultShell). ASSUMED; proper PowerShell support goes into v0.3. Blocks: nothing in the build.
- The Linux server and Pi/NAS are not on the tailnet yet (2 peers: macOS, windows, 2026-10-26). Blocks: nothing in the build.
- How fast tailscale `Online` turns false after a host sleeps: UNKNOWN; `ls` shows `LastSeen` so a stale "up" is visible. Blocks: nothing.

## Milestones

### M1: inventory, tailnet status, `hosts init`, `ls`
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 1 | done | NEW `internal/inventory/inventory.go`, NEW `internal/inventory/inventory_test.go` | `go test ./internal/inventory` passes, including TestRejectsUnsafeFields and TestRejectsBadMAC |
| 2 | done | NEW `internal/tailnet/status.go`, NEW `internal/tailnet/status_test.go`, NEW `internal/tailnet/testdata/status.json` (synthetic) | `go test ./internal/tailnet` passes |
| 3 | done | NEW `internal/cli/cli.go`, NEW `internal/cli/ls_test.go`, `cmd/labctl/main.go` | `go test ./internal/cli -run 'TestLs|TestHostsInit'` passes |

### M2: SSH runner, `<host> [cmd]`, `off`
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 4 | done | NEW `internal/sshx/sshx.go`, NEW `internal/sshx/sshx_test.go` | `go test ./internal/sshx` passes, including TestQuoteRoundTrip and TestControlDirPerms |
| 5 | done | `internal/cli/cli.go`, NEW `internal/cli/run_test.go` | `go test ./internal/cli -run 'TestRun|TestShell|TestOff|TestExitCode'` passes |

### M3: wake through the relay, auto-wake, end-to-end test
| # | Status | Files | Acceptance check |
|---|---|---|---|
| 6 | done | NEW `internal/wol/wol.go`, NEW `internal/wol/wol_test.go` | `go test ./internal/wol` passes (packet bytes; sent to a local UDP listener) |
| 7 | done | `internal/cli/cli.go`, NEW `internal/cli/wake_test.go` | `go test ./internal/cli -run 'TestWake|TestAutoWake|TestWol'` passes |
| 8 | done | NEW `cmd/labctl/e2e_test.go`, `Makefile` (`dist`: darwin/arm64, darwin/amd64, linux/amd64, linux/arm64, windows/amd64) | `go test ./cmd/labctl -run TestEndToEnd -v` prints `--- PASS: TestEndToEnd`; `make dist` builds 5 binaries |

## Out of scope
- The hub, the node service, live state streaming (v0.2).
- VM control: WSL2, Hyper-V, VirtualBox, Lima, OrbStack, Docker (v0.3).
- Agents and moving Hermes to the Mac mini (v0.4). Dashboards (v0.5).
- Porting the fabric helpers (status, labcap, labwalk, labui): they stay in bash.
- Installing labctl on the relay: v0.1 documents `scp bin/labctl-darwin-arm64 mini:~/.local/bin/labctl`.
- Tailscale ACLs and tags: set by the human in the Tailscale admin console; documented, not automated.

## Risks
- Wake-on-LAN needs Ethernet, firmware and NIC settings on each host: not testable here. Caught by a manual
  `labctl wake <host>` after M3; `wake` prints a clear timeout message naming those settings.
- A stale shared SSH connection after the MacBook sleeps: keepalives drop it in about 10 s; `labctl off` resets it.
  Checked by TestRun asserting the keepalive options are in the argv.
- Fakes drifting from the real tools: the fixture follows the real `tailscale status --json` field names seen on
  2026-10-26; the e2e test runs the real binary and real exec path.
