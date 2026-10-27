---
name: labctl-trust-boundaries
description: labctl trust boundaries and security conventions (ssh argv, remote quoting, relay wol, control dir, tailnet peer data)
metadata:
  type: project
---

Trust boundaries of labctl, as they stood at v01-foundation (review of 2026-10-26, tree 61493a8):
- hosts file -> local ssh argv: name/tailnet/user/tmux are checked against a safe regex (internal/inventory/inventory.go `safe`). Local exec is argv only (internal/cli/exec.go).
- Command arguments -> ssh argv: OpenSSH keeps parsing options AFTER the host unless `--` is given. Fixed in 83de264: Argv/OffArgv put `--` before the target (TestOptionInjection). On every review, confirm `--` is still there and that any new ssh argv builder uses it.
- MacBook -> remote shell: POSIX single quotes (sshx.Quote). A single argument passes raw on purpose.
- MacBook -> relay: `PATH=... labctl wol '<canonical mac>'`. The relay parses the MAC again.
- ~/.cache/labctl: 0700, owner uid checked (sshx.EnsureControlDir). The mode and uid checks are Unix-only (checkPrivate), because Go reports 0777 on Windows.
- tailscale status: peer HostName and OS are chosen by the peer (untrusted). DNSName is set by control. Since 83de264, Lookup prefers the MagicDNS name and ls passes peer fields through printable(). Residual Low: two peers with the same first label (a shared-in node) resolve at random.
- Tests: fakes only. The e2e test puts fake ssh/tailscale first on PATH. The only real UDP goes to 127.0.0.1.

**Why:** these are the points where labctl's untrusted inputs turn into commands.
**How to apply:** on the next review, re-check these points first, and re-verify the `--` placement.

Practical: a ControlPath longer than 104 bytes fails on macOS. For a local proof, use a short relative HOME (cd into the scratchpad, HOME=h).
