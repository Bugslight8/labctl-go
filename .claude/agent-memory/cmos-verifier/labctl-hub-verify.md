---
name: labctl-hub-verify
description: How to safely exercise labctl hub on this MacBook
metadata:
  type: reference
---
- Verdict file must be at .cmos/evidence/<slug>/verify.md for `cmos ground check verify.md` (ground error message).
- Safe: temp HOME, fake `tailscale`/`launchctl` first on PATH=fakes:/usr/bin:/bin; LABCTL_HOSTS selects the hosts file (internal/inventory/inventory.go:73); tailnet.Binary uses LookPath first (internal/tailnet/status.go:134).
- No `timeout` binary, and cat/ls are aliased (bat/eza) in zsh: use /bin/cat, background + kill watchdog.
- Never fake `tailscale ip` as 0.0.0.0 against a hub that could bind; use 127.0.0.1 or 192.168.1.5.
