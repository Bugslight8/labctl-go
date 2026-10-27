# labctl

Project facts for Claude: stack, commands, layout, traps. Keep it short.

- Go; `make check` (gofmt + vet + tests) must stay green. One binary for every OS: macOS, Linux, Windows, arm64.
- This tool runs commands on every machine in the home: remote exec, SSH, wake and inventory code is review tier sensitive.
- Tests must never touch real hosts or the real tailnet: fake the SSH runner, the Tailscale status and the network.

@.cmos/CLAUDE.md
