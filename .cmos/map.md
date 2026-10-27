# Codebase map

labctl: command center for the home lab: reach, wake and control every host and its VMs over Tailscale (design: .cmos/plans/).

## Stack
- Go 1.27.1, module github.com/Bugslight8/labctl (go.mod); one dependency: github.com/BurntSushi/toml (hosts file).

## Commands (Makefile)
- check :4 = gofmt -l, go vet ./..., go test ./... (the cmos project check, .cmos/config.json "check").
- build -> bin/labctl; dist -> bin/labctl-<os>-<arch> for 5 platforms (git-ignored, .gitignore:1).

## Layout
- cmd/labctl/main.go: wires the real tailscale, ssh, clock and WoL into cli.App; e2e_test.go: real binary + fake tailscale/ssh on PATH.
- internal/cli: cli.go (dispatch, ls, hosts init, <host> [cmd], off), wake.go (wake, auto-wake, wol), exec.go (SystemExec, DefaultControlDir). App fields are the fakes' seams.
- internal/inventory: hosts.toml parse + validation (safe regex, 6-byte MAC, unknown keys rejected).
- internal/tailnet: `tailscale status --json` parse (peer name = first MagicDNS label), Query.
- internal/sshx: ssh argv with ControlMaster options, POSIX Quote, EnsureControlDir (0700, owner).
- internal/wol: magic packet + UDP broadcast send.

## Predecessor
- Bash version: ../fabric/tools/mac/{labctl,common.sh,labcap,labwalk,labui} (one host, fabric-twin, over Tailscale SSH).
