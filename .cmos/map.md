# Codebase map

labctl: command center for the home lab: reach, wake and control every host and its VMs over Tailscale (design: .cmos/plans/).

## Stack
- Go 1.27.1, module github.com/Bugslight8/labctl (go.mod); one dependency: github.com/BurntSushi/toml (hosts file).

## Commands (Makefile)
- check :4 = gofmt -l, go vet ./..., go test ./... (the cmos project check, .cmos/config.json "check").
- build -> bin/labctl; dist -> bin/labctl-<os>-<arch> for 5 platforms (git-ignored, .gitignore:1).

## Layout
- cmd/labctl/main.go: newApp(hubDial) wires the real tailscale, ssh, clock, WoL and hub client into cli.App; e2e_hub_test.go: real hub.Serve + newApp; e2e_test.go: real binary + fake tailscale/ssh on PATH.
- internal/cli: cli.go (dispatch, ls, hosts init, <host> [cmd], off), wake.go (wake, auto-wake, wol), exec.go (SystemExec, DefaultControlDir). App fields are the fakes' seams.
- internal/inventory: hosts.toml parse + validation (safe regex, 6-byte MAC, unknown keys rejected).
- internal/tailnet: `tailscale status --json` parse (peer name = first MagicDNS label), Query.
- internal/sshx: ssh argv with ControlMaster options, POSIX Quote, EnsureControlDir (0700, owner).
- internal/wol: magic packet + UDP broadcast send.
- internal/hubclient (v0.2b): Client (Hosts/Events/Wake by MagicDNS name, X-Labctl), Inventory (CheckHost on every hub host), SaveCache/LoadCache, Dialer (Tailscale addresses only).
- internal/cli/view.go: load() = hub list when hub_host answers, else cache + local hosts (direct mode); lsHub. watch.go: labctl watch (long poll, boot id, retry).
- internal/hub (v0.2a): state.go (Monitor: tailscale status + port-22 probe -> up/unreachable/asleep/not-on-tailnet, event ring, Wait long poll), auth.go (Authorizer: RemoteAddr -> tailscale whois -> [hub] allow; ListenAddrs tailnet-only), api.go (Server: guard -> auth -> /v1/hosts, /v1/events, POST /v1/wake/{name}), audit.go (audit.jsonl 0600), launchd.go (LaunchAgent plist, bootstrap/bootout), serve.go (Serve, Main). e2e_test.go: real Serve over loopback with remote-address-spoofing listeners.

## Predecessor
- Bash version: ../fabric/tools/mac/{labctl,common.sh,labcap,labwalk,labui} (one host, fabric-twin, over Tailscale SSH).
