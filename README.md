# labctl

Command center for the home lab: see every machine, wake a sleeping one, and get a shell or run a command on it,
from anywhere on your tailnet.

```
labctl                      every host: up / asleep, OS, Tailscale address, last seen
labctl wake fabric-twin     the relay (always-on Mac mini) sends Wake-on-LAN; waits until it is online
labctl fabric-twin          shell in its tmux session (wakes it first when asleep)
labctl fabric-twin make deploy
labctl off                  close the shared SSH connections
```

## Set up
1. Build: `make build` (this Mac) or `make dist` (every platform, in `bin/`). Put `labctl` on your PATH.
2. `labctl hosts init` writes `~/.config/labctl/hosts.toml` from your tailnet. Then set `relay = "<always-on host>"`
   and `mac = "aa:bb:cc:dd:ee:ff"` (the Ethernet MAC) on each host to wake.
3. Install labctl on the relay too: `scp bin/labctl-darwin-arm64 <relay>:.local/bin/labctl`.
4. Each host needs SSH over Tailscale: Tailscale SSH on macOS/Linux (`tailscale set --ssh`); OpenSSH Server on
   Windows, with a POSIX DefaultShell (WSL bash or Git Bash) for v0.1.
5. Each host to wake: Wake-on-LAN on in the firmware and the network adapter, on Ethernet.

Every command reuses one SSH connection per host for 10 minutes, so only the first pays the handshake.

## The hub (v0.2, on the always-on Mac mini)
`labctl hub` watches every host (up / unreachable / asleep / not-on-tailnet, with history), serves that state and
wake requests to your own devices over the tailnet, and logs every wake to `~/.local/state/labctl/audit.jsonl`.

1. On the mini, give its hosts file a `[hub]` table:
   ```toml
   [hub]
   allow = ["you@example.com"]   # your Tailscale login (tailscale whois shows it); nobody else gets in
   ```
2. `labctl hub install` runs it as a launchd login service that restarts if it stops (log:
   `~/.local/state/labctl/hub.log`). Set the mini to log in automatically. `labctl hub uninstall` removes it.

It listens only on the mini's Tailscale addresses (port 7300), identifies every caller with `tailscale whois`, refuses
tagged devices and browser-style requests, and sends Wake-on-LAN itself, at most once per host every 10 s.

## Using the hub from your devices (v0.2)
On the MacBook (and any other device), the hosts file can be one line:
```toml
hub_host = "mini"   # the hub's MagicDNS name
```
- `labctl ls` shows the hub's state for every host, and since when.
- `labctl wake <host>` asks the hub (it holds the MACs), and `labctl <host>` uses the hub's hosts list.
- `labctl watch` streams the hub's events live.
- When the hub does not answer, labctl says so once and works in direct mode from its cached copy of the list
  (`~/.cache/labctl/hosts.json`) plus any hosts in the local file, which can still wake through the relay.

labctl only connects to the hub at a Tailscale address, and refuses a host list with unsafe names.
