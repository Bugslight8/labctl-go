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
