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

Hub (v02a-hub review, 2026-10-26, tree d6d5bae; internal/hub):
- Caller identity = RemoteAddr -> `tailscale whois` -> [hub] allow. Verified live on a Mac: a local connect to the
  machine's own tailnet IP arrives FROM that IP, and whois of the own IP returns self + the owner's login, so local
  processes pass as the owner unless own IPs are refused (finding M1). Re-check this on every hub review.
- The guard and the deny path write the audit log BEFORE auth: any bytes logged there are under attacker control (M2).
  Check for truncation, MaxHeaderBytes and rate limits.
- Origin/X-Labctl stops CSRF on POST but not DNS rebinding on GET. The Host header must be allow-listed (M3).
- whois is a subprocess per cache miss: check that misses are deduplicated and limited (M4).
- macOS here has net.inet.ip.check_interface=1, so LAN packets to the utun IP are dropped. The mini is UNKNOWN.
- Proof method that worked: `git archive HEAD | tar -x` into the scratchpad, add a zz_proof_test.go, then
  `go test -count=1 -run TestProof`.
- Round 2 (1fafecc, 2026-10-26): M1-M4 fixed. The fixes are the self refusal (Authorizer.RefuseFrom), the Host
  allow-list plus Sec-Fetch refusal, deny dedupe with clipping plus rotation, and whois singleflight plus semaphore.
  On later reviews, check that new endpoints sit behind guard -> Wrap, and that dedupe does not hide wake refusals
  (L2 was fixed in a238a20: wake refusals are keyed addr|wake|<canonical name or ?>; the shared whois runs
  detached with a 5 s deadline under the semaphore of 4). The dedupe key must stay canonical (inventory.Find), or
  made-up names would reopen the log flood.
