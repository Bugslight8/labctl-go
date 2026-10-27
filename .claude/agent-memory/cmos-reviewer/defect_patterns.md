---
name: defect-patterns
description: Defect patterns found in labctl reviews (stdout pollution, swallowed errors, per-item validation, lost subprocess stderr, Self never matched, cursor read under a separate lock, shutdown tests that cannot fail), each with its source
metadata:
  type: project
---

Defect patterns seen in labctl reviews. Check for them first on new diffs.

- Progress text on Stdout in helpers that `labctl <host> <cmd>` also uses corrupts piped command output; child ssh inherits stdin without -n. Source: v01-foundation review 2026-10-26, internal/cli/wake.go:76 (fixed in 83de264).
- Errors swallowed inside poll or fan-out loops (`continue`, `err == nil &&` guards), then a misleading final message. Source: v01 review, internal/cli/wake.go:91 and internal/cli/cli.go:149 (fixed in 83de264). Again in v02a: launchd Uninstall `_ = l.Run("bootout")` then prints success (internal/hub/launchd.go:114).
- Validation that checks each generated item alone but never the whole result (duplicates slip through). Source: v01 review, internal/cli/cli.go:245 (hosts init; fixed in 83de264).
- exec `.Output()` errors are wrapped without ExitError.Stderr, so the tool's own reason is lost. Source: v01 review, internal/tailnet/status.go:101 (fixed in 83de264). Came back in v02a: internal/hub/auth.go:58 and :204.
- Tests with tolerance windows wide enough to accept an off-by-one, plus comments that don't match the harness. Source: v01 review, internal/cli/wake_test.go:62 (fixed in 83de264). Again in v02a: the e2e stop bound of 2.5 s always passes, because an idle connection forces the 2 s grace path (internal/hub/e2e_test.go:194; removing BaseContext still passes).
- JSON map iteration + sort.Slice on a non-unique key gives a random pick on ties. Source: v01 round 2, internal/tailnet/status.go:74 (fixed in 790e5b2, sort by Name then DNSName).
- e2e tests that merge stdout and stderr cannot catch stdout pollution; check for a separate stdout assertion. Source: v01 round 2, cmd/labctl/e2e_test.go:69 (fixed in 790e5b2).
- tailnet.Status.Self is never consulted: code running on a host (the hub on the relay) resolves itself via Peers only and gets not-on-tailnet; the fakes hide it by putting the local machine in Peers. Source: v02a review 2026-10-26, internal/hub/state.go:92, state_test.go:45.
- A response cursor read under a separate lock from its data (Wait, then Mon.Last()) skips events; prove it with a steady record loop plus a since=Last client. Source: v02a review, internal/hub/api.go:116 (798 events lost in 2 s).
- A fix for one review finding can break a plan rule elsewhere: the v02a audit dedupe (added to stop disk fill) was keyed by address alone and dropped refused wakes the plan requires. Check rate-limit/dedupe keys against the plan's "every X" rules. Source: v02a round 2, internal/hub/api.go:120.
- Singleflight that runs the shared call under the first caller's request ctx hands that caller's cancel to every follower (false 403). Source: v02a round 2, internal/hub/auth.go:198.

**Why:** these came back more than once in the v01 and v02a reviews; the e2e and unit tests did not catch them at first.
**How to apply:** on labctl diffs, probe with a scratch copy of the tree (git archive HEAD) plus probe tests, never edits to the repo. In zsh, an unmatched glob aborts the whole command (it bit a cleanup `rm`): use find -delete. Verdict file goes to .cmos/evidence/<slug>/review.md.
