---
name: defect-patterns
description: Defect patterns found in labctl reviews (stdout pollution, swallowed errors in loops, per-item-only validation, lost subprocess stderr, map+unstable-sort ties), each with its source
metadata:
  type: project
---

Defect patterns seen in labctl reviews. Check for them first on new diffs.

- Progress text on Stdout in helpers that `labctl <host> <cmd>` also uses corrupts piped command output; child ssh inherits stdin without -n. Source: v01-foundation review 2026-10-26, internal/cli/wake.go:76 (fixed in 83de264).
- Errors swallowed inside poll or fan-out loops (`continue`, `err == nil &&` guards), then a misleading final message. Source: v01 review, internal/cli/wake.go:91 and internal/cli/cli.go:149 (fixed in 83de264).
- Validation that checks each generated item alone but never the whole result (duplicates slip through). Source: v01 review, internal/cli/cli.go:245 (hosts init; fixed in 83de264).
- exec `.Output()` errors are wrapped without ExitError.Stderr, so the tool's own reason is lost. Source: v01 review, internal/tailnet/status.go:101 (fixed in 83de264).
- Tests with tolerance windows wide enough to accept an off-by-one, plus comments that don't match the harness. Source: v01 review, internal/cli/wake_test.go:62 (fixed in 83de264).
- JSON map iteration + sort.Slice on a non-unique key gives a random pick on ties (same first DNS label). Source: v01 round 2, internal/tailnet/status.go:74 (open, non-blocking).
- e2e tests that merge stdout and stderr cannot catch stdout pollution; check for a separate stdout assertion. Source: v01 round 2, cmd/labctl/e2e_test.go:69.

**Why:** these came back more than once in the v01 reviews; the e2e and unit tests did not catch them at first.
**How to apply:** on labctl diffs, probe with a scratch copy of the tree (git archive HEAD) plus probe tests, never edits to the repo. In zsh, an unmatched glob aborts the whole command (it bit a cleanup `rm`): use find -delete.
