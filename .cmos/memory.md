# Project memory

Durable facts that a new session needs. One line each, with a source. `/cmos:learn` keeps this file short.
- Mutation checks ("does this test fail without the fix?") must run `go test -count=1`: the test cache reported a stale pass for cmd/labctl e2e after a source change (2026-10-26).
