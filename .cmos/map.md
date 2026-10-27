# Codebase map

labctl: command center for the home lab: reach, wake and control every host and its VMs over Tailscale (design: .cmos/plans/).

## Stack
- Go 1.27.1, module github.com/Bugslight8/labctl (go.mod:1-3). No dependencies yet.

## Commands (Makefile)
- check :4 = gofmt -l, go vet ./..., go test ./... (the cmos project check, .cmos/config.json "check").
- build :12 -> bin/labctl (git-ignored, .gitignore:1).

## Layout
- cmd/labctl/main.go: entry point; prints the version (:6-10).

## Predecessor
- Bash version: ../fabric/tools/mac/{labctl,common.sh,labcap,labwalk,labui} (one host, fabric-twin, over Tailscale SSH).
