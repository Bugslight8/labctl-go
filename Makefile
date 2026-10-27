.PHONY: check build test dist

# the project check (cmos runs it): formatting, vet, tests
check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	go test ./...

test:
	go test ./...

build:
	go build -o bin/labctl ./cmd/labctl

# one binary per platform the home lab runs: bin/labctl-<os>-<arch>
PLATFORMS = darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64
dist:
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -o bin/labctl-$$os-$$arch$$ext ./cmd/labctl || exit 1; \
	done; ls bin/
