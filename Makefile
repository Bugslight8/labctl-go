.PHONY: check build test

# the project check (cmos runs it): formatting, vet, tests
check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go vet ./...
	go test ./...

test:
	go test ./...

build:
	go build -o bin/labctl ./cmd/labctl
