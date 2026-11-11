.PHONY: build test integration check

build:
	go build -trimpath -o bin/pug ./cmd/pug

test:
	go test -race ./...

integration:
	go test -tags=integration -count=1 -timeout=15m ./...

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test -race ./...
