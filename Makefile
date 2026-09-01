VERSION ?= dev

.PHONY: build test clean

build:
	go build -trimpath -ldflags="-X main.toolVersion=$(VERSION)" -o ./bin/sakamichi-token-extractor ./cmd/sakamichi-token-extractor

test:
	go test ./...

clean:
	go clean
