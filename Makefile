.PHONY: build test clean

build:
	go build -trimpath -o ./bin/sakamichi-token-extractor ./cmd/sakamichi-token-extractor

test:
	go test ./...

clean:
	go clean
