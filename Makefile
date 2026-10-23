.PHONY: lint lint-fix test build clean security ci release dry-release

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

test:
	go test -race ./...

build:
	go build -trimpath ./...

clean:
	go clean
	rm -rf dist

security:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

ci: lint test security

release:
	goreleaser release --clean

dry-release:
	goreleaser release --snapshot --clean
