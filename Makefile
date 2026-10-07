MODULE  := github.com/atsvetko/directory-auditor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo local)
DATE    ?= $(shell date -u +%Y-%m-%d)
LDFLAGS := -buildid= -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(DATE)
TARGETS := linux/amd64 linux/arm64 windows/amd64 darwin/arm64

.PHONY: all build test lint release readonly synth clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dirauditor ./cmd/dirauditor

test:
	go test -race -count=1 ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

release:
	@mkdir -p dist
	@for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dirauditor-$$os-$$arch$$ext ./cmd/dirauditor || exit 1; \
	done
	@cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS

readonly: release
	scripts/readonly-check.sh dist/dirauditor-linux-amd64

synth:
	go run ./tools/mksynth

clean:
	rm -rf dist dirauditor dirauditor.exe out dirauditor-out
