GO ?= go
BIN := bin/portwhy
PKG := github.com/atop0914/portwhy
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "")
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo "")
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: all
all: fmt-check vet test build-check

.PHONY: fmt
fmt:
	gofmt -s -w $(shell find . -name '*.go' -not -path './bin/*')

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -s -l $$(find . -name '*.go' -not -path './bin/*')); \
	if [ -n "$$out" ]; then echo "UNFORMATTED:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test -count=1 ./...

# A skipped test proves nothing, and this project's value rests entirely on
# assertions that can fail. On a non-Linux host every kernel test skips, which
# must be loud rather than quietly green.
.PHONY: test-noskip
test-noskip:
	@out=$$($(GO) test -count=1 -v ./... 2>&1); \
	echo "$$out" | grep -E '^(ok|FAIL|---)' | tail -10; \
	n=$$(echo "$$out" | grep -c -- '--- SKIP' || true); \
	echo "SKIP=$$n"; \
	if [ "$$n" -ne 0 ]; then echo "skipped tests are not allowed"; exit 1; fi; \
	if echo "$$out" | grep -q -- '--- FAIL'; then exit 1; fi

.PHONY: race
race:
	$(GO) test -count=1 -race -timeout 300s ./...

# A fuzz run finds inputs by chance, so a green run says nothing about what it did
# not try — which is why this is not part of `ci`. The deterministic part is the
# corpus: every file under internal/procnet/testdata/fuzz/<Target>/ is replayed by
# an ordinary `go test`, so an input the fuzzer once found cannot come back without
# the suite going red. When a run does fail, commit the file it wrote.
FUZZTIME ?= 10s
.PHONY: fuzz
fuzz:
	@for t in FuzzParse FuzzDecodeAddr; do \
		echo "--- procnet/$$t $(FUZZTIME)"; \
		$(GO) test -run=^$$ -fuzz=^$$t$$ -fuzztime=$(FUZZTIME) ./internal/procnet/ || exit 1; \
	done

.PHONY: build
build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/portwhy

# Zero dependencies is a promise to the machine this runs on: a diagnostic tool
# gets run on broken hosts, where a module download is not available.
.PHONY: deps-check
deps-check:
	@n=$$($(GO) list -m all | wc -l); echo "modules=$$n"; \
	if [ "$$n" -ne 1 ]; then echo "runtime dependencies are not allowed"; exit 1; fi

# Every platform must compile, and the two that cannot read /proc/net must say
# so at runtime instead of reporting an empty result that reads as "free".
.PHONY: build-check
build-check:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -o /dev/null ./cmd/portwhy || exit 1; \
	done
	@echo "vet darwin (catches build-tag rot on the other unix)"
	@GOOS=darwin GOARCH=arm64 $(GO) vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

# The documents are checked by internal/docs, and its tests already run as part of
# `test`. This target is a name for that gate, not a second implementation of it:
# when it fails you want the broken claim without the noise of the other 500
# tests. It fails closed — a missing README or an empty docs/ is an error.
.PHONY: docs-check
docs-check:
	$(GO) test -count=1 -run 'TestRepositoryDocuments|TestCheck' ./internal/docs/

.PHONY: ci
ci: fmt-check vet test-noskip race deps-check build-check docs-check readme lint

# Every command the README prints, executed once, with the exit code as the
# assertion. It builds its own binary and binds its own sockets, so it is honest
# about a machine it has never seen — see the header of the script.
.PHONY: readme
readme:
	bash scripts/readme-rehearsal.sh

.PHONY: clean
clean:
	rm -rf bin
