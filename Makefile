# Auth Center local gates for the UC-AUTH-001 bootstrap implementation.
GO ?= go
WIRE_PACKAGE := github.com/goforj/wire/cmd/wire@v1.2.0
override GOFLAGS += -buildvcs=false
export GOFLAGS

.PHONY: help
help:
	@echo "Auth Center targets:"
	@echo "  make generate      regenerate cmd/auth-center/wire_gen.go"
	@echo "  make api-generate  regenerate managed API Proto code"
	@echo "  make fmt-check     fail if any Go file is not gofmt-ed"
	@echo "  make build         compile all packages"
	@echo "  make test          run unit, contract and real-listener E2E tests"
	@echo "  make test-race     run the full suite with the race detector"
	@echo "  make vet           run go vet"
	@echo "  make wire-check    fail if wire_gen.go is stale"
	@echo "  make api-check     fail if generated API code drifted from Proto"
	@echo "  make check         run every local gate"
	@echo "  make run           start the native gRPC server"

.PHONY: generate
generate:
	$(GO) run $(WIRE_PACKAGE) gen ./cmd/auth-center

.PHONY: api-generate
api-generate:
	$(MAKE) -C api proto-gen

.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

.PHONY: build
build:
	$(GO) build ./...

.PHONY: test
test:
	$(GO) test ./...

.PHONY: test-race
test-race:
	$(GO) test -race ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: wire-check
wire-check:
	$(GO) run $(WIRE_PACKAGE) diff ./cmd/auth-center

.PHONY: api-check
api-check:
	$(MAKE) -C api proto-check

.PHONY: check
check: fmt-check build test vet wire-check api-check

.PHONY: run
run:
	$(GO) run ./cmd/auth-center
