# This package is a fork of golang.org/x/crypto/argon2 whose only local addition
# is argon2d.go (exporting DKey). Every file listed in UPSTREAM_FILES is a
# verbatim copy of upstream and must never be edited by hand: run `make update`
# to pull in the newest upstream code instead.

UPSTREAM_MODULE  := golang.org/x/crypto
UPSTREAM_PKG     := argon2
UPSTREAM_VERSION ?= latest
UPSTREAM_FILES   := \
	argon2.go \
	argon2_test.go \
	blake2b.go \
	blamka_amd64.go \
	blamka_amd64.s \
	blamka_generic.go \
	blamka_ref.go

.PHONY: all help update diff-upstream test vet tidy

all: vet test

help:
	@echo "make update        - copy the newest upstream sources into this fork, then tidy and test"
	@echo "                     (pin a version with: make update UPSTREAM_VERSION=v0.54.0)"
	@echo "make diff-upstream - show how the local copies differ from upstream"
	@echo "make test          - run the test suite"
	@echo "make vet           - run go vet"
	@echo "make tidy          - run go mod tidy"

update:
	@set -eu; \
	json=$$(go mod download -json $(UPSTREAM_MODULE)@$(UPSTREAM_VERSION)); \
	dir=$$(printf '%s\n' "$$json" | sed -n 's/.*"Dir": "\([^"]*\)".*/\1/p'); \
	version=$$(printf '%s\n' "$$json" | sed -n 's/.*"Version": "\([^"]*\)".*/\1/p'); \
	src="$$dir/$(UPSTREAM_PKG)"; \
	test -d "$$src" || { echo "upstream package not found: $$src" >&2; exit 1; }; \
	echo "==> syncing from $(UPSTREAM_MODULE)/$(UPSTREAM_PKG)@$$version"; \
	for f in $$(cd "$$src" && ls); do \
		case " $(UPSTREAM_FILES) " in \
			*" $$f "*) ;; \
			*) echo "    WARNING: untracked upstream file $$f - add it to UPSTREAM_FILES if it belongs in the fork" >&2 ;; \
		esac; \
	done; \
	for f in $(UPSTREAM_FILES); do \
		test -f "$$src/$$f" || { echo "    ERROR: $$f no longer exists upstream - drop it from UPSTREAM_FILES" >&2; exit 1; }; \
		cp "$$src/$$f" "$$f"; \
		chmod u+w "$$f"; \
		echo "    copied $$f"; \
	done; \
	go get $(UPSTREAM_MODULE)@$$version
	@$(MAKE) tidy test

diff-upstream:
	@set -eu; \
	json=$$(go mod download -json $(UPSTREAM_MODULE)@$(UPSTREAM_VERSION)); \
	dir=$$(printf '%s\n' "$$json" | sed -n 's/.*"Dir": "\([^"]*\)".*/\1/p'); \
	version=$$(printf '%s\n' "$$json" | sed -n 's/.*"Version": "\([^"]*\)".*/\1/p'); \
	src="$$dir/$(UPSTREAM_PKG)"; \
	echo "==> comparing against $(UPSTREAM_MODULE)/$(UPSTREAM_PKG)@$$version"; \
	drift=0; \
	for f in $(UPSTREAM_FILES); do \
		diff -u "$$src/$$f" "$$f" || drift=1; \
	done; \
	if [ "$$drift" -eq 0 ]; then echo "==> up to date"; else echo "==> differences found, run: make update"; fi

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy
