# Nigg — common build/test/cross-compile shortcuts. POSIX make.
#
# Run `make ci` to replicate the CI gates locally (fmt-check + clippy + build + test).
# See docs/development.md for prerequisites and details.

CARGO      ?= cargo
WIN_TARGET  = x86_64-pc-windows-gnu
FIXTURES    = -p nigg-tests-fixtures

.PHONY: check build test clippy fmt fmt-check cross ci

check:
	$(CARGO) check --workspace

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

clippy:
	$(CARGO) clippy --workspace --all-targets

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# Cross-compile the test fixtures for x86_64-pc-windows-gnu.
cross:
	$(CARGO) build --target $(WIN_TARGET) $(FIXTURES)

# Replicate the CI gates locally (does not install system deps or cross-compile).
ci: fmt-check clippy build test
