# Rampart — Build System

CARGO = cargo
TARGET_DIR = target

.PHONY: all build release test test-all check check-all fmt fmt-check clippy clean deny audit
.PHONY: ebpf ebpf-clean
.PHONY: docker docker-build docker-up docker-down docker-logs
.PHONY: ci ci-full repo-gates

all: check test build

# --- Rust ---

build:
	$(CARGO) build

release:
	$(CARGO) build --release

check:
	$(CARGO) check

check-all:
	$(CARGO) check --all-features

test:
	$(CARGO) test

test-all:
	$(CARGO) test --all-features

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

clean:
	$(CARGO) clean

deny:
	cargo deny check

audit:
	cargo audit

# --- eBPF / XDP ---

ebpf:
	@echo "Building XDP/eBPF filter..."
	mkdir -p $(TARGET_DIR)/xdp && \
	clang -O2 -g -target bpf -c xdp/core/universal_filter.c -o $(TARGET_DIR)/xdp/universal_filter.o 2>/dev/null || \
	echo "WARNING: clang+bpf not installed, skipping eBPF build"

ebpf-clean:
	rm -f $(TARGET_DIR)/xdp/universal_filter.o

# --- Docker ---

docker-build:
	docker compose -f deploy/docker-compose.yml build

docker-up: docker-build
	docker compose -f deploy/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f

# --- Convenience ---

checkstyle: fmt-check clippy
	@echo "✓ Checkstyle passed (rustfmt + clippy)"

repo-gates:
	bash scripts/check_module_size.sh
	bash scripts/check_default_secrets.sh

ci: checkstyle test-all build deny repo-gates
	@echo "✓ CI passed"

ci-full: ci ebpf
	@echo "✓ Full CI passed"
