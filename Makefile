# Rampart — Build System

CARGO = cargo
TARGET_DIR = target
GRADLE = ./gradlew

.PHONY: all build test check fmt clippy clean release
.PHONY: deny audit ebpf
.PHONY: plugins paper velocity
.PHONY: docker docker-build docker-up docker-down docker-logs
.PHONY: dash dash-dev dash-build
.PHONY: ci ci-full

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
	cd xdp && clang -O2 -target bpf -c xdp_filter.c -o xdp_filter.o 2>/dev/null || \
	echo "WARNING: clang+bpf not installed, skipping eBPF build"

ebpf-clean:
	rm -f xdp/xdp_filter.o

# --- Java Plugins ---

plugins:
	cd plugins && $(GRADLE) build

paper:
	cd plugins && $(GRADLE) :paper:build

velocity:
	cd plugins && $(GRADLE) :velocity:build

# --- Dashboard ---

dash-install:
	cd dashboard && npm ci

dash-dev:
	cd dashboard && npm run dev

dash-build:
	cd dashboard && npm run build

# --- Docker ---

docker-build: plugins
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

ci: checkstyle test build deny
	@echo "✓ CI passed"

ci-full: ci plugins dash-build
	@echo "✓ Full CI passed"
