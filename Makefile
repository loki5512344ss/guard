# Rampart — Build System

CARGO = cargo
TARGET_DIR = target
GRADLE = gradle

.PHONY: all build test check fmt clippy clean release plugins

all: check test build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

check:
	$(CARGO) check

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy -- -D warnings

clean:
	$(CARGO) clean

plugins:
	cd plugins && ./gradlew build

docker-build: plugins
	docker compose -f deploy/docker-compose.yml build

docker-up: docker-build
	docker compose -f deploy/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f

# Full checkstyle (analog of Java's checkstyle + PMD + spotbugs)
checkstyle: fmt-check clippy
	@echo "✓ Checkstyle passed (rustfmt + clippy)"

ci: checkstyle test build
