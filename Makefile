GO ?= go
LDFLAGS = -s -w

all:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o bin/labd ./cmd/labd
	CGO_ENABLED=0 $(GO) build -ldflags '$(LDFLAGS)' -o bin/lab ./cmd/lab
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o bin/lab-agent-linux-arm64 ./cmd/lab-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o bin/lab-linux-arm64 ./cmd/lab
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o bin/oobd-darwin-arm64 ./cmd/oobd
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o bin/lab-builder-darwin-arm64 ./cmd/lab-builder

test:
	$(GO) vet ./...
	$(GO) test -race ./...

.PHONY: all test

# Produces a private local install prefix. Never installs a service or contacts a Mac.
BOOT_TEST_OUT ?= dist/boot-test
boot-test-dist:
	test ! -e "$(BOOT_TEST_OUT)" || { echo "Refusing existing boot-test output prefix" >&2; exit 1; }
	mkdir -p "$(BOOT_TEST_OUT)/bin"
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$(BOOT_TEST_OUT)/bin/lab" ./cmd/lab
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$(BOOT_TEST_OUT)/bin/lab-workflow" ./cmd/lab-workflow
	python3 -E -B scripts/boot-test/bundle.py --output "$(BOOT_TEST_OUT)/frontend-resources.tar.gz"
	tar -xzf "$(BOOT_TEST_OUT)/frontend-resources.tar.gz" -C "$(BOOT_TEST_OUT)"

.PHONY: boot-test-dist
