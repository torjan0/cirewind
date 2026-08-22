GO ?= go
GO_VERSION := $(shell awk '/^go / { print $$2; exit }' go.mod)
GO_TOOLCHAIN ?= go$(GO_VERSION)
GO_EXACT = GOTOOLCHAIN="$(GO_TOOLCHAIN)" $(GO)
BINARY ?= bin/cirewind
DEMO_OUT ?= demo-case
RELEASE_OUT ?=
RELEASE_TAG ?=
RELEASE_WORK_ROOT ?=
SPDX_VALIDATOR ?=
SPDX_TOOLS_VERSION ?=

.PHONY: build test vet race vuln licenses demo browser-audit safety-audit release release-test release-verify release-spdx release-workflow-audit preflight clean

build:
	mkdir -p "$(dir $(BINARY))"
	$(GO_EXACT) build -trimpath -o "$(BINARY)" ./cmd/cirewind

test:
	$(GO_EXACT) test ./...

vet:
	$(GO_EXACT) vet ./...

race:
	$(GO_EXACT) test -race ./...

vuln:
	GO_TOOLCHAIN="$(GO_TOOLCHAIN)" sh ./scripts/vulncheck.sh

licenses:
	$(GO_EXACT) test ./third_party/licenses

demo: build
	./scripts/demo.sh "$(DEMO_OUT)" "$(BINARY)"

browser-audit:
	sh ./scripts/browser-audit.sh

safety-audit:
	sh ./scripts/offline-safety-audit.sh

release:
	@test -n "$(RELEASE_OUT)" || { echo "RELEASE_OUT is required" >&2; exit 2; }
	@test -n "$(RELEASE_TAG)" || { echo "RELEASE_TAG=vSEMVER is required" >&2; exit 2; }
	CIREWIND_RELEASE_WORK_ROOT="$(RELEASE_WORK_ROOT)" sh ./scripts/release.sh "$(RELEASE_OUT)" "$(RELEASE_TAG)"

release-test:
	@test -n "$(RELEASE_WORK_ROOT)" || { echo "RELEASE_WORK_ROOT is required" >&2; exit 2; }
	sh ./scripts/test-release.sh "$(RELEASE_WORK_ROOT)"

release-verify:
	@test -n "$(RELEASE_OUT)" || { echo "RELEASE_OUT is required" >&2; exit 2; }
	CIREWIND_RELEASE_WORK_ROOT="$(RELEASE_WORK_ROOT)" sh ./scripts/verify-release.sh "$(RELEASE_OUT)"

release-spdx:
	@test -n "$(RELEASE_OUT)" || { echo "RELEASE_OUT is required" >&2; exit 2; }
	@test -n "$(SPDX_VALIDATOR)" || { echo "SPDX_VALIDATOR is required" >&2; exit 2; }
	@test -n "$(SPDX_TOOLS_VERSION)" || { echo "SPDX_TOOLS_VERSION is required" >&2; exit 2; }
	sh ./scripts/validate-release-spdx.sh "$(RELEASE_OUT)" "$(SPDX_VALIDATOR)" "$(SPDX_TOOLS_VERSION)"

release-workflow-audit:
	$(GO_EXACT) test ./internal/acceptance -run 'TestReleaseWorkflow|TestActionPins|TestCIUsesExactSixTarget|TestReleaseEnvironmentPolicy'

preflight:
	sh ./scripts/preflight.sh

clean:
	$(GO_EXACT) clean ./...
