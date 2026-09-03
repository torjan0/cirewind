GO ?= go
GO_VERSION := $(shell awk '/^go / { print $$2; exit }' go.mod)
GO_TOOLCHAIN ?= go$(GO_VERSION)
GO_EXACT = GOTOOLCHAIN="$(GO_TOOLCHAIN)" $(GO)
PACK_REVIEW_HEAD ?= $(shell git rev-parse --verify HEAD)
BINARY ?= bin/cirewind
DEMO_OUT ?= demo-case
RELEASE_OUT ?=
RELEASE_TAG ?=
RELEASE_WORK_ROOT ?=
SPDX_VALIDATOR ?=
SPDX_TOOLS_VERSION ?=
PUBLIC_LAB_REQUIRE_ACTIONLINT ?= 0
PUBLIC_LAB_WORK_ROOT ?=

.PHONY: build test vet race vuln licenses demo browser-audit safety-audit public-lab-build public-lab-check public-lab-syscall-audit pack-review-check pack-review-clean release release-test release-verify release-spdx release-workflow-audit preflight clean go-install-check go-install-qualify go-install-public-check go-install-public-qualify

SITE_OUT ?=
SITE_VERSION ?=
README_VERSION ?= 0.2.0
BREW_WORK_ROOT ?=

.PHONY: build test vet race vuln licenses demo browser-audit safety-audit pack-review-check pack-review-clean release release-test release-verify release-spdx release-workflow-audit sample-site sample-site-check sample-site-browser-audit readme-candidate readme-candidate-check brew-formula-check preflight clean

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

public-lab-build:
	sh -n ./scripts/public-lab-artifacts.sh
	sh -n ./scripts/public-lab-marker-audit.sh
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" CIREWIND_PUBLIC_LAB_WORK_ROOT="$(PUBLIC_LAB_WORK_ROOT)" sh ./scripts/public-lab-artifacts.sh build

public-lab-check:
	sh -n ./scripts/public-lab-artifacts.sh
	sh -n ./scripts/public-lab-marker-audit.sh
	sh -n ./scripts/test-public-lab-artifacts.sh
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" CIREWIND_PUBLIC_LAB_WORK_ROOT="$(PUBLIC_LAB_WORK_ROOT)" CIREWIND_PUBLIC_LAB_REQUIRE_ACTIONLINT="$(PUBLIC_LAB_REQUIRE_ACTIONLINT)" sh ./scripts/public-lab-artifacts.sh check
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" sh ./scripts/test-public-lab-artifacts.sh

public-lab-syscall-audit:
	sh ./scripts/public-lab-marker-audit.sh

go-install-check:
	sh -n ./scripts/go-install-proxy.sh
	sh -n ./scripts/test-go-install-version.sh
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" sh ./scripts/test-go-install-version.sh

go-install-qualify:
	sh -n ./scripts/go-install-proxy.sh
	sh -n ./scripts/qualify-go-install.sh
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" sh ./scripts/qualify-go-install.sh

go-install-public-check:
	sh -n ./scripts/go-install-proxy.sh
	sh -n ./scripts/qualify-public-go-install.sh
	sh -n ./scripts/test-qualify-public-go-install.sh
	GO="$(GO)" GOTOOLCHAIN="$(GO_TOOLCHAIN)" sh ./scripts/test-qualify-public-go-install.sh

go-install-public-qualify:
	@test -n "$(GO_INSTALL_TAG)" || { echo "GO_INSTALL_TAG=vMAJOR.MINOR.PATCH is required" >&2; exit 2; }
	@test -n "$(GO_INSTALL_OUT)" || { echo "GO_INSTALL_OUT is required" >&2; exit 2; }
	sh -n ./scripts/qualify-public-go-install.sh
	GO="$(GO)" sh ./scripts/qualify-public-go-install.sh "$(GO_INSTALL_TAG)" "$(GO_INSTALL_OUT)"

pack-review-check:
	bash -n scripts/pack-review-git-guard.sh
	sh scripts/test-pack-review-git-guard.sh
	bash -n scripts/pack-review-candidate-change-guard.sh
	sh scripts/test-pack-review-candidate-change-guard.sh
	$(GO_EXACT) test ./internal/packreview ./tools/packreview ./internal/releaseartifact
	$(GO_EXACT) run ./tools/packreview validate-governance --repository-root .
	scripts/pack-review-git-guard.sh --repository-root . --expected-head "$(PACK_REVIEW_HEAD)" -- env GOTOOLCHAIN="$(GO_TOOLCHAIN)" $(GO) run ./tools/packreview validate-candidate-tree --repository-root . --candidate-commit "$(PACK_REVIEW_HEAD)"

pack-review-clean:
	git diff --exit-code
	git diff --cached --exit-code
	@test -z "$$(git ls-files --others --exclude-standard)" || { echo "untracked files are outside the reviewed Git state" >&2; exit 1; }

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
	$(GO_EXACT) test ./internal/acceptance -run 'TestReleaseWorkflow|TestActionPins|TestCIUsesExactSixTarget|TestCIDarwinArm64RunsNativeDemoQualification|TestReleaseEnvironmentPolicy'

sample-site:
	@test -n "$(SITE_OUT)" || { echo "SITE_OUT is required" >&2; exit 2; }
	@test -n "$(SITE_VERSION)" || { echo "SITE_VERSION=SEMVER without a v prefix is required" >&2; exit 2; }
	sh ./scripts/build-sample-site.sh "$(SITE_OUT)" "$(SITE_VERSION)"

sample-site-check:
	sh -n scripts/build-sample-site.sh
	sh -n scripts/test-sample-site.sh
	$(GO_EXACT) test ./internal/samplesite ./tools/samplesite
	sh ./scripts/test-sample-site.sh

sample-site-browser-audit:
	sh ./scripts/site-browser-audit.sh

readme-candidate:
	sh ./scripts/readme-candidate.sh "$(README_VERSION)"

readme-candidate-check:
	sh -n scripts/readme-candidate.sh
	sh ./scripts/readme-candidate.sh "$(README_VERSION)" --check

brew-formula-check:
	@test -n "$(BREW_WORK_ROOT)" || { echo "BREW_WORK_ROOT is required" >&2; exit 2; }
	sh -n scripts/test-brew-formula.sh
	sh ./scripts/test-brew-formula.sh "$(BREW_WORK_ROOT)"

preflight:
	sh ./scripts/preflight.sh

clean:
	$(GO_EXACT) clean ./...
