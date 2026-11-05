.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
# Targets share generated output; serialize aggregate invocations even with -j.
.NOTPARALLEL:
.PHONY: check
check: ci-lint ci-test ## Run lint and tests without executing system audits
ifeq ($(OS),Windows_NT)
PYTHON ?= python
NPM ?= npm.cmd
COMPOSER ?= composer.cmd
else
PYTHON ?= python3
NPM ?= npm
COMPOSER ?= composer
endif
NODE ?= node
PHP ?= php
DOTNET ?= dotnet

RUNNER ?= common/runner.py
REPORT_DIR ?= reports
ARCHIVE_DIR ?= reports/archive
TIMESTAMP = $(shell "$(PYTHON)" -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S'))")
REPORT_BASE = $(REPORT_DIR)/cyberswiss_$(TIMESTAMP)
SCRIPTS ?=
MIN_SEV ?= Info
DELAY ?= 0
TAG ?=
BASELINE ?= ci/baseline.json
TREND ?= 10
KEEP ?= 50
SCAN_ID ?=
ALLOW_FIX ?=
CONFIRM_DB_DELETE ?=
CONFIRM_REPORT_DELETE ?=
SHELLCHECK ?= shellcheck
_VERBOSE = $(if $(filter 1,$(VERBOSE)),--verbose,)

.PHONY: help help-dev check-python check-runner check-env install install-all scan scan-linux scan-windows scan-high scan-critical scan-sev scan-dry scan-fix scan-id scan-tag scan-delay report report-db report-diff report-sarif report-trend baseline baseline-show scan-baselined archive archive-clean clean clean-reports clean-all db-list db-show db-prune db-clean upgrade format format-check test test-cov test-fast test-verbose check-lint-tools lint-python lint-shell lint-pylint lint ci-lint ci-test ci-scan ci dev build package security

help: ## Show commands; defaults never install, build, bump or deploy
	@echo "CyberSWISS-Cybersecurity-Scan-Win-Linux - local development commands"
	@echo "  help-dev                Show the complete command help including developer checks"
	@echo "  check-python            Check the selected Python is at least 3.8"
	@echo "  check-runner            Check the local runner file exists"
	@echo "  check-env               Check Python, runner and the current OS script runner"
	@echo "  install                 Install the declared Python development requirements"
	@echo "  install-all             Explicitly run the OS-level Linux installer after Python install"
	@echo "  scan                    Run current-OS audits; propagate findings/failures"
	@echo "  scan-linux              Run Linux audits; propagate the runner exit code"
	@echo "  scan-windows            Run Windows audits; propagate the runner exit code"
	@echo "  scan-high               Report High and Critical findings"
	@echo "  scan-critical           Report Critical findings"
	@echo "  scan-sev                Use the explicit MIN_SEV severity filter"
	@echo "  scan-dry                List applicable audits without executing any system checks"
	@echo "  scan-fix                Explicit remediation requires ALLOW_FIX=1; failures propagate"
	@echo "  scan-id                 Run explicit space-separated SCRIPTS IDs"
	@echo "  scan-tag                Run scripts carrying TAG"
	@echo "  scan-delay              Run rate-limited audits with DELAY seconds"
	@echo "  report                  Write JSON/CSV/HTML reports; preserve nonzero finding exit status"
	@echo "  report-db               Write reports and explicitly store/diff the scan history"
	@echo "  report-diff             Read stored drift without running system checks"
	@echo "  report-sarif            Write SARIF/Markdown and propagate finding failures"
	@echo "  report-trend            Read TREND stored history entries without rescanning"
	@echo "  baseline                Explicitly record accepted-risk baseline; retain runner status"
	@echo "  baseline-show           Read the explicitly configured baseline"
	@echo "  scan-baselined          Explicitly apply the configured user baseline"
	@echo "  archive                 Archive generated report files only"
	@echo "  archive-clean           Delete only generated archive ZIPs older than 30 days"
	@echo "  clean                   Remove owned untracked caches/distribution outputs only"
	@echo "  clean-reports           Delete generated report files only with CONFIRM_REPORT_DELETE=1"
	@echo "  clean-all               Compatibility cleanup keeps scan reports, archives and database"
	@echo "  db-list                 Read the 20 most recent stored scans"
	@echo "  db-show                 Read explicit SCAN_ID from local history"
	@echo "  db-prune                Explicitly keep KEEP stored scans"
	@echo "  db-clean                Delete only reports/cyberswiss.db with CONFIRM_DB_DELETE=1"
	@echo "  upgrade                 Explicitly upgrade only packages declared by this project"
	@echo "  format                  Explicitly run installed Black and isort; never silently skip"
	@echo "  format-check            Check formatting without writing sources"
	@echo "  test                    Run the Python suite with the configured interpreter"
	@echo "  test-cov                Run Python coverage and write only reports/coverage"
	@echo "  test-fast               Run tests and stop at the first failure"
	@echo "  test-verbose            Run tests with verbose captured output"
	@echo "  check-lint-tools        Require the same Python lint tools used by CI"
	@echo "  lint-python             Run the canonical flake8 source/test/collector scope"
	@echo "  lint-shell              Run ShellCheck on Linux scripts and shared JSON helpers"
	@echo "  lint-pylint             Run the canonical CI pylint gate; propagate failure"
	@echo "  lint                    Run all required Python and shell lint checks"
	@echo "  ci-lint                 Compatibility alias for the complete lint gate"
	@echo "  ci-test                 Compatibility alias for tests"
	@echo "  ci-scan                 List scripts only; CI never performs a system scan"
	@echo "  ci                      Run lint, tests and a non-executing scan listing in order"
	@echo "  dev                     Run the optional Flask API (requires its documented dependency)"
	@echo "  build                   Compile-check the Python modules without performing audits"
	@echo "  package                 Archive committed source to dist/cyberswiss-source.zip"
	@echo "  security                Audit declared Python dependencies without accepted-risk suppression"
	@echo "Override executable paths with PYTHON, NODE, NPM, PHP, COMPOSER or DOTNET. Run from the repository root."

help-dev: help ## Show the complete command help including developer checks

check-python: ## Check the selected Python is at least 3.8
	"$(PYTHON)" -c "import sys; print(sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3,8) else 1)"

check-runner: ## Check the local runner file exists
	"$(PYTHON)" tools/make_support.py require "$(RUNNER)"

check-env: check-python check-runner ## Check Python, runner and the current OS script runner
	"$(PYTHON)" tools/make_runtime.py check-env

install: check-python ## Install the declared Python development requirements
	"$(PYTHON)" -m pip install -r requirements.txt

install-all: install ## Explicitly run the OS-level Linux installer after Python install
	"$(PYTHON)" tools/make_runtime.py install-runtime

scan: check-python check-runner ## Run current-OS audits; propagate findings/failures
	"$(PYTHON)" "$(RUNNER)" $(_VERBOSE)

scan-linux: check-python check-runner ## Run Linux audits; propagate the runner exit code
	"$(PYTHON)" "$(RUNNER)" --os linux $(_VERBOSE)

scan-windows: check-python check-runner ## Run Windows audits; propagate the runner exit code
	"$(PYTHON)" "$(RUNNER)" --os windows $(_VERBOSE)

scan-high: check-python check-runner ## Report High and Critical findings
	"$(PYTHON)" "$(RUNNER)" --min-severity High $(_VERBOSE)

scan-critical: check-python check-runner ## Report Critical findings
	"$(PYTHON)" "$(RUNNER)" --min-severity Critical $(_VERBOSE)

scan-sev: check-python check-runner ## Use the explicit MIN_SEV severity filter
	"$(PYTHON)" "$(RUNNER)" --min-severity "$(MIN_SEV)" $(_VERBOSE)

scan-dry: check-python check-runner ## List applicable audits without executing any system checks
	"$(PYTHON)" "$(RUNNER)" --dry-run

scan-fix: check-python check-runner ## Explicit remediation requires ALLOW_FIX=1; failures propagate
	"$(PYTHON)" tools/make_runtime.py confirm "$(ALLOW_FIX)"
	"$(PYTHON)" "$(RUNNER)" --fix $(_VERBOSE)

scan-id: check-python check-runner ## Run explicit space-separated SCRIPTS IDs
	"$(PYTHON)" tools/make_runtime.py scan-ids "$(SCRIPTS)" $(_VERBOSE)

scan-tag: check-python check-runner ## Run scripts carrying TAG
	"$(PYTHON)" "$(RUNNER)" --tag "$(TAG)" $(_VERBOSE)

scan-delay: check-python check-runner ## Run rate-limited audits with DELAY seconds
	"$(PYTHON)" "$(RUNNER)" --delay "$(DELAY)" $(_VERBOSE)

report: check-python check-runner ## Write JSON/CSV/HTML reports; preserve nonzero finding exit status
	"$(PYTHON)" tools/make_support.py mkdir "$(REPORT_DIR)"
	"$(PYTHON)" "$(RUNNER)" $(_VERBOSE) --output "$(REPORT_BASE).json" --csv "$(REPORT_BASE).csv" --html "$(REPORT_BASE).html"

report-db: check-python check-runner ## Write reports and explicitly store/diff the scan history
	"$(PYTHON)" tools/make_support.py mkdir "$(REPORT_DIR)"
	"$(PYTHON)" "$(RUNNER)" $(_VERBOSE) --output "$(REPORT_BASE).json" --csv "$(REPORT_BASE).csv" --html "$(REPORT_BASE).html" --save-db --diff

report-diff: check-python check-runner ## Read stored drift without running system checks
	"$(PYTHON)" "$(RUNNER)" --diff --dry-run $(_VERBOSE)

report-sarif: check-python check-runner ## Write SARIF/Markdown and propagate finding failures
	"$(PYTHON)" tools/make_support.py mkdir "$(REPORT_DIR)"
	"$(PYTHON)" "$(RUNNER)" $(_VERBOSE) --sarif "$(REPORT_BASE).sarif" --markdown "$(REPORT_BASE).md"

report-trend: check-python check-runner ## Read TREND stored history entries without rescanning
	"$(PYTHON)" "$(RUNNER)" --trend "$(TREND)" --dry-run $(_VERBOSE)

baseline: check-python check-runner ## Explicitly record accepted-risk baseline; retain runner status
	"$(PYTHON)" "$(RUNNER)" --write-baseline "$(BASELINE)" $(_VERBOSE)

baseline-show: check-python ## Read the explicitly configured baseline
	"$(PYTHON)" common/baseline.py show "$(BASELINE)"

scan-baselined: check-python check-runner ## Explicitly apply the configured user baseline
	"$(PYTHON)" "$(RUNNER)" --baseline "$(BASELINE)" $(_VERBOSE)

archive: ## Archive generated report files only
	"$(PYTHON)" tools/make_runtime.py archive "$(REPORT_DIR)" "$(ARCHIVE_DIR)"

archive-clean: ## Delete only generated archive ZIPs older than 30 days
	"$(PYTHON)" tools/make_runtime.py archive-clean "$(ARCHIVE_DIR)"

clean: ## Remove owned untracked caches/distribution outputs only
	"$(PYTHON)" tools/make_support.py clean ".pytest_cache" "dist" "__pycache__" "common/__pycache__" "tests/__pycache__" "ci/__pycache__"

clean-reports: ## Delete generated report files only with CONFIRM_REPORT_DELETE=1
	"$(PYTHON)" tools/make_runtime.py confirm "$(CONFIRM_REPORT_DELETE)"
	"$(PYTHON)" tools/make_runtime.py clean-reports "$(REPORT_DIR)"

clean-all: clean ## Compatibility cleanup keeps scan reports, archives and database

db-list: check-python ## Read the 20 most recent stored scans
	"$(PYTHON)" common/db.py list --limit 20

db-show: check-python ## Read explicit SCAN_ID from local history
	"$(PYTHON)" tools/make_runtime.py require-value "$(SCAN_ID)"
	"$(PYTHON)" common/db.py show "$(SCAN_ID)"

db-prune: check-python ## Explicitly keep KEEP stored scans
	"$(PYTHON)" common/db.py prune --keep "$(KEEP)"

db-clean: ## Delete only reports/cyberswiss.db with CONFIRM_DB_DELETE=1
	"$(PYTHON)" tools/make_runtime.py confirm "$(CONFIRM_DB_DELETE)"
	"$(PYTHON)" tools/make_runtime.py db-clean

upgrade: check-python ## Explicitly upgrade only packages declared by this project
	"$(PYTHON)" -m pip install --upgrade -r requirements.txt

format: check-python ## Explicitly run installed Black and isort; never silently skip
	"$(PYTHON)" -m black common tests
	"$(PYTHON)" -m isort common tests

format-check: check-python ## Check formatting without writing sources
	"$(PYTHON)" -m black --check common tests
	"$(PYTHON)" -m isort --check-only common tests

test: check-python ## Run the Python suite with the configured interpreter
	"$(PYTHON)" -m pytest tests -v

test-cov: check-python ## Run Python coverage and write only reports/coverage
	"$(PYTHON)" -m pytest tests -v --cov=common --cov-report=term-missing --cov-report=html:reports/coverage

test-fast: check-python ## Run tests and stop at the first failure
	"$(PYTHON)" -m pytest tests -x -q

test-verbose: check-python ## Run tests with verbose captured output
	"$(PYTHON)" -m pytest tests -v -s

check-lint-tools: check-python ## Require the same Python lint tools used by CI
	"$(PYTHON)" -c "import flake8,pylint"

lint-python: check-lint-tools ## Run the canonical flake8 source/test/collector scope
	"$(PYTHON)" -m flake8 common tests ci/collect_audit.py

lint-shell: ## Run ShellCheck on Linux scripts and shared JSON helpers
	"$(PYTHON)" tools/make_runtime.py shell-lint "$(SHELLCHECK)"

lint-pylint: check-lint-tools ## Run the canonical CI pylint gate; propagate failure
	"$(PYTHON)" -m pylint common --disable=C0114,C0115,C0116,R0903,W0611,R0801 --fail-under=8.0

lint: ## Run all required Python and shell lint checks
	"$(MAKE)" lint-python lint-shell lint-pylint

ci-lint: lint ## Compatibility alias for the complete lint gate

ci-test: test ## Compatibility alias for tests

ci-scan: scan-dry ## List scripts only; CI never performs a system scan

ci: ## Run lint, tests and a non-executing scan listing in order
	"$(MAKE)" ci-lint
	"$(MAKE)" ci-test
	"$(MAKE)" ci-scan

dev: ## Run the optional Flask API (requires its documented dependency)
	"$(PYTHON)" common/api.py

build: ## Compile-check the Python modules without performing audits
	"$(PYTHON)" -m compileall -q common

package: build ## Archive committed source to dist/cyberswiss-source.zip
	"$(PYTHON)" tools/make_support.py source-zip "dist/cyberswiss-source.zip"

security: ## Audit declared Python dependencies without accepted-risk suppression
	"$(PYTHON)" -m pip_audit -r requirements.txt
