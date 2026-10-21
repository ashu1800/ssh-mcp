# Thin wrappers around scripts/dev.py.
#
# The logic lives in Python so it behaves the same on Windows (where make is
# often absent) and on Linux/macOS. On Windows without GNU make, use the
# underlying command directly: python scripts/dev.py <target>
#
#   make dev      first-time setup: venv, deps, src/ on the import path
#   make install  refresh deps after pulling
#   make test     run the suite against src/
#   make doctor   report which code is live and what is stale
#   make serve    run the MCP server from src/
#   make clean    remove build artefacts and caches

PYTHON ?= python
DEV := $(PYTHON) scripts/dev.py

.PHONY: dev setup install test doctor serve clean help

help:
	@echo "make dev      first-time setup (venv + deps + src/ on path)"
	@echo "make install  refresh dependencies"
	@echo "make test     run tests against src/"
	@echo "make doctor   check the environment"
	@echo "make serve    run the server from src/"
	@echo "make clean    remove build artefacts"

dev:
	$(DEV) setup

setup: dev

install:
	$(DEV) install

test:
	$(DEV) test $(ARGS)

doctor:
	$(DEV) doctor

serve:
	$(DEV) serve $(if $(TRANSPORT),--transport $(TRANSPORT),)

clean:
	$(DEV) clean
