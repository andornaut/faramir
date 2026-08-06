PYTHON ?= python3
PREFIX ?= /usr/local

.PHONY: help test test-unit test-e2e check lint install install-accounts install-agent verify clean

help:
	@echo "make test            run the whole suite (needs sops + age)"
	@echo "make test-unit       everything that needs neither sops, age, nor privileges"
	@echo "make test-e2e        end-to-end against a real broker in a temp dir"
	@echo "make check           byte-compile + config validation + unit hardening score"
	@echo "make install         install the broker (root)"
	@echo "make verify          Phase 7 matrix against the live deployment (root)"

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

test-unit:
	$(PYTHON) -m unittest tests.test_redact tests.test_allowlist tests.test_protocol tests.test_config tests.test_secretstore tests.test_server tests.test_execserver tests.test_hook -v

test-e2e:
	$(PYTHON) -m unittest tests.test_e2e tests.test_keeper tests.test_exec tests.test_ssh -v

check:
	$(PYTHON) -m compileall -q src bin/faramir-broker bin/faramir bin/faramir-mcp bin/faramir-keeper bin/faramir-exec agent/hooks
	$(PYTHON) -c "import glob, sys, tomllib; sys.path.insert(0,'src'); \
	from faramir.config import Config; \
	[print('config OK:', p, '->', ', '.join(r.name for r in \
	  Config.from_dict(tomllib.load(open(p,'rb')), p).allow)) \
	 for p in ['etc/config.toml'] + sorted(glob.glob('etc/examples/*.toml'))]"
	@command -v systemd-analyze >/dev/null && \
	  systemd-analyze security --offline=true systemd/faramir-broker.service systemd/faramir-keeper.service systemd/faramir-exec.service | tail -3 || true

install:
	install/20-install-broker.sh

install-accounts:
	install/10-accounts.sh

install-agent:
	install/40-agent-config.sh

verify:
	tests/verify.sh

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf /tmp/faramir-e2e-*
