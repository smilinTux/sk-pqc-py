# sk-pqc (Python) — light dev tasks. No native compile here: the ML-KEM leg's
# liboqs builds via the `pq`/`test` pip extras, everything else is pure-Python.
.PHONY: help test docs docs-deps

help:
	@echo "make test       - run the pytest suite"
	@echo "make docs       - build the HTML API reference into docs/api/ (pdoc)"
	@echo "make docs-deps  - pip install the docs toolchain (pdoc)"

test:
	python -m pytest tests -q

docs-deps:
	pip install pdoc

docs:
	scripts/build-api-docs.sh
