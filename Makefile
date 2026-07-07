PY := .venv/bin/python3
PIP := .venv/bin/pip

install:
	$(PIP) install -r requirements.txt

install-extras:
	-$(PIP) install -r requirements-extras.txt

test:
	$(PY) -m pytest

pipeline: install install-extras
	$(PY) scripts/run_pipeline.py --all

.PHONY: install install-extras test pipeline
