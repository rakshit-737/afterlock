PY ?= .venv/bin/python

.PHONY: bootstrap lint type test differential verify fixtures bench demo api doctor

bootstrap:
	./scripts/bootstrap

lint:
	$(PY) -m ruff check packages services tests datasets benchmarks

type:
	$(PY) -m mypy

test:
	$(PY) -m pytest -q

differential:
	AFTERLOCK_DIFFERENTIAL_EXAMPLES=1000 $(PY) -m pytest -q tests/differential

fixtures:
	$(PY) datasets/generators/build_semantic_cases.py

bench:
	$(PY) benchmarks/run.py

verify:
	./scripts/verify

doctor:
	$(PY) scripts/doctor --profile replay

demo:
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock replay import datasets/replay/residual-token
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock analyze --case residual-token
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock explain --latest
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock verify --latest
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock analyze --case residual-token --remediation datasets/fixtures/targeted-plan.json
	AFTERLOCK_HOME=.afterlock-demo .venv/bin/afterlock explain --latest

api:
	$(PY) -m uvicorn afterlock_api.app:app --host 127.0.0.1 --port 8080
