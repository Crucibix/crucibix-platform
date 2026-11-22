.PHONY: install lint type test check
install:
	pip install -e ".[dev]"
lint:
	ruff check src tests
type:
	mypy src
test:
	pytest -q
check: lint type test  ## the local gate
