.PHONY: test

test:
	pytest -v tests/
	python scripts/verify_no_polling.py
