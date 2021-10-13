SOURCE=src
PYTHON=$(shell which python)
PIPCOMPILE=pip-compile --generate-hashes --upgrade --extra-index-url https://pypi.sunet.se/simple
PIPSYNC=pip-sync --index-url https://pypi.sunet.se/simple --python-executable $(PYTHON)

test:
	pytest --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project auth_server $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

sync_deps:
	$(PIPSYNC) requirements.txt

dev_sync_deps:
	$(PIPSYNC) dev_requirements.txt

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
