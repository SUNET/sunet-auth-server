SOURCE=src
UV=$(shell which uv)
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple

test:
	pytest --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project auth_server $(SOURCE)
	black --line-length 120 --target-version py311 $(SOURCE)

typecheck:
	mypy --install-types --non-interactive --pretty --ignore-missing-imports --warn-unused-ignores $(SOURCE)

sync_deps:
	$(PIPSYNC) requirements.txt

dev_sync_deps:
	$(PIPSYNC) dev_requirements.txt

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
