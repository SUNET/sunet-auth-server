SOURCE=src
UV=$(shell which uv)
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple

test:
	pytest --log-cli-level DEBUG

reformat:
	# sort imports and remove unused imports
	ruff check --select F401,I --fix
	# reformat
	ruff format
	# make an extended check with rules that might be triggered by reformat
	ruff check --config ruff-extended.toml

typecheck:
	mypy --install-types --non-interactive --pretty --ignore-missing-imports --warn-unused-ignores $(SOURCE)

sync_deps:
	$(PIPSYNC) requirements.txt

dev_sync_deps:
	$(PIPSYNC) dev_requirements.txt

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
