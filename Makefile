SOURCE=src
PIPCOMPILE=pip-compile --generate-hashes --upgrade --extra-index-url https://pypi.sunet.se/simple

test:
	pytest --log-cli-level DEBUG

reformat:
	isort --line-width 120 --atomic --project auth_server $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

sync_deps: update_deps
	# Can't use pip-sync until https://github.com/jazzband/pip-tools/issues/1087 is resolved
	# pip-sync
	pip freeze | xargs pip uninstall -y || true
	pip install -r requirements.txt

dev_deps: sync_deps
	pip install -r dev_requirements.txt

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
