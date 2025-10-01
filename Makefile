.PHONY: install test sample report preview clean

install:
	python3 -m venv .venv || true
	. .venv/bin/activate && pip install --upgrade pip && pip install -e . && pip install -r requirements-dev.txt || true

test:
	. .venv/bin/activate && pytest -q

sample:
	. .venv/bin/activate && python -m webloghunter.cli --input samples/access.log --report-dir reports

report:
	. .venv/bin/activate && webloghunter --input samples/access.log --report-dir reports -c config.sample.yaml --top-talkers 5

preview:
	. .venv/bin/activate && webloghunter -i samples/access.log -o reports -c config.sample.yaml --top-talkers 5
	BROWSER_BIN=chromium ./tools/snap_report.sh || true

clean:
	rm -rf __pycache__ .pytest_cache .venv build dist *.egg-info reports/*
