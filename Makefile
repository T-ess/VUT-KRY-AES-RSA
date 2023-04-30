SHELL := /bin/bash
build: requirements.txt
	python3 -m venv venv
	source venv/bin/activate
	./venv/bin/pip install -r requirements.txt
run:
	./venv/bin/python3 kry.py -port $(PORT) -$(TYPE)
clean:
	rm -rf venv