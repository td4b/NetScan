
SHELL := /bin/bash

setup:
	echo "[*] Setting up Virtualenv and Build Deps."
	python3 -m virtualenv --python=python3 venv
	source venv/bin/activate . && \
	pip3 install maturin

clean:
	rm -rf bin/
	rm -rf $(PWD)/target/wheels/*
	mkdir bin

build:
	echo "[*] Building Project."
	source venv/bin/activate . && \
	make clean && \
	maturin build -- && \
	cp ./target/wheels/*.whl ./bin/. 
	echo "[*] Wheels Library Available in bin."
