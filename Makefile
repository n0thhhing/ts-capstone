.PHONY: format
format:
	prettier -w --ignore-unknown *
	shfmt -w build/scripts/build.sh compile.sh

.PHONY: build
build: build/libcapstone.a src/capstone.cpp
	sh build/scripts/build.sh

.PHONY: compile
compile:
	sh build/scripts/compile.sh

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Usage: make [format|build|compile]"
