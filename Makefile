.PHONY: format
format:
	prettier -w --ignore-unknown *
	shfmt -w build/scripts/build.sh build/scripts/compile.sh

.PHONY: build
build: build/libcapstone.a
	sh build/scripts/build.sh

.PHONY: compile
compile:
	sh build/scripts/compile.sh

.PHONY: bundle
bundle: src/wrapper.ts build/capstone.js src/constants.js
	bun build/scripts/bundle.ts

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Usage: make [format|build|compile]"
