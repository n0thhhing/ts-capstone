.PHONY: format
format:
	-rm **/*bak
	prettier -w --ignore-unknown *
	shfmt -w build/scripts/*.sh

.PHONY: build
build: build/libcapstone.a
	sh build/scripts/build.sh

.PHONY: compile
compile:
	sh build/scripts/compile.sh

.PHONY: bundle
bundle: src/wrapper.ts src/capstone.js
	bun build/scripts/bundle.ts

.PHONY: type
type:
	-tsc src/wrapper.ts src/memory.ts src/structures.ts --downlevelIteration true --declaration --outDir src --emitDeclarationOnly --allowJs true --esModuleInterop true
	bun build/scripts/declare.ts

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Usage: make [format|build|compile]"
