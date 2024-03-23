EXPORTED_FUNCTIONS=(
	malloc
	free
	strlen
	strncpy
	cs_close
	cs_disasm
	cs_disasm_iter
	cs_errno
	cs_free
	cs_group_name
	cs_insn_group
	cs_insn_name
	cs_malloc
	cs_open
	cs_option
	cs_reg_name
	cs_strerror
	cs_support
	cs_version
)
METHODS=(
	cwrap
	ccall
	getValue
	setValue
	writeArrayToMemory
	UTF8ToString
)

METHODS=$(echo -n "${METHODS[*]}" | jq -cR 'split(" ")')
EXPORTED_FUNCTIONS=$(echo -n "${EXPORTED_FUNCTIONS[*]}" | jq -cR 'split(" ") | map("_" + .)')

EMSCRIPTEN_SETTINGS=(
	-s EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS
	-s EXPORTED_RUNTIME_METHODS=$METHODS
	-s EXPORT_NAME=LibCapstone
	-s WASM=0
	-s ALLOW_MEMORY_GROWTH=1
	-s MODULARIZE=1
	-s WASM_ASYNC_COMPILATION=0
	-s ASSERTIONS=0
	#   -fvectorize
	#	-flto
	-v
	-O2
	--memory-init-file 0
)

emcc build/libcapstone.a ${EMSCRIPTEN_SETTINGS[*]} -o src/capstone.js
