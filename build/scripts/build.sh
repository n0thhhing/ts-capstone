EXPORTED_FUNCTIONS=(
	malloc
	free
	cs_close
	cs_open
	cs_option
	cs_strerror
	cs_support
	cs_version
	cs_errno
	cs_free
	cs_malloc
	cs_disasm
	cs_disasm_iter
	cs_group_name
	cs_insn_group
	cs_insn_name
	cs_reg_name
	cs_reg_write
	cs_reg_read
	cs_regs_access
	cs_op_count
	cs_op_index
)
METHODS=(
	stringToNewUTF8
	#POINTER_SIZE
	addFunction
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
	#	-s MALLOC='emmalloc-memvalidate-verbose'
	#	-s ALLOW_TABLE_GROWTH
	#	--profiling
	#	-fvectorize
	#	-flto
	-O3
	-v
	--memory-init-file 0
)

emcc build/libcapstone.a ${EMSCRIPTEN_SETTINGS[*]} -o src/capstone.js
