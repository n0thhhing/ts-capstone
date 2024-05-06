#!/usr/bin/env bash

set -eu

CURRENT_DIR=$(realpath .)
CAPSTONE_DIR=capstone

ARCHS=(
	ARM
	ARM64
	MIPS
	PPC
	SPARC
	M68K
	M680X
	SYSZ
	XCORE
	X86
	EVM
	TMS320C64X
	MOS65XX
	BPF
	RISCV
	WASM
	SH
)

BUILD_FLAGS=(
	-D CAPSTONE_BUILD_TESTS=OFF
	-D CAPSTONE_BUILD_SHARED=OFF
	-D CMAKE_C_FLAGS="-Wno-warn-absolute-paths"
	-D CMAKE_BUILD_TYPE=Release
)

for ARCH in "${ARCHS[@]}"; do
	BUILD_FLAGS+=(
		-DCAPSTONE_${ARCH}_SUPPORT=ON
	)
done

cd $CAPSTONE_DIR

CACHE=CMakeCache.txt
if [ -f build/$CACHE ]; then
	rm build/$CACHE
fi

emcmake cmake -B build ${BUILD_FLAGS[*]}

cd build
cmake --build . -j
mv libcapstone.a $CURRENT_DIR/build

# irrelevant
: <<'END_COMMENT'
EXPORTED_CONSTANTS=(
	'bindings/python/capstone/arm64_const.py'
	'bindings/python/capstone/tms320c64x_const.py'
	'bindings/python/capstone/arm_const.py'
	'bindings/python/capstone/m68k_const.py'
	'bindings/python/capstone/m680x_const.py'
	'bindings/python/capstone/mips_const.py'
	'bindings/python/capstone/ppc_const.py'
	'bindings/python/capstone/sparc_const.py'
	'bindings/python/capstone/sysz_const.py'
	'bindings/python/capstone/x86_const.py'
	'bindings/python/capstone/xcore_const.py'
	'bindings/python/capstone/evm_const.py'
	'bindings/python/capstone/mos65xx_const.py'
	'bindings/python/capstone/riscv_const.py'
	'bindings/python/capstone/tricore_const.py'
	'bindings/python/capstone/bpf_const.py'
	'bindings/python/capstone/wasm_const.py'
)

combine_files() {
	if [ $# -lt 2 ]; then
		echo "Usage: combine_files <array_of_paths> <output_file>"
		return 1
	fi
	file_paths=("${!1}")
	output_file=$2
	temp_file=$(mktemp)
	echo '' >"$temp_file"
	cat "${file_paths[@]}" >>"$temp_file"
	mv "$temp_file" "$output_file"
	echo "Files combined successfully into $output_file"
}

FILES=(
	'src/constants/evm_const.ts'
	'src/constants/mos65xx_const.ts'
	'src/constants/sysz_const.ts'
	'src/constants/x86_const.ts'
	'src/constants/arm64_const.ts'
	'src/constants/m680x_const.ts'
	'src/constants/ppc_const.ts'
	'src/constants/tms320c64x_const.ts'
	'src/constants/xcore_const.ts'
	'src/constants/arm_const.ts'
	'src/constants/m68k_const.ts'
	'src/constants/riscv_const.ts'
	'src/constants/tricore_const.ts'
	'src/constants/bpf_const.ts'
	'src/constants/mips_const.ts'
	'src/constants/sparc_const.ts'
	'src/constants/wasm_const.ts'
)
for filePath in "${EXPORTED_CONSTANTS[@]}"; do
	fileName=$(basename "$filePath" .py)
	OUT_FILE="$CURRENT_DIR/src/constants/$fileName.ts"
	fullPath="$CURRENT_DIR/$CAPSTONE_DIR/$filePath"
	code=$(sed -E 's/^([^#[:blank:]]+)/export const \1/g; s/^(.* = [A-Za-z_])/\/\/ \1/g; s/#/\/\//g; s/.*from.*//g' "$fullPath")
	echo "$code" >"$OUT_FILE"
done

cd $CURRENT_DIR

combine_files FILES[@] src/constants/all_const.js || echo "Error: Unable to combine files"
END_COMMENT
