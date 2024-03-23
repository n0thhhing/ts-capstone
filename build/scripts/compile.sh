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
	SYSZ
	XCORE
	X86
)

BUILD_FLAGS=(
	-DCAPSTONE_BUILD_TESTS=OFF
	-DCAPSTONE_BUILD_SHARED=OFF
	-DCMAKE_C_FLAGS="-Wno-warn-absolute-paths"
	-DCMAKE_BUILD_TYPE=Release
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

EXPORTED_CONSTANTS=(
	'bindings/python/capstone/arm64_const.py'
	'bindings/python/capstone/arm_const.py'
	'bindings/python/capstone/mips_const.py'
	'bindings/python/capstone/ppc_const.py'
	'bindings/python/capstone/sparc_const.py'
	'bindings/python/capstone/sysz_const.py'
	'bindings/python/capstone/x86_const.py'
	'bindings/python/capstone/xcore_const.py'
)

OUT_FILE="$CURRENT_DIR/src/constants.js"
echo "" >"$OUT_FILE"
for filePath in "${EXPORTED_CONSTANTS[@]}"; do
	fullPath="$CURRENT_DIR/$CAPSTONE_DIR/$filePath"
	code=$(sed -E 's/^([^#[:blank:]]+)/export const \1/g; s/^(.* = [A-Za-z_])/\/\/ \1/g; s/#/\/\//g' "$fullPath")
	echo "$code" >>"$OUT_FILE"
done
