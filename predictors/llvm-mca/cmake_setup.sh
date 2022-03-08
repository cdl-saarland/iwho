#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

mkdir -p $SCRIPT_DIR/build
mkdir -p $SCRIPT_DIR/install

cd $SCRIPT_DIR/build

cmake -G Ninja \
    -DLLVM_ENABLE_PROJECTS='clang' \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DLLVM_ENABLE_ASSERTIONS:BOOL=ON \
    -DLLVM_INCLUDE_TESTS:BOOL=OFF \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DLLVM_PARALLEL_LINK_JOBS=2 \
    -DCMAKE_INSTALL_PREFIX:PATH="$SCRIPT_DIR/install" \
    $SCRIPT_DIR/repo/llvm/

