#!/bin/bash

LLVM_VERSION=release/13.x

set -ex

git clone -b $LLVM_VERSION https://github.com/llvm/llvm-project.git repo
./cmake_setup.sh
cd build
ninja install-llvm-mc
ninja install-llvm-mca

