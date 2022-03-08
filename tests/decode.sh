#!/bin/bash

# this is a simple llvm-mc wrapper for decoding an array of hex numbers of the form [0xXX,0xYY,...]

LLVM_MC=~/projects/portmapping/llvm/install/bin/llvm-mc

printf "$*" | $LLVM_MC --disassemble --filetype=asm --arch=x86-64 --output-asm-variant=1 --print-imm-hex --show-inst
