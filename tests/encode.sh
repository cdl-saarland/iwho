#!/bin/bash

# this is a simple llvm-mc wrapper for encoding an ASM instruction

LLVM_MC=~/projects/portmapping/llvm/install/bin/llvm-mc

printf ".intel_syntax noprefix\n$*" | $LLVM_MC --assemble --filetype=asm --output-asm-variant=1 --show-encoding --arch=x86-64
