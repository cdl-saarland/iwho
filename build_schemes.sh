#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $SCRIPT_DIR

./scripts/scheme_extractor_uops_info.py \
    -l info \
    -o ./iwho/inputfiles/schemes/x86_uops_info.json \
    --no-validate \
    ./inputs/uops_info/instructions.xml
