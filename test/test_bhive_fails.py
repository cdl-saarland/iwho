#!/usr/bin/env pytest

import pytest

import json

import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

import iwho
import iwho.x86 as x86

@pytest.fixture(scope="module")
def ctx():
    return iwho.get_context("x86")

start_idx = 0
# num = 200
num = None

with open(os.path.join(os.path.dirname(__file__), "bhive_fails.json"), "r") as infile:
    input_hex_strs = json.load(infile)
    if num is not None and start_idx is not None:
        input_hex_strs = input_hex_strs[start_idx:start_idx + num]

@pytest.mark.parametrize("hex_str", input_hex_strs)
def test_bhive_fail(ctx, hex_str):
    insns = ctx.decode_insns(hex_str)
    assert len(insns) > 0

