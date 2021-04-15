#!/usr/bin/env pytest

import pytest

import os
import sys

# import_path = os.path.join(os.path.dirname(__file__), "..", "muanalyzer")
import_path = os.path.dirname(__file__)
sys.path.append(import_path)

import iwho
import x86


def test_construct_insn():
    ctx = x86.X86_Context()
    str_template = "ADC |0|, |1|"
    isGPR64 = iwho.SetConstraint(ctx.gp_regs)
    explicit = {
            "0": iwho.OperandScheme(constraint=isGPR64, read=True, written=True),
            "1": iwho.OperandScheme(constraint=isGPR64, read=True),
        }
    implicit = [iwho.OperandScheme(fixed_operand=f, written=True) for f in ctx.flag_regs]
    scheme = iwho.InsnScheme("adc_r64_r64", str_template=str_template, operand_schemes=explicit, implicit_operands=implicit)
    print(repr(scheme))

if __name__ == "__main__":
    test_construct_insn()
