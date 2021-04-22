#!/usr/bin/env pytest

import pytest

import string

import os
import sys

# import_path = os.path.join(os.path.dirname(__file__), "..", "muanalyzer")
import_path = os.path.dirname(__file__)
sys.path.append(import_path)

import iwho
import x86

def get_adc_scheme():
    ctx = x86.X86_Context()
    str_template = string.Template("ADC ${r0}, ${r1}")
    isGPR64 = iwho.SetConstraint("GPR64", ctx.gp_regs)
    explicit = {
            "r0": iwho.OperandScheme(constraint=isGPR64, read=True, written=True),
            "r1": iwho.OperandScheme(constraint=isGPR64, read=True),
        }
    implicit = [iwho.OperandScheme(fixed_operand=f, written=True) for f in ctx.flag_regs]
    scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit, implicit_operands=implicit)
    return scheme

def test_construct_insn():
    scheme = get_adc_scheme()

    print("scheme:")
    print(scheme)
    print(repr(scheme))

    operands = dict()
    operands["r0"] = scheme.operand_schemes["r0"].get_valid_operand()
    operands["r1"] = scheme.operand_schemes["r1"].get_valid_operand(not_in=[operands["r0"]])

    insn = scheme.instantiate(operands)

    print("instance:")
    print(repr(insn))

    print(str(insn))

    print("read operands:")
    print(insn.read_operands)

    print("written operands:")
    print(insn.written_operands)

def test_construct_invalid_insn_op_missing():
    scheme = get_adc_scheme()

    operands = dict()
    operands["r0"] = scheme.operand_schemes["r0"].get_valid_operand()

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)


def test_construct_invalid_insn_wrong_op():
    scheme = get_adc_scheme()

    operands = dict()
    operands["r0"] = scheme.operand_schemes["r0"].get_valid_operand()
    operands["r1"] = x86.X86_ImmediateOperand(x86.X86_ImmKind.INT, 32, 42)

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)

def test_construct_invalid_insn_superfluous_op():
    scheme = get_adc_scheme()

    operands = dict()
    operands["r0"] = scheme.operand_schemes["r0"].get_valid_operand()
    operands["r1"] = scheme.operand_schemes["r1"].get_valid_operand(not_in=[operands["r0"]])
    operands["r2"] = scheme.operand_schemes["r1"].get_valid_operand(not_in=[operands["r0"], operands["r1"]])

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)


if __name__ == "__main__":
    test_construct_insn()
