#!/usr/bin/env pytest

import pytest

import string

import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

import_path = os.path.dirname(__file__)
sys.path.append(import_path)

import iwho
import x86

def get_adc_scheme():
    ctx = x86.X86_Context()
    str_template = string.Template("ADC ${r0}, ${r1}")
    isGPR64 = iwho.SetConstraint(ctx.gp_regs)
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

def test_construct_memory_op():
    ctx = x86.X86_Context()
    str_template = string.Template("ADC qword ptr ${m0}, ${r0}")
    isGPR64 = iwho.SetConstraint(ctx.gp_regs)
    isMem64 = x86.X86_MemConstraint(64)
    explicit = {
            "m0": iwho.OperandScheme(constraint=isMem64, read=True, written=True),
            "r0": iwho.OperandScheme(constraint=isGPR64, read=True),
        }
    implicit = [iwho.OperandScheme(fixed_operand=f, written=True) for f in ctx.flag_regs]
    scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit, implicit_operands=implicit)

    print("scheme:")
    print(scheme)
    print(repr(scheme))

    operands = dict()
    operands["m0"] = x86.X86_MemoryOperand(width=64, base=ctx.all_registers["RBX"], scale=2, index=ctx.all_registers["RDX"], displacement=42)
    operands["r0"] = scheme.operand_schemes["r0"].get_valid_operand()

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

def test_uops_info_parsing():
    ctx = x86.X86_Context()
    xml_path = os.path.join(os.path.dirname(__file__), "..", "..", "inputs", "uops_info", "instructions.xml")
    ctx.add_uops_info_xml(xml_path)

    for scheme in ctx.insn_schemes:
        print(scheme)

if __name__ == "__main__":
    from utils import init_logging
    init_logging('debug')

    # test_construct_insn()
    test_uops_info_parsing()

    test_construct_memory_op()
