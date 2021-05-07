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

def get_regs(ctx, category, width=None):
    res = []
    for k, reg in ctx.all_registers.items():
        if (width is None or reg.width == width) and reg.category == ctx._reg_category_enum[category]:
            res.append(reg)

    return res

def get_adc_scheme():
    ctx = x86.Context()
    str_template = "ADC ${r0}, ${r1}"
    isGPR64 = iwho.SetConstraint(get_regs(ctx, "GPR", 64))
    explicit = {
            "r0": iwho.OperandScheme(constraint=isGPR64, read=True, written=True),
            "r1": iwho.OperandScheme(constraint=isGPR64, read=True),
        }
    implicit = [iwho.OperandScheme(fixed_operand=f, written=True) for f in get_regs(ctx, "FLAG")]
    scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit, implicit_operands=implicit)
    return scheme, ctx

def test_construct_insn():
    scheme, ctx = get_adc_scheme()

    print("scheme:")
    print(scheme)
    print(repr(scheme))

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])
    operands["r1"] = instor(scheme.operand_schemes["r1"])

    insn = scheme.instantiate(operands)

    print("instance:")
    print(repr(insn))

    print(str(insn))

    print("read operands:")
    print(insn.read_operands)

    print("written operands:")
    print(insn.written_operands)

def test_construct_memory_op():
    ctx = x86.Context()
    str_template = "ADC qword ptr ${m0}, ${r0}"
    isGPR64 = iwho.SetConstraint(get_regs(ctx, "GPR", 64))
    isMem64 = x86.MemConstraint(ctx, 64)
    explicit = {
            "m0": iwho.OperandScheme(constraint=isMem64, read=True, written=True),
            "r0": iwho.OperandScheme(constraint=isGPR64, read=True),
        }
    implicit = [iwho.OperandScheme(fixed_operand=f, written=True) for f in get_regs(ctx, "FLAG")]
    scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit, implicit_operands=implicit)

    print("scheme:")
    print(scheme)
    print(repr(scheme))

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["m0"] = x86.MemoryOperand(width=64, base=ctx.all_registers["RBX"], scale=2, index=ctx.all_registers["RDX"], displacement=42)
    operands["r0"] = instor(scheme.operand_schemes["r0"])

    insn = scheme.instantiate(operands)

    print("instance:")
    print(repr(insn))

    print(str(insn))

    print("read operands:")
    print(insn.read_operands)

    print("written operands:")
    print(insn.written_operands)

def test_construct_invalid_insn_op_missing():
    scheme, ctx = get_adc_scheme()

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)


def test_construct_invalid_insn_wrong_op():
    scheme, ctx = get_adc_scheme()

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])
    operands["r1"] = x86.ImmediateOperand(32, 42)

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)

def test_construct_invalid_insn_superfluous_op():
    scheme, ctx = get_adc_scheme()

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])
    operands["r1"] = instor(scheme.operand_schemes["r1"])
    operands["r2"] = instor(scheme.operand_schemes["r1"])

    with pytest.raises(iwho.InvalidOperandsError):
        insn = scheme.instantiate(operands)

def make_uops_info_ctx():
    ctx = x86.Context()
    xml_path = os.path.join(os.path.dirname(__file__), "..", "..", "inputs", "uops_info", "instructions.xml")
    ctx.add_uops_info_xml(xml_path)
    return ctx

@pytest.fixture(scope="module")
def uops_info_ctx():
    return make_uops_info_ctx()

def test_uops_info_parsing(uops_info_ctx):
    pass

    # for scheme in uops_info_ctx.insn_schemes:
    #     print(scheme)
    #     print(repr(scheme))

def test_uops_info_instantiate_all(uops_info_ctx):
    instor = x86.DefaultInstantiator(uops_info_ctx)

    for scheme in uops_info_ctx.insn_schemes:
        instance = instor(scheme)
        str(instance)
        # print(instance)

def test_uops_info_assemble_all(uops_info_ctx):
    instor = x86.DefaultInstantiator(uops_info_ctx)

    num_errors = 0

    for x, scheme in enumerate(uops_info_ctx.insn_schemes):
        instance = instor(scheme)
        print(f"instruction number {x} : {instance}")
        try:
            hex_str = uops_info_ctx.assemble_single(instance)
            assert len(hex_str) > 0
        except iwho.IWHOError as e:
            print(f"error: {e}")
            num_errors += 1

    assert num_errors == 0



if __name__ == "__main__":
    from utils import init_logging
    init_logging('debug')

    # test_construct_insn()
    test_uops_info_parsing(make_uops_info_ctx())

    # test_construct_memory_op()

