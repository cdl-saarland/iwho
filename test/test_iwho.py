#!/usr/bin/env pytest

import pytest

import string

from collections import namedtuple
import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

import iwho.iwho as iwho
import iwho.x86 as x86


from inputs import make_test_x86ctx


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

    with pytest.raises(iwho.InstantiationError):
        insn = scheme.instantiate(operands)


def test_construct_invalid_insn_wrong_op():
    scheme, ctx = get_adc_scheme()

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])
    operands["r1"] = x86.ImmediateOperand(32, 42)

    with pytest.raises(iwho.InstantiationError):
        insn = scheme.instantiate(operands)

def test_construct_invalid_insn_superfluous_op():
    scheme, ctx = get_adc_scheme()

    instor = x86.DefaultInstantiator(ctx)

    operands = dict()
    operands["r0"] = instor(scheme.operand_schemes["r0"])
    operands["r1"] = instor(scheme.operand_schemes["r1"])
    operands["r2"] = instor(scheme.operand_schemes["r1"])

    with pytest.raises(iwho.InstantiationError):
        insn = scheme.instantiate(operands)

@pytest.fixture(scope="module")
def x86_ctx():
    return make_test_x86ctx()

def test_instantiate_all(x86_ctx):
    instor = x86.DefaultInstantiator(x86_ctx)

    for scheme in x86_ctx.insn_schemes:
        instance = instor(scheme)
        str(instance)
        # print(instance)


import pyparsing as pp

def test_parser_adcx(x86_ctx):
    ctx = x86_ctx
    res = []
    for scheme in x86_ctx.insn_schemes:
        if scheme.str_template.template == "ADC ${REG0}, ${IMM0}":
            res.append(scheme)

    assert len(res) > 0
    print("candidate schemes:")
    for scheme in res:
        print("  {}".format(scheme))

    insn_str = "ADC RAX, 42"

    matches = []
    for scheme in res:
        pat = scheme.parser_pattern
        print(pat)
        try:
            match = pat.parseString(insn_str)
            matches.append((scheme, match))
        except pp.ParseException as e:
            pass

    assert len(matches) > 0

    print("matching scheme:")
    scheme, match = matches[0]
    print("  {} ; match: {}".format(scheme, match))

    insn_instance = scheme.instantiate(insn_str)
    print(repr(insn_instance))

    print(insn_instance)
    assert str(insn_instance) == insn_str

Task = namedtuple('Task', ['text', 'hex_str', 'template'], defaults=(None, None))

valid_insns = [
        Task(text="ADCX RAX, R12", hex_str="66490f38f6c4", template="ADCX ${REG0}, ${REG1}"),
        Task(text="ADCX RAX, qword ptr [R12+RBX*2+42]", hex_str="66490f38f6445c2a", template="ADCX ${REG0}, qword ptr ${MEM0}"),
        Task(text="ADCX RAX, qword ptr [R12]", hex_str="66490f38f60424", template="ADCX ${REG0}, qword ptr ${MEM0}"),
        Task(text="ADCX RAX, qword ptr [R12+42]", hex_str="66490f38f644242a", template="ADCX ${REG0}, qword ptr ${MEM0}"),
        # Task(text="ADCX RAX, qword ptr [RBX*4+48]", hex_str="0x66480f38f64330", template="ADCX ${REG0}, qword ptr ${MEM0}"),
        # XED apparently has weird constraints on the position of the scale component in memory operands:
        #   if a base register is present, the scale has to come after the index, if no base register is present, it has to be in front of the index.
        Task(text="ADC EAX, 42", hex_str="83d02a", template="ADC ${REG0}, ${IMM0}"),

        # b"\x01\xc0",
        # b"\x48\x81\xc4\xc8\x00\x00\x00", # add rsp, 0xc8
        # b"\x81\xc4\xc8\x00\x00\x00", # add esp, 0xc8
        # b"\x48\xd1\xfe", # sar rsi, 1
        # b"\x48\xc1\xfe\x07", # sar rsi, 7
        # b"\x48\xd3\xfe", # sar rsi, cl
        # b"\xd1\xfa", # sar edx, 1
        # b"\xf3\x0f\xc2\xc8\x06", # cmpnless xmm1, xmm0
        # b"\x4f\x11\x44\x6e\x08", # adc qword ptr [r14+2*r13+8], r8
    ]

invalid_insns = [
        Task(text="ADDIU $V1, $zero, 1"), # that's a MIPS instruction, not an x86 one
        Task(text="ADC UAX, 42"), # that's not a valid register (yet?)
    ]


@pytest.mark.parametrize("task", valid_insns)
def test_parser_bulk(x86_ctx, task):
    insn_str = task.text
    template = task.template

    print("trying to match instruction: {}".format(insn_str))

    ctx = x86_ctx
    res = []
    for scheme in x86_ctx.insn_schemes:
        if scheme.str_template.template == template:
            res.append(scheme)

    assert len(res) > 0
    print("candidate schemes:")
    for scheme in res:
        print("  {}".format(scheme))

    matches = []
    for scheme in res:
        pat = scheme.parser_pattern
        try:
            match = pat.parseString(insn_str)
            matches.append((scheme, match))
        except pp.ParseException as e:
            pass

    assert len(matches) > 0
    print("matching scheme:")
    scheme, match = matches[0]
    print("  {} ; match: {}".format(scheme, match))

    insn_instance = scheme.instantiate(insn_str)
    print(repr(insn_instance))

    assert str(insn_instance) == insn_str


@pytest.mark.parametrize("task", valid_insns)
def test_matcher_success(x86_ctx, task):
    # in contrast to the test_parser_bulk test, this also tests the selection
    # of candidate schemes
    insn_str = task.text
    template = task.template

    print("trying to match instruction: {}".format(insn_str))

    ctx = x86_ctx

    insn_instance = ctx.match_insn_str(insn_str)

    print(repr(insn_instance))
    assert str(insn_instance) == insn_str

@pytest.mark.parametrize("task", invalid_insns)
def test_matcher_fail(x86_ctx, task):
    insn_str = task.text

    ctx = x86_ctx

    with pytest.raises(iwho.InstantiationError):
        insn_instance = ctx.match_insn_str(insn_str)


# def test_assemble_all(x86_ctx):
#     instor = x86.DefaultInstantiator(x86_ctx)
#
#     num_errors = 0
#
#     for x, scheme in enumerate(x86_ctx.insn_schemes):
#         instance = instor(scheme)
#         print(f"instruction number {x} : {instance}")
#         try:
#             hex_str = x86_ctx.assemble_single(instance)
#             assert len(hex_str) > 0
#         except iwho.IWHOError as e:
#             print(f"error: {e}")
#             num_errors += 1
#
#     assert num_errors == 0

# def test_assemble_then_disassemble_all(x86_ctx):
#     instor = x86.DefaultInstantiator(x86_ctx)
#
#     num_assemble_errors = 0
#
#     instances = []
#     for x, scheme in enumerate(x86_ctx.insn_schemes):
#         instance = instor(scheme)
#         print(f"instruction number {x} : {instance}")
#         try:
#             hex_str = x86_ctx.assemble_single(instance)
#             assert len(hex_str) > 0
#             instances.append((instance, hex_str))
#         except iwho.IWHOError as e:
#             print(f"error: {e}")
#             num_assemble_errors += 1
#
#     num_disassemble_errors = 0
#
#     for original_instance, hex_str in instances:
#         try:
#             new_instance = x86_ctx.disassemble(hex_str)
#             assert new_instance == original_instance
#         except iwho.IWHOError as e:
#             print(f"error: {e}")
#             num_disassemble_errors += 1
#
#     assert num_assemble_errors == 0 and num_disassemble_errors == 0


if __name__ == "__main__":
    from utils import init_logging
    init_logging('debug')

