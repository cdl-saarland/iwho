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
    str_template = "adc ${r0}, ${r1}"
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
    str_template = "adc qword ptr ${m0}, ${r0}"
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
    operands["m0"] = x86.MemoryOperand(width=64, base=ctx.all_registers["rbx"], scale=2, index=ctx.all_registers["rdx"], displacement=42)
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
        if scheme.str_template.template == "adc ${reg0}, ${imm0}":
            res.append(scheme)

    assert len(res) > 0
    print("candidate schemes:")
    for scheme in res:
        print("  {}".format(scheme))

    insn_str = "adc rax, 0x2a"

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
        Task(text="adcx rax, r12", hex_str="66490f38f6c4", template="adcx ${reg0}, ${reg1}"),
        Task(text="adcx rax, qword ptr [r12 + 2*rbx + 0x2a]", hex_str="66490f38f6445c2a", template="adcx ${reg0}, qword ptr ${mem0}"),
        Task(text="adcx rax, qword ptr [r12]", hex_str="66490f38f60424", template="adcx ${reg0}, qword ptr ${mem0}"),
        Task(text="adcx rax, qword ptr [r12 + 0x2a]", hex_str="66490f38f644242a", template="adcx ${reg0}, qword ptr ${mem0}"),
        # Task(text="adcx rax, qword ptr [4 * rbx + 0x30]", hex_str="66480f38f64330", template="adcx ${reg0}, qword ptr ${mem0}"), # todo
        Task(text="adc eax, 0x2a", hex_str="83d02a", template="adc ${reg0}, ${imm0}"),

        # b"\x01\xc0",
        # b"\x48\x81\xc4\xc8\x00\x00\x00", # add rsp, 0Xc8
        # b"\x81\xc4\xc8\x00\x00\x00", # add esp, 0Xc8
        # b"\x48\xd1\xfe", # sar rsi, 1
        # b"\x48\xc1\xfe\x07", # sar rsi, 7
        # b"\x48\xd3\xfe", # sar rsi, cl
        # b"\xd1\xfa", # sar edx, 1
        # b"\xf3\x0f\xc2\xc8\x06", # cmpnless xmm1, xmm0
        # b"\x4f\x11\x44\x6e\x08", # adc qword ptr [r14+2*r13+8], r8
    ]

invalid_insns = [
        Task(text="addiu $v1, $zero, 0x1"), # that's a mips instruction, not an x86 one
        Task(text="adc uax, 0x42"), # that's not a valid register (yet?)
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

    print("trying to match instruction: {}".format(insn_str))

    ctx = x86_ctx

    insn_instance = ctx.match_insn_str(insn_str)

    print(repr(insn_instance))
    assert str(insn_instance) == insn_str

def test_matcher_inclusion_order(x86_ctx):
    # This test checks that among multiple matching schemes, the most specific
    # is chosen.
    insn_str = "adc dword ptr [rbx + 0x64], 0x0"
    ctx = x86_ctx
    insn_instance = ctx.match_insn_str(insn_str)
    assert insn_instance.scheme.operand_schemes["imm0"].is_fixed()

@pytest.mark.parametrize("task", invalid_insns)
def test_matcher_fail(x86_ctx, task):
    insn_str = task.text

    ctx = x86_ctx

    with pytest.raises(iwho.InstantiationError):
        insn_instance = ctx.match_insn_str(insn_str)


@pytest.mark.parametrize("task", valid_insns)
def test_llvmmc_encoder_single(task):
    asm = task.text
    ref_hex_str = task.hex_str

    coder = x86.LLVMMCCoder("llvm-mc") # use the system llvm-mc
    hex_str = coder.asm2hex(asm)

    assert hex_str == ref_hex_str

def test_llvmmc_encoder_cat():
    asm = ""
    ref_hex_str = ""
    for task in valid_insns:
        asm += task.text + "\n"
        ref_hex_str += task.hex_str

    coder = x86.LLVMMCCoder("llvm-mc") # use the system llvm-mc
    hex_str = coder.asm2hex(asm)

    assert hex_str == ref_hex_str

@pytest.mark.parametrize("task", valid_insns)
def test_llvmmc_decoder_single(task):
    ref_asm = task.text
    hex_str = task.hex_str

    coder = x86.LLVMMCCoder("llvm-mc") # use the system llvm-mc
    asm_lines = coder.hex2asm(hex_str)

    assert len(asm_lines) == 1

    asm = asm_lines[0]

    assert asm == ref_asm

def test_llvmmc_decoder_cat():
    ref_asm = ""
    hex_str = ""
    for task in valid_insns:
        ref_asm += task.text + "\n"
        hex_str += task.hex_str

    coder = x86.LLVMMCCoder("llvm-mc") # use the system llvm-mc
    asm_lines = coder.hex2asm(hex_str)
    asm_str = "\n".join(asm_lines) + "\n"

    assert asm_str == ref_asm


def test_assemble_all(x86_ctx):
    instor = x86.DefaultInstantiator(x86_ctx)

    num_errors = 0

    for x, scheme in enumerate(x86_ctx.insn_schemes):
        instance = instor(scheme)
        print(f"instruction number {x} : {instance}")
        try:
            hex_str = x86_ctx.encode_insns([instance])
            assert len(hex_str) > 0
        except iwho.IWHOError as e:
            print(f"error: {e}")
            num_errors += 1

    assert num_errors == 0

def test_assemble_then_disassemble_all(x86_ctx):
    instor = x86.DefaultInstantiator(x86_ctx)

    num_assemble_errors = 0

    instances = []
    for x, scheme in enumerate(x86_ctx.insn_schemes):
        instance = instor(scheme)
        print(f"instruction number {x} : {instance}")
        try:
            hex_str = x86_ctx.encode_insns([instance])
            assert len(hex_str) > 0
            instances.append((instance, hex_str))
        except iwho.IWHOError as e:
            print(f"error: {e}")
            num_assemble_errors += 1

    num_disassemble_errors = 0

    for original_instance, hex_str in instances:
        print(f"trying to decode {original_instance}")
        try:
            new_instances = x86_ctx.decode_insns(hex_str)
            assert len(new_instances) == 1
            new_instance = new_instances[0]
            if new_instance != original_instance:
                print(repr(new_instance))
                print(repr(original_instance))
            assert new_instance == original_instance
        except iwho.IWHOError as e:
            print(f"error: {e}")
            num_disassemble_errors += 1

    assert num_assemble_errors == 0 and num_disassemble_errors == 0


if __name__ == "__main__":
    from iwho.iwho_utils import init_logging
    init_logging('debug')

    x86_ctx = make_test_x86ctx()
    test_assemble_then_disassemble_all(x86_ctx)

