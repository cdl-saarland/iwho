#!/usr/bin/env python3

# This script is basically a collection of hardcoded special cases to make the
# uops.info instruction descriptions compatible with llvm-mc's en/decoding

import json
import os
import re
import sys

from collections import defaultdict

import pyparsing as pp

import iwho.iwho as iwho
import iwho.x86 as x86

import logging
logger = logging.getLogger(__name__)


class UnsupportedFeatureError(Exception):
    def __init__(self, message):
        super().__init__(message)



def main():
    from iwho.iwho_utils import parse_args_with_logging

    xml_path = os.path.join(os.path.dirname(__file__), "..", "..", "inputs", "uops_info", "instructions.xml")

    import argparse
    argparser = argparse.ArgumentParser(
            description="Script for extracting muanalyzer instruction descriptions from the uops.info xml file",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
    argparser.add_argument("inpath", metavar="INFILE", help="the uops.info xml file")


    argparser.add_argument("-o", "--outpath", default="uops_info_schemes.json",
            help="destination file for the json output")

    args = parse_args_with_logging(argparser, "debug")

    xml_path = args.inpath
    outpath = args.outpath

    ctx = x86.Context()
    add_uops_info_xml(ctx, xml_path)

    jsondict = ctx.to_json_dict()

    with open(outpath, "w") as outfile:
        json.dump(jsondict, outfile, indent="  ")
        # for x in jsondict:
        #     if not ( x['str_template'].startswith("adc") or x['str_template'].startswith("add") or x['str_template'].startswith("sar") ):
        #         continue
        #     json.dump(x, outfile)
        #     outfile.write(",\n")


def make_operands_explicit(scheme, operand_keys):
    implicit_operand_indices_to_remove = set()

    new_explicit_operands = dict(scheme.operand_schemes)

    # find the next free numbers to use in the keys for the operands
    next_op_indices = defaultdict(lambda: 0)
    for k in new_explicit_operands:
        patterns = [r"(mem)(\d+)", r"(reg)(\d+)", r"(imm)(\d+)", r"(agen)(\d+)", r"(relbr)(\d+)"]
        patterns = list(map(lambda x: re.compile(x), patterns))
        for p in patterns:
            mat = p.fullmatch(k)
            if mat is not None:
                next_op_indices[mat.group(1)] = max(next_op_indices[mat.group(1)], int(mat.group(2)) + 1)
                break

    op_strs = []
    for key in operand_keys:
        for idx, opscheme in enumerate(scheme.implicit_operands):
            try:
                match = opscheme.parser_pattern.parseString(key, parseAll=True)
                operand = opscheme.from_match(match)
                if isinstance(operand, x86.MemoryOperand):
                    x = next_op_indices["mem"]
                    next_op_indices["mem"] += 1
                    op_key = f"mem{x}"
                    prefix = {64: "qword", 32: "dword", 16: "word", 8: "byte"}[operand.width]
                    prefix += " ptr"
                    op_strs.append(prefix + " ${" + op_key +"}")
                    assert op_key not in new_explicit_operands
                    new_explicit_operands[op_key] = opscheme
                elif isinstance(operand, x86.RegisterOperand):
                    x = next_op_indices["reg"]
                    next_op_indices["reg"] += 1
                    op_key = f"reg{x}"
                    op_strs.append("${" + op_key +"}")
                    assert op_key not in new_explicit_operands
                    new_explicit_operands[op_key] = opscheme
                elif isinstance(operand, x86.ImmediateOperand):
                    x = next_op_indices["imm"]
                    next_op_indices["imm"] += 1
                    op_key = f"imm{x}"
                    op_strs.append("${" + op_key +"}")
                    assert op_key not in new_explicit_operands
                    new_explicit_operands[op_key] = opscheme
                else:
                    assert False, "Unknown operand: {}".format(operand)

                implicit_operand_indices_to_remove.add(idx)
                break
            except pp.ParseException as e:
                pass
        else:
            assert False, "operand key {}, which should be made explicit, not found in this scheme: {}".format(key, repr(scheme))

    # remove from implicit operands
    new_implicit_operands = [op for x, op in enumerate(scheme.implicit_operands) if x not in implicit_operand_indices_to_remove]

    new_str_template = scheme.str_template.template
    if len(op_strs) > 0:
        if len(scheme.operand_schemes) > 0:
            # account for potential previous operands
            new_str_template += ","
        new_str_template += " " + ", ".join(op_strs)

    new_affects_cf = scheme.affects_control_flow

    return iwho.InsnScheme(
            str_template=new_str_template,
            operand_schemes=new_explicit_operands,
            implicit_operands=new_implicit_operands,
            affects_control_flow=new_affects_cf,
        )

def add_uops_info_xml(ctx, xml_path):

    import xml.etree.ElementTree as ET

    logger.debug("start parsing uops.info xml")
    with open(xml_path, 'r') as xml_file:
        xml_root = ET.parse(xml_file)
    logger.debug("done parsing uops.info xml")

    num_errors = 0

    all_schemes = dict()

    for instrNode in xml_root.iter('instruction'):
        try:
            affects_control_flow = False

            if instrNode.attrib['category'] in ['COND_BR', 'UNCOND_BR', 'CALL', 'RET', 'INTERRUPT', 'SYSRET']:
                affects_control_flow = True

            if instrNode.attrib.get('cpl', '0') != '3':
                # that's a kernel mode instruction, we don't support these
                continue

            if instrNode.attrib['category'] in ['XSAVE', 'XSAVEOPT', 'SYSCALL', 'VTX', 'RDWRFSGS', 'RDPID',
                    'X87_ALU', 'FCMOV', 'MMX', '3DNOW', 'MPX', 'CET', 'SYSTEM', 'SEGOP', 'VIA_PADLOCK'
                    ]:
                # Unsupported instructions
                continue

            if any(x in instrNode.attrib['isa-set'] for x in ['XOP', 'AVX512', 'LWP']):
                continue

            # if any(x in instrNode.attrib['extension'] for x in ['AVX512']):
            #     continue

            if instrNode.attrib['extension'] in ['AMD_INVLPGB', 'AMX_BF16',
                    'AMX_INT8', 'AMX_TILE', 'CLDEMOTE', 'ENQCMD', 'HRESET',
                    'KEYLOCKER', 'KEYLOCKER_WIDE', 'MCOMMIT', 'MOVDIR',
                    'PCONFIG', 'RDPRU', 'SERIALIZE', 'SNP', 'TDX',
                    'TSX_LDTRK', 'UINTR', 'WAITPKG', 'WBNOINVD']:
                # Unsupported (future) instruction set extensions (taken
                # from the uops.info script)
                continue

            if any(x in instrNode.attrib['isa-set'] for x in ['BF16_', 'VP2INTERSECT']):
                continue

            str_template = instrNode.get('asm')
            str_template = str_template.replace("{load} ", "")
            str_template = str_template.replace("{store} ", "")
            str_template = str_template.replace("{disp32} ", "")
            str_template = str_template.replace("REX64 ", "")

            # replace some wrong mnemonics
            mnemonic_replacements = {
                    "VPCMPESTRIQ": "VPCMPESTRI", # the Q here is not actually part of the mnemonic, it just signifies a different encoding
                    "VPCMPESTRMQ": "VPCMPESTRM", # the Q here is not actually part of the mnemonic, it just signifies a different encoding
                    "PCMPESTRIQ": "PCMPESTRI", # the Q here is not actually part of the mnemonic, it just signifies a different encoding
                    "PCMPESTRMQ": "PCMPESTRM", # the Q here is not actually part of the mnemonic, it just signifies a different encoding
                    "CALL FAR": "CALL", # the `FAR` would here be interpreted as a symbol and result in a relocation
                    "JMP FAR": "JMP", # the `FAR` would here be interpreted as a symbol and result in a relocation
                    "CMOVNB": "CMOVAE", # those are aliases for the same instruction ("not below" and "above or equal"), and llvm-mc produces the AE version
                    "CMOVNBE": "CMOVA", # those are aliases for the same instruction ("not below or equal" and "above"), and llvm-mc produces the A version
                    "CMOVNL": "CMOVGE", # those are aliases for the same instruction ("not less" and "greater or equal"), and llvm-mc produces the GE version
                    "CMOVNLE": "CMOVG", # those are aliases for the same instruction ("not less or equal" and "greater"), and llvm-mc produces the G version
                    "CMOVNZ": "CMOVNE", # those are aliases for the same instruction ("not zero" and "not equal"), and llvm-mc produces the NE version
                    "CMOVZ": "CMOVE", # those are aliases for the same instruction ("zero" and "equal"), and llvm-mc produces the E version

                    "JNB": "JAE", # those are aliases for the same instruction ("not below" and "above or equal"), and llvm-mc produces the AE version
                    "JNBE": "JA", # those are aliases for the same instruction ("not below or equal" and "above"), and llvm-mc produces the A version
                    "JNL": "JGE", # those are aliases for the same instruction ("not less" and "greater or equal"), and llvm-mc produces the GE version
                    "JNLE": "JG", # those are aliases for the same instruction ("not less or equal" and "greater"), and llvm-mc produces the G version
                    "JNZ": "JNE", # those are aliases for the same instruction ("not zero" and "not equal"), and llvm-mc produces the NE version
                    "JZ": "JE", # those are aliases for the same instruction ("zero" and "equal"), and llvm-mc produces the E version

                    "SETNB": "SETAE", # those are aliases for the same instruction ("not below" and "above or equal"), and llvm-mc produces the AE version
                    "SETNBE": "SETA", # those are aliases for the same instruction ("not below or equal" and "above"), and llvm-mc produces the A version
                    "SETNL": "SETGE", # those are aliases for the same instruction ("not less" and "greater or equal"), and llvm-mc produces the GE version
                    "SETNLE": "SETG", # those are aliases for the same instruction ("not less or equal" and "greater"), and llvm-mc produces the G version
                    "SETNZ": "SETNE", # those are aliases for the same instruction ("not zero" and "not equal"), and llvm-mc produces the NE version
                    "SETZ": "SETE", # those are aliases for the same instruction ("zero" and "equal"), and llvm-mc produces the E version

                    "ENTERW": "ENTER", # llvm-mc doesn't recognize ENTERW, the W signifies an 66H prefix that sets the frame pointer operand size to 16bit
                    "LEAVEW": "LEAVE", # llvm-mc doesn't recognize LEAVEW, the W signifies an 66H prefix that sets the frame pointer operand size to 16bit
                    "POPW": "POP", # llvm-mc doesn't recognize POPW, the W probably signifies another 66H prefix
                    "POPFW": "POPFQ", # llvm-mc doesn't recognize POPW, the W probably signifies another 66H prefix
                    "POPF": "POPFQ", # llvm-mc calls it POPFQ
                    "PUSHW": "PUSH", # llvm-mc doesn't recognize POPW, the W probably signifies another 66H prefix
                    "PUSHFW": "PUSHFQ", # llvm-mc doesn't recognize POPW, the W probably signifies another 66H prefix
                    "PUSHF": "PUSHFQ", # llvm-mc calls it PUSHFQ
                    "RETFW": "RETF", # W refers to something else

                    "XLAT": "XLATB", # llvm-mc wants the width specified (even though B is the only option)
                }
            str_template = mnemonic_replacements.get(str_template, str_template)

            if str_template.startswith("REPE"):
                # llvm-mc calls this "REP" instead of "REPE"
                str_template = str_template.replace("REPE", "REP", 1)

            mnemonic = str_template

            if mnemonic in [ "CLFLUSHOPT", "CLFLUSH", "CLWB",
                    "INS", "INSB", "INSW", "INSD", # input from port
                    "REP INS", "REP INSB", "REP INSW", "REP INSD", # input from port
                    "REPNE INS", "REPNE INSB", "REPNE INSW", "REPNE INSD", # input from port
                    "OUTS", "OUTSB", "OUTSW", "OUTSD", # output to port
                    "REP OUTS", "REP OUTSB", "REP OUTSW", "REP OUTSD", # output to port
                    "REPNE OUTS", "REPNE OUTSB", "REPNE OUTSW", "REPNE OUTSD", # output to port
                    "IRETW",]:
                continue

            if "PREFETCH" in mnemonic:
                continue

            explicit_operands = dict()
            implicit_operands = []

            first = True
            for operandNode in instrNode.iter('operand'):
                operandIdx = int(operandNode.attrib['idx'])

                if operandNode.attrib.get('suppressed', '0') == '1':
                    # implicit operands (here marked as suppressed)
                    op_type = operandNode.attrib['type']

                    op_schemes, t1, t2 = handle_uops_info_operand(ctx, operandNode, instrNode)
                    implicit_operands += op_schemes

                    continue

                if not first and not operandNode.attrib.get('opmask', '') == '1':
                    str_template += ', '
                else:
                    str_template += ' '
                    first = False

                op_schemes, op_name, str_template = handle_uops_info_operand(ctx, operandNode, instrNode, str_template)
                assert len(op_schemes) == 1
                explicit_operands[op_name] = op_schemes[0]

            if not 'sae' in str_template:
                if instrNode.attrib.get('roundc', '') == '1':
                    str_template += ', {rn-sae}'
                elif instrNode.attrib.get('sae', '') == '1':
                    str_template += ', {sae}'

            str_template = str_template.lower()

            if (str_template == "mov ${reg0}, ${imm0}" and
                    explicit_operands["reg0"].operand_constraint.acceptable_operands[0].width == 64 and
                    explicit_operands["imm0"].operand_constraint.width == 64):
                # this move with a very wide immediate is known by llvm-mc as 'movabs'
                str_template = "movabs ${reg0}, ${imm0}"

            if (str_template == "xchg ${reg0}, ${reg1}" and explicit_operands["reg1"].is_fixed()):
                # llvm-mc likes to have the hardcoded register as a first operand here
                str_template = "xchg ${reg1}, ${reg0}"

            scheme = iwho.InsnScheme(
                    str_template=str_template,
                    operand_schemes=explicit_operands,
                    implicit_operands=implicit_operands,
                    affects_control_flow=affects_control_flow
                )

            # llvm-mc prefers to give these operands explicitly, so we need to
            # transform some implicit  operands to explicit ones.
            if str_template in ["cmpsb", "cmpsw", "cmpsd", "cmpsq",
                    "rep cmpsb", "rep cmpsw", "rep cmpsd", "rep cmpsq",
                    "repne cmpsb", "repne cmpsw", "repne cmpsd", "repne cmpsq"]:
                scheme = make_operands_explicit(scheme, ["[rsi]", "es:[rdi]"])

            elif str_template in ["movsb", "movsw", "movsd", "movsq",
                    "rep movsb", "rep movsw", "rep movsd", "rep movsq",
                    "repne movsb", "repne movsw", "repne movsd", "repne movsq"]:
                scheme = make_operands_explicit(scheme, ["es:[rdi]", "[rsi]"])

            elif str_template in ["lodsb", "rep lodsb", "repne lodsb"]:
                scheme = make_operands_explicit(scheme, ["al", "[rsi]"])
            elif str_template in ["lodsw", "rep lodsw", "repne lodsw"]:
                scheme = make_operands_explicit(scheme, ["ax", "[rsi]"])
            elif str_template in ["lodsd", "rep lodsd", "repne lodsd"]:
                scheme = make_operands_explicit(scheme, ["eax", "[rsi]"])
            elif str_template in ["lodsq", "rep lodsq", "repne lodsq"]:
                scheme = make_operands_explicit(scheme, ["rax", "[rsi]"])

            elif str_template in ["scasb", "rep scasb", "repne scasb"]:
                scheme = make_operands_explicit(scheme, ["al", "es:[rdi]"])
            elif str_template in ["scasw", "rep scasw", "repne scasw"]:
                scheme = make_operands_explicit(scheme, ["ax", "es:[rdi]"])
            elif str_template in ["scasd", "rep scasd", "repne scasd"]:
                scheme = make_operands_explicit(scheme, ["eax", "es:[rdi]"])
            elif str_template in ["scasq", "rep scasq", "repne scasq"]:
                scheme = make_operands_explicit(scheme, ["rax", "es:[rdi]"])

            elif str_template in ["stosb", "rep stosb", "repne stosb"]:
                scheme = make_operands_explicit(scheme, ["es:[rdi]", "al"])
            elif str_template in ["stosw", "rep stosw", "repne stosw"]:
                scheme = make_operands_explicit(scheme, ["es:[rdi]", "ax"])
            elif str_template in ["stosd", "rep stosd", "repne stosd"]:
                scheme = make_operands_explicit(scheme, ["es:[rdi]", "eax"])
            elif str_template in ["stosq", "rep stosq", "repne stosq"]:
                scheme = make_operands_explicit(scheme, ["es:[rdi]", "rax"])

            elif ctx.extract_mnemonic(scheme) in ["sha256rnds2", "blendvpd", "blendvps", "pblendvb"]:
                # AVX2 mask registers (which are hardwired to xmm0) are explicit in llvm-mc
                scheme = make_operands_explicit(scheme, ["xmm0"])


            if ctx.extract_mnemonic(scheme) in ["rcl", "rcr", "rol", "ror", "shl", "shr", "sar"]:
                imop = scheme.operand_schemes.get("imm0", None)
                if imop is not None and imop.is_fixed() and imop.fixed_operand.value == 1:
                    # llvm-mc prefers those with the hardcoded shift amount not present
                    new_template = scheme.str_template.template.replace(", ${imm0}", "")
                    new_explicit_operands = { k: v for k, v in scheme.operand_schemes.items() if k != "imm0" }
                    new_implicit_operands = [imop] + scheme.implicit_operands
                    new_affects_cf = scheme.affects_control_flow
                    scheme = iwho.InsnScheme(str_template=new_template,
                                operand_schemes=new_explicit_operands,
                                implicit_operands=new_implicit_operands,
                                affects_control_flow=new_affects_cf,
                            )

            key = str(scheme)

            # filter out schemes that lead to mismatches when their instances are encoded and then again decoded
            blocked_schemes = {
                    "vpcmpestri R:XMM0..15, R:MEM(128), IMM(8)", # that's actually a vpcmpestriq that we changed before, llvm-mc does not produce this without `qword ptr`
                    "vpcmpestrm R:XMM0..15, R:MEM(128), IMM(8)", # that's actually a vpcmpestrmq that we changed before, llvm-mc does not produce this without `qword ptr`
                    "pcmpestri R:XMM0..15, R:MEM(128), IMM(8)", # that's actually a vpcmpestriq that we changed before, llvm-mc does not produce this without `qword ptr`
                    "pcmpestrm R:XMM0..15, R:MEM(128), IMM(8)", # that's actually a vpcmpestrmq that we changed before, llvm-mc does not produce this without `qword ptr`
                    "call R:MEM(32)", # wrong width, missing `qword ptr`
                    "call R:MEM(48)", # wrong width, missing `qword ptr`
                    "call R:MEM(80)", # wrong width, missing `qword ptr`
                    "jmp R:MEM(32)", # wrong width, missing `qword ptr`
                    "jmp R:MEM(48)", # wrong width, missing `qword ptr`
                    "jmp R:MEM(80)", # wrong width, missing `qword ptr`
                    "mov W:GPR:16, R:SEGMENT:16", # wrong width, is implicitly changed to GPR:32

                    }
            if key in blocked_schemes:
                continue
            elif key in all_schemes:
                print(f"Duplicate scheme key: {key}")
                continue
            else:
                all_schemes[key] = scheme
                ctx.add_insn_scheme(scheme)

            # validate that we caught all control flow instructions
            writes_ip = False
            for k, op in scheme.operand_schemes.items():
                if op.is_written and op.is_fixed() and isinstance(op, x86.RegisterOperand) and op.alias_class == ctx._reg_alias_class_enum["GPR_IP"]:
                    writes_ip = True
            for op in scheme.implicit_operands:
                if op.is_written and op.is_fixed() and isinstance(op.fixed_operand, x86.RegisterOperand) and op.fixed_operand.alias_class == ctx._reg_alias_class_enum["GPR_IP"]:
                    writes_ip = True

            if writes_ip and not scheme.affects_control_flow:
                # This could be an equals, except for XEND and XABORT
                raise UnsupportedFeatureError("inconsistent control flow info")

        except UnsupportedFeatureError as e:
            logger.info("Unsupported uops.info entry: {}\n  Exception: {}".format(ET.tostring(instrNode, encoding='utf-8')[:50], repr(e)))
            num_errors += 1

    if num_errors > 0:
        logger.info(f"Encountered {num_errors} error(s) while processing uops.info xml.")

    logger.info(f"{len(ctx.insn_schemes)} instruction schemes after processing uops.info xml.")

    # ensure that all schemes are realizable and make it through encoder and decoder
    instor = x86.DefaultInstantiator(ctx)

    with open("./error_log.txt", "w") as err_file:

        mismatches = 0
        errors = 0
        for x, scheme in enumerate(ctx.insn_schemes):
            instance = instor(scheme)
            error_log = f"scheme no. {x}\n"
            error_log += "original scheme: {}\n  {}\n".format(str(scheme), repr(scheme))
            error_log += "original instance: {}\n".format(str(instance))
            print(f"instruction number {x} : {instance}")
            try:
                hex_str = ctx.encode_insns([instance])
                if not (len(hex_str) > 0):
                    error_log += "ERROR: encoded to empty hex string\n"
                    raise iwho.IWHOError("see error log")

                new_instances = ctx.decode_insns(hex_str)

                if not (len(new_instances) == 1):
                    error_log += "ERROR: decoded to {} instructions\n".format(len(new_instances))
                    raise iwho.IWHOError("see error log")

                new_instance = new_instances[0]
                error_log += "decoded instance: {}\n".format(str(new_instance))
                new_scheme = new_instance.scheme
                error_log += "decoded scheme: {}\n  {}\n".format(str(new_scheme), repr(new_scheme))

                if str(new_scheme) != str(scheme):
                    mismatches += 1
                    error_log += "ERROR: scheme mismatch\n"
                    raise iwho.IWHOError("see error log")


            except iwho.IWHOError as e:
                print(f"error: {e}")
                errors += 1
                error_log += f"EXCEPTION: {e}\n"
                print("### NEXT ERROR ###\n" + error_log, file=err_file)


    print(f"found {mismatches} mismatches")
    print(f"found {errors} errors")



def handle_uops_info_operand(ctx, operandNode, instrNode, str_template=""):
    op_schemes = []
    op_name = operandNode.attrib['name']

    read = operandNode.attrib.get('r', '0') == '1'
    written = operandNode.attrib.get('w', '0') == '1'

    op_type = operandNode.attrib['type']
    if op_type == 'reg':
        registers = operandNode.text.lower().split(',')
        try:
            allowed_registers = frozenset(( ctx.all_registers[reg] for reg in registers ))
        except KeyError as e:
            raise UnsupportedFeatureError(f"Unsupported register: {e}")

        if len(allowed_registers) == 1:
            fixed_op = next(iter(allowed_registers))
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, fixed_operand=fixed_op, read=read, written=written))
        else:
            constraint = ctx.dedup_store.get(iwho.SetConstraint, acceptable_operands=allowed_registers)
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written))

        if not operandNode.attrib.get('opmask', '') == '1':
            str_template += "${" + op_name + "}"
        else:
            str_template += "{${" + op_name + "}}"
            if instrNode.attrib.get('zeroing', '') == '1':
                str_template += '{z}'
    elif op_type == 'mem':
        memoryPrefix = operandNode.attrib.get('memory-prefix', '')
        if memoryPrefix:
            str_template += memoryPrefix + ' '

        if operandNode.attrib.get('VSIB', '0') != '0':
            raise UnsupportedFeatureError("instruction with VSIB: {}".format(instrNode))
            # TODO
            str_template += '[' + operandNode.attrib.get('VSIB') + '0]'
        else:
            str_template += "${" + op_name + "}"
            width = int(operandNode.attrib.get('width'))
            if operandNode.attrib.get('base', '') != '':
                # fixed memory operand
                base_reg = ctx.all_registers[operandNode.attrib['base'].lower()]
                segment = None
                if operandNode.attrib.get('seg', 'DS') != 'DS':
                    segment = ctx.all_registers[operandNode.attrib['seg'].lower()]

                op = ctx.dedup_store.get(x86.MemoryOperand, width=width, base=base_reg, segment=segment)
                op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, fixed_operand=op, read=read, written=written))
            else:
                constraint = ctx.dedup_store.get(x86.MemConstraint, unhashed_kwargs={"context": ctx}, width=width)
                op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written))

        memorySuffix = operandNode.attrib.get('memory-suffix', '')
        if memorySuffix:
            str_template += ' ' + memorySuffix

    elif op_type == 'agen':
        str_template += "${" + op_name + "}"
        # agen memory operands are neither read nor written
        constraint = ctx.dedup_store.get(x86.MemConstraint, unhashed_kwargs={"context": ctx}, width=0)
        op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

    elif op_type == 'imm':
        if instrNode.attrib.get('roundc', '') == '1':
            str_template += '{rn-sae}, '
        elif instrNode.attrib.get('sae', '') == '1':
            str_template += '{sae}, '
        str_template += "${" + op_name + "}"

        width = int(operandNode.attrib['width'])
        if operandNode.text is not None:
            imm = int(operandNode.text)
            op = ctx.dedup_store.get(x86.ImmediateOperand, width=width, value=imm)
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, fixed_operand=op, read=False, written=False))
        else:
            constraint = ctx.dedup_store.get(x86.ImmConstraint, unhashed_kwargs={"context": ctx}, width=width)
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

    elif op_type == 'relbr':
        width = int(operandNode.attrib['width'])
        str_template += "${" + op_name + "}"
        constraint = ctx.dedup_store.get(x86.SymbolConstraint, unhashed_kwargs={"context": ctx})
        op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

    elif op_type == 'flags':
        for f in ["flag_AF", "flag_CF", "flag_OF", "flag_PF", "flag_SF", "flag_ZF", "flag_DF"]:
            fval = operandNode.attrib.get(f, '')
            read = False
            written = False
            if fval == "w":
                written = True
            elif fval == "r":
                read = True
            elif fval == "r/w":
                read = True
                written = True
            elif fval == "undef":
                written = True
            if not (read or written):
                continue
            reg = ctx.all_registers[f.lower()]
            op_schemes.append(iwho.OperandScheme(fixed_operand=reg, read=read, written=written))

    else:
        raise UnsupportedFeatureError("unsupported operand type: {}".format(operandNode.attrib['type']))

    return op_schemes, op_name.lower(), str_template


if __name__ == "__main__":
    main()
