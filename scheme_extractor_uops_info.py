#!/usr/bin/env python3

import json
import os

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


def add_uops_info_xml(ctx, xml_path):

    import xml.etree.ElementTree as ET

    logger.debug("start parsing uops.info xml")
    with open(xml_path, 'r') as xml_file:
        xml_root = ET.parse(xml_file)
    logger.debug("done parsing uops.info xml")

    num_errors = 0

    for instrNode in xml_root.iter('instruction'):
        try:
            if instrNode.attrib['category'] in ['XSAVE', 'XSAVEOPT',
                    'X87_ALU', 'FCMOV', 'MMX', '3DNOW', 'MPX', 'COND_BR',
                    'UNCOND_BR', 'CALL', 'CET', 'SYSTEM', 'SEGOP']:
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
            mnemonic = str_template

            if mnemonic in ["PREFETCHW", "PREFETCH"]:
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

            str_template = str_template.upper()
            # TODO set affects_control_flow
            scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit_operands, implicit_operands=implicit_operands)

            ctx.insn_schemes.append(scheme)
            ctx.mnemonic_to_insn_schemes[mnemonic].append(scheme)

        except Exception as e:
            logger.info("Unsupported uops.info entry: {}\n  Exception: {}".format(ET.tostring(instrNode, encoding='utf-8')[:50], repr(e)))
            num_errors += 1

    if num_errors > 0:
        logger.info(f"Encountered {num_errors} error(s) while processing uops.info xml.")

    logger.info(f"{len(ctx.insn_schemes)} instruction schemes after processing uops.info xml.")


def handle_uops_info_operand(ctx, operandNode, instrNode, str_template=""):
    op_schemes = []
    op_name = operandNode.attrib['name']

    read = operandNode.attrib.get('r', '0') == '1'
    written = operandNode.attrib.get('w', '0') == '1'

    op_type = operandNode.attrib['type']
    if op_type == 'reg':
        registers = operandNode.text.split(',')
        try:
            allowed_registers = frozenset(( ctx.all_registers[reg] for reg in registers ))
        except KeyError as e:
            raise UnsupportedFeatureError(f"Unsupported register: {e}")
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
            width = str(operandNode.attrib.get('width'))
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
            imm = operandNode.text
            op = ctx.dedup_store.get(x86.ImmediateOperand, width=width, value=imm)
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, fixed_operand=op, read=False, written=False))
        else:
            constraint = ctx.dedup_store.get(x86.ImmConstraint, unhashed_kwargs={"context": ctx}, width=width)
            op_schemes.append(ctx.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

    # elif op_type == 'relbr':
        # str_template = '1: ' + str_template + '1b'
        # TODO
    elif op_type == 'flags':
        for f in ["flag_AF", "flag_CF", "flag_OF", "flag_PF", "flag_SF", "flag_ZF"]:
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
            reg = ctx.all_registers[f]
            op_schemes.append(iwho.OperandScheme(fixed_operand=reg, read=read, written=written))

    else:
        raise UnsupportedFeatureError("unsupported operand type: {}".format(operandNode.attrib['type']))

    return op_schemes, op_name, str_template


if __name__ == "__main__":
    main()
