#!/usr/bin/env python3

""" Adjust BHive basic blocks such that PITE can benchmark them.

This includes replacing all memory operands (while preserving dependencies as
far as reasonably possible) and some register operands, as well as rejecting
basic blocks with unsupported instructions, like push and pop.
"""

import argparse
import textwrap

import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

import iwho
import iwho.x86 as x86

import pandas as pd

import logging
logger = logging.getLogger(__name__)


def get_memop_key(op):
    return (op.segment, op.base, op.index, op.scale, op.displacement) # everything except width

def sanitize_bb(iwho_ctx, context, hex_code):
    reserved_register_classes  = context["reserved_register_classes"]
    allowed_memory_operands  = context["allowed_memory_operands"]
    all_gpr_classes  = context["all_gpr_classes"]

    # decode the basic block
    try:
        insns = iwho_ctx.decode_insns(hex_code)
    except iwho.IWHOError:
        logger.warning("Failed to decode basic block: {}".format(hex_code))
        return None

    # identify the register classes used in the basic block
    taken_register_classes = set()
    need_replacement = set()

    for i in insns:
        for op, (key, op_scheme) in i.get_operands():
            if isinstance(op, x86.RegisterOperand) and op.category == x86.RegKind.GPR:
                if op.alias_class in reserved_register_classes:
                    need_replacement.add(op.alias_class)
                else:
                    taken_register_classes.add(op.alias_class)
    replacement_candidates = (all_gpr_classes - taken_register_classes) - reserved_register_classes
    if len(replacement_candidates) < len(need_replacement):
        logger.warning("Not enough replacement candidates for basic block: {}".format(hex_code))
        return None

    replacement_map = { old: new for old, new in zip(need_replacement, replacement_candidates) }
    # This could make problems with 8 bit registers, where not all replacements are allowed.
    # print("Replacement map: {}".format(replacement_map))
    curr_allowed_memop_idx = 0

    res_insns = []
    for i in insns:
        new_operands = {}
        for op, (key, op_scheme) in i.get_operands():
            replacement = None
            if isinstance(op, x86.MemoryOperand):
                memop_key = get_memop_key(op)
                replacement = replacement_map.get(memop_key, None)
                if replacement is None:
                    if curr_allowed_memop_idx >= len(allowed_memory_operands):
                        logger.warning("Not enough replacement memory operands for basic block: {}".format(hex_code))
                        return None
                    replacement = allowed_memory_operands[curr_allowed_memop_idx]
                    curr_allowed_memop_idx += 1
                    replacement_map[memop_key] = replacement
            elif isinstance(op, x86.RegisterOperand) and op.category == x86.RegKind.GPR:
                replacement_cls = replacement_map.get(op.alias_class, None)
                if replacement_cls is not None:
                    replacement_candidates = iwho_ctx.get_registers_where(alias_class=replacement_cls, width=op.width)
                    replacement = replacement_candidates[0]
            if replacement is not None:
                new_operands[key] = iwho_ctx.adjust_operand(replacement, op_scheme)
        if len(new_operands) == 0:
            new_i = i
        else:
            try:
                new_i = i.replace_operands(new_operands)
            except iwho.IWHOError:
                logger.warning("Failed to replace operands in basic block: {}\n  new operands: {}".format(hex_code, new_operands))
                return None
        res_insns.append(new_i)

    # print("BB before:\n{}\nBB after:\n{}".format(textwrap.indent("\n".join(map(str, insns)), '  '), textwrap.indent("\n".join(map(str, res_insns)), '  ')))

    # encode the result and return it, or None if the basic block was rejected
    return iwho_ctx.encode_insns(res_insns)


def sanitize_bb_chunk(context, hex_codes):
    iwho_ctx = iwho.get_context_by_name('x86')
    res = []
    for hex_code in hex_codes:
        res.append(sanitize_bb(iwho_ctx, context, hex_code))
    return res


def main():
    argparser = argparse.ArgumentParser(description=__doc__)

    argparser.add_argument('-o', '--output', metavar="OUTFILE", required=True,
        help='the output csv file')

    argparser.add_argument('input', metavar="INFILE",
        help='the input csv file')

    # args = argparser.parse_args()
    args = parse_args_with_logging(argparser, default_loglevel="info")

    df = pd.read_csv(args.input, header="infer")

    print("Starting with {} unsanitized basic blocks.".format(len(df)))

    base_reg = x86.all_registers["r14"]
    num_mem_ops = 62 # 32 + 62 * 64 = 4000 fits within a page
    context = {
            "reserved_register_classes": {
                    x86.RegAliasClass.GPR_R15, # reserved for loop counter
                    x86.RegAliasClass.GPR_R14, # reserved for memory
                    x86.RegAliasClass.GPR_SP,  # try to not mess up the stack pointer
                },
            "allowed_memory_operands": [
                    x86.MemoryOperand(base=base_reg, displacement=disp, width=64)
                    for disp in range(32, 32 + num_mem_ops * 64, 64)
                ],
            "all_gpr_classes": {
                x86.RegAliasClass.GPR_A,
                x86.RegAliasClass.GPR_B,
                x86.RegAliasClass.GPR_C,
                x86.RegAliasClass.GPR_D,
                x86.RegAliasClass.GPR_BP,
                x86.RegAliasClass.GPR_DI,
                x86.RegAliasClass.GPR_SI,
                # x86.RegAliasClass.GPR_SP,
                # x86.RegAliasClass.GPR_IP,
                x86.RegAliasClass.GPR_R8,
                x86.RegAliasClass.GPR_R9,
                x86.RegAliasClass.GPR_R10,
                x86.RegAliasClass.GPR_R11,
                x86.RegAliasClass.GPR_R12,
                x86.RegAliasClass.GPR_R13,
                x86.RegAliasClass.GPR_R14,
                x86.RegAliasClass.GPR_R15,
            },
        }

    hex_codes = df["hexCode"].tolist()
    if "hexCodeDec" in df.columns:
        full_hex_codes = [ f"{a}{b}" for a, b in zip(hex_codes, df["hexCodeDec"].tolist())]
        hex_codes = full_hex_codes

    # TODO parallelize
    res_list = sanitize_bb_chunk(context, hex_codes)

    df["sanitizedHexCode"] = res_list

    df.dropna(inplace=True)

    print("Remaining sanitized basic blocks: {}".format(len(df)))

    df.to_csv(args.output, index=False)

    return 0


def init_logging(loglevel, logfile=None):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(loglevel))

    handlers = [logging.StreamHandler()]
    if logfile is not None:
        handlers.append(logging.FileHandler(logfile))

    kwargs = {
            "format": '%(asctime)s - %(levelname)s:%(name)s: %(message)s',
            "level": numeric_level, "handlers": handlers,
        }

    logging.basicConfig(**kwargs)

def parse_args_with_logging(argparser, default_loglevel="warning"):
    loglevels = ["debug", "info", "warning", "error"]
    argparser.add_argument("-l", "--loglevel", choices=loglevels, default=default_loglevel,
            help="configures the amount of logging information to print")
    argparser.add_argument("--logfile", default=None,
            help="print logs to this file, stdout if none is given")

    args = argparser.parse_args()
    init_logging(args.loglevel, args.logfile)

    return args

if __name__ == "__main__":
    sys.exit(main())
