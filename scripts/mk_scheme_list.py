#!/usr/bin/env python3

"""A small script for taking a csv file with hex-encoded basic blocks in its
first column and storing keys for all the occuring InsnSchemes.

This is useful for filtering according to a white or black list.
"""

import argparse
import csv
import os
import sys

import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)

import iwho
from iwho.utils import parse_args_with_logging

import logging
logger = logging.getLogger(__name__)

def main():
    argparser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    argparser.add_argument('-a', '--isa', default='x86', metavar="ARCH", help='instruction set architecture to use for the iwho Context')

    argparser.add_argument('-o', '--out', metavar="FILE", help='output file for the InsnScheme keys')

    argparser.add_argument('infiles', nargs='+', metavar="FILE", help='paths of csv files to use as inputs')

    args = parse_args_with_logging(argparser, "info")

    ctx = iwho.get_context(args.isa)

    all_insn_schemes = set()
    for fn in args.infiles:
        logger.info(f"analyzing '{fn}'")
        with open(fn, 'r') as f:
            reader = csv.reader(f)

            for l in reader:
                hex_str = l[0]
                try:
                    insns = ctx.decode_insns(hex_str)
                    for ii in insns:
                        all_insn_schemes.add(str(ii.scheme))
                except iwho.InstantiationError as e:
                    logger.warning(f'block {hex_str} contains an unsupported instruction:\n{e}')

    logger.info(f"found {len(all_insn_schemes)} distinct insn schemes")

    with open(args.out, 'w') as f:
        for scheme in sorted(all_insn_schemes):
            print(scheme, file=f)

if __name__ == "__main__":
    main()
