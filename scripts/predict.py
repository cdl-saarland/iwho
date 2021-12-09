#!/usr/bin/env python3

""" Script to run and execute basic block predictors.
"""

import argparse
from collections import Counter
import os
import sys
import textwrap


import_path = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(import_path)


import logging
logger = logging.getLogger(__name__)


from iwho.configurable import load_json_config, pretty_print
from iwho.predictors.predictor_manager import PredictorManager
from iwho.utils import parse_args_with_logging

from iwho import Config

def main():
    default_seed = 424242

    argparser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    argparser.add_argument('--iwhoconfig', metavar="CONFIG", default=None,
            help='path to an iwho config in json format')
    argparser.add_argument('--predconfig', metavar="CONFIG", default=None,
            help='path to a predictor config in json format')

    argparser.add_argument('-p', '--predictors', nargs="+", required=True, metavar="PREDICTOR_ID",
            help='one or more keys or key patterns of predictors specified in the config')

    input_group = argparser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-a', '--asm', nargs="+", default=None, metavar='ASM file',
            help='path(s) to a file containing the assembly of a basic block to evaluate')
    input_group.add_argument('-x', '--hex', metavar='HEX str', default=None,
            help='a hex string of a basic block to evaluate')
    input_group.add_argument('--testbasic', action='store_true',
            help='run the predictors on a simple default test')
    input_group.add_argument('--testallinsns', action='store_true',
            help='run the predictors on all supported instructions')

    argparser.add_argument('-s', '--seed', type=int, default=default_seed, metavar="N",
            help='seed for the rng')

    args = parse_args_with_logging(argparser, "info")

    iwhoconfig = load_json_config(args.iwhoconfig)
    ctx = Config(config=iwhoconfig).context

    predconfig = load_json_config(args.predconfig)
    pm = PredictorManager(config=predconfig)

    pm.set_predictors(args.predictors)

    if args.testbasic:
        bbs = [ ctx.make_example_bb() ]
    elif args.testallinsns:
        bbs = []
        # TODO implement this!
    elif args.hex is not None:
        bbs = [ctx.decode_insns_bb(args.hex)]
    else:
        assert args.asm is not None
        bbs = []
        for path in args.asm:
            with open(path, 'r') as f:
                asm_str = f.read()
            bbs.append(ctx.parse_asm_bb(asm_str))

    results, series_id = pm.eval_with_all_and_report(bbs)

    errors = Counter()

    for bb, res in results:
        print("Basic Block:")
        print(textwrap.indent(str(bb), "    "))
        print("  Result:")
        print(textwrap.indent(pretty_print(res), "    "))
        for k, v in res.items():
            if v['TP'] is None or v['TP'] < 0.0:
                errors[k] += 1

    if len(errors) > 0:
        print("there were prediction errors:")
        for k, n in errors.most_common():
            print(f"  {k}: {n} error{'s' if n != 1 else ''}")

if __name__ == "__main__":
    main()
