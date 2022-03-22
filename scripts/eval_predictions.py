#!/usr/bin/env python3

""" Compute prediction quality metrics for a csv file with prediction columns
and a ground truth column.
"""

import argparse
import csv
import json
import math

# import os
import sys


from numpy import mean, median
from scipy.stats.mstats import gmean
from scipy.stats import pearsonr, spearmanr

# import_path = os.path.join(os.path.dirname(__file__), "..")
# sys.path.append(import_path)


def main():
    argparser = argparse.ArgumentParser(description=__doc__)

    # argparser.add_argument('-o', '--output', metavar="OUTFILE", default=None,
    #     help='the output file')

    argparser.add_argument('-g', '--groundtruth', metavar="COLNAME", default="nanobench",
        help='column name that is used as ground truth for the metrics. If no column matches exactly, one that includes the default is used.')

    argparser.add_argument('-f', '--filter-invalid', action="store_true",
        help='if provided, omit invalid runs (with <= 0.0 cycles) from consideration without crashing.')

    argparser.add_argument('input', metavar="INFILE",
        help='the input csv file')

    args = argparser.parse_args()

    with open(args.input, 'r') as f:
        r = csv.DictReader(f)
        data = list(r)

    if len(data) == 0:
        print("No data provided!", file=sys.stderr)
        return 1

    keys = { x for x in data[0].keys() if x != 'bb'}

    if args.groundtruth in keys:
        grountruth_key = args.groundtruth
    else:
        candidates = [x for x in keys if args.groundtruth in x]
        if len(candidates) < 1:
            print(f"Ground truth key {args.groundtruth} does not match any column.", file=sys.stderr)
            return 1
        if len(candidates) > 1:
            print(f"Ground truth key {args.groundtruth} matches more than one column:", file=sys.stderr)
            for c in candidates:
                print(f"  - {c}", file=sys.stderr)
            return 1
        groundtruth_key = candidates[0]

    keys.remove(groundtruth_key)

    print(f"Ground truth key: {groundtruth_key}")
    print("Evaluated keys:")
    for k in keys:
        print(f"  - {k}")

    for k in keys:
        ref_cycles_list = []
        sim_cycles_list = []
        rel_errors = []
        num_invalid = 0

        print(f"metrics for '{k}':")
        for d in data:
            ref = float(d[groundtruth_key])
            sim = float(d[k])

            if ref <= 0.0 or sim <= 0.0:
                if args.filter_invalid:
                    num_invalid += 1
                    continue
                else:
                    raise RuntimeError(f'Invalid measurement encountered: {ref=}; {sim=}')

            rel_error = abs(sim - ref) / ref
            rel_errors.append(rel_error)
            ref_cycles_list.append(ref)
            sim_cycles_list.append(sim)

        metrics = dict(
                min_error = min(rel_errors),
                max_error = max(rel_errors),
                gm_error = gmean(rel_errors),
                gm1_error = gmean([r + 1 for r in rel_errors]) - 1,
                am_error = mean(rel_errors),
                median_error = median(rel_errors),
                pearson_corr = pearsonr(ref_cycles_list, sim_cycles_list)[0],
                spearman_corr = spearmanr(ref_cycles_list, sim_cycles_list)[0],
            )
        print(f"encountered {num_invalid} invalid run(s)")
        print(json.dumps(metrics, indent='  '))


    return 0

if __name__ == "__main__":
    sys.exit(main())
