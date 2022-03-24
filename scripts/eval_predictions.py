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

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def main():
    argparser = argparse.ArgumentParser(description=__doc__)

    # argparser.add_argument('-o', '--output', metavar="OUTFILE", default=None,
    #     help='the output file')

    argparser.add_argument('-g', '--groundtruth', metavar="COLNAME", default="nanobench",
        help='column name that is used as ground truth for the metrics. If no column matches exactly, one that includes the default is used.')

    argparser.add_argument('-f', '--filter-invalid', action="store_true",
        help='if provided, omit invalid runs (with <= 0.0 cycles) from consideration without crashing.')

    argparser.add_argument('-d', '--diff', metavar='baseline', default=None,
        help="print differences in the metrics between the different predictors with the provided column name's metrics acting as the base line")

    argparser.add_argument('-j', '--json-log', metavar='F', default=None,
        help="if specified, dump the detailed metrics to the given file in json format and do not print them")


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

    diff_metrics = None

    other_metrics = []

    all_metrics = dict()

    for k in keys:
        ref_cycles_list = []
        sim_cycles_list = []
        rel_errors = []
        rel_differences = []
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

            rel_diff = (abs(sim - ref) * 2) / (sim + ref)
            rel_differences.append(rel_diff)

        thresholds = [0.1, 0.2, 0.3, 0.5, 1.0]
        metrics = dict(
                gm_error = gmean(rel_errors),
                gm1_error = gmean([r + 1 for r in rel_errors]) - 1,
                median_error = median(rel_errors),
                mape = mean(rel_errors) * 100,
                pearson_R = pearsonr(ref_cycles_list, sim_cycles_list)[0],
                spearman_R = spearmanr(ref_cycles_list, sim_cycles_list)[0],
                **{ f'num_error_over_{t}': len(list(filter(lambda x: x >= t, rel_errors))) for t in thresholds },
                **{ f'num_difference_over_{t}': len(list(filter(lambda x: x >= t, rel_differences))) for t in thresholds },
            )
        all_metrics[k] = metrics

        print(f"encountered {num_invalid} invalid run(s)")

        if args.json_log is None:
            print(json.dumps(metrics, indent='  '))

        if args.diff == k:
            diff_metrics = metrics
        else:
            other_metrics.append((k, metrics))

    if args.json_log is not None:
        with open(args.json_log, 'w') as f:
            json.dump(all_metrics, f, indent='  ')

    if args.diff is not None:
        for k, metrics in other_metrics:
            print(f"Differences for {k}:")
            for l in metrics.keys():
                base = diff_metrics[l]
                curr = metrics[l]
                diff = curr - base
                if diff == 0.0:
                    col = bcolors.OKBLUE
                elif diff < 0.0:
                    # smaller errors are better
                    col = bcolors.OKGREEN
                elif diff > 0.0:
                    col = bcolors.FAIL
                print(f"  {col}{l+':':14} {diff:+}" + bcolors.ENDC)

    return 0

if __name__ == "__main__":
    sys.exit(main())
