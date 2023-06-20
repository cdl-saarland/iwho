"""

Ultimately, this implementation is based on work by Kallistos Weis.
"""

import json
import os
from pathlib import Path
import re
import textwrap
import subprocess
import tempfile
from timeit import default_timer as timer

from iwho.predictors import Predictor, PredictorConfigError, PWManager

import logging
logger = logging.getLogger(__name__)

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pite_frame.c')) as f:
    program_frame = f.read()


def fmt_output(res):
    err_str = "  stdout:\n"
    err_str += textwrap.indent(res.stdout, 4*' ')
    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
    return err_str

# Things that PITE cannot benchmark:
# - anything affecting rsp, including push and pop, since they could mess up
#   the local variables of the benchmarking code

# Using PITE to count uops requires the 'msr-tools' package.
# Make sure to run ../../scripts/pite_setup.sh before using PITE for the first
# time in a boot.

class PITEPredictor(Predictor):
    predictor_name = "pite"
    predictor_options = [
            "isa", # the architecture the basic blocks are from, currently supported: 'x86'
            "pinned_core", # processor core to run benchmarks on
            "timeout", # a timeout for subprocess calls in seconds
            "aggregator", # aggregation method to use among the samples ("median" or "min")
            "compiler_cmd", # a compiler command, with arguments listed
            "freq_threshold", # runs are rejected if their pre and post frequency differs by more than this value times their average
            "subconfigs", # a list of dictionaries with keys "target_usec" (the target time in microseconds that the code should be executed), "num_samples_internal" (how often this subconfig should be executed, taking the minimum result)
        ]

    def requires_sudo(self):
        return True

    def needs_to_run_alone(self):
        return True

    def __init__(self, config):
        for opt in self.predictor_options:
            setattr(self, opt, config[opt])

    @staticmethod
    def from_config(config):
        return PITEPredictor(config)

    def evaluate(self, basic_block, disable_logging=False, *, add_details=False, dvars=dict(), excessive_log=None):

        if PWManager.password is None:
            raise PredictorConfigError("Trying to run PITE without sudo privileges!")

        timeout = self.timeout

        with tempfile.TemporaryDirectory(prefix="PITEbench_") as work_dir_name:
            work_dir = Path(work_dir_name)
            src_path = work_dir / 'bench.c'
            bin_path = work_dir / 'bench.bin'

            # generate benchmark code in file with unique name

            bench_code_lines = []
            for line in basic_block.get_asm(unwrapped=True).split('\n'):
                bench_code_lines.append('        "    {}\\n"'.format(line))

            bench_code = "\n".join(bench_code_lines)

            rt = 0.0

            all_results = []

            for subconfig_id, subconfig in enumerate(self.subconfigs):
                target_usec = subconfig['target_usec']
                num_samples_internal = subconfig['num_samples_internal']
                replacements = {
                    "PLACEHOLDER_TARGET_USEC": str(target_usec),
                    "PLACEHOLDER_NUM_REPS": str(num_samples_internal),
                    "PLACEHOLDER_PINNED_CORE": str(self.pinned_core),
                    "PLACEHOLDER_BENCH_CODE": bench_code,
                }
                instantiated_frame = program_frame
                for k, v in replacements.items():
                    instantiated_frame = instantiated_frame.replace(k, v)

                with open(src_path, 'w') as f:
                    f.write(instantiated_frame)

                # compile benchmark code
                cmd = self.compiler_cmd + ('-DUSE_PERF_COUNTERS=1',
                                           '-DINIT_ADDITIONAL_MEM_REGS=1',
                                           '-o', bin_path, src_path)

                # set macro values in the C code via compiler flags
                for k, v in dvars.items():
                    cmd = cmd + (f'-D{k}={v}',)

                try:
                    res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
                except subprocess.TimeoutExpired:
                    err_str = f"PITE template compilation hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str})

                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': None,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': -1.0,
                                'num_uops': -1.0,
                                'res_entry': None,
                                'msg': err_str,
                            }
                        excessive_log.append(excessive_entry)
                    continue

                if res.returncode != 0:
                    err_str = f"failed to compile the PITE source template:\n" + fmt_output(res)
                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': None,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': -1.0,
                                'num_uops': -1.0,
                                'res_entry': None,
                                'msg': err_str,
                            }
                        excessive_log.append(excessive_entry)

                    err_str += "  source code:" + textwrap.indent(instantiated_frame, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str})
                    continue

                # run benchmark code
                try:
                    # we use the timeout command instead of the timeout option
                    # of subprocess.run here since the latter apparently cannot
                    # handle timeouting processes with root privileges, which
                    # would lead to failing timeouts
                    cmd = ["sudo", "-S",
                           "timeout", "-k", str(timeout*1.5), str(timeout),
                           "taskset", "-c", str(self.pinned_core),
                           bin_path]
                    start = timer()
                    res = subprocess.run(cmd, capture_output=True, encoding="latin1", input=PWManager.password)
                    end = timer()
                    rt += end - start
                except subprocess.TimeoutExpired:
                    err_str = f"PITE call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str})
                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': None,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': -1.0,
                                'num_uops': -1.0,
                                'res_entry': None,
                                'msg': err_str,
                            }
                        excessive_log.append(excessive_entry)
                    continue

                if res.returncode != 0:
                    err_str = "PITE benchmark run failed:\n" + fmt_output(res)
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str, 'rt': rt })
                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': None,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': -1.0,
                                'num_uops': -1.0,
                                'res_entry': None,
                                'msg': err_str,
                            }
                        excessive_log.append(excessive_entry)
                    continue

                try:
                    str_res = res.stdout
                    res_data = json.loads(str_res)

                except:
                    err_str = "PITE benchmark run had invalid result:\n  stdout:\n"
                    err_str += textwrap.indent(res.stdout, 4*' ')
                    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str, 'rt': rt })
                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': None,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': -1.0,
                                'num_uops': -1.0,
                                'res_entry': None,
                                'msg': err_str,
                            }
                        excessive_log.append(excessive_entry)
                    continue

                valid_results = []
                for internal_res_id, res_entry in enumerate(res_data):
                    if excessive_log is not None:
                        excessive_entry = {
                                'predictor': "PITE",
                                'subconfig_id': subconfig_id,
                                'internal_res_id': internal_res_id,
                                'target_usec': target_usec,
                                'num_samples_internal': num_samples_internal,
                                'cycles': res_entry["cycles_per_iteration"],
                                'num_uops': res_entry["perf_counter_per_iteration"],
                                'res_entry': res_entry,
                                'msg': None,
                            }
                        excessive_log.append(excessive_entry)
                    if abs(res_entry["freq_early_kHz"] - res_entry["freq_late_kHz"]) > self.freq_threshold * res_entry["avg_freq_kHz"]:
                        logger.warning('discarding run because of unstable clock frequency:\n  before measurements: {} kHz\n  after measurements: {} kHz\n  average: {} kHz'.format(res_entry["freq_early_kHz"], res_entry["freq_late_kHz"], res_entry["avg_freq_kHz"]))
                        res_entry["discarded"] = True
                        if excessive_log is not None:
                            excessive_entry['msg'] = 'discarded because of unstable clock frequency'
                        continue
                    if res_entry["total_perf_counter"] > 2**48: # uneducated overflow check
                        logger.warning('discarding run because of likely perf counter overflow:\n  value: {}'.format(res_entry["total_perf_counter"]))
                        res_entry["discarded"] = True
                        if excessive_log is not None:
                            excessive_entry['msg'] = 'discarded because of likely perf counter overflow'
                        continue
                    valid_results.append({"cycles": res_entry["cycles_per_iteration"], "perf_counter": res_entry["perf_counter_per_iteration"]})

                if len(valid_results) < len(res_data) / 2:
                    err_str = "discarded more than half of the PITE benchmark runs"
                    if not disable_logging:
                        logger.error(err_str)
                    all_results.append({ 'TP': -1.0, 'error': err_str, 'rt': rt })
                    continue

                sorted_results = sorted(valid_results, key=lambda x: x['cycles'])
                if self.aggregator == "min":
                    chosen_result = sorted_results[0]
                elif self.aggregator == "median":
                    chosen_result = sorted_results[len(sorted_results)//2]
                else:
                    assert False, f"aggregator {self.aggregator} not handled!"

                agg_cycles_per_iteration = chosen_result['cycles']
                agg_perf_counter_per_iteration = chosen_result['perf_counter']

                agg_perf_counter_per_iteration -= 2 # the SUB and JNZ instructions from the benchmarking loop

                all_results.append({
                    'TP': agg_cycles_per_iteration,
                    'num_uops': agg_perf_counter_per_iteration,
                    'run_details': res_data})

        chosen_results = all_results

        non_negative_results = [ r for r in chosen_results if r['TP'] >= 0 ]

        if len(non_negative_results) > 0:
            res = min(non_negative_results, key=lambda x: x['TP'])
            if len(non_negative_results) < len(chosen_results):
                res['negative_results_omitted'] = True
                logger.warning("some broken runs were omitted")
        else:
            res = min(chosen_results, key=lambda x: x['TP'])
            logger.warning("only broken runs observed")

        res['rt'] = rt
        if add_details:
            pass
            # res = deepcopy(res) # avoid a recursive datastructure
            # res['chosen_results'] = chosen_results
            # res['all_results'] = sorted(all_results, key=lambda x: x['TP'])
        return res


