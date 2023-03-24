from . import Predictor, PredictorConfigError, PWManager

from copy import deepcopy
import os
import re
import json
import subprocess
import tempfile
import textwrap
from timeit import default_timer as timer

import logging
logger = logging.getLogger(__name__)


class NanoBenchPredictor(Predictor):
    """
    Use nanoBench to measure the number of cycles required to execute the basic
    block.

    Requires sudo permissions and needs to run alone to avoid measurement
    noise. It is strongly recommended to also disable hyperthreading/
    simultaneous multi-threeading before using this predictor.

    Predictor options:

    * `result_key`: key of the performance counter in nanoBench's output to use
    * `nanobench_path`: the path to the nanobench.sh script
    * `nanobench_opts`: a list of command line options to nanoBench, e.g., `["-config", "${NANOBENCH_BASE}/configs/cfg_Skylake_common.txt"]`
    * `timeout`: a timeout for subprocess calls in seconds
    * `num_samples`: take the minimum of this many runs of nanoBench
    * `aggregator`: aggregation method to use among the samples ("median" or "min")
    """
    predictor_name = "nanobench"
    predictor_options = [
            "result_key", # key of the performance counter in nanoBench's output to use
            "additional_counters", # dictionary mapping identifiers to the counter name (as given in the nanobench config)
            "nanobench_path", # path to the nanobench.sh script
            "nanobench_opts", # list of options to nanobench, e.g. ["-config", "${NANOBENCH_BASE}/configs/cfg_Skylake_common.txt"]
            "timeout", # a timeout for subprocess calls in seconds
            "num_samples", # take the minimum of this many runs of nanoBench
            "aggregator", # a timeout for subprocess calls in seconds
        ]

    aggregator_funs = { "min", "median", }

    def __init__(self, result_key, additional_counters, nanobench_path, nanobench_opts, timeout, num_samples, aggregator):
        self.result_key = result_key
        self.additional_counters = additional_counters
        self.base_path = os.path.dirname(nanobench_path)
        self.nanobench_script = os.path.basename(nanobench_path)

        # nanobench_opts may either be a list of strings or a list of lists of
        # strings. We normalize it to the latter case:
        if len(nanobench_opts) != 0:
            if isinstance(nanobench_opts[0], str):
                option_lists = [nanobench_opts]
            else:
                option_lists = nanobench_opts
        else:
            option_lists = []

        self.nanobench_opts = [
                    list(map(lambda x: x.replace("${NANOBENCH_BASE}", self.base_path), ol)) for ol in option_lists
                ]
        self.timeout = timeout
        self.num_samples = num_samples

        if aggregator not in self.aggregator_funs:
            raise PredictorConfigError(f"Invalid aggregator: {aggregator}")
        self.aggregator = aggregator

        # regular expression for extracting the number of cycles from nanobench's output
        self.parsing_re = re.compile(f"{self.result_key}" + r": (-?\d+\.\d+)")

        self.additional_counter_res = [
                (k, re.compile(f"{counter}" + r": (\d+\.\d+)"))
                for k, counter in self.additional_counters.items()
            ]

    def requires_sudo(self):
        return True

    def needs_to_run_alone(self):
        return True

    @staticmethod
    def from_config(config):
        nanobench_opts = config["nanobench_opts"]
        nanobench_path = config["nanobench_path"]
        result_key = config["result_key"]
        additional_counters = config["additional_counters"]
        timeout = config["timeout"]
        num_samples = config["num_samples"]
        aggregator = config["aggregator"]
        if not os.path.isfile(nanobench_path):
            err_str = "no nanobench.sh script found at specified path '{}'".format(nanobench_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return NanoBenchPredictor(result_key, additional_counters, nanobench_path, nanobench_opts, timeout, num_samples, aggregator)

    def evaluate(self, basic_block, disable_logging=False, *, add_details=False):

        if PWManager.password is None:
            raise PredictorConfigError("Trying to run nanoBench without sudo password!")

        # we do not want the block to be wrapped in a loop, since nanoBench adds its own loop
        asm_str = '; '.join(basic_block.get_asm(unwrapped=True).split('\n'))

        timeout = self.timeout

        # We perform two levels of aggregation:
        # (1) We try different nanobench configs. The goal is to have one in
        #     there that achieves optimal throughput. We want to take the
        #     result of the config that executes in the minimal number of
        #     cycles.
        # (2) For each of these configs, we run a number of samples. The
        #     purpose of that is to handle CPUs that produce messy, noisy
        #     measurements (looking at you, Zen+...). Since we cannot assume
        #     that we will always measure things take at least as long as an
        #     optimal execution (we even observed executions with a negative
        #     number of cycles!), the median is a better choice for such cases.
        #     This aggregation function is however configurable with the
        #     `aggregator` config option. For architectures with more reliable
        #     measurements, `minimum` is a viable option here.
        #
        # `all_results` contains ALL run results
        # `chosen_results` contains for each config one result that has been
        #   chosen according to aggregation (2). Aggregation (1) is performed
        #   on this list.

        chosen_results = []
        all_results = []

        rt = 0

        for nb_opt in self.nanobench_opts:
            cmd = ['sudo', '-S', './' + self.nanobench_script]
            cmd.extend(('-asm', asm_str))
            cmd.extend(nb_opt)

            logger.debug(f"nanoBench command (with cwd={self.base_path}):\n" + ' '.join(map(lambda x: f'"{x}"', cmd)))

            sample_results = []
            for it in range(self.num_samples):
                try:
                    start = timer()
                    res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout, cwd=self.base_path, input=PWManager.password)
                    end = timer()
                    rt += end - start

                    if res.returncode != 0:
                        err_str = "nanoBench call failed:\n  stdout:\n"
                        err_str += textwrap.indent(res.stdout, 4*' ')
                        err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                        if not disable_logging:
                            logger.error(err_str)
                        sample_results.append({ 'TP': -1.0, 'error': err_str, 'nb_command': " ".join(map(repr, cmd)), 'rt': rt })
                        continue
                except subprocess.TimeoutExpired:
                        err_str = f"nanoBench call hit the timeout of {timeout} seconds"
                        if not disable_logging:
                            logger.error(err_str)
                        sample_results.append({ 'TP': -1.0, 'error': err_str, 'nb_command': " ".join(map(repr, cmd))})
                        continue

                str_res = res.stdout

                # parse nanoBenchs's results
                m = self.parsing_re.search(str_res)
                if m is None:
                    out_str = "nanoBench output:\n  stdout:\n"
                    out_str += textwrap.indent(res.stdout, 4*' ')
                    out_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    sample_result = { 'TP': -1.0, 'error': "throughput missing in nanoBench output", 'rt': rt, 'nb_command': " ".join(map(repr, cmd)), 'nb_output': out_str }
                    sample_results.append(sample_result)
                    if not disable_logging:
                        logger.debug("nanobench result:\n  " + json.dumps(sample_result))
                    continue

                tp_val = float(m.group(1))

                if tp_val < 0.0:
                    out_str = "nanoBench output:\n  stdout:\n"
                    out_str += textwrap.indent(res.stdout, 4*' ')
                    out_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    sample_result = { 'TP': -1.0, 'error': "negative throughput in nanoBench output", 'rt': rt, 'nb_command': " ".join(map(repr, cmd)), 'nb_output': out_str }
                    sample_results.append(sample_result)
                    if not disable_logging:
                        logger.debug("nanobench result:\n  " + json.dumps(sample_result))
                    continue

                result = {'TP': tp_val}

                for k, pat in self.additional_counter_res:
                    m = pat.search(str_res)
                    if m is None:
                        result[k] = -1.0
                    else:
                        result[k] = float(m.group(1))

                if add_details:
                    result['nb_command'] = " ".join(map(repr, cmd))

                if not disable_logging:
                    logger.debug("nanobench result:\n  " + json.dumps(result))

                sample_results.append(result)

            # level (2) of aggregation, configurable
            sorted_results = sorted(sample_results, key=lambda x: x['TP'])
            if self.aggregator == "min":
                chosen_result = sorted_results[0]
            elif self.aggregator == "median":
                chosen_result = sorted_results[len(sorted_results)//2]
            else:
                assert False, f"aggregator {self.aggregator} not handled!"

            chosen_results.append(chosen_result)
            all_results += sample_results

        # level (1) of aggregation, min
        res = min(chosen_results, key=lambda x: x['TP'])

        res['rt'] = rt
        if add_details:
            res = deepcopy(res) # avoid a recursive datastructure
            res['chosen_results'] = sorted_results
            res['all_results'] = sorted(all_results, key=lambda x: x['TP'])
        return res


