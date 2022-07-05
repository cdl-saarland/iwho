from . import Predictor, PredictorConfigError, PWManager

import os
import re
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
    """
    predictor_name = "nanobench"
    predictor_options = [
            "result_key", # key of the performance counter in nanoBench's output to use
            "nanobench_path", # path to the nanobench.sh script
            "nanobench_opts", # list of options to nanobench, e.g. ["-config", "${NANOBENCH_BASE}/configs/cfg_Skylake_common.txt"]
            "timeout", # a timeout for subprocess calls in seconds
            "num_samples", # take the minimum of this many runs of nanoBench
        ]

    def __init__(self, result_key, nanobench_path, nanobench_opts, timeout, num_samples):
        self.result_key = result_key
        self.base_path = os.path.dirname(nanobench_path)
        self.nanobench_script = os.path.basename(nanobench_path)
        self.nanobench_opts = list(map(lambda x: x.replace("${NANOBENCH_BASE}", self.base_path), nanobench_opts))
        self.timeout = timeout
        self.num_samples = num_samples

        # regular expression for extracting the number of cycles from nanobench's output
        self.parsing_re = re.compile(f"{self.result_key}" + r": (\d+\.\d+)")

    def requires_sudo(self):
        return True

    def needs_to_run_alone(self):
        return True

    @staticmethod
    def from_config(config):
        nanobench_opts = config["nanobench_opts"]
        nanobench_path = config["nanobench_path"]
        result_key = config["result_key"]
        timeout = config["timeout"]
        num_samples = config["num_samples"]
        if not os.path.isfile(nanobench_path):
            err_str = "no nanobench.sh script found at specified path '{}'".format(nanobench_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return NanoBenchPredictor(result_key, nanobench_path, nanobench_opts, timeout, num_samples)

    def evaluate(self, basic_block, disable_logging=False):

        if PWManager.password is None:
            raise PredictorConfigError("Trying to run nanoBench without sudo password!")

        # we do not want the block to be wrapped in a loop, since nanoBench adds its own loop
        asm_str = '; '.join(basic_block.get_asm(unwrapped=True).split('\n'))

        timeout = self.timeout

        cmd = ['sudo', '-S', './' + self.nanobench_script]
        cmd.extend(('-asm', asm_str))
        cmd.extend(self.nanobench_opts)

        rt = 0

        tps = []

        logger.debug(f"nanoBench command (with cwd={self.base_path}):\n" + ' '.join(map(lambda x: f'"{x}"', cmd)))

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
                    return { 'TP': -1.0, 'error': err_str, 'rt': rt }
            except subprocess.TimeoutExpired:
                    err_str = f"nanoBench call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str}

            str_res = res.stdout

            # parse nanoBenchs's results
            m = self.parsing_re.search(str_res)
            if m is None:
                return { 'TP': -1.0, 'error': "throughput missing in nanoBench output", 'rt': rt }

            tps.append(float(m.group(1)))

        tp = min(tps)
        return {"TP": tp, 'rt': rt}


