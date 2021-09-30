from . import Predictor, PredictorConfigError

import binascii
import os
import re
import subprocess
import tempfile
import textwrap
from timeit import default_timer as timer

import logging
logger = logging.getLogger(__name__)


class NanoBenchPredictor(Predictor):
    predictor_name = "nanobench"
    predictor_options = [
            "nanobench_path", # path to the nanobench.sh script
            "nanobench_opts", # list of options to nanobench, e.g. ["-config", "${BASE}/configs/cfg_Skylake_common.txt"]
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from nanobench's output
    parsing_re = re.compile(r"Core cycles: (\d+\.\d+)")

    def __init__(self, nanobench_path, nanobench_opts, timeout):
        self.nanobench_path = nanobench_path
        base_path = os.path.dirname(nanobench_path)
        self.nanobench_opts = list(map(lambda x: x.replace("${BASE}", base_path), nanobench_opts))
        self.timeout = timeout

    @staticmethod
    def from_config(config):
        nanobench_opts = config["nanobench_opts"]
        nanobench_path = config["nanobench_path"]
        timeout = config["timeout"]
        if not os.path.isfile(nanobench_path):
            err_str = "no nanobench.sh script found at specified path '{}'".format(nanobench_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return NanoBench(nanobench_path, nanobench_opts, timeout)

    def evaluate(self, basic_block, disable_logging=False):
        """
            Use nanobench to measure the number of cycles required to execute
            the basic block.
        """

        asm_str = '; '.join(basic_block.get_asm().split('\n'))

        timeout = self.timeout

        try:
            cmd = [self.nanobench_path]
            cmd.extend(('-asm', asm_str))
            cmd.extend(self.nanobench_opts)

            start = timer()
            res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
            end = timer()
            rt = end - start

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

        tp = float(m.group(1))
        return {"TP": tp, 'rt': rt}


