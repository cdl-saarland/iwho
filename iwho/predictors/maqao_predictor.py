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


class MAQAOPredictor(Predictor):
    """
    Use MAQAO CQA to estimate the number of cycles required to execute the
    basic block. (Only applicable to basic blocks wrapped in explicit loops!)

    Predictor options:

    * `maqao_path`: the path to the maqao binary
    * `maqao_opts`: a list of command line options to maqao, e.g., `["--uarch", "SKYLAKE"]`
    * `as_path`: a path to an assembler to use, e.g. `"as"`
    * `timeout`: a timeout for subprocess calls in seconds
    """

    predictor_name = "maqao"
    predictor_options = [
            "maqao_path", # path to the maqao binary
            "maqao_opts", # list of options to maqao, e.g. ["--uarch", "SKYLAKE"]
            "as_path", # path to an assembler to use, e.g. "as"
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from maqao's output
    parsing_re = re.compile(r"Overall L1: (\d+\.\d+)")

    def __init__(self, config):
        for opt in self.predictor_options:
            setattr(self, opt, config[opt])

        if not os.path.isfile(self.maqao_path):
            err_str = "no maqao binary found at specified path '{}'".format(self.maqao_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

    @staticmethod
    def from_config(config):
        return MAQAOPredictor(config)

    def evaluate(self, basic_block, disable_logging=False):
        # basic_block.wrap_in_loop = True

        assert basic_block.wrap_in_loop, "MAQAO CQA can only handle loops!"

        asm_str = basic_block.get_asm()
        asm_str = ".intel_syntax noprefix\n" + asm_str

        timeout = self.timeout

        # Write the prepared byte string into a temporary file and run maqao on
        # it.
        # Using a temporary file like this only works on Unix. Windows would
        # not allow the tool to concurrently open the temporary file.
        # The temporary file is deleted when it's closed.
        with tempfile.NamedTemporaryFile("w") as tmp_file:
            tmp_file.write(asm_str)
            tmp_file.flush()
            tmp_name = tmp_file.name

            bin_name = tmp_name + ".bin"
            try:
                cmd = [self.as_path, "-o", bin_name, tmp_name]
                res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
                if res.returncode != 0:
                    err_str = "as call failed:\n  stdout:\n"
                    err_str += textwrap.indent(res.stdout, 4*' ')
                    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str, 'rt': 0.0 }
            except subprocess.TimeoutExpired:
                    err_str = f"as call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str}

            try:
                cmd = [self.maqao_path, "cqa"]
                cmd.extend(self.maqao_opts)
                cmd.append('--fct-loops=.*')
                cmd.append('--confidence-levels=expert')
                cmd.append(bin_name)
                start = timer()
                res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
                end = timer()
                rt = end - start

                if res.returncode != 0:
                    err_str = "maqao call failed:\n  stdout:\n"
                    err_str += textwrap.indent(res.stdout, 4*' ')
                    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str, 'rt': rt }
            except subprocess.TimeoutExpired:
                    err_str = f"maqao call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str}

            str_res = res.stdout

        # parse maqao's results
        m = self.parsing_re.search(str_res)
        if m is None:
            print(str_res)
            return { 'TP': -1.0, 'error': "throughput missing in maqao output", 'rt': rt }

        tp = float(m.group(1))
        return {"TP": tp, 'rt': rt}

