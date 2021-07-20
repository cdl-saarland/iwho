from . import Predictor, PredictorConfigError

import binascii
import os
import re
import subprocess
import textwrap
from timeit import default_timer as timer

import logging
logger = logging.getLogger(__name__)


class LLVMMCAPredictor(Predictor):
    predictor_name = "llvmmca"
    predictor_options = [
            "llvmmca_path", # path to the llvmmca binary
            "llvmmca_opts", # list of options to llvm-mca, e.g. ["-mcpu", "skylake"]
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from llvm-mca's output
    parsing_re = re.compile(r"Total Cycles:\s*(\d+)")

    def __init__(self, llvmmca_path, llvmmca_opts, timeout):
        self.llvmmca_path = llvmmca_path
        self.llvmmca_opts = llvmmca_opts
        self.timeout = timeout

    @staticmethod
    def from_config(config):
        llvmmca_opts = config["llvmmca_opts"]
        llvmmca_path = config["llvmmca_path"]
        timeout = config["timeout"]
        if not os.path.isfile(llvmmca_path):
            err_str = "no llvmmca binary found at specified path '{}'".format(llvmmca_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return LLVMMCAPredictor(llvmmca_path, llvmmca_opts, timeout)

    def evaluate(self, basic_block, disable_logging=False):
        """ Use llvmmca to estimate the number of cycles required to execute
        the basic block.

        Annotations are ignored, llvmmca only uses the encoded instructions.
        """

        asm_str = basic_block.get_asm()
        asm_str = ".intel_syntax noprefix\n" + asm_str

        cmd = [self.llvmmca_path]
        cmd.extend(self.llvmmca_opts)

        timeout = self.timeout

        try:
            start = timer()
            res = subprocess.run(cmd, input=asm_str, capture_output=True, encoding="latin1", timeout=timeout)

            end = timer()
            rt = end - start

            if res.returncode != 0:
                err_str = "llvm-mca call failed:\n  stdout:\n"
                err_str += textwrap.indent(res.stdout, 4*' ')
                err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str, 'rt': rt}
        except subprocess.TimeoutExpired:
                err_str = f"llvm-mca call hit the timeout of {timeout} seconds"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str}

        str_res = res.stdout

        # parse llvm-mca's results
        m = self.parsing_re.search(str_res)
        if m is None:
            return { 'TP': -1.0, 'error': "throughput missing in llvm-mca output", 'rt': rt }

        tp = float(m.group(1)) / 100
        # llvm-mca delivers the cycles for 100 iterations
        return {"TP": tp, 'rt': rt}

