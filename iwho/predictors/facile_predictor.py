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


class FacilePredictor(Predictor):
    """
    Use facile to estimate the number of cycles required to execute the basic
    block.

    Predictor options:

    * `script_path`: the path to the facile executable
    * `run_opts`: a list of command line options to the script, e.g., `["-arch", "SKL"]`
    * `timeout`: a timeout for subprocess calls in seconds
    """

    predictor_name = "facile"
    predictor_options = [
            "script_path", # path to the facile executable
            "run_opts", # list of options to facile, e.g. ["-arch", "SKL"]
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from facile's output
    parsing_re = re.compile(r"(\d+\.\d+)")

    def __init__(self, config):
        for opt in self.predictor_options:
            setattr(self, opt, config[opt])

        if not os.path.isfile(self.script_path):
            err_str = "no facile.py script found at specified path '{}'".format(self.script_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

    @staticmethod
    def from_config(config):
        return FacilePredictor(config)

    def evaluate(self, basic_block, disable_logging=False):

        hex_str = basic_block.get_hex()
        timeout = self.timeout

        try:
            cmd = [self.script_path]
            cmd.extend(self.run_opts)
            cmd.extend(['-hex', hex_str])
            start = timer()
            res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
            end = timer()
            rt = end - start

            if res.returncode != 0:
                err_str = "facile call failed:\n  stdout:\n"
                err_str += textwrap.indent(res.stdout, 4*' ')
                err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str, 'rt': rt }
        except subprocess.TimeoutExpired:
                err_str = f"facile call hit the timeout of {timeout} seconds"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str}

        str_res = res.stdout

        # parse the results
        m = self.parsing_re.search(str_res)
        if m is None:
            return { 'TP': -1.0, 'error': "throughput missing in facile output", 'rt': rt }

        tp = float(m.group(1))
        return {"TP": tp, 'rt': rt}
