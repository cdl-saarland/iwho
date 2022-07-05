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


class UICAPredictor(Predictor):
    """
    Use uiCA to estimate the number of cycles required to execute the basic
    block.

    Predictor options:

    * `uica_path`: the path to the uiCA executable
    * `uica_opts`: a list of command line options to llvm-mca, e.g., `["-arch", "SKL"]`
    * `timeout`: a timeout for subprocess calls in seconds
    """

    predictor_name = "uica"
    predictor_options = [
            "uica_path", # path to the uiCA executable
            "uica_opts", # list of options to uiCA, e.g. ["-arch", "SKL"]
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from uiCA's output
    parsing_re = re.compile(r"(\d+\.\d+)")

    def __init__(self, config):
        for opt in self.predictor_options:
            setattr(self, opt, config[opt])

        if not os.path.isfile(self.uica_path):
            err_str = "no uica.py script found at specified path '{}'".format(self.uica_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

    @staticmethod
    def from_config(config):
        return UICAPredictor(config)

    def evaluate(self, basic_block, disable_logging=False):

        hex_str = basic_block.get_hex()

        byte_str = binascii.unhexlify(hex_str.encode('latin1'))

        timeout = self.timeout

        # Write the prepared byte string into a temporary file and run uiCA on
        # it.
        # Using a temporary file like this only works on Unix. Windows would
        # not allow the tool to concurrently open the temporary file.
        # The temporary file is deleted when it's closed.
        with tempfile.NamedTemporaryFile("wb") as tmp_file:
            tmp_file.write(byte_str)
            tmp_file.flush()
            tmp_name = tmp_file.name

            try:
                cmd = [self.uica_path]
                cmd.extend(self.uica_opts)
                cmd.extend(('-TPonly', '-raw'))
                cmd.append(tmp_name)
                start = timer()
                res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
                end = timer()
                rt = end - start

                if res.returncode != 0:
                    err_str = "uiCA call failed:\n  stdout:\n"
                    err_str += textwrap.indent(res.stdout, 4*' ')
                    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str, 'rt': rt }
            except subprocess.TimeoutExpired:
                    err_str = f"uiCA call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str}

            str_res = res.stdout

        # parse uiCA's results
        m = self.parsing_re.search(str_res)
        if m is None:
            return { 'TP': -1.0, 'error': "throughput missing in uica output", 'rt': rt }

        tp = float(m.group(1))
        return {"TP": tp, 'rt': rt}

