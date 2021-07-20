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


class IACAPredictor(Predictor):
    predictor_name = "iaca"
    predictor_options = [
            "iaca_path", # path to the IACA binary
            "iaca_opts", # list of options to IACA, e.g. ["-arch", "SKL"]
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # magic iaca markers, to be placed before and after benchmarked kernel
    marker_start = "BB6F000000646790" # mov ebx, 111; .byte 0x64, 0x67, 0x90
    marker_end = "BBDE000000646790"   # mov ebx, 222; .byte 0x64, 0x67, 0x90

    # regular expression for extracting the number of cycles from IACA's output
    parsing_re = re.compile(r"Block Throughput: (\d+\.\d+)")

    def __init__(self, iaca_path, iaca_opts, timeout):
        self.iaca_path = iaca_path
        self.iaca_opts = iaca_opts
        self.timeout = timeout

    @staticmethod
    def from_config(config):
        iaca_opts = config["iaca_opts"]
        iaca_path = config["iaca_path"]
        timeout = config["timeout"]
        if not os.path.isfile(iaca_path):
            err_str = "no iaca binary found at specified path '{}'".format(iaca_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return IACAPredictor(iaca_path, iaca_opts, timeout)

    def evaluate(self, basic_block, disable_logging=False):
        """
            Use IACA to estimate the number of cycles required to execute the
            basic block.
            Annotations are ignored, IACA only uses the encoded instructions.
        """

        hex_str = basic_block.get_hex()

        # pre/append iaca marker bytes
        hex_str = self.marker_start + hex_str + self.marker_end
        byte_str = binascii.unhexlify(hex_str.encode('latin1'))

        timeout = self.timeout

        # Write the prepared byte string into a temporary file and run IACA on
        # it.
        # Using a temporary file like this only works on Unix. Windows would
        # not allow IACA to concurrently open the temporary file.
        # The temporary file is deleted when it's closed.
        with tempfile.NamedTemporaryFile("wb") as tmp_file:
            tmp_file.write(byte_str)
            tmp_file.flush()
            tmp_name = tmp_file.name

            try:
                cmd = [self.iaca_path]
                cmd.extend(self.iaca_opts)
                cmd.append(tmp_name)
                start = timer()
                res = subprocess.run(cmd, capture_output=True, encoding="latin1", timeout=timeout)
                end = timer()
                rt = end - start

                if res.returncode != 0:
                    err_str = "IACA call failed:\n  stdout:\n"
                    err_str += textwrap.indent(res.stdout, 4*' ')
                    err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str, 'rt': rt }
            except subprocess.TimeoutExpired:
                    err_str = f"IACA call hit the timeout of {timeout} seconds"
                    if not disable_logging:
                        logger.error(err_str)
                    return { 'TP': -1.0, 'error': err_str}

            str_res = res.stdout

        # parse IACA's results
        m = self.parsing_re.search(str_res)
        if m is None:
            return { 'TP': -1.0, 'error': "throughput missing in iaca output", 'rt': rt }

        tp = float(m.group(1))
        return {"TP": tp, 'rt': rt}

