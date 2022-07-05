from . import Predictor, PredictorConfigError

import binascii
import os
import re
import shutil
import subprocess
import textwrap
from timeit import default_timer as timer

import logging
logger = logging.getLogger(__name__)


class OSACAPredictor(Predictor):
    """
    Use osaca to estimate the number of cycles required to execute the basic
    block.

    Annotations are ignored, osaca only uses the encoded instructions.

    Predictor options:

    * `osaca_path`: the path to the osaca executable
    * `osaca_opts`: a list of command line options to osaca, e.g., `["--arch", "SKL"]`
    * `llvmmc_path`: the path to llvm-mc (used to assemble with AT&T syntax)
    * `timeout`: a timeout for subprocess calls in seconds
    """

    predictor_name = "osaca"
    predictor_options = [
            "osaca_path", # path to the osaca binary
            "osaca_opts", # list of options to osaca, e.g. ["--arch", "SKL"]
            "llvmmc_path", # path to llvm-mc (used to assemble with AT&T syntax)
            "timeout", # a timeout for subprocess calls in seconds
        ]

    # regular expression for extracting the number of cycles from osaca's output
    parsing_re = re.compile(r"Total Cycles:\s*(\d+)")

    def __init__(self, osaca_path, osaca_opts, llvmmc_path, timeout):
        self.osaca_path = osaca_path
        self.osaca_opts = osaca_opts
        self.llvmmc_path = llvmmc_path
        self.timeout = timeout

    @staticmethod
    def from_config(config):
        osaca_opts = config["osaca_opts"]
        osaca_path = config["osaca_path"]
        llvmmc_path = config["llvmmc_path"]
        timeout = config["timeout"]
        if shutil.which(osaca_path) is None:
            err_str = "no osaca binary found at specified path '{}'".format(osaca_path)
            logger.error(err_str)
            raise PredictorConfigError(err_str)

        return OSACAPredictor(osaca_path, osaca_opts, llvmmc_path, timeout)

    def evaluate(self, basic_block, disable_logging=False):

        orig_asm_str = basic_block.get_asm()
        orig_asm_str = ".intel_syntax noprefix\n" + orig_asm_str

        timeout = self.timeout

        # First, use llvm-mc to convert this from our Intel syntax to osaca's
        # AT&T syntax.

        cmd = [self.llvmmc_path, '--arch=x86-64', '--assemble', '--filetype=asm']

        try:
            res = subprocess.run(cmd, input=orig_asm_str, capture_output=True, encoding="latin1", timeout=timeout)

            if res.returncode != 0:
                err_str = "llvm-mc call for converting assembly for osaca failed:\n  stdout:\n"
                err_str += textwrap.indent(res.stdout, 4*' ')
                err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str}
        except subprocess.TimeoutExpired:
                err_str = f"llvm-mc call for converting assembly for osaca hit the timeout of {timeout} seconds"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str}

        att_asm = res.stdout

        cmd = [self.osaca_path]
        cmd.extend(self.osaca_opts)
        cmd.append('-') # read from stdin

        timeout = self.timeout

        try:
            start = timer()
            res = subprocess.run(cmd, input=att_asm, capture_output=True, encoding="latin1", timeout=timeout)

            end = timer()
            rt = end - start

            if res.returncode != 0:
                err_str = "osaca call failed:\n  stdout:\n"
                err_str += textwrap.indent(res.stdout, 4*' ')
                err_str += "\n  stderr:" + textwrap.indent(res.stderr, 4*' ') + "\n"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str, 'rt': rt}
        except subprocess.TimeoutExpired:
                err_str = f"osaca call hit the timeout of {timeout} seconds"
                if not disable_logging:
                    logger.error(err_str)
                return { 'TP': -1.0, 'error': err_str}

        str_res = res.stdout

        # parse osaca's results

        # The extraction of throughput is based on the code here:
        # https://github.com/RRZE-HPC/kerncraft/blob/1686f85555a92dbf91a3e8ed3aa1b1613c284bc7/kerncraft/incore_model.py#L667
        # There, the throughput is the maximum of all port pressures and the loop-carried dependency result.
        lines = str_res.split('\n')

        # look for the last non-empty line before the LCD analysis report
        validate_next = False
        validated = False
        prev_non_empty_line = None
        summary_line = None
        for idx, l in enumerate(lines):
            if validate_next:
                # This checks that the table actually contains the data that we expect
                validated = "".join(l.split()).endswith('||CP|LCD|')
                validate_next = False
            elif 'Port pressure in cycles' in l:
                validate_next = True
            elif 'Loop-Carried Dependencies Analysis Report' in l:
                summary_line = prev_non_empty_line
                break
            if len(l) > 0:
                prev_non_empty_line = l

        if summary_line is None or not validated:
            return { 'TP': -1.0, 'error': "could not assemble throughput from osaca output", 'rt': rt }

        # this should only contain decimal numbers and whitespace

        entries = summary_line.split()
        try:
            entries = list(map(float, entries))
        except ValueError:
            return { 'TP': -1.0, 'error': "could not assemble throughput from osaca output", 'rt': rt }

        # The second to last entry is the critical path length, which is an
        # upper bound to the throughput according to the OSACA devs (which
        # sounds implausible), so we don't take that one into the maximum.

        if len(entries) < 2:
            return { 'TP': -1.0, 'error': "could not assemble throughput from osaca output", 'rt': rt }

        if len(entries) == 2:
            # if no information is available for any instruction, there will be no port usage
            tp = entries[-1]
        else:
            tp = max(entries[:-2] + [entries[-1]])

        return {"TP": tp, 'rt': rt}


