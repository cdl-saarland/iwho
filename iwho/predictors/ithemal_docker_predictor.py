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


from pathlib import Path

import rpyc

def unwrap_netref(o):
    if isinstance(o, dict):
        return { unwrap_netref(k): unwrap_netref(o[k]) for k in o }
    elif isinstance(o, list):
        return [ unwrap_netref(v) for v in o]
    else:
        return o

class RemoteLink:
    def __init__(self, hostname, port, sslpath, request_timeout):
        sslpath = Path(sslpath)
        self.hostname = hostname
        self.port = port
        self.certfile = str(sslpath / "cert.pem")
        self.keyfile = str(sslpath / "key.pem")
        self.request_timeout = request_timeout

        self.conn = None

    def __enter__(self):
        # self.conn = rpyc.ssl_connect(self.hostname,
        #         port=self.port,
        #         keyfile=self.keyfile,
        #         certfile=self.certfile,
        #         config={'sync_request_timeout': self.request_timeout},
        #         )
        self.conn = rpyc.connect(self.hostname,
                port=self.port,
                config={'sync_request_timeout': self.request_timeout},
                )
        return self

    def __exit__(self, exc_info, exc_value, trace):
        self.conn.close()
        self.conn = None
        return

    def run_ithemal(self, model_path, byte_str):
        assert self.conn is not None, "Connection must be open!"
        try:
            return unwrap_netref(self.conn.root.run_ithemal(model_path, byte_str))
        except rpyc.AsyncResultTimeout:
            return {'TP': -1.0, 'error': 'RPyC request timeout'}


class IthemalDockerPredictor(Predictor):
    predictor_name = "ithemal_docker"
    predictor_options = [
            "host", # hostname of the ithemal docker container (probably 127.0.0.1)
            "port", # port where the ithemal docker container is listening
            "ssl_path", # path to a directory containing SSL certificates for connecting to the container
            "model", # path to the ithemal predictor model (in the container, e.g. 'bhive/skl')
            "timeout", # a timeout for rpyc calls in seconds
        ]

    # magic iaca markers, to be placed before and after benchmarked kernel
    marker_start = "BB6F000000646790" # mov ebx, 111; .byte 0x64, 0x67, 0x90
    marker_end = "BBDE000000646790"   # mov ebx, 222; .byte 0x64, 0x67, 0x90

    def __init__(self, host, port, ssl_path, model, timeout):
        self.host = host
        self.port = port
        self.ssl_path = ssl_path
        self.model = model
        self.timeout = timeout
        self.remote_link = RemoteLink(host, port, ssl_path, request_timeout=timeout)

    @staticmethod
    def from_config(config):
        host = config["host"]
        port = config["port"]
        ssl_path = config["ssl_path"]
        model = config["model"]
        timeout = config["timeout"]

        return IthemalDockerPredictor(host=host, port=port, ssl_path=ssl_path, model=model, timeout=timeout)

    def evaluate(self, basic_block, *args, **kwargs):
        hex_str = basic_block.get_hex()

        # pre/append iaca marker bytes
        hex_str = self.marker_start + hex_str + self.marker_end
        byte_str = binascii.unhexlify(hex_str.encode('latin1'))

        timeout = self.timeout

        with self.remote_link as rl:
            res = rl.run_ithemal(model_path=self.model, byte_str=byte_str)

        return res

