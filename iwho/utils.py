""" Helper classes and functions for iwho
"""


from collections import defaultdict

import logging
import sys


def export(fn):
    """ A decorator to automatically add the decorated object to the __all__
    list of the module (which describes what is imported in
    `from module import *` statements).
    """
    mod = sys.modules[fn.__module__]
    if hasattr(mod, '__all__'):
        mod.__all__.append(fn.__name__)
    else:
        mod.__all__ = [fn.__name__]
    return fn

class DedupStore:
    """ TODO document thouroughly
    """
    def __init__(self):
        self.stores = defaultdict(dict)

    def get(self, constructor, unhashed_kwargs=dict(), **kwargs):
        """ TODO document
        """
        store = self.stores[constructor]
        key = tuple(sorted(kwargs.items(), key=lambda x: x[0]))
        stored_res = store.get(key, None)
        if stored_res is not None:
            return stored_res
        new_res = constructor(**unhashed_kwargs, **kwargs)
        store[key] = new_res
        return new_res

def is_hex_str(hex_str: str) -> bool:
    try:
        int(hex_str, 16)
    except ValueError as e:
        return False
    return True


def init_logging(loglevel, logfile=None):
    """ Initialize the python logging facilities.

    `loglevel` should be a string from ["debug", "info", "warning", "error",
    "critical"], indicating what kind of logging messages to display.
    Logging is always printed to stderr, and, if it is not None, also to the
    file at `logfile`.

    Only call this function once per execution, subsequent calls will not do
    anything. If you want to change the logfile on the fly, use the
    `update_logfile` function instead.
    """
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(loglevel))

    handlers = [logging.StreamHandler()]
    if logfile is not None:
        handlers.append(logging.FileHandler(logfile))

    kwargs = {
            "format": '%(asctime)s - %(levelname)s:%(name)s: %(message)s',
            "level": numeric_level,
            "handlers": handlers,
        }

    logging.basicConfig(**kwargs)

def update_logfile(logfile=None):
    """ Change the logfile used by the logging facilities.

    This will remove any FileHandlers from the root logger and, if it is not
    None, will add a new handler for the specified `logfile`.
    StreamHandlers are not touched by this.

    Only use this function after initializing the logging facilities.
    """

    log = logging.getLogger()  # root logger

    for hdlr in log.handlers[:]:
        if isinstance(hdlr,logging.FileHandler):
            log.removeHandler(hdlr)

    if logfile is None:
        return

    new_filehandler = logging.FileHandler(logfile)
    log.addHandler(new_filehandler)


def parse_args_with_logging(argparser, default_loglevel="warning"):
    loglevels = ["debug", "info", "warning", "error"]
    argparser.add_argument("-l", "--loglevel", choices=loglevels, default=default_loglevel,
            help="configures the amount of logging information to print")
    argparser.add_argument("--logfile", default=None,
            help="print logs to this file, stdout if none is given")

    args = argparser.parse_args()

    init_logging(args.loglevel, args.logfile)

    return args
