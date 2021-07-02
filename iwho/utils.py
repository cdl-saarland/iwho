""" Helper classes and functions for iwho
"""


from collections import defaultdict

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
    import logging
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(loglevel))
    kwargs = {
            "format": '%(asctime)s - %(levelname)s:%(name)s: %(message)s',
            "level": numeric_level,
        }

    if logfile is not None:
        kwargs["filename"] = logfile

    logging.basicConfig(**kwargs)

def parse_args_with_logging(argparser, default_loglevel="warning"):
    loglevels = ["debug", "info", "warning", "error"]
    argparser.add_argument("-l", "--loglevel", choices=loglevels, default=default_loglevel,
            help="configures the amount of logging information to print")
    argparser.add_argument("--logfile", default=None,
            help="print logs to this file, stdout if none is given")

    args = argparser.parse_args()

    init_logging(args.loglevel, args.logfile)

    return args