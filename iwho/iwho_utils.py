""" Helper classes and functions for iwho
"""


from collections import defaultdict


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
