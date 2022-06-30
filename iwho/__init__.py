"""
IWHO: Instructions With Holes
"""

from functools import partial
import pickle

from .configurable import ConfigMeta
from .core import *

import logging
logger = logging.getLogger(__name__)

def _filter_uarch(scheme, ctx, uarch_name):
    return (ctx.get_features(scheme) is not None
        and uarch_name in ctx.get_features(scheme)[0]["measurements"])


class Config(metaclass=ConfigMeta):
    """ Helper class to configure iwho contexts.

    Since the Context is an abstract base class from which any actual context
    is derived, ConfigMeta hits its limits: Ideally, one would want to specify
    some general options in Context and some specific ones in the subclasses.
    While this might be possible with more metaclass hacking, it's not in the
    current focus.
    """
    config_options = dict(
        context_specifier = ('x86_uops_info',
            'identifier for the IWHO context to use'
            ),
        filters = ([{'kind': 'no_cf'}],
            'a list of filters to restrict the InsnSchemes used for sampling.'
            ),
    )
    # as the file_path keys end in '_path', storing and loading them as json
    # makes their values absolute and relative as necessary

    def __init__(self, config):
        if 'iwho' in config:
            config = config['iwho']
        self.configure(config)
        self._context = None

    @property
    def context(self):
        if self._context is None:
            self._context = self._create_context()
        return self._context

    def _create_context(self):
        iwho_ctx = get_context_by_name(self.context_specifier)
        for f in self.filters:
            if f['kind'] == 'no_cf':
                iwho_ctx.push_filter(Filters.no_control_flow)
                continue
            if f['kind'] == 'with_measurements':
                for uarch in f['archs']:
                    uarch_filter = partial(_filter_uarch, uarch_name=uarch)
                    iwho_ctx.push_filter(uarch_filter)
                continue
            if f['kind'] == 'only_mnemonics':
                iwho_ctx.push_filter(Filters.only_mnemonics(f['mnemonics']))
                continue
            if f['kind'] == 'whitelist':
                iwho_ctx.push_filter(Filters.whitelist(f['file_path']))
                continue
            if f['kind'] == 'blacklist':
                iwho_ctx.push_filter(Filters.blacklist(f['file_path']))
                continue

        return iwho_ctx


def get_context_by_name(ctx_id: str) -> Context:
    """ Try to create an IWHo Context that corresponds to the given identifier.

    If the identifier matches the filename (without extension) of a json file
    containing instruction schemes in the schemes directory, a Context for this
    file will be created. Otherwise, if the identifier is a prefix of one (or
    more) of the names of these known json files (e.g. "x86"), a Context for
    one of the matching files will be created.

    In case no matching file is found or any other error occurs, an IHWOError
    is raised.
    """
    from .x86 import Context as x86Context
    supported_contexts = [x86Context]
    # new Contexts should be added here

    import json
    import os
    from pathlib import Path

    script_location = Path(__file__).parent
    schemes_dir = script_location / "inputfiles" / "schemes"

    scheme_files = os.listdir(schemes_dir)
    scheme_files = set(filter(lambda x: os.path.isfile(schemes_dir / x) and x.endswith(".json"), scheme_files))

    selected_file_name = None
    if ctx_id + ".json" in scheme_files:
        selected_file_name = ctx_id + ".json"
    else:
        for f in scheme_files:
            if f.startswith(ctx_id) and not f.endswith("_features.json"):
                selected_file_name = f
                break

    if selected_file_name is None:
        raise IWHOError(f"No scheme data for id '{ctx_id}' found")

    pickle_name = os.path.splitext(selected_file_name)[0] + "_cached.pickle"
    pickle_file = schemes_dir / pickle_name

    if pickle_file.exists():
        with open(pickle_file, "rb") as f:
            return pickle.load(f)

    selected_file = schemes_dir / selected_file_name

    try:
        with open(selected_file, "r") as scheme_file:
            schemes_data = json.load(scheme_file)
    except Exception as exc:
        raise IWHOError(f"Failed to load schemes from '{selected_file}'") from exc

    if not isinstance(schemes_data, dict):
        raise IWHOError(f"Scheme data loaded from '{selected_file}' is malformed: not a dict")

    required_keys = ["isa", "schemes"]
    if any(map(lambda x: x not in schemes_data.keys(), required_keys)):
        raise IWHOError(f"Scheme data loaded from '{selected_file}' is malformed: missing required key(s)")

    isa = schemes_data["isa"]

    filename, ext = os.path.splitext(selected_file)
    feature_path = filename + "_features.json"

    features = None
    if os.path.isfile(feature_path):
        logger.debug(f"Feature file found at {feature_path}.")
        try:
            with open(feature_path, "r") as feature_file:
                features = json.load(feature_file)
        except:
            logger.warning(f"Failed to read features from feature file {feature_path}.")

    for ctx in supported_contexts:
        if isa == ctx.get_ISA_id():
            res = ctx()
            res.fill_from_json_dict(schemes_data)
            if features is not None:
                res.set_features(features)
            with open(pickle_file, 'wb') as f:
                pickle.dump(res, f)
            return res

    raise IWHOError(f"Found no IWHo Context for the isa '{isa}'")

