"""
IWHo: Instructions With Holes
"""

from .iwho import *


def get_context(ctx_id: str) -> Context:
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
    schemes_dir = script_location.parent / "schemes"

    scheme_files = os.listdir(schemes_dir)
    scheme_files = set(filter(lambda x: os.path.isfile(schemes_dir / x) and x.endswith(".json"), scheme_files))

    selected_file_name = None
    if ctx_id + ".json" in scheme_files:
        selected_file_name = ctx_id + ".json"
    else:
        for f in scheme_files:
            if f.startswith(ctx_id):
                selected_file_name = f
                break

    if selected_file_name is None:
        raise IWHOError(f"No scheme data for id '{ctx_id}' found")

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

    for ctx in supported_contexts:
        if isa == ctx.get_ISA_id():
            res = ctx()
            res.fill_from_json_dict(schemes_data)
            return res

    raise IWHOError(f"Found no IWHo Context for the isa '{isa}'")

