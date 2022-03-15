""" A module to manage a number of available basic block predictors.

It provides features like concurrent batch processing, storing measurements,
creating predictors by identifier, and timely acquisition of root privileges if
required.
"""

from datetime import datetime
from functools import partial
import json
import multiprocessing
from multiprocessing import Pool
import os
import re
import socket

from . import Predictor, get_sudo

from ..configurable import ConfigMeta, load_json_config, ConfigError

class UnknownPredictorError(Exception):
    """ We don't know this predictor.
    """

    def __init__(self, message):
        super().__init__(message)

def evaluate_bb(bb, pred):
    """ Evaluate the given basic block with the given predictor.

    Catches exceptions and turns them into an error result.
    """

    try:
        result = pred.evaluate(bb, disable_logging=True)
    except Exception as e:
        result = { 'TP': None, 'error': "an exception occured: " + str(e) }
    return result

def evaluate_multiple(bb, preds):
    """ Evaluate the given basic block with a list of predictors (given as a
    list of key/Predictor tuples).

    The result is a dictionary mapping the predictor keys to the respective
    result.
    Catches exceptions and turns them into an error result.
    """

    res = dict()
    for pkey, pred in preds:
        res[pkey] = evaluate_bb(bb, pred)
    return res


class LightBBWrapper:
    """ Light-weight wrapper of all things necessary to get the hex
    representation of a BasicBlock.

    The key is the execution time distribution:
    Creating this wrapper is fast, serializing it is efficient (since nothing
    unnecessary from the iwho context is present), and `get_hex()` does the
    heavy lifting (i.e. calls to the coder, which might require expensive
    subprocesses).

    This makes this very effective to use as a task for a PredictorManager,
    since all expensive things can be done by the process pool.

    This could be considered a hack.
    """
    def __init__(self, bb):
        self.asm_str = bb.get_asm()
        self.coder = bb.context.coder
        self.hex = None
        self.unwrapped_hex = None
        self.wrap_in_loop = bb.wrap_in_loop

    def get_hex(self, unwrapped=False):
        if unwrapped:
            if self.unwrapped_hex is None:
                res = self.coder.asm2hex(self.get_asm(unwrapped=True))
                self.unwrapped_hex = res
            else:
                res = self.unwrapped_hex
        else:
            if self.hex is None:
                res = self.coder.asm2hex(self.get_asm(unwrapped=False))
                self.hex = res
            else:
                res = self.hex
        return res

    def get_asm(self, unwrapped=False):
        res = self.asm_str
        if self.wrap_in_loop and not unwrapped:
            res = "loop:\n" + res + "\ndec r15\n jnz loop\n"
            # TODO this is x86 specific and should go!
            # TODO we should probably check whether r15 is unused
        return res


class PredictorManager(metaclass=ConfigMeta):
    """ A helper class to work with a number of iwho.Predictors, to
    conveniently support multiprocessing.

    Make sure to call `close()` when done using it or use it as a context
    manager:
    ```
    with PredictorManager() as predman:
        predman.register_predictor(...)
        ...
    ```

    If num_processes is 0 (the default) all available processes are used.
    If num_processes is None, no multiprocessing is used (faster for very small
    batch sizes, mainly for testing).

    Typical usage would register several Predictors in the manager and then use
    the PredictorManager methods to run (some of) them on a batch of basic
    blocks.
    """

    config_options = dict(
            registry_path=(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    '..', 'inputfiles', 'default_pred_registry.json'),
                'path to a predictor registry in json format'),
            num_processes=(0,
                'number of predictor processes to use. A value <= 0 uses the number of available cores, None/null runs everything in the main process.')
        )


    def __init__(self, config):
        self.configure(config)

        try:
            self.pred_registry = load_json_config(self.registry_path)
        except FileNotFoundError:
            raise ConfigError('No predictor registry found at the path specified by the predictor config: {}'.format(self.registry_path)) from None

        self.dbman = None
        self.pool = None

        num_processes = self.num_processes

        # created lazily when/if needed
        self._pool = None

        self.predictor_map = dict()

        self.source_computer = socket.gethostname()

        self.next_result_ref = 0

    @property
    def pool(self):
        num_processes = self.num_processes
        if self._pool is None and num_processes is not None:
            if num_processes <= 0:
                num_processes = multiprocessing.cpu_count()
            self._pool = Pool(num_processes)
        return self._pool

    @pool.setter
    def pool(self, value):
        self._pool = value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """ This method should be called at the end of the lifetime of the
        PredictorManager.
        """
        if getattr(self, '_pool', None) is not None:
            self._pool.close()
            self._pool = None

    def set_measurement_db(self, dbmanager):
        """ Set a database manager to be used for storing measurements.
        """
        self.dbman = dbmanager


    def get_sudo_if_necessary(self, keys):
        """ Ask for the sudo password if any of the predictors specified by
        keys needs it and it is not yet available.
        """
        actual_keys = self.resolve_key_patterns(keys)
        for k in actual_keys:
            pred_config = self.pred_registry[k]['config']
            pred = Predictor.get(pred_config)
            if pred.requires_sudo():
                get_sudo()
                break

    def resolve_key_patterns(self, keys):
        actual_keys = []
        for key in keys:
            if key in self.pred_registry:
                actual_keys.append(key)
            else:
                pat = re.compile(key)
                found = False
                for k in self.pred_registry.keys():
                    if pat.fullmatch(k):
                        actual_keys.append(k)
                        found = True

                if not found:
                    raise UnknownPredictorError(f"unknown predictor key/pattern: {key}")
        return actual_keys

    def get_insn_filter_files(self, keys):
        """Get a list of file names that include lists of instruction schemes
        that are not supported by some the predictors referenced by `keys`. """
        actual_keys = self.resolve_key_patterns(keys)
        res = []
        for key in actual_keys:
            filter_file = self.pred_registry[key].get('unsupported_insns_path', None)
            if filter_file is not None:
                filter_file = filter_file.format(KEY=key)
                res.append(filter_file)
        return res

    def set_predictors(self, keys):
        """ Set the group of predictors to use.

        `keys` is expected to be a list of keys into the predictor registry
        with which the PredictorManager has been configured.
        """

        self.get_sudo_if_necessary(keys)

        self.predictor_map.clear()
        actual_keys = self.resolve_key_patterns(keys)

        for key in actual_keys:
            if key in self.predictor_map:
                # ignore duplicates
                continue

            pred_entry = self.pred_registry[key]
            pred_config = pred_entry['config']

            self.predictor_map[key] = {
                    "predictor": Predictor.get(pred_config),
                    "toolname": pred_entry['tool'],
                    "version": pred_entry['version'],
                    "uarch": pred_entry['uarch'],
                }

    @property
    def predictors(self):
        return [ (k, v['predictor']) for k, v in self.predictor_map.items() ]

    def do(self, pred, bbs, lazy=True):
        """ Use the given predictor to predict inverse throughputs for all
        basic blocks in the given list.

        If lazy is true, return an asynchronous iterator for the results and
        return before they are all predicted.
        If lazy is false, return a complete list of predictions (awaiting all
        results).
        """

        if isinstance(pred, str):
            pred_entry = self.pred_registry[pred]
            pred_config = pred_entry['config']
            pred = Predictor.get(pred_config)

        tasks = map(lambda x: LightBBWrapper(x), bbs)
        if self.pool is None or pred.needs_to_run_alone():
            results = map(partial(evaluate_bb, pred=pred), tasks)
        else:
            results = self.pool.imap(partial(evaluate_bb, pred=pred), tasks)
        if not lazy:
            results = list(results)
        return results # also use zip(bbs, results) here?

    def eval_with_all(self, bbs):
        """TODO document"""
        # Some predictors want to run alone (e.g. because they do actual
        # measurements that should not be too noisy), we run those first.
        run_alone = []
        run_parallel = []
        for k, p in self.predictors:
            if p.needs_to_run_alone():
                run_alone.append((k, p))
            else:
                run_parallel.append((k, p))

        tasks = list(map(lambda x: LightBBWrapper(x), bbs))

        alone_results = list(map(partial(evaluate_multiple, preds=run_alone), tasks))

        if self.pool is None:
            parallel_results = list(map(partial(evaluate_multiple, preds=run_parallel), tasks))
        else:
            parallel_results = self.pool.imap(partial(evaluate_multiple, preds=run_parallel), tasks)
        results = alone_results
        for r1, r2 in zip(results, parallel_results):
            r1.update(r2)
        return zip(bbs, results)

    def eval_with_all_and_report(self, bbs):
        series_date = datetime.now().isoformat()

        eval_res = list(self.eval_with_all(bbs))

        if self.dbman is None:
            return eval_res, None

        measurements = []
        for bb, result in eval_res:
            predictor_runs = []
            for predkey, res in result.items():
                tp = res.get('TP', -1.0)
                if tp is not None and tp < 0:
                    tp = None
                remark = json.dumps(res)
                predictor_runs.append({
                        "predictor": predkey,
                        "result": tp,
                        "remark": remark
                    })
            record = {
                    "input": bb.get_hex(),
                    "predictor_runs": predictor_runs,
                }
            measurements.append(record)

        measdict = {
                "series_date": series_date,
                "source_computer": self.source_computer,
                "measurements": measurements,
            }

        with self.dbman as dbman:
            result_ref = dbman.add_series(measdict)

        return eval_res, result_ref

