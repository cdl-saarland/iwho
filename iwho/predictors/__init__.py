from abc import ABC, abstractmethod
import subprocess

import logging
logger = logging.getLogger(__name__)

from ..core import IWHOError
from ..utils import export

# some predictors, e.g. nanoBench, require execution as root, so we might have
# to ask for the root password
from getpass import getpass

class PWManager:
    password = None

def get_sudo():
    """ This function should be called before a predictor that requires root is
    used.
    Currently, the sudo access is not shared among processes. Therefore, if you
    have a predictor that requires root privileges but does not require to be
    run sequentially, it will not have the right privileges.

    This could be fixed by sharing the password with subprocesses if necessary.
    """
    if PWManager.password is not None:
        return
    PWManager.password = getpass("Please enter your sudo password to run predictors with: ")
    subprocess.run(['sudo', '-S', 'ls', '/'], check=True, capture_output=True, encoding="latin1", timeout=2, input=PWManager.password)


available_classes = []

def _add_available_classes():
    global available_classes
    from .llvmmca_predictor import LLVMMCAPredictor
    from .iaca_predictor import IACAPredictor
    from .uica_predictor import UICAPredictor
    from .maqao_predictor import MAQAOPredictor
    from .nanobench_predictor import NanoBenchPredictor
    from .osaca_predictor import OSACAPredictor
    from .test_predictor import TestPredictor
    available_classes = [
            LLVMMCAPredictor,
            IACAPredictor,
            UICAPredictor,
            MAQAOPredictor,
            NanoBenchPredictor,
            OSACAPredictor,
            TestPredictor,
        ]

    try:
        from .ithemal_docker_predictor import IthemalDockerPredictor
        available_classes.append(IthemalDockerPredictor)
    except ImportError as e:
        logger.info(f"Import of IthemalDockerPredictor failed, skipping:\n{e}")


@export
class PredictorConfigError(IWHOError):
    """ A predictor configuration dict is broken
    """

    def __init__(self, message):
        super().__init__(message)

@export
class Predictor(ABC):

    def requires_sudo(self):
        return False

    def needs_to_run_alone(self):
        """ Subclasses should override this method if they require to be
        executed in a sequential fashion, e.g. because they are actually
        running benchmarks on the machine.
        """
        return False

    @abstractmethod
    def evaluate(self, basic_block):
        pass

    @staticmethod
    def get(predictor_config):
        """ Construct a new Predictor instance from the given config dict.
        """
        predictor_kind = predictor_config.get("kind", None)
        if predictor_kind is None:
            raise PredictorConfigError("no predictor kind specified in config")

        for cls in available_classes:
            if cls.predictor_name == predictor_kind:
                for opt in cls.predictor_options:
                    if opt not in predictor_config:
                        raise PredictorConfigError(f"required option '{opt}' for predictor '{predictor_kind}' not specified in config")
                for opt in predictor_config:
                    if not opt.endswith("_info") and opt not in cls.predictor_options and opt != "kind":
                        logger.warning(f"predictor option '{opt}' given in the config is not used by predictor '{predictor_kind}'")
                return cls.from_config(predictor_config)
        else:
            raise PredictorConfigError(f"predictor '{predictor_kind}' specified in config is not available")


_add_available_classes()

