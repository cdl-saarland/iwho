from abc import ABC, abstractmethod

import logging
logger = logging.getLogger(__name__)

from ..core import IWHOError
from ..utils import export

available_classes = []

def _add_available_classes():
    global available_classes
    from .llvmmca_predictor import LLVMMCAPredictor
    from .iaca_predictor import IACAPredictor
    from .osaca_predictor import OSACAPredictor
    from .test_predictor import TestPredictor
    available_classes = [LLVMMCAPredictor, IACAPredictor, OSACAPredictor, TestPredictor]


@export
class PredictorConfigError(IWHOError):
    """ A predictor configuration dict is broken
    """

    def __init__(self, message):
        super().__init__(message)

@export
class Predictor(ABC):

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

