from . import Predictor, PredictorConfigError

# This is a hardcoded to x86, maybe configuring it would be better
from ..x86 import extract_mnemonic

class TestPredictor(Predictor):
    """ A simple, platform independent predictor just for testing.
    By default, it just counts the number of instructions in an experiment
    """

    predictor_name = "test"
    predictor_options = [
            "mnemonic_costs", # dict mappings mnemonic strings to float costs (non-present mnemonics have cost 1.0)
        ]

    def __init__(self, mnemonic_costs):
        self.mnemonic_costs = mnemonic_costs

    @staticmethod
    def from_config(config):
        mnemonic_costs = config["mnemonic_costs"]
        return TestPredictor(mnemonic_costs)

    def evaluate(self, basic_block, *args, **kwargs):
        s = basic_block.get_asm()
        lines = s.split('\n')
        res = 0.0
        for l in lines:
            mnemonic = extract_mnemonic(l)
            res += self.mnemonic_costs.get(mnemonic, 1.0)
        return {'TP': res}
