
# IWHO: Instructions With HOles

from typing import Sequence, Optional, Dict

from abc import ABC, abstractmethod
from dataclasses import dataclass

import logging
logger = logging.getLogger(__name__)

class IWHOError(Exception):
    def __init__(self, message):
        self.message = message

class NoValidInstanceError(IWHOError):
    def __init__(self, message):
        super().__init__(message)




class Operand(ABC):
    def additionally_read(self) -> Sequence["Operand"]:
        return []

    def additionally_written(self) -> Sequence["Operand"]:
        return []


class OperandConstraint(ABC):
    @abstractmethod
    def is_valid(self, operand):
        pass

    @abstractmethod
    def get_valid(self, not_in=[]):
        pass

class SetConstraint(OperandConstraint):
    def __init__(self, acceptable_operands):
        self.acceptable_operands = set(acceptable_operands)

    def is_valid(self, operand):
        return operand in self.acceptable_operands

    def get_valid(self, not_in):
        diff = self.acceptable_operands - set(not_in)
        if len(diff) == 0:
            return None
        return next(iter(diff))

class FixedConstraint(OperandConstraint):
    def __init__(self, acceptable_operand):
        self.acceptable_operand = set(acceptable_operand)

    def is_valid(self, operand):
        return operand == self.acceptable_operand

    def get_valid(self, not_in):
        return self.acceptable_operand

class OperandScheme:
    def __init__(self, *, constraint: Optional[OperandConstraint]=None, fixed_operand: Optional[Operand]=None, read: bool=False, written: bool=False):
        assert (constraint is None) != (fixed_operand is None)
        self.operand_constraint = constraint
        self.fixed_operand = fixed_operand
        self.read = read
        self.written = written

    def is_fixed(self):
        return self.fixed_operand is not None

    def is_operand_valid(self, operand):
        return self.operand_constraint(operand)

    def get_valid_operand(self, not_in=[]):
        # TODO
        pass

    def __str__(self):
        return repr(self)

    def __repr__(self):
        res = "OperandScheme("
        if self.operand_constraint is not None:
            res += "constraint" # TODO
        else:
            res += "fixed_operand={}".format(repr(self.fixed_operand))
        res += f", read={self.read}, written={self.written})"
        return res


class InsnScheme:
    def __init__(self, identifier: str, *, str_template: str, operand_schemes: Dict[str, OperandScheme], implicit_operands: Sequence[OperandScheme]):
        self.identifier = identifier
        self.str_template = str_template
        self.operand_schemes = operand_schemes
        self.implicit_operands = implicit_operands

    def instantiatate(self, args):
        # TODO create an instance with the fitting arguments
        pass

    # @property
    # def operand_schemes(self):
    #     pass

    def __str__(self):
        return repr(self) # TODO

    def __repr__(self):
        res = "InsnScheme(identifier={},\n".format(repr(self.identifier))
        res += "  str_template={},\n".format(repr(self.str_template))
        res += "  operand_schemes={},\n".format(repr(self.operand_schemes))
        res += "  implicit_operands={},\n".format(repr(self.implicit_operands))
        res += ")"
        return res

class Context(ABC):

    @abstractmethod
    def disassemble(self, data):
        # create an instruction instance
        pass


class InsnInstance:
    def __init__(self, scheme, operands):
        # TODO check that operands fit
        self._scheme = scheme
        self._operands = operands

    @property
    def scheme(self):
        return self._scheme

    def assemble(self):
        # generate code for the instruction instance
        pass

    def read_operands(self):
        pass

    def written_operands(self):
        pass

    def __str__(self):
        pass

    def __repr__(self):
        pass



