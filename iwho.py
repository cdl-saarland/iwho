
# IWHO: Instructions With HOles

from typing import Sequence, Optional, Dict

from abc import ABC, abstractmethod
from dataclasses import dataclass

from functools import cached_property

import logging
logger = logging.getLogger(__name__)

class IWHOError(Exception):
    def __init__(self, message):
        self.message = message

class NoValidInstanceError(IWHOError):
    def __init__(self, message):
        super().__init__(message)

class InvalidOperandsError(IWHOError):
    def __init__(self, message):
        super().__init__(message)

class UnsupportedFeatureError(IWHOError):
    def __init__(self, message):
        super().__init__(message)


class Context(ABC):

    @abstractmethod
    def disassemble(self, data):
        # create an instruction instance
        pass

    @abstractmethod
    def assemble(self, insn_instance):
        # generate code for the instruction instance
        pass


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
    def __str__(self):
        pass

class SetConstraint(OperandConstraint):
    def __init__(self, acceptable_operands):
        self.name = None
        self.acceptable_operands = frozenset(acceptable_operands)

    def __str__(self):
        if self.name is not None:
            return self.name
        else:
            return ",".join(map(str, self.acceptable_operands))

    def is_valid(self, operand):
        return operand in self.acceptable_operands

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.acceptable_operands == other.acceptable_operands)

    def __hash__(self):
        return hash((self.acceptable_operands))

class OperandScheme:
    def __init__(self, *, constraint: Optional[OperandConstraint]=None, fixed_operand: Optional[Operand]=None, read: bool=False, written: bool=False):
        assert (constraint is None) != (fixed_operand is None)
        self.operand_constraint = constraint
        self.fixed_operand = fixed_operand
        self.is_read = read
        self.is_written = written

    def is_fixed(self):
        return self.fixed_operand is not None

    def is_operand_valid(self, operand):
        return self.operand_constraint.is_valid(operand)

    def __str__(self):
        res = ""
        if self.is_read:
            res += 'R'
        if self.is_written:
            res += 'W'

        if self.is_read or self.is_written:
            res += ":"

        if self.operand_constraint is not None:
            res += str(self.operand_constraint)
        else:
            res += str(self.fixed_operand)
        return res

    def __repr__(self):
        res = "OperandScheme("
        if self.operand_constraint is not None:
            res += "constraint: " + str(self.operand_constraint)
        else:
            res += "fixed_operand={}".format(repr(self.fixed_operand))
        res += f", read={self.is_read}, written={self.is_written})"
        return res


class InsnScheme:
    def __init__(self, *, str_template: str, operand_schemes: Dict[str, OperandScheme], implicit_operands: Sequence[OperandScheme]):
        self._str_template = str_template
        self._operand_schemes = operand_schemes
        self._implicit_operands = implicit_operands
        # TODO check whether operand_schemes and str_template match

    def instantiate(self, args):
        return InsnInstance(scheme=self, operands=args)

    @property
    def str_template(self):
        return self._str_template

    @property
    def operand_schemes(self):
        return self._operand_schemes

    @property
    def implicit_operands(self):
        return self._implicit_operands

    def __str__(self):
        mapping = { k: str(v) for k, v in self._operand_schemes.items()}
        return self.str_template.substitute(mapping)

    def __repr__(self):
        res = "InsnScheme("
        res += "str_template={},\n".format(repr(self.str_template))
        res += "  operand_schemes={},\n".format(repr(self.operand_schemes))
        res += "  implicit_operands={},\n".format(repr(self.implicit_operands))
        res += ")"
        return res


class InsnInstance:
    def __init__(self, scheme, operands):
        self._scheme = scheme
        self._operands = operands
        self.validate_operands()

    def validate_operands(self):
        for k, opscheme in self.scheme.operand_schemes.items():
            if k not in self._operands:
                raise InvalidOperandsError(f"instruction instance for scheme {self.scheme} does not specify operand {k}")

            opinst = self._operands[k]
            if not opscheme.is_operand_valid(opinst):
                raise InvalidOperandsError(f"instruction instance for scheme {self.scheme} specifies invalid operand {k}: {opinst}")

        for k in self._operands.keys():
            if k not in self.scheme.operand_schemes:
                raise InvalidOperandsError(f"instruction instance for scheme {self.scheme} specifies superfluous operand {k}")

    @property
    def scheme(self):
        return self._scheme

    @cached_property
    def read_operands(self):
        res = []
        # all explicit operands that are read
        for k, v in self._scheme.operand_schemes.items():
            if v.is_read:
                res.append(self._operands[k])

        # all implicit operands that are read
        for opscheme in self._scheme.implicit_operands:
            if opscheme.is_read:
                res.append(opscheme.fixed_operand)

        # all nested operands that are read to evaluate explicit operands
        for k, operand in self._operands.items():
            res += operand.additionally_read()

        # all nested operands that are read to evaluate implicit operands
        for opscheme in self._scheme.implicit_operands:
            res += opscheme.fixed_operand.additionally_read()

        return res


    @cached_property
    def written_operands(self):
        res = []
        # all explicit operands that are written
        for k, v in self._scheme.operand_schemes.items():
            if v.is_written:
                res.append(self._operands[k])

        # all implicit operands that are written
        for opscheme in self._scheme.implicit_operands:
            if opscheme.is_written:
                res.append(opscheme.fixed_operand)

        # all nested operands that are written to evaluate explicit operands
        for k, operand in self._operands.items():
            res += operand.additionally_written()

        # all nested operands that are written to evaluate implicit operands
        for opscheme in self._scheme.implicit_operands:
            res += opscheme.fixed_operand.additionally_written()

        return res

    def __str__(self):
        op_strs = { k: str(v) for k, v in self._operands.items() }
        return self.scheme.str_template.substitute(op_strs)

    def __repr__(self):
        return "InsnInstance(scheme={}, operands={})".format(self._scheme, self._operands)


