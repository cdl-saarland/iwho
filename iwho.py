
# IWHO: Instructions With HOles

from typing import Sequence, Optional, Dict

from abc import ABC, abstractmethod
from dataclasses import dataclass

from functools import cached_property
import string

import pyparsing as pp


import logging
logger = logging.getLogger(__name__)

class IWHOError(Exception):
    def __init__(self, message):
        self.message = message

class NoValidInstanceError(IWHOError):
    def __init__(self, message):
        super().__init__(message)

class UnknownInstructionError(IWHOError):
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

    @abstractmethod
    def add_insn_scheme(self, scheme):
        pass

    def fill_from_json_dict(self, jsondict):
        # currently, that's actually a list. TODO: add a version check
        for insn_scheme_dict in jsondict:
            self.add_insn_scheme(InsnScheme.from_json_dict(self, insn_scheme_dict))

    def to_json_dict(self):
        # currently, that's actually a list. TODO: add a version check
        res = []
        for insn_scheme in self.insn_schemes:
            res.append(insn_scheme.to_json_dict())
        return res


class Operand(ABC):
    def additionally_read(self) -> Sequence["Operand"]:
        return []

    def additionally_written(self) -> Sequence["Operand"]:
        return []

    @property
    def parser_pattern(self):
        return pp.Literal(str(self))

    @abstractmethod
    def to_json_dict(self):
        pass


class OperandConstraint(ABC):
    @abstractmethod
    def is_valid(self, operand):
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def from_match(self, match):
        pass

    @property
    @abstractmethod
    def parser_pattern(self):
        pass

    @abstractmethod
    def to_json_dict(self):
        pass


class SetConstraint(OperandConstraint):
    def __init__(self, acceptable_operands):
        self.name = None
        self.acceptable_operands = tuple(set(acceptable_operands))

    def __str__(self):
        if self.name is not None:
            return self.name
        else:
            return ",".join(map(str, self.acceptable_operands))

    def is_valid(self, operand):
        return operand in self.acceptable_operands

    def from_match(self, match):
        assert len(match) == 1

        keys = list(match.keys())
        assert len(keys) == 1
        key  = keys[0]
        return self.acceptable_operands[int(key)]

    @cached_property
    def parser_pattern(self):
        return pp.Group(pp.MatchFirst([pp.Group(o.parser_pattern).setResultsName(str(x)) for x, o in enumerate(self.acceptable_operands)]))

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.acceptable_operands == other.acceptable_operands)

    def __hash__(self):
        return hash((self.acceptable_operands))

    def to_json_dict(self):
        return {"kind": self.__class__.__name__,
                "acceptable_operands": [ op.to_json_dict() for op in self.acceptable_operands ],
            }

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
        if self.is_fixed():
            return self.fixed_operand == operand
        else:
            return self.operand_constraint.is_valid(operand)

    def from_match(self, match):
        if self.is_fixed():
            return self.fixed_operand.from_match(match)
        else:
            return self.operand_constraint.from_match(match)

    @property
    def parser_pattern(self):
        if self.is_fixed():
            return self.fixed_operand.parser_pattern
        else:
            return self.operand_constraint.parser_pattern

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
        return str(self.to_json_dict())

    def to_json_dict(self):
        res = {"kind": self.__class__.__name__,}
        if self.operand_constraint is not None:
            res["operand_constraint"] = self.operand_constraint.to_json_dict()
        else:
            res["fixed_operand"] = self.fixed_operand.to_json_dict()
        res["read"] = self.is_read
        res["written"] = self.is_written

        return res

    def from_json_dict(ctx, jsondict):
        assert "kind" in jsondict and jsondict["kind"] == "OperandScheme"

        if "operand_constraint" in jsondict:
            operand_constraint = ctx.operand_constraint_from_json_dict(jsondict["operand_constraint"])
            fixed_operand = None
        else:
            operand_constraint = None
            fixed_operand = ctx.operand_from_json_dict(jsondict["fixed_operand"])

        read = jsondict["read"]
        written = jsondict["written"]

        return ctx.dedup_store.get(OperandScheme,
                constraint=operand_constraint,
                fixed_operand=fixed_operand,
                read = read,
                written = written,
            )


class InsnScheme:
    def __init__(self, *, str_template: str, operand_schemes: Dict[str, OperandScheme], implicit_operands: Sequence[OperandScheme], affects_control_flow: bool=False):
        self._str_template = string.Template(str_template)
        self._operand_schemes = operand_schemes
        self._implicit_operands = implicit_operands
        self.affects_control_flow = affects_control_flow
        # TODO check whether operand_schemes and str_template match

    def instantiate(self, args):
        if isinstance(args, str):
            match = self.parser_pattern.parseString(args) # TODO try except

            args = dict()

            for key, op_scheme in self._operand_schemes.items():
                sub_match = match[key]
                args[key] = op_scheme.from_match(sub_match)

            # TODO an extra case for a pattern match could be helpful

        assert isinstance(args, dict)

        return InsnInstance(scheme=self, operands=args)

    @cached_property
    def parser_pattern(self):
        template_str = self._str_template.template

        fragments = template_str.split("${")
        # This separates an instruction template string with N operands into
        # N + 1 strings. Every one except the first one starts with the key of
        # an operand followed by a '}'.

        assert len(fragments) > 0

        pattern = pp.Suppress(pp.Empty())

        first = True
        for frag in fragments:
            if not first:
                key, frag = frag.split("}", maxsplit=1)
                op_pattern = self._operand_schemes[key].parser_pattern
                pattern += op_pattern.setResultsName(key)

            first = False

            for f in frag.split():
                pattern += pp.Suppress(pp.Literal(f))

        return pattern


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
        return str(self.to_json_dict())

    def to_json_dict(self):
        return { "kind": self.__class__.__name__,
                "str_template": self._str_template.template,
                "operand_schemes": { key: op_scheme.to_json_dict() for key, op_scheme in self._operand_schemes.items()},
                "implicit_operands": [ op_scheme.to_json_dict() for op_scheme in self._implicit_operands],
                "affects_control_flow": self.affects_control_flow,
            }

    def from_json_dict(ctx, jsondict):
        assert "kind" in jsondict and jsondict["kind"] == "InsnScheme"

        str_template = jsondict["str_template"]
        operand_schemes = {
                key: OperandScheme.from_json_dict(ctx, opdict) for key, opdict in jsondict["operand_schemes"].items()}
        implicit_operands = [OperandScheme.from_json_dict(ctx, opdict) for opdict in jsondict["implicit_operands"]]
        affects_control_flow = jsondict["affects_control_flow"]

        return InsnScheme(str_template=str_template,
                operand_schemes=operand_schemes,
                implicit_operands=implicit_operands,
                affects_control_flow=affects_control_flow)


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
        pretty_operands = "{\n  " + ",\n  ".join(( f"'{k}' : {repr(v)}" for k, v in self._operands.items() )) + "\n}"
        return "InsnInstance(scheme='{}',\n operands={})".format(self._scheme, pretty_operands)


