
# IWHO: Instructions With HOles

from typing import Sequence, Optional, Dict, Union

from abc import ABC, abstractmethod
from dataclasses import dataclass

from functools import cached_property
import string
from collections import defaultdict

from iwho.iwho_utils import DedupStore

import pyparsing as pp


import logging
logger = logging.getLogger(__name__)

class IWHOError(Exception):
    """ Superclass for exceptions in the package
    """
    pass

class SchemeError(IWHOError):
    """ An instruction scheme itself or a component of it is broken
    """

    def __init__(self, message):
        super().__init__(message)

class InstantiationError(IWHOError):
    """ An error occured while instantiating a scheme
    """

    def __init__(self, message):
        super().__init__(message)


class ASMCoderError(IWHOError):
    """ An error occured in the asm <-> hex transformation
    """

    def __init__(self, message):
        super().__init__(message)


class Context(ABC):
    """ Manager for the instruction schemes of a single instruction set
    architecture.
    It provides access to the available instruction schemes, manages and
    caches related objects and provides functionality to encode and decode
    instructions according to the schemes.

    When implementing iwho for a new ISA, an early  step will be to create
    a new subclass of this, overwriting the abstract methods.

    Most applications using this library will only need one instance of this in
    a program run.
    """

    def __init__(self, coder: "ASMCoder"):
        """ Super class constructor, requires an ASMCoder that is used for
        encoding and decoding instructions.
        """
        self.coder = coder

        self.insn_schemes = []

        # used for caching OperandInstances, OperandSchemes,
        # OperandConstraints,...
        # This requires usage from subclasses!
        self.dedup_store = DedupStore()

        # this is an index to speed up parsing by only trying to match
        # instruction schemes with a fitting mnemonic
        self.mnemonic_to_insn_schemes = defaultdict(list)
        self.mnemonic_pattern_cache = dict()

    @abstractmethod
    def extract_mnemonic(self, insn: Union[str, "InsnScheme", "InsnInstance"]) -> str:
        """ Extract the mnemonic from the assembly of a single instruction
        """
        pass

    @abstractmethod
    def operand_constraint_from_json_dict(self, jsondict):
        """ Produce an OperandConstraint from a jsondict representing one
        """
        pass

    @abstractmethod
    def operand_from_json_dict(self, jsondict):
        """ Produce an OperandInstance from a jsondict representing one
        """
        pass

    def decode_insns(self, hex_str: str) -> Sequence["InsnInstance"]:
        """ Decode a byte stream represented as string of hex characters into a
        sequence of instruction instances.

        Raises an ASMCoderError decoding the hex_str fails, or an
        InstantiationError if there is no fitting scheme for a decoded
        instruction.
        """

        asm_lines = self.coder.hex2asm(hex_str)

        insns = []
        for l in asm_lines:
            insn_instance = self.match_insn_str(l)
            insns.append(insn_instance)

        return insns


    def match_insn_str(self, insn_str: str):
        """ Match the assembly string representing an instruction to the
        InsnScheme that captures it best and return an instance of this scheme
        with appropriate operands.

        Raises an InstantiationError if no fitting scheme is found.
        """

        insn_str = insn_str.strip()
        mnemonic = self.extract_mnemonic(insn_str)

        # Get schemes with this mnemonic, sort them according to their
        # priority, and get a pattern that maches the first of them.
        candidate_schemes = self.mnemonic_to_insn_schemes[mnemonic]
        if len(candidate_schemes) == 0:
            raise InstantiationError(
                    f"instruction: {insn_str}, no schemes with matching mnemonic '{mnemonic}' found")

        candidate_schemes = sorted(candidate_schemes, key=lambda x: x.parser_priority)

        cached_pattern = self.mnemonic_pattern_cache.get(mnemonic, None)

        if cached_pattern is not None:
            pat = cached_pattern
        else:
            pat = pp.MatchFirst(
                    [pp.Group(cs.parser_pattern).setResultsName(str(x)) + pp.StringEnd() for x, cs in enumerate(candidate_schemes)])
            # The StringEnd() at this specific location is very much
            # non-optional. If it were placed outside of the MatchFirst (as it
            # is done implicitly by parseString(..., parseAll=True)), a too
            # short prefix pattern might match, so that the end of string is
            # not reached.

            self.mnemonic_pattern_cache[mnemonic] = pat

        try:
            match = pat.parseString(insn_str)
        except pp.ParseException as e:
            raise InstantiationError(f"instruction '{insn_str}' does not match any candidate scheme")

        assert len(match) == 1, "an internal pyparsing assumption is violated"

        keys = list(match.keys())
        assert len(keys) == 1, "an internal pyparsing assumption is violated"
        key  = keys[0]
        matching_scheme = candidate_schemes[int(key)]
        submatch = match[key]

        return matching_scheme.instantiate(submatch)


    def encode_insns(self, insn_instances: Sequence["InsnInstance"]) -> str:
        """ Encode a sequence of instruction instances into a byte stream
        represented as string of hex characters.

        Raises an ASMCoderError encoding the instances fails.
        """

        asm_str = ""
        for ii in insn_instances:
            asm_str += str(ii)

        res = self.coder.asm2hex(asm_str)

        return res


    def add_insn_scheme(self, scheme: "InsnScheme"):
        """ Add an instruction scheme to the Context and make it known to the
        necessary data structures. """

        self.insn_schemes.append(scheme)
        mnemonic = self.extract_mnemonic(scheme)
        self.mnemonic_to_insn_schemes[mnemonic].append(scheme)

        # invalidate the pattern cache
        self.mnemonic_pattern_cache.pop(mnemonic, None)


    def fill_from_json_dict(self, jsondict):
        """ TODO document
        """

        # currently, that's actually a list. TODO: add a version check
        for insn_scheme_dict in jsondict:
            self.add_insn_scheme(InsnScheme.from_json_dict(self, insn_scheme_dict))

    def to_json_dict(self):
        """ TODO document
        """

        # currently, that's actually a list. TODO: add a version check
        res = []
        for insn_scheme in self.insn_schemes:
            res.append(insn_scheme.to_json_dict())
        return res


class ASMCoder(ABC):
    """ Interface for transforming readable assembly strings into hex strings
    and vice versa.
    """

    @abstractmethod
    def asm2hex(self, asm_str: str) -> str:
        """ Turn a readable assembly string into a sequence of bytes.

        Bytes are represented as a string of an even number of [0-9a-f]
        characters, each two successive ones representing one byte.
        """
        pass

    @abstractmethod
    def hex2asm(self, hex_str: str) -> Sequence[str]:
        """ Turn a sequence of bytes into a readable assembly string.

        Bytes are represented as a string of an even number of [0-9a-f]
        characters, each two successive ones representing one byte.
        """
        pass


class OperandInstance(ABC):
    """ TODO document
    """

    def additionally_read(self) -> Sequence["OperandInstance"]:
        """ TODO document
        """
        return []

    def additionally_written(self) -> Sequence["OperandInstance"]:
        """ TODO document
        """
        return []

    @property
    def parser_pattern(self):
        """ TODO document
        """
        return pp.Literal(str(self))

    @abstractmethod
    def to_json_dict(self):
        """ TODO document
        """
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass



class OperandConstraint(ABC):
    """ TODO document
    """

    @abstractmethod
    def is_valid(self, operand):
        """ TODO document
        """
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def from_match(self, match):
        """ TODO document
        """
        pass

    @property
    @abstractmethod
    def parser_pattern(self):
        """ TODO document
        """
        pass

    @property
    def parser_priority(self) -> int:
        """ An positive number corresponding to the priority with which an
        instruction scheme with this constraint should be matched.

        The smaller the number, the earlier the pattern should be tried. This
        only really matters for constellations of patterns where one is more
        specific than the other (and should therefore be matched first). If
        this can happen, the number of possible matching operands would be a
        reasonable choice here. If this cannot happen, the default
        implementation will do.

        The priorities for the operand constraints are multiplied to produce
        the priority of the instruction scheme.
        """
        return 2**16 - 1

    @abstractmethod
    def to_json_dict(self):
        """ TODO document
        """
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass


class SetConstraint(OperandConstraint):
    """ TODO document
    """

    def __init__(self, acceptable_operands):
        """ TODO document
        """

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

    @property
    def parser_priority(self) -> int:
        return len(self.acceptable_operands)

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
    """ TODO document
    """

    def __init__(self, *, constraint: Optional[OperandConstraint]=None, fixed_operand: Optional[OperandInstance]=None, read: bool=False, written: bool=False):
        """ TODO document
        """
        assert (constraint is None) != (fixed_operand is None)
        self.operand_constraint = constraint
        self.fixed_operand = fixed_operand
        self.is_read = read
        self.is_written = written

    def is_fixed(self):
        """ TODO document
        """
        return self.fixed_operand is not None

    def is_operand_valid(self, operand):
        """ TODO document
        """
        if self.is_fixed():
            return self.fixed_operand == operand
        else:
            return self.operand_constraint.is_valid(operand)

    def from_match(self, match):
        """ TODO document
        """
        if self.is_fixed():
            return self.fixed_operand
        else:
            return self.operand_constraint.from_match(match)

    @property
    def parser_pattern(self):
        """ TODO document
        """
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
        """ TODO document
        """

        res = {"kind": self.__class__.__name__,}
        if self.operand_constraint is not None:
            res["operand_constraint"] = self.operand_constraint.to_json_dict()
        else:
            res["fixed_operand"] = self.fixed_operand.to_json_dict()
        res["read"] = self.is_read
        res["written"] = self.is_written

        return res

    def from_json_dict(ctx, jsondict):
        """ TODO document
        """

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
                written = written)

    def __hash__(self):
        raise NotImplementedError("No hash implemented on OperandSchemes")

    def __eq__(self, other):
        raise NotImplementedError("No equality implemented on OperandSchemes")


class InsnScheme:
    """ TODO document
    """

    def __init__(self, *, str_template: str, operand_schemes: Dict[str, OperandScheme], implicit_operands: Sequence[OperandScheme], affects_control_flow: bool=False):
        """ TODO document
        """

        self._str_template = string.Template(str_template)
        self._operand_schemes = operand_schemes
        self._implicit_operands = implicit_operands
        self.affects_control_flow = affects_control_flow

        # check whether operand_schemes and str_template match
        try:
            mapping = { k: "<hole>" for k in self._operand_schemes.keys() }
            self._str_template.substitute(mapping)
        except (ValueError, KeyError) as e:
            raise SchemeError("The operand schemes {} do not fit to the string template '{}'\n".format(
                    list(self._operand_schemes.keys()), self._str_template.template) +
                "  substitution error: {}".format(repr(e)))


    def instantiate(self, args):
        """ TODO document
        """
        if isinstance(args, str):
            try:
                match = self.parser_pattern.parseString(args)
            except pp.ParseException as e:
                raise InstantiationError("Invalid instruction for scheme: {}".format(args))

            args = dict()

            for key, op_scheme in self._operand_schemes.items():
                sub_match = match[key]
                args[key] = op_scheme.from_match(sub_match)

        elif isinstance(args, pp.ParseResults):
            match = args
            args = dict()

            for key, op_scheme in self._operand_schemes.items():
                sub_match = match[key]
                args[key] = op_scheme.from_match(sub_match)

        assert isinstance(args, dict)

        return InsnInstance(scheme=self, operands=args)

    @cached_property
    def parser_pattern(self):
        """ TODO document
        """

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
    def parser_priority(self) -> int:
        """ An positive number corresponding to the priority with which this
        instruction scheme should be matched.

        The smaller the number, the earlier the pattern should be tried. This
        only really matters for constellations of patterns where one is more
        specific than the other (and should therefore be matched first).

        The priorities for the operand constraints are multiplied to produce
        the priority of the instruction scheme.
        """
        res = 1
        for key, opscheme in self._operand_schemes.items():
            if not opscheme.is_fixed():
                res *= opscheme.operand_constraint.parser_priority
        return res


    @property
    def str_template(self):
        """ TODO document
        """

        return self._str_template

    @property
    def operand_schemes(self):
        """ TODO document
        """

        return self._operand_schemes

    @property
    def implicit_operands(self):
        """ TODO document
        """

        return self._implicit_operands

    def __str__(self):
        mapping = { k: str(v) for k, v in self._operand_schemes.items()}
        return self.str_template.substitute(mapping)

    def __repr__(self):
        return str(self.to_json_dict())

    def to_json_dict(self):
        """ TODO document
        """

        return { "kind": self.__class__.__name__,
                "str_template": self._str_template.template,
                "operand_schemes": { key: op_scheme.to_json_dict() for key, op_scheme in self._operand_schemes.items()},
                "implicit_operands": [ op_scheme.to_json_dict() for op_scheme in self._implicit_operands],
                "affects_control_flow": self.affects_control_flow,
            }

    def from_json_dict(ctx, jsondict):
        """ TODO document
        """

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

    def __hash__(self):
        return hash((self.str_template.template,))

    def __eq__(self, other):
        raise NotImplementedError("No equality implemented on InsnSchemes")

class InsnInstance:
    """ TODO document
    """

    def __init__(self, scheme: InsnScheme, operands: Dict[str, OperandInstance]):
        """ TODO document
        """

        self._scheme = scheme
        self._operands = operands
        self.validate_operands()

    def validate_operands(self):
        """ TODO document
        """

        for k, opscheme in self.scheme.operand_schemes.items():
            if k not in self._operands:
                raise InstantiationError(f"instruction instance for scheme {self.scheme} does not specify operand {k}")

            opinst = self._operands[k]
            if not opscheme.is_operand_valid(opinst):
                raise InstantiationError(f"instruction instance for scheme {self.scheme} specifies invalid operand {k}: {opinst}")

        for k in self._operands.keys():
            if k not in self.scheme.operand_schemes:
                raise InstantiationError(f"instruction instance for scheme {self.scheme} specifies superfluous operand {k}")

    @property
    def scheme(self):
        """ TODO document
        """

        return self._scheme

    @cached_property
    def read_operands(self):
        """ TODO document
        """

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
        """ TODO document
        """

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

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self._scheme is other._scheme # schemes should be unique anyway, so we can compare references
                and self._operands == other._operands)

    def __hash__(self):
        return hash((self._scheme, self._operands))

