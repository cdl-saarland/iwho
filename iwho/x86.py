""" IWHO infrastructure for the x86-64 ISA.

Implements the necessary interfaces from `iwho.core`.
"""

from typing import Sequence, Optional, Union

from csv import DictReader
from enum import Enum
from collections import defaultdict
import os
import random
import shutil
import subprocess


from functools import cached_property
import pyparsing as pp

from . import core
from .utils import is_hex_str, export

import logging
logger = logging.getLogger(__name__)

__all__ = []

@export
def extract_mnemonic(insn: Union[str, core.InsnScheme, core.InsnInstance]) -> str:
    """ Extract the mnemonic from the assembly of a single instruction.

    Here, this is the first whitespace-separated token that does not
    start with a brace and that is not a prefix.
    """
    if isinstance(insn, core.InsnScheme):
        insn_str = insn.str_template.template
    elif isinstance(insn, core.InsnInstance):
        insn_str = insn.scheme.str_template.template
    else:
        assert isinstance(insn, str)
        insn_str = insn

    tokens = insn_str.split()
    for t in tokens:
        if t.startswith("{"):
            continue
        if t == 'lock': # lock prefixes are not the mnemonic
            continue
        if t.startswith('rep'): # rep prefixes are not the mnemonic
            continue
        return t
    return None

all_registers = None
"""A dictionary mapping `RegisterOperand`s to the strings of register names.

Filled at module loading time by `_find_registers()`.
"""
__all__.append('all_registers')

_RegAliasClass_doc = """
An enum of all register aliasing classes (registers alias iff they have the
same aliasing class).

Filled at module loading time by `_find_registers()`.
"""
RegAliasClass = None
__all__.append('RegAliasClass')

_RegKind_doc = """
An enum of all register kinds.

Filled at module loading time by `_find_registers()`.
"""
RegKind = None
__all__.append('RegKind')

def _find_registers():
    """ Read the x86 registers from a csv file in the `inputfiles` directory.

    This is called at the end of the module and initializes global variables of
    this module:
        - all_registers: Dict[str, RegisterOperand]
        - RegAliasClass: Enum
        - RegKind: Enum
    """

    global all_registers,  RegAliasClass, RegKind

    class CSVKeywords:
        name = 'name'
        alias_class = 'alias_class'
        category = 'category'
        width = 'width'

    # read the registers from the specification in csv format
    csv_path = os.path.join(os.path.dirname(__file__), "inputfiles", "x86_registers.csv")
    with open(csv_path, "r") as csv_file:
        reader = DictReader(csv_file)
        data = [row for row in reader]

    # create enums for the alias classes (aliasing registers have the same
    # alias class) and categories
    alias_classes = { row[CSVKeywords.alias_class] for row in data }
    categories = { row[CSVKeywords.category] for row in data }

    RegAliasClass = Enum('RegAliasClass', sorted(alias_classes), module=__name__)
    RegAliasClass.__doc__ = _RegAliasClass_doc

    RegKind = Enum('RegKind', sorted(categories), module=__name__)
    RegKind.__doc__ = _RegKind_doc

    all_registers = dict()

    for row in data:
        name = row[CSVKeywords.name]
        alias_class = RegAliasClass[row[CSVKeywords.alias_class]]
        category = RegKind[row[CSVKeywords.category]]
        width = int(row[CSVKeywords.width])

        assert row["name"] not in all_registers.keys()
        regop = RegisterOperand(name=name, alias_class=alias_class, category=category, width=width)
        all_registers[name] = regop


@export
class RegisterOperand(core.OperandInstance):
    """ `core.OperandInstance` subclass to represent an x86 register for use as
    an operand.

    Characterized by a `name`, by which the register is referenced, an
    `alias_class` that is shared among registers that (fully or partially)
    alias, a `category` describing the kind of values the register can handle,
    and a `width` in bits.
    """

    def __init__(self, name: str, alias_class: "X86_RegAliasClass", category: "X86_RegKind", width: int):
        self.name = name
        self.alias_class = alias_class
        self.category = category
        self.width = width

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return "RegisterOperand(name: {}, alias_class: {}, category: {}, width: {})".format(repr(self.name), self.alias_class, self.category, self.width)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.name == other.name

    def __hash__(self):
        return hash((self.name))

    def to_json_dict(self):
        # all the other information is in the register description
        return { "kind": "x86RegisterOperand", "name": self.name }

@export
class RegisterConstraint(core.SetConstraint):
    """ A `core.OperandConstraint` for sets of `RegisterOperand`s.

    It differs from the `core.SetConstraint` in that it has a bit width
    annotated.
    """

    def __init__(self, acceptable_operands):
        super().__init__(acceptable_operands)

        # used for the json representation
        self.json_kind_id = "x86RegisterConstraint"

        # we assume that all acceptable register operands here have the same
        # width
        self.width = next(iter(self.acceptable_operands)).width


@export
class MemoryOperand(core.OperandInstance):
    """ A `core.OperandInstance` for x86 memory operands.

    The accessed address (wrt. an optional and mostly obsolete `segment`
    register) of such a memory operand is
    ```
        address = base + index * scale + displacement
    ```
    (where scale is a small power of two and displacement an immediate value.)
    """

    def __init__(self, width: int,
                segment: Optional[RegisterOperand]=None,
                base: Optional[RegisterOperand]=None,
                index: Optional[RegisterOperand]=None,
                scale: int=1,
                displacement: int=0,
                ):
        """ Constructor for a memory operand with the given components.
        Most of them are optional.
        """

        self.width = width
        self.segment = segment
        self.base = base
        self.index = index
        self.scale = scale
        self.displacement = displacement

    def additionally_read(self) -> Sequence[core.OperandInstance]:
        """ Return a list of `core.OperandInstance`s that are read to compute
        the memory location.

        That is: all present register components.
        """
        res = []
        if self.segment is not None:
            res.append(self.segment)
        if self.base is not None:
            res.append(self.base)
        if self.index is not None:
            res.append(self.index)
        return res

    def __str__(self):
        parts = []

        if self.base is not None:
            parts.append(str(self.base))

        if self.index is not None:
            offset = ""
            if self.scale != 1:
                offset += "{}*".format(str(self.scale))
            offset += str(self.index)
            parts.append(offset)
        if self.displacement != 0:
            parts.append(hex(self.displacement))

        res = " + ".join(parts)
        res = "[" + res + "]"
        res = res.replace("+ -", "- ") # negative displacements should be reported as subtraction

        if self.segment is not None:
            res = f"{self.segment}:" + res

        return res

    def __repr__(self):
        res = "MemoryOperand(width={}, ".format(self.width)
        if self.segment is not None:
            res += "segment={}, ".format(repr(self.segment))
        if self.base is not None:
            res += "base={}, ".format(repr(self.base))
        if self.index is not None:
            res += "index={}, ".format(repr(self.index))
        if self.scale != 1:
            res += "scale={}, ".format(repr(self.scale))
        if self.displacement != 0:
            res += "displacement={}, ".format(repr(self.displacement))
        if res.endswith(', '):
            res = res[:-2]
        res += ")"
        return res

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width
                and self.segment == other.segment
                and self.base == other.base
                and self.index == other.index
                and self.scale == other.scale
                and self.displacement == other.displacement)

    def __hash__(self):
        return hash((self.segment, self.base, self.index, self.scale, self.displacement))

    def to_json_dict(self):
        return { "kind": "x86MemoryOperand", "width": self.width,
                "segment": None if self.segment is None else self.segment.to_json_dict(),
                "base": None if self.base is None else self.base.to_json_dict(),
                "index": None if self.index is None else self.index.to_json_dict(),
                "scale": self.scale,
                "displacement": self.displacement,
                }


@export
class MemConstraint(core.OperandConstraint):
    """ A `core.OperandConstraint` for a `MemoryOperand` of a given `width`.
    """

    def __init__(self, context: "Context", width: int):
        self.ctx = context
        self.width = width

    def is_valid(self, operand):
        return (isinstance(operand, MemoryOperand) and
                self.width == operand.width)

    def from_match(self, match: pp.ParseResults) -> core.OperandInstance:
        kwargs = dict()
        reg_fun = lambda r: all_registers[r]
        hex_fun = lambda x: x[0]
        for k, fun in (("segement", reg_fun), ("base", reg_fun), ("index", reg_fun), ("scale", int), ("displacement", hex_fun)):
            if k in match:
                kwargs[k] = fun(match[k])
        if "minus" in match and "displacement" in match:
            kwargs["displacement"] *= -1

        op = self.ctx.dedup_store.get(MemoryOperand, width=self.width, **kwargs)
        return op

    @cached_property
    def parser_pattern(self):
        # this is a pyparsing parser for normalized x86 memory operands
        int_pattern = pp.pyparsing_common.integer
        hex_pattern = pp.Suppress(pp.Literal('0x')) + pp.pyparsing_common.hex_integer
        reg_pattern = self.ctx.pattern_all_gprs
        seg_pattern = self.ctx.pattern_all_segs

        # plus_or_end = (pp.Suppress(pp.Literal("+") + pp.NotAny(pp.Literal("]"))) | pp.FollowedBy(pp.Literal("]")))
        plus_minus_or_end = (((pp.Suppress(pp.Literal("+")) | pp.Literal("-")("minus")) + pp.NotAny(pp.Literal("]"))) | pp.FollowedBy(pp.Literal("]")))

        # order seems to be more or less irrelevant
        opt_scale_and_index = (
                (reg_pattern("index") + pp.Suppress(pp.Literal("*")) + int_pattern("scale")) |
                (int_pattern("scale") + pp.Suppress(pp.Literal("*")) + reg_pattern("index")) |
                reg_pattern("index") # it's important that this is after "index * scale"
                )

        mem_pattern = pp.Optional(seg_pattern.setResultsName("segment") + pp.Suppress(pp.Literal(":")))
        mem_pattern += pp.Suppress(pp.Literal("["))
        mem_pattern += pp.Optional(reg_pattern.setResultsName("base") + plus_minus_or_end)
        mem_pattern += pp.Optional(opt_scale_and_index + plus_minus_or_end)
        mem_pattern += pp.Optional(hex_pattern.setResultsName("displacement"))
        mem_pattern += pp.Suppress(pp.Literal("]"))

        mem_pattern = pp.Group(mem_pattern)

        return mem_pattern

    def __str__(self):
        return "MEM({})".format(self.width)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width)

    def __hash__(self):
        return hash((self.width))

    def to_json_dict(self):
        return { "kind": "x86MemConstraint", "width": self.width }


@export
class ImmediateOperand(core.OperandInstance):
    """ `core.OperandInstance` subclass to represent an immediate constant for
    use as an operand.

    Immediates have a `width` and a `value`
    """

    def __init__(self, width, value):
        assert isinstance(value, int)
        self.width = width
        self.value = value

    def __str__(self):
        return hex(self.value)

    def __repr__(self):
        return "ImmediateOperand(width={}, value={})".format(self.width, hex(self.value))

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width
                and self.value == other.value)

    def __hash__(self):
        return hash((self.width, self.value))

    def to_json_dict(self):
        return { "kind": "x86ImmediateOperand", "width": self.width, "value": self.value }


@export
class ImmConstraint(core.OperandConstraint):
    """ A `core.OperandConstraint` for an `ImmediateOperand` of a given width.

    Operand values are loosely checked to be in the range implied by the width.
    """

    def __init__(self, context: "Context", width: int):
        self.ctx = context
        self.width = width

    def is_valid(self, operand):
        if not (isinstance(operand, ImmediateOperand) and self.width == operand.width):
            return False

        val = operand.value
        # the union of the possible ranges if interpreted signed or unsigned
        inbounds = -(2 ** (self.width - 1)) <= val < (2 ** (self.width))

        return inbounds

    def from_match(self, match):
        # a match will be a single token, which is the constant
        imm = match[0]
        assert isinstance(imm, int)
        op = self.ctx.dedup_store.get(ImmediateOperand, width=self.width, value=imm)
        return op

    @cached_property
    def parser_pattern(self):
        # since we use hex immediates, we can match for width easily
        assert self.width % 4 == 0, "Width checking of immedidates is only supported for multiples of 4"
        max_num_nibbles = self.width // 4
        hex_pat = pp.Word("0123456789abcdefABCDEF", min=1, max=max_num_nibbles)
        return (pp.Optional(pp.Literal("-")("minus")) + pp.Literal('0x') + hex_pat("hex_pat")).setParseAction(lambda tokens: [int(tokens["hex_pat"], 16) * (-1 if "minus" in tokens else 1)])

    @property
    def parser_priority(self) -> int:
        # the smaller the width, the earlier we should try to match this
        return self.width

    def __str__(self):
        return "IMM({})".format(self.width)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width)

    def __hash__(self):
        return hash((self.width))

    def to_json_dict(self):
        return { "kind": "x86ImmConstraint", "width": self.width }


@export
class SymbolOperand(core.OperandInstance):
    """ A `core.OperandInstance` for symbolic x86 memory operands, i.e.,
    relocation symbols.

    The actual symbols are not represented, relocations are therefore not
    handled accurately.
    """

    def __init__(self):
        pass

    def __str__(self):
        return "pseudo_reloc_symbol"

    def __repr__(self):
        return "SymbolOperand()"

    def __eq__(self, other):
        return (self.__class__ == other.__class__)

    def __hash__(self):
        return 42

    def to_json_dict(self):
        return { "kind": "x86SymbolOperand" }


@export
class SymbolConstraint(core.OperandConstraint):
    """ `core.OperandConstraint` for symbol operands (for relocations/labels).

    Those are bit odd, since for encoding, llvm-mc will not accept integer
    operands in place of symbols (i.e. we would need to print them as labels,
    but that would yield an instruction with a hole for a relocation). llvm-mc
    is however happy to decode corresponding instructions with an immediate
    operand.

    We therefore parse them just as immediates (which we throw away) and encode
    them as the string `"SYM"`.
    """

    def __init__(self, context: "Context"):
        self.ctx = context

    def from_match(self, match):
        logger.warning("Encountered a relocation (e.g. for a jump label) in the input. It will not be handled in a semantically correct way.")
        # we don't care for the actual value
        op = self.ctx.dedup_store.get(SymbolOperand)
        return op

    @cached_property
    def parser_pattern(self):
        hex_pat = pp.Word("0123456789abcdefABCDEF", min=1)
        return (pp.Optional(pp.Literal("-")("minus")) + pp.Literal('0x') + hex_pat("hex_pat")).setParseAction(lambda tokens: [int(tokens["hex_pat"], 16) * (-1 if "minus" in tokens else 1)])

    def is_valid(self, operand):
        return (isinstance(operand, SymbolOperand))

    def __str__(self):
        return "SYM"

    def __eq__(self, other):
        return (self.__class__ == other.__class__)

    def __hash__(self):
        return 42

    def to_json_dict(self):
        return { "kind": "x86SymbolConstraint" }


@export
class Context(core.Context):
    """ A `core.Context` implementation for the x86-64 ISA.
    """

    @classmethod
    def get_ISA_id(cls) -> str:
        return "x86_64"

    def __init__(self, coder: Optional[core.ASMCoder]=None):
        if coder is None:
            coder = LLVMMCCoder("llvm-mc")

        super().__init__(coder)

        self._introduce_reg_group_names()

    def _introduce_reg_group_names(self):
        # establish some names for common groups of allowed registers
        # This makes the str representation of constraints and schemes more readable
        def intro_name_for_reg_group(name, group):
            assert len(group) > 0
            if isinstance(next(iter(group)), str):
                group = map(lambda x: all_registers[x], group)
            obj = self.dedup_store.get(RegisterConstraint, acceptable_operands=frozenset(group))
            obj.name = name

        groups = defaultdict(list)
        for k, regop in all_registers.items():
            if "ip" not in k:
                groups[(regop.category, regop.width)].append(regop)

        for (category, width), group in groups.items():
            intro_name_for_reg_group(f"{category.name}:{width}", group)

        intro_name_for_reg_group("K1..7", {f"k{n}" for n in range(1, 8)})
        intro_name_for_reg_group("XMM0..15", {f"xmm{n}" for n in range(0, 16)})
        intro_name_for_reg_group("YMM0..15", {f"ymm{n}" for n in range(0, 16)})



    def get_registers_where(self, *, name=None, alias_class=None, category=None, width=None):
        """ Get a tuple of registers that fulfill the conjunction of all
        constraints specified via keyword arguments.

        E.g., `get_registers_where(alias_class=foo, width=32)` provides a list
        of all 32-bit registers with the alias class `foo`.
        """
        # TODO improvement: this could benefit from an index

        it = tuple(( reg_op for k, reg_op in all_registers.items() ))

        for key, cond in (("name", name), ("alias_class", alias_class), ("category", category), ("width", width)):
            if cond is not None:
                it = tuple(filter(lambda x: getattr(x, key) == cond, it))

        return it

    @classmethod
    def get_default_instantiator_cls(cls):
        return DefaultInstantiator


    def must_alias(self, op1: core.OperandInstance, op2: core.OperandInstance):
        if isinstance(op1, RegisterOperand) and isinstance(op2, RegisterOperand):
            return op1.alias_class == op2.alias_class
        else:
            # Immediates are not considered aliasing.
            # Without further information MemoryOperands may or may not alias.
            return False


    def may_alias(self, op1: core.OperandInstance, op2: core.OperandInstance):
        if type(op1) != type(op2):
            # no cross-type aliases
            return False

        if isinstance(op1, RegisterOperand) and isinstance(op2, RegisterOperand):
            # registers may only alias if they must alias
            return op1.alias_class == op2.alias_class

        if isinstance(op1, ImmediateOperand) and isinstance(op2, ImmediateOperand):
            # Immediates are not considered aliasing.
            return False

        # Without further information MemoryOperands may alias.
        return True

    def make_example_bb(self) -> Optional["BasicBlock"]:
        return self.parse_asm_bb("add qword ptr [rcx + 0x42], rdx\nvaddpd ymm1, ymm2, ymm3")

    def adjust_operand(self, operand: core.OperandInstance, op_scheme: core.OperandScheme) -> core.OperandInstance:
        # if the operand is already valid: nothing to be done
        if op_scheme.is_operand_valid(operand):
            return operand

        if isinstance(operand, SymbolOperand):
            # we can't handle those in a meaningful way
            return None

        if op_scheme.is_fixed():
            fixed_operand = op_scheme.fixed_operand
            target_width = fixed_operand.width
            if isinstance(operand, RegisterOperand) and isinstance(fixed_operand, RegisterOperand):
                if operand.alias_class == fixed_operand.alias_class:
                    return fixed_operand
            # TODO improvement: we could do something better for immediates and memory operands
            return None

        constraint = op_scheme.operand_constraint
        target_width = constraint.width
        if isinstance(constraint, RegisterConstraint):
            if not isinstance(operand, RegisterOperand):
                return None
            acceptable = constraint.acceptable_operands
            fitting_regs = set(self.get_registers_where(alias_class=operand.alias_class, width=target_width))
            assert len(fitting_regs) >= 1
            if acceptable is not None:
                fitting_regs.intersection_update(acceptable)
            if len(fitting_regs) == 0:
                return None
            return next(iter(fitting_regs))

        if isinstance(constraint, MemConstraint):
            if not isinstance(operand, MemoryOperand):
                return None
            return self.dedup_store.get(MemoryOperand,
                    width=target_width, # just a different width, everything else stays the same
                    segment=operand.segment,
                    base=operand.base, index=operand.index,
                    scale=operand.scale,
                    displacement=operand.displacement)

        if isinstance(constraint, ImmConstraint):
            # TODO this can lead to invalid values if the value is too large
            # for the target width.
            return self.dedup_store.get(ImmediateOperand,
                    width=target_width, # just a different width, everything else stays the same
                    value=operand.value)

        if isinstance(constraint, SymbolConstraint):
            # we can't handle those in a meaningful way
            return None

        assert False, f"unsupported operand: {operand}"


    @cached_property
    def pattern_all_gprs(self):
        allowed_registers = self.get_registers_where(category=RegKind["GPR"])
        return pp.MatchFirst([pp.Keyword(r.name) for r in allowed_registers])


    @cached_property
    def pattern_all_segs(self):
        segment_registers = self.get_registers_where(category=RegKind["SEGMENT"])
        return pp.MatchFirst([pp.Keyword(r.name) for r in segment_registers])


    def extract_mnemonic(self, insn: Union[str, core.InsnScheme, core.InsnInstance]) -> str:
        return extract_mnemonic(insn)


    def operand_constraint_from_json_dict(self, jsondict):
        kind = jsondict["kind"]
        if kind == "x86RegisterConstraint":
            acceptable_operands = (self.operand_from_json_dict(op_dict) for op_dict in jsondict["acceptable_operands"])
            return self.dedup_store.get(RegisterConstraint, acceptable_operands=frozenset(acceptable_operands))
        elif kind == "x86ImmConstraint":
            return self.dedup_store.get(ImmConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86MemConstraint":
            return self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86SymbolConstraint":
            return self.dedup_store.get(SymbolConstraint, unhashed_kwargs={"context": self})
        raise core.SchemeError("unknown operand constraint kind: '{}'".format(kind))


    def operand_from_json_dict(self, jsondict):
        kind = jsondict["kind"]
        if kind == "x86RegisterOperand":
            register_op = all_registers.get(jsondict["name"], None)
            if register_op is None:
                raise core.SchemeError("unknown register: '{}'".format(jsondict["name"]))
            return register_op
        elif kind == "x86ImmediateOperand":
            return self.dedup_store.get(ImmediateOperand, width=jsondict["width"], value=jsondict["value"])
        elif kind == "x86SymbolOperand":
            return self.dedup_store.get(SymbolOperand)
        elif kind == "x86MemoryOperand":
            width = jsondict["width"]
            if jsondict["segment"] is not None:
                segment = self.operand_from_json_dict(jsondict["segment"])
            else:
                segment = None
            if jsondict["base"] is not None:
                base = self.operand_from_json_dict(jsondict["base"])
            else:
                base = None
            if jsondict["index"] is not None:
                index = self.operand_from_json_dict(jsondict["index"])
            else:
                index = None
            scale = jsondict["scale"]
            displacement = jsondict["displacement"]

            return self.dedup_store.get(MemoryOperand, width=width, segment=segment, base=base, index=index, scale=scale, displacement=displacement)

        raise core.SchemeError("unknown operand kind: '{}'".format(kind))


@export
class LLVMMCCoder(core.ASMCoder):
    """ Use the llvm-mc binary with subprocess calls (LLVM's assembly
    playground) for assembly encoding/decoding.
    """

    def __init__(self, llvm_mc_path):
        self.llvm_mc_path = llvm_mc_path
        if shutil.which(self.llvm_mc_path) is None:
            raise core.ASMCoderError(f"Could not find llvm-mc binary '{self.llvm_mc_path}'. Make sure it is on the PATH.")

    def asm2hex(self, asm_str) -> str:
        if not isinstance(asm_str, str):
            asm_str = "\n".join(asm_str)
        cmd = [self.llvm_mc_path]
        cmd.append("--arch=x86-64")
        cmd.append("--assemble")
        cmd.append("--show-encoding")
        cmd.append("--filetype=asm")

        input_str = ".intel_syntax noprefix\n" + asm_str

        subprocess_args = dict(
                input = input_str,
                capture_output = True,
                encoding = "latin1",
            )

        res = subprocess.run(cmd, **subprocess_args)
        if res.returncode != 0:
            raise core.ASMCoderError(
                    "Non-zero return code {} from llvm-mc when encoding input \"{}\"\nstderr:\n".format(res.returncode, input_str) + res.stderr)

        if "warning" in res.stderr:
            raise core.ASMCoderError(
                    "llvm-mc produced a warning when encoding input \"{}\":\n".format(input_str) + res.stderr)

        asm_output = res.stdout
        lines = asm_output.split("\n")

        hex_lines = []
        for l in lines:
            split_str = "# encoding: "
            if split_str not in l:
                continue
            # expected format: <instruction assembly> # encoding: [0x**,0x**,...]
            tokens = l.split(split_str)
            if len(tokens) != 2:
                raise core.ASMCoderError("Unexpected llvm-mc output line:\n  {}".format(l))
            hexlist = tokens[1]
            hexlist = hexlist.strip()
            if hexlist[0] != '[' or hexlist[-1] != ']':
                raise core.ASMCoderError("Unexpected llvm-mc output line:\n  {}".format(l))
            hex_tokens = hexlist[1:-1].split(",")
            hex_bytes = []
            for t in hex_tokens:
                if not t.startswith("0x"):
                    # this is most likely a relocation (represented as an "A" byte)
                    if t == "A":
                        # we "resolve" the relocation with a dummy value to allow testing jump instructions
                        hex_bytes.append("42")
                    else:
                        raise core.ASMCoderError("Unexpected llvm-mc output line (weird relocation?):\n  {}".format(l))
                hex_bytes.append(t[2:])

            hexstr = "".join(hex_bytes)

            if len(hexstr) == 0 or not is_hex_str(hexstr):
                raise core.ASMCoderError("Unexpected llvm-mc output line:\n  {}".format(l))
            hex_lines.append(hexstr)

        return "".join(hex_lines)


    def hex2asm(self, hex_str: str) -> Sequence[str]:
        cmd = [self.llvm_mc_path]
        cmd.append("--arch=x86-64")
        cmd.append("--disassemble")
        cmd.append("--filetype=asm")
        cmd.append("--print-imm-hex") # print immediates as hex
        cmd.append("--output-asm-variant=1") # use intel syntax

        # "ABCDEF" -> "[0xAB,0xCD,0xEF]"
        input_str = ",".join(map(lambda x: "0x"+x[0]+x[1], zip(hex_str[0::2], hex_str[1::2])))
        input_str = "[" + input_str + "]"

        subprocess_args = dict(
                input = input_str,
                capture_output = True,
                encoding = "latin1",
            )

        res = subprocess.run(cmd, **subprocess_args)
        if res.returncode != 0:
            raise core.ASMCoderError(
                    "Non-zero return code {} from llvm-mc when decoding input \"{}\"\nstderr:\n".format(res.returncode, input_str) + res.stderr)

        if "warning" in res.stderr:
            raise core.ASMCoderError(
                    "llvm-mc produced a warning when decoding input \"{}\":\n".format(input_str) + res.stderr)

        asm_output = res.stdout
        lines = asm_output.split("\n")

        asm_lines = []
        prev_line_prefix = ""
        for l in lines:

            # eliminate comments
            loc = l.find("#")
            if loc >= 0:
                l = l[:loc]

            tokens = l.split()
            asm_str = " ".join(tokens)
            if len(asm_str) == 0 or asm_str[0] == '.':
                continue
            asm_str = asm_str.lower()

            if asm_str == "lock":
                prev_line_prefix += asm_str + " "
                continue

            asm_lines.append(prev_line_prefix + asm_str)
            prev_line_prefix = ""

        assert prev_line_prefix == ""

        return asm_lines


@export
class DefaultInstantiator:
    """ Convenience class to quickly instantiate a `core.InsnScheme` with
    arbitrary but valid values, mainly for testing.
    """

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def __call__(self, scheme):
        """ Return an arbitrary, but fixed, instantiation of the passed `scheme`.
        Can handle `core.InsnScheme`s as well as `core.OperandScheme`s.
        """

        if isinstance(scheme, core.InsnScheme):
            return self.for_insn(scheme)
        elif isinstance(scheme, core.OperandScheme):
            return self.for_operand(scheme)
        raise core.SchemeError("trying to instantiate incompatible object: {}".format(repr(scheme)))

    def for_insn(self, insn_scheme: core.InsnScheme) -> core.InsnInstance:
        """ Create an arbitrary, but fixed, `core.InsnInstance` from a scheme.
        """

        args = dict()
        for name, operand_scheme in insn_scheme.explicit_operands.items():
            args[name] = self.for_operand(operand_scheme)
        return insn_scheme.instantiate(args)

    def for_operand(self, operand_scheme: core.OperandScheme) -> core.OperandInstance:
        """ Create an arbitrary, but fixed, `core.OperandInstance` instance from a scheme.
        """

        if operand_scheme.is_fixed():
            return operand_scheme.fixed_operand

        constraint = operand_scheme.operand_constraint

        if isinstance(constraint, RegisterConstraint):
            for op in constraint.acceptable_operands:
                if "a" in str(op) or "c" in str(op):
                    # rax and ecx (and variants thereof) might be used for more
                    # specific hard-wired schemes, so avoid them here if
                    # possible
                    continue
                return op
            # if not possible, just return the last one
            return op
        elif isinstance(constraint, MemConstraint):
            return self.get_valid_memory_operand(constraint)
        elif isinstance(constraint, SymbolConstraint):
            return self.ctx.dedup_store.get(SymbolOperand)
        elif isinstance(constraint, ImmConstraint):
            return self.get_valid_imm_operand(constraint)

    def get_valid_memory_operand(self, mem_constraint):
        """ Create an arbitrary `MemoryOperand` for a constraint.
        """

        base_reg = all_registers["rbx"]
        displacement = 64

        return MemoryOperand(width=mem_constraint.width, base=base_reg, displacement=displacement)

    def get_valid_imm_operand(self, imm_constraint):
        """ Create an arbitrary `ImmediateOperand` for a constraint.
        """

        # choose a value that is not representable with width - 8 bits
        width = imm_constraint.width
        assert width >= 8
        val = 2 ** (width-8) + 42

        return ImmediateOperand(width=width, value=val)

@export
class RandomRegisterInstantiator(DefaultInstantiator):
    """ Modification of the `DefaultInstantiator` to produce somewhat
    randomized `core.InsnInstances` rather the fixed ones produced by the
    original.
    """

    def __init__(self, ctx: Context):
        super().__init__(ctx)
        self.mem_registers = [all_registers[x] for x in ["rbx", "rdx", "r12", "r13"]]

    def for_operand(self, operand_scheme: core.OperandScheme) -> core.OperandInstance:
        if operand_scheme.is_fixed():
            return operand_scheme.fixed_operand

        constraint = operand_scheme.operand_constraint

        if isinstance(constraint, RegisterConstraint):
            return random.choice(constraint.acceptable_operands)
        else:
            return super().for_operand(operand_scheme)

    def get_valid_memory_operand(self, mem_constraint):
        base_reg = random.choice(self.mem_registers)
        displacement = random.choice([0, 0, 0, 8, 64, 2000])
        index_reg = None
        if random.choice([True, False, False, False]):
            index_reg = random.choice(self.mem_registers)

        return MemoryOperand(width=mem_constraint.width, base=base_reg, displacement=displacement)


# Populate the register set and related enums
_find_registers()

