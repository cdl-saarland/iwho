
from typing import Sequence, Optional, Union

from csv import DictReader
from enum import Enum
from collections import defaultdict
import os
import random
import subprocess


from functools import cached_property
import pyparsing as pp

from . import core
from .utils import is_hex_str, export

import logging
logger = logging.getLogger(__name__)


all_registers = None
RegAliasClass = None
RegKind = None

def _find_registers():
    """ Read the x86 registers from a csv file next to this source file.

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
    csv_path = os.path.join(os.path.dirname(__file__), "x86_registers.csv")
    with open(csv_path, "r") as csv_file:
        reader = DictReader(csv_file)
        data = [row for row in reader]

    # create enums for the alias classes (aliasing registers have the same
    # alias class) and categories
    alias_classes = { row[CSVKeywords.alias_class] for row in data }
    categories = { row[CSVKeywords.category] for row in data }

    RegAliasClass = Enum('RegAliasClass', sorted(alias_classes), module=__name__)
    RegKind = Enum('RegKind', sorted(categories), module=__name__)

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
    """ TODO document
    """

    def __init__(self, name: str, alias_class: "X86_RegAliasClass", category: "X86_RegKind", width: int):
        """ TODO document
        """

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
class MemoryOperand(core.OperandInstance):
    """ TODO document
    """

    def __init__(self, width: int,
                segment: Optional[RegisterOperand]=None,
                base: Optional[RegisterOperand]=None,
                index: Optional[RegisterOperand]=None,
                scale: int=1,
                displacement: int=0,
                ):
        """ TODO document
        """

        # address = base + index * scale + displacement
        self.width = width
        self.segment = segment
        self.base = base
        self.index = index
        self.scale = scale
        self.displacement = displacement

    def additionally_read(self) -> Sequence[core.OperandInstance]:
        # to evaluate a memory operand, independently of whether it is written
        # or read (or only used for the agen in a LEA instruction), the
        # involved address registers are read.
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
    """ TODO document
    """

    def __init__(self, context: "Context", width: int):
        """ TODO document
        """
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
    """ TODO document
    """

    def __init__(self, width, value):
        """ TODO document
        """
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
    """ TODO document
    """

    def __init__(self, context: "Context", width: int):
        """ TODO document
        """

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
    """ TODO document
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
    """ Constraint for symbol operands (for relocations/labels).

    Those are bit odd, since for encoding, llvm-mc will not accept integer
    operands in place of symbols (i.e. we would need to print them as labels,
    but that would yield an instruction with a hole for a relocation). llvm-mc
    is however happy to decode corresponding instructions with an immediate
    operand.

    We therefore parse them just as immediates so that we can decode them (by
    inheriting most functionality from ImmConstraint), but don't allow encoding
    them.
    """
    # TODO update documentation

    def __init__(self, context: "Context"):
        self.ctx = context

    def from_match(self, match):
        logger.warning("Encountered a relocation (e.g. for a jump label) in the input. It will not be handled semantically correct.")
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
    """ TODO document
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
            obj = self.dedup_store.get(core.SetConstraint, acceptable_operands=frozenset(group))
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



    def get_registers_where(self, *, name=None, alias_class=None, category=None):
        """ TODO document
        """
        # TODO this could benefit from an index

        it = tuple(( reg_op for k, reg_op in all_registers.items() ))

        for key, cond in (("name", name), ("alias_class", alias_class), ("category", category)):
            if cond is not None:
                it = tuple(filter(lambda x: getattr(x, key) == cond, it))

        return it


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


    @cached_property
    def pattern_all_gprs(self):
        allowed_registers = self.get_registers_where(category=RegKind["GPR"])
        return pp.MatchFirst([pp.Keyword(r.name) for r in allowed_registers])


    @cached_property
    def pattern_all_segs(self):
        segment_registers = self.get_registers_where(category=RegKind["SEGMENT"])
        return pp.MatchFirst([pp.Keyword(r.name) for r in segment_registers])


    def extract_mnemonic(self, insn: Union[str, core.InsnScheme, core.InsnInstance]) -> str:
        """ Extract the mnemonic from the assembly of a single instruction

        Here, this is the first whitespace-separated token that does not
        start with a brace.
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
            return t
        return None


    def operand_constraint_from_json_dict(self, jsondict):
        """ TODO document
        """

        kind = jsondict["kind"]
        if kind == "SetConstraint":
            acceptable_operands = (self.operand_from_json_dict(op_dict) for op_dict in jsondict["acceptable_operands"])
            return self.dedup_store.get(core.SetConstraint, acceptable_operands=frozenset(acceptable_operands))
        elif kind == "x86ImmConstraint":
            return self.dedup_store.get(ImmConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86MemConstraint":
            return self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86SymbolConstraint":
            return self.dedup_store.get(SymbolConstraint, unhashed_kwargs={"context": self})
        raise core.SchemeError("unknown operand constraint kind: '{}'".format(kind))


    def operand_from_json_dict(self, jsondict):
        """ TODO document
        """

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
    """ Use the llvm-mc binary with subprocess calls (LLVM's assmebly
    playground) for assembly encoding/decoding.
    """

    def __init__(self, llvm_mc_path):
        self.llvm_mc_path = llvm_mc_path

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
    """ TODO document
    """

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def __call__(self, scheme):
        """ TODO document
        """

        if isinstance(scheme, core.InsnScheme):
            return self.for_insn(scheme)
        elif isinstance(scheme, core.OperandScheme):
            return self.for_operand(scheme)
        raise core.SchemeError("trying to instantiate incompatible object: {}".format(repr(scheme)))

    def for_insn(self, insn_scheme: core.InsnScheme) -> core.InsnInstance:
        """ Create an instruction instance from a scheme
        """

        args = dict()
        for name, operand_scheme in insn_scheme.operand_schemes.items():
            args[name] = self.for_operand(operand_scheme)
        return insn_scheme.instantiate(args)

    def for_operand(self, operand_scheme: core.OperandScheme) -> core.OperandInstance:
        """ Create an OperandInstance instance from a scheme
        """

        if operand_scheme.is_fixed():
            return operand_scheme.fixed_operand

        constraint = operand_scheme.operand_constraint

        if isinstance(constraint, core.SetConstraint):
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
        """ Create an OperandInstance instance from a scheme
        """

        base_reg = all_registers["rbx"]
        displacement = 64

        return MemoryOperand(width=mem_constraint.width, base=base_reg, displacement=displacement)

    def get_valid_imm_operand(self, imm_constraint):
        """ Create an OperandInstance instance from a scheme
        """

        # choose a value that is not representable with width - 8 bits
        width = imm_constraint.width
        assert width >= 8
        val = 2 ** (width-8) + 42

        return ImmediateOperand(width=width, value=val)

@export
class RandomRegisterInstantiator(DefaultInstantiator):
    def __init__(self, ctx: Context):
        super().__init__(ctx)

    def for_operand(self, operand_scheme: core.OperandScheme) -> core.OperandInstance:
        if operand_scheme.is_fixed():
            return operand_scheme.fixed_operand

        constraint = operand_scheme.operand_constraint

        if isinstance(constraint, core.SetConstraint):
            return random.choice(constraint.acceptable_operands)
        else:
            return super().for_operand(operand_scheme)


# Populate the register set and related enums
_find_registers()

