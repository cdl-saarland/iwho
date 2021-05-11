
from typing import Sequence, Optional

from enum import Enum
from collections import defaultdict
import os
import subprocess

from functools import cached_property
import pyparsing as pp

import iwho.iwho as iwho
from iwho.iwho_utils import is_hex_str


class RegisterOperand(iwho.OperandInstance):
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


class MemoryOperand(iwho.OperandInstance):
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

    def additionally_read(self) -> Sequence[iwho.OperandInstance]:
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
        res = ""

        if self.segment is not None:
            res += "{}:".format(str(self.segment))

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

        res += " + ".join(parts)
        res = "[" + res + "]"
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


class MemConstraint(iwho.OperandConstraint):
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

    def from_match(self, match):
        kwargs = dict()
        reg_fun = lambda r: self.ctx.all_registers[r]
        hex_fun = lambda x: x[0]
        for k, fun in (("segement", reg_fun), ("base", reg_fun), ("index", reg_fun), ("scale", int), ("displacement", hex_fun)):
            if k in match:
                kwargs[k] = fun(match[k])

        op = self.ctx.dedup_store.get(MemoryOperand, width=self.width, **kwargs)
        return op

    @cached_property
    def parser_pattern(self):
        int_pattern = pp.pyparsing_common.integer
        hex_pattern = pp.Suppress(pp.Literal('0x')) + pp.pyparsing_common.hex_integer
        allowed_registers = self.ctx.get_registers_where(category=self.ctx._reg_category_enum["GPR"])
        reg_pattern = pp.MatchFirst([pp.Literal(r.name) for r in allowed_registers]) # TODO this should probably be cached

        segment_registers = self.ctx.get_registers_where(category=self.ctx._reg_category_enum["SEGMENT"])
        seg_pattern = pp.MatchFirst([pp.Literal(r.name) for r in segment_registers]) # TODO this should probably be cached

        plus_or_end = (pp.Suppress(pp.Literal("+") + pp.NotAny(pp.Literal("]"))) | pp.FollowedBy(pp.Literal("]")))

        # order seems to be more or less irrelevant
        scale_and_index = (
                (reg_pattern("index") + pp.Suppress(pp.Literal("*")) + int_pattern("scale")) |
                (int_pattern("scale") + pp.Suppress(pp.Literal("*")) + reg_pattern("index")))

        mem_pattern = pp.Suppress(pp.Literal("["))
        mem_pattern += pp.Optional(seg_pattern.setResultsName("segment") + pp.Suppress(pp.Literal(":")))
        mem_pattern += pp.Optional(reg_pattern.setResultsName("base") + plus_or_end)
        mem_pattern += pp.Optional(scale_and_index + plus_or_end)
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


class ImmediateOperand(iwho.OperandInstance):
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


class ImmConstraint(iwho.OperandConstraint):
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
        return pp.Suppress(pp.Literal('0x')) + pp.pyparsing_common.hex_integer

    def __str__(self):
        return "IMM({})".format(self.width)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width)

    def __hash__(self):
        return hash((self.width))

    def to_json_dict(self):
        return { "kind": "x86ImmConstraint", "width": self.width }


class Context(iwho.Context):
    """ TODO document
    """

    def __init__(self, coder: Optional[iwho.ASMCoder]=None):
        self.all_registers = dict()

        if coder is None:
            coder = LLVMMCCoder("llvm-mc")

        super().__init__(coder)

        self._add_registers()

    def get_registers_where(self, *, name=None, alias_class=None, category=None):
        """ TODO document
        """
        # TODO this could benefit from an index

        it = tuple(( reg_op for k, reg_op in self.all_registers.items() ))

        for key, cond in (("name", name), ("alias_class", alias_class), ("category", category)):
            if cond is not None:
                it = tuple(filter(lambda x: getattr(x, key) == cond, it))

        return it


    def extract_mnemonic(self, insn_str: str) -> str:
        """ Extract the mnemonic from the assembly of a single instruction

        Here, this is the first whitespace-separated token that does not
        start with a brace.
        """
        tokens = insn_str.split()
        for t in tokens:
            if t.startswith("{"):
                continue
            return t
        return None


    class CSVKeywords:
        """ TODO document
        """

        name = 'name'
        alias_class = 'alias_class'
        category = 'category'
        width = 'width'


    def _add_registers(self):
        """ TODO document
        """

        from csv import DictReader

        alias_class_mapping = dict()
        alias_class_mapping = dict()

        # read the registers from the specification in csv format
        csv_path = os.path.join(os.path.dirname(__file__), "x86_registers.csv")
        with open(csv_path, "r") as csv_file:
            reader = DictReader(csv_file)
            data = [row for row in reader]

        # create enums for the alias classes (aliasing registers have the same
        # alias class) and categories
        alias_classes = { row[self.CSVKeywords.alias_class] for row in data }
        categories = { row[self.CSVKeywords.category] for row in data }

        self._reg_alias_class_enum = Enum('X86_RegAliasClass', sorted(alias_classes), module="__name__")
        self._reg_category_enum = Enum('X86_RegKind', sorted(categories), module="__name__")

        for row in data:
            name = row[self.CSVKeywords.name]
            alias_class = self._reg_alias_class_enum[row[self.CSVKeywords.alias_class]]
            category = self._reg_category_enum[row[self.CSVKeywords.category]]
            width = int(row[self.CSVKeywords.width])

            assert row["name"] not in self.all_registers.keys()
            regop = RegisterOperand(name=name, alias_class=alias_class, category=category, width=width)
            self.all_registers[name] = regop


        # establish some names for common groups of allowed registers
        # This makes the str representation of constraints and schemes more readable
        def intro_name_for_reg_group(name, group):
            assert len(group) > 0
            if isinstance(next(iter(group)), str):
                group = map(lambda x: self.all_registers[x], group)
            obj = self.dedup_store.get(iwho.SetConstraint, acceptable_operands=frozenset(group))
            obj.name = name

        groups = defaultdict(list)
        for k, regop in self.all_registers.items():
            if "ip" not in k:
                groups[(regop.category, regop.width)].append(regop)

        for (category, width), group in groups.items():
            intro_name_for_reg_group(f"{category.name}:{width}", group)

        intro_name_for_reg_group("K1..7", {f"k{n}" for n in range(1, 8)})
        intro_name_for_reg_group("XMM0..15", {f"xmm{n}" for n in range(0, 16)})
        intro_name_for_reg_group("YMM0..15", {f"ymm{n}" for n in range(0, 16)})


    def operand_constraint_from_json_dict(self, jsondict):
        """ TODO document
        """

        kind = jsondict["kind"]
        if kind == "SetConstraint":
            acceptable_operands = (self.operand_from_json_dict(op_dict) for op_dict in jsondict["acceptable_operands"])
            return self.dedup_store.get(iwho.SetConstraint, acceptable_operands=acceptable_operands)
        elif kind == "x86ImmConstraint":
            return self.dedup_store.get(ImmConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86MemConstraint":
            return self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        raise iwho.SchemeError("unknown operand constraint kind: '{}'".format(kind))


    def operand_from_json_dict(self, jsondict):
        """ TODO document
        """

        kind = jsondict["kind"]
        if kind == "x86RegisterOperand":
            register_op = self.all_registers.get(jsondict["name"], None)
            if register_op is None:
                raise iwho.SchemeError("unknown register: '{}'".format(jsondict["name"]))
            return register_op
        elif kind == "x86ImmediateOperand":
            return self.dedup_store.get(ImmediateOperand, width=jsondict["width"], value=jsondict["value"])
        elif kind == "x86MemoryOperand":
            width = jsondict["width"]
            segment = self.operand_from_json_dict(jsondict["segment"])
            base = self.operand_from_json_dict(jsondict["base"])
            index = self.operand_from_json_dict(jsondict["index"])
            scale = jsondict["scale"]
            displacement = jsondict["displacement"]

            return self.dedup_store.get(MemoryOperand, width=width, segment=segment, base=base, index=index, scale=scale, displacement=displacement)

        raise iwho.SchemeError("unknown operand kind: '{}'".format(kind))


class LLVMMCCoder(iwho.ASMCoder):
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
            raise iwho.ASMCoderError(
                    "Non-zero return code from llvm-mc when encoding: {}\nstderr:\n".format(res.returncode) + res.stderr)

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
                raise iwho.ASMCoderError("Unexpected llvm-mc output line:\n  {}".format(l))
            hexlist = tokens[1]
            hexlist = hexlist.strip()
            hexlist = hexlist.replace("[", "")
            hexlist = hexlist.replace("]", "")
            hexlist = hexlist.replace(",", "")
            hexlist = hexlist.replace("0x", "")
            if len(hexlist) == 0 or not is_hex_str(hexlist):
                raise iwho.ASMCoderError("Unexpected llvm-mc output line:\n  {}".format(l))
            hex_lines.append(hexlist)

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
            raise iwho.ASMCoderError(
                    "Non-zero return code from llvm-mc when decoding: {}\nstderr:\n".format(res.returncode) + res.stderr)

        asm_output = res.stdout
        lines = asm_output.split("\n")

        asm_lines = []
        for l in lines:
            tokens = l.split()
            asm_str = " ".join(tokens)
            if len(asm_str) == 0 or asm_str[0] == '.':
                continue
            asm_str = asm_str.lower()
            asm_lines.append(asm_str)

        return asm_lines


class DefaultInstantiator:
    """ TODO document
    """

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def __call__(self, scheme):
        """ TODO document
        """

        if isinstance(scheme, iwho.InsnScheme):
            return self.for_insn(scheme)
        elif isinstance(scheme, iwho.OperandScheme):
            return self.for_operand(scheme)
        raise iwho.SchemeError("trying to instantiate incompatible object: {}".format(repr(scheme)))

    def for_insn(self, insn_scheme: iwho.InsnScheme) -> iwho.InsnInstance:
        """ Create an instruction instance from a scheme
        """

        args = dict()
        for name, operand_scheme in insn_scheme.operand_schemes.items():
            args[name] = self.for_operand(operand_scheme)
        return insn_scheme.instantiate(args)

    def for_operand(self, operand_scheme: iwho.OperandScheme) -> iwho.OperandInstance:
        """ Create an OperandInstance instance from a scheme
        """

        if operand_scheme.is_fixed():
            return operand_scheme.fixed_operand

        constraint = operand_scheme.operand_constraint

        if isinstance(constraint, iwho.SetConstraint):
            return next(iter(constraint.acceptable_operands))
        elif isinstance(constraint, MemConstraint):
            return self.get_valid_memory_operand(constraint)
        elif isinstance(constraint, ImmConstraint):
            return self.get_valid_imm_operand(constraint)

    def get_valid_memory_operand(self, mem_constraint):
        """ Create an OperandInstance instance from a scheme
        """

        base_reg = self.ctx.all_registers["rbx"]
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

