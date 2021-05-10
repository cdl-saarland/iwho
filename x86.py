
from typing import Sequence, Optional

from enum import Enum
from collections import defaultdict
import os
import string
import subprocess

from functools import cached_property
import pyparsing as pp

import iwho as iwho


def extract_mnemonic(insn_str):
    # TODO also use this in parsing
    tokens = insn_str.split()
    for t in tokens:
        if t.startswith("{"):
            continue
        return t
    return None

class RegisterOperand(iwho.Operand):
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


class MemoryOperand(iwho.Operand):
    def __init__(self, width: int,
                segment: Optional[RegisterOperand]=None,
                base: Optional[RegisterOperand]=None,
                index: Optional[RegisterOperand]=None,
                scale: int=1,
                displacement: int=0,
                ):
        # address = base + index * scale + displacement
        self.width = width
        self.segment = segment
        self.base = base
        self.index = index
        self.scale = scale
        self.displacement = displacement

    def additionally_read(self) -> Sequence[iwho.Operand]:
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
            offset += str(self.index)
            if self.scale != 1:
                offset += "*{}".format(str(self.scale))
            parts.append(offset)
        if self.displacement != 0:
            parts.append(str(self.displacement))

        res += "+".join(parts)
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


class ImmediateOperand(iwho.Operand):
    def __init__(self, width, value):
        self.width = width
        self.value = value

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return "ImmediateOperand(width={}, value={})".format(self.width, repr(self.value))

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width
                and self.value == other.value)

    def __hash__(self):
        return hash((self.width, self.value))

    def to_json_dict(self):
        return { "kind": "x86ImmediateOperand", "width": self.width, "value": self.value }


class ImmConstraint(iwho.OperandConstraint):
    def __init__(self, context: "Context", width: int):
        self.ctx = context
        self.width = width

    def is_valid(self, operand):
        return (isinstance(operand, ImmediateOperand) and
                self.width == operand.width)
        # TODO check if the value is in range

    def from_match(self, match):
        # a match will be a parsing result object with a single token, which is
        # the constant
        # assert len(match) == 1
        imm = str(match)
        op = self.ctx.dedup_store.get(ImmediateOperand, width=self.width, value=imm)
        return op

    @cached_property
    def parser_pattern(self):
        # TODO hex and other constants might be needed as well
        return pp.pyparsing_common.integer

    def __str__(self):
        return "IMM({})".format(self.width)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.width == other.width)

    def __hash__(self):
        return hash((self.width))

    def to_json_dict(self):
        return { "kind": "x86ImmConstraint", "width": self.width }


class MemConstraint(iwho.OperandConstraint):
    def __init__(self, context: "Context", width: int):
        self.ctx = context
        self.width = width

    def is_valid(self, operand):
        return (isinstance(operand, MemoryOperand) and
                self.width == operand.width)

    def from_match(self, match):
        kwargs = dict()
        reg_fun = lambda r: self.ctx.all_registers[r]
        for k, fun in (("segement", reg_fun), ("base", reg_fun), ("index", reg_fun), ("scale", int), ("displacement", int)):
            if k in match:
                kwargs[k] = fun(match[k])

        op = self.ctx.dedup_store.get(MemoryOperand, width=self.width, **kwargs)
        return op

    @cached_property
    def parser_pattern(self):
        int_pattern = pp.pyparsing_common.integer
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
        mem_pattern += pp.Optional(int_pattern.setResultsName("displacement"))
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

class DedupStore:
    def __init__(self):
        self.stores = defaultdict(dict)

    def get(self, constructor, unhashed_kwargs=dict(), **kwargs):
        store = self.stores[constructor]
        key = tuple(sorted(kwargs.items(), key=lambda x: x[0]))
        stored_res = store.get(key, None)
        if stored_res is not None:
            return stored_res
        new_res = constructor(**unhashed_kwargs, **kwargs)
        store[key] = new_res
        return new_res


class Context(iwho.Context):

    def __init__(self):
        self.all_registers = dict()
        self.insn_schemes = []
        self.dedup_store = DedupStore()

        # this is an index to speed up parsing by only trying to match
        # instruction schemes with a fitting mnemonic
        self.mnemonic_to_insn_schemes = defaultdict(list)

        self._add_registers()

    def get_registers_where(self, *, name=None, alias_class=None, category=None):
        # TODO this could benefit from an index

        it = tuple(( reg_op for k, reg_op in self.all_registers.items() ))

        for key, cond in (("name", name), ("alias_class", alias_class), ("category", category)):
            if cond is not None:
                it = tuple(filter(lambda x: getattr(x, key) == cond, it))

        return it


    class CSVKeywords:
        name = 'name'
        alias_class = 'alias_class'
        category = 'category'
        width = 'width'


    def _add_registers(self):
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
            if "IP" not in k:
                groups[(regop.category, regop.width)].append(regop)

        for (category, width), group in groups.items():
            intro_name_for_reg_group(f"{category.name}:{width}", group)

        intro_name_for_reg_group("K1..7", {f"K{n}" for n in range(1, 8)})
        intro_name_for_reg_group("XMM0..15", {f"XMM{n}" for n in range(0, 16)})
        intro_name_for_reg_group("YMM0..15", {f"YMM{n}" for n in range(0, 16)})



    def add_insn_scheme(self, scheme):
        self.insn_schemes.append(scheme)
        mnemonic = extract_mnemonic(scheme.str_template.template)
        self.mnemonic_to_insn_schemes[mnemonic].append(scheme)


    def disassemble(self, hex_str):
        # TODO make generic
        cmd = ["/home/ritter/projects/portmapping/xedplayground/build_XEDWrappers/dec", hex_str]
        res = subprocess.run(cmd, capture_output=True, encoding='utf-8')

        if res.returncode != 0:
            err_str = "instruction decoder call failed:\n" + res.stderr
            raise iwho.IWHOError(err_str)

        output = res.stdout

        insns = []

        lines = output.split('\n')
        for l in lines:
            insn_instance = self.match_insn_str
            insns.append(insn_instance)

        return insns


    def match_insn_str(self, insn_str):
        insn_str = insn_str.strip()
        mnemonic = extract_mnemonic(insn_str)

        candidate_schemes = self.mnemonic_to_insn_schemes[mnemonic]
        if len(candidate_schemes) == 0:
            raise iwho.UnknownInstructionError(
                    f"instruction: {insn_str}, no schemes with matching mnemonic '{mnemonic}' found")

        # TODO cache that instead?
        pat = pp.MatchFirst([pp.Group(cs.parser_pattern).setResultsName(str(x)) for x, cs in enumerate(candidate_schemes)])
        try:
            match = pat.parseString(insn_str)
        except pp.ParseException as e:
            raise iwho.UnknownInstructionError(f"instruction: {insn_str}, ParsingError: {e.msg}")

        assert len(match) == 1, "an internal pyparsing assumption is violated"

        keys = list(match.keys())
        assert len(keys) == 1, "an internal pyparsing assumption is violated"
        key  = keys[0]
        matching_scheme = candidate_schemes[int(key)]

        # TODO deduplicate parsing
        return matching_scheme.instantiate(insn_str)


    def assemble(self, insn_instances):
        if not isinstance(insn_instances, list):
            insn_instances = [insn_instances]

        res = []
        for ii in insn_instances:
            res.append(self.assemble_single(ii))

        return res


    def assemble_single(self, insn_instance):
        insn_str = str(insn_instance)

        # TODO make generic
        cmd = ["/home/ritter/projects/portmapping/xedplayground/build_XEDWrappers/enc", "-64", insn_str]
        res = subprocess.run(cmd, capture_output=True, encoding='utf-8')

        if res.returncode != 0:
            err_str = "instruction encoder call failed:\n" + res.stderr
            raise iwho.IWHOError(err_str)

        output = res.stdout

        hex_str = ""

        lines = output.split('\n')
        for l in lines:
            l = l.strip()
            if len(l) == 0 or l[0] == '#':
                continue
            prefix = ".byte "
            if l.startswith(prefix):
                ls = l[len(prefix):]
                hex_line = "".join(map(lambda x: x[2:], ls.split(",")))
                if not all(map(lambda c: c in "0123456789abcdef", hex_line)):
                    err_str = "unexpected output line from encoder (not a hex string):\n" + l
                    raise iwho.IWHOError(err_str)
                hex_str += hex_line
            else:
                err_str = "unexpected output line from encoder:\n" + l
                raise iwho.IWHOError(err_str)

        return hex_str

    def operand_constraint_from_json_dict(self, jsondict):
        kind = jsondict["kind"]
        if kind == "SetConstraint":
            acceptable_operands = (self.operand_from_json_dict(op_dict) for op_dict in jsondict["acceptable_operands"])
            return self.dedup_store.get(iwho.SetConstraint, acceptable_operands=acceptable_operands)
        elif kind == "x86ImmConstraint":
            return self.dedup_store.get(ImmConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        elif kind == "x86MemConstraint":
            return self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=jsondict["width"])
        raise IWHOError("unknown operand constraint kind: '{}'".format(kind))

    def operand_from_json_dict(self, jsondict):
        kind = jsondict["kind"]
        if kind == "x86RegisterOperand":
            register_op = self.all_registers.get(jsondict["name"], None)
            if register_op is None:
                raise IWHOError("unknown register: '{}'".format(jsondict["name"]))
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

        raise IWHOError("unknown operand kind: '{}'".format(kind))


        # with tempfile.NamedTemporaryFile("w") as tmp_file:
        #     tmp_file.write(insn_str)
        #     tmp_file.flush()
        #     tmp_name = tmp_file.name
        #     bin_name = tmp_name + ".bin"
        #
        #     cmd = ["as", "-msyntax=intel", "-mnaked-reg", "-o", bin_name, tmp_name]
        #     res = subprocess.run(cmd)
        #
        #     if res.returncode != 0:
        #         err_str = "as call failed!"
        #         raise MuAnalyzerError(err_str)
        #
        #     with open(bin_name, 'rb') as infile:
        #         code, addr = extract_code(infile)
        #
        #     if os.path.exists(bin_name):
        #         os.remove(bin_name)
        # return code


# def scheme_for_insnstr(ctx: Context, insnstr: str):
#     insnstr = insnstr.toupper()
#
#     tokens = []
#     i = 0
#     L = len(insnstr)
#     while i < L:
#         c = insnstr[i]
#         if c.isspace():
#             i += 1
#         elif c == '{':
#             prefix = ""
#             while insnstr[i] != '}': # TODO check for overflow
#                 if not insnstr[i].isspace():
#                     prefix += insnstr[i]
#                 i += 1
#             prefix += insnstr[i]
#             i += 1
#             tokens.append(prefix)
#         elif c == '[':
#             memop = ""
#             while insnstr[i] != ']': # TODO check for overflow
#                 if not insnstr[i].isspace():
#                     memop += insnstr[i]
#                 i += 1
#             memop += insnstr[i]
#             i += 1
#             tokens.append(memop)
#         else:
#             for prefix in ["BYTE PTR", "WORD PTR", "DWORD PTR", "QWORD PTR", "XMMWORD PTR", "YMMWORD PTR", "ZMMWORD PTR"]:
#                 if insnstr[i:].startswith(prefix):
#                     i += len(prefix)
#                     tokens += prefix
#                     break
#             else:
#                 token = ""
#                 while i < L and not insnstr[i].isspace():
#                     token += insnstr[i]
#                     i += 1
#                 tokens.append(token)
#
#
#
#
#
#
#     tokens = insnstr.split()))
#     try:
#         # the first token after the prefixes (which are wrapped in {...}) is
#         # the mnemonic
#         mnemonic = next(iter(filter(lambda x: x[0] != '{', tokens)))
#     except Exception as e:
#         # TODO raise some more informative exception instead?
#         return None
#
#     candidates = context.schemes_for_mnemonics[mnemonic]





class DefaultInstantiator:

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def __call__(self, scheme):
        if isinstance(scheme, iwho.InsnScheme):
            return self.for_insn(scheme)
        elif isinstance(scheme, iwho.OperandScheme):
            return self.for_operand(scheme)
        raise IWHOError("trying to instantiate incompatible object: {}".format(repr(scheme)))

    def for_insn(self, insn_scheme):
        # create an instruction instance from a scheme
        args = dict()
        for name, operand_scheme in insn_scheme.operand_schemes.items():
            args[name] = self.for_operand(operand_scheme)
        return insn_scheme.instantiate(args)

    def for_operand(self, operand_scheme):
        # create an Operand instance from a scheme
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
        base_reg = self.ctx.all_registers["RBX"]
        displacement = 64

        return MemoryOperand(width=mem_constraint.width, base=base_reg, displacement=displacement)

    def get_valid_imm_operand(self, imm_constraint):
        val = 42
        # if len(not_in) > 0:
        #     not_vals = [int(x.value) for x in not_in]
        #     max_val = max(not_vals)
        #     val = max_val + 8
        #     # TODO check if in range
        return ImmediateOperand(width=imm_constraint.width, value=str(val))

    # def get_valid(self, not_in=[]):
    #     diff = self.acceptable_operands - set(not_in)
    #     if len(diff) == 0:
    #         return None
    #     return sorted(diff, key=str)[0]


