
from typing import Sequence, Optional

from enum import Enum
from collections import defaultdict
import os
import string
import subprocess

from functools import cached_property
import pyparsing as pp

import iwho as iwho


import logging
logger = logging.getLogger(__name__)


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


    def add_uops_info_xml(self, xml_path):

        # First, establish some names for common groups of allowed registers
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

        import xml.etree.ElementTree as ET

        logger.debug("start parsing uops.info xml")
        with open(xml_path, 'r') as xml_file:
            xml_root = ET.parse(xml_file)
        logger.debug("done parsing uops.info xml")

        num_errors = 0

        for instrNode in xml_root.iter('instruction'):
            try:
                if instrNode.attrib['category'] in ['XSAVE', 'XSAVEOPT',
                        'X87_ALU', 'FCMOV', 'MMX', '3DNOW', 'MPX', 'COND_BR',
                        'UNCOND_BR', 'CALL', 'CET', 'SYSTEM', 'SEGOP']:
                    # Unsupported instructions
                    continue

                if any(x in instrNode.attrib['isa-set'] for x in ['XOP', 'AVX512', 'LWP']):
                    continue

                # if any(x in instrNode.attrib['extension'] for x in ['AVX512']):
                #     continue

                if instrNode.attrib['extension'] in ['AMD_INVLPGB', 'AMX_BF16',
                        'AMX_INT8', 'AMX_TILE', 'CLDEMOTE', 'ENQCMD', 'HRESET',
                        'KEYLOCKER', 'KEYLOCKER_WIDE', 'MCOMMIT', 'MOVDIR',
                        'PCONFIG', 'RDPRU', 'SERIALIZE', 'SNP', 'TDX',
                        'TSX_LDTRK', 'UINTR', 'WAITPKG', 'WBNOINVD']:
                    # Unsupported (future) instruction set extensions (taken
                    # from the uops.info script)
                    continue

                if any(x in instrNode.attrib['isa-set'] for x in ['BF16_', 'VP2INTERSECT']):
                    continue

                str_template = instrNode.get('asm')
                str_template = str_template.replace("{load} ", "")
                str_template = str_template.replace("{store} ", "")
                mnemonic = str_template

                if mnemonic in ["PREFETCHW", "PREFETCH"]:
                    continue

                explicit_operands = dict()
                implicit_operands = []

                first = True
                for operandNode in instrNode.iter('operand'):
                    operandIdx = int(operandNode.attrib['idx'])

                    if operandNode.attrib.get('suppressed', '0') == '1':
                        # implicit operands (here marked as suppressed)
                        op_type = operandNode.attrib['type']

                        op_schemes, t1, t2 = self.handle_uops_info_operand(operandNode, instrNode)
                        implicit_operands += op_schemes

                        continue

                    if not first and not operandNode.attrib.get('opmask', '') == '1':
                        str_template += ', '
                    else:
                        str_template += ' '
                        first = False

                    op_schemes, op_name, str_template = self.handle_uops_info_operand(operandNode, instrNode, str_template)
                    assert len(op_schemes) == 1
                    explicit_operands[op_name] = op_schemes[0]

                if not 'sae' in str_template:
                    if instrNode.attrib.get('roundc', '') == '1':
                        str_template += ', {rn-sae}'
                    elif instrNode.attrib.get('sae', '') == '1':
                        str_template += ', {sae}'

                scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit_operands, implicit_operands=implicit_operands)

                self.insn_schemes.append(scheme)
                self.mnemonic_to_insn_schemes[mnemonic].append(scheme)

            except Exception as e:
                logger.info("Unsupported uops.info entry: {}\n  Exception: {}".format(ET.tostring(instrNode, encoding='utf-8')[:50], repr(e)))
                num_errors += 1

        if num_errors > 0:
            logger.info(f"Encountered {num_errors} error(s) while processing uops.info xml.")

        logger.info(f"{len(self.insn_schemes)} instruction schemes after processing uops.info xml.")

    def handle_uops_info_operand(self, operandNode, instrNode, str_template=""):
        op_schemes = []
        op_name = operandNode.attrib['name']

        read = operandNode.attrib.get('r', '0') == '1'
        written = operandNode.attrib.get('w', '0') == '1'

        op_type = operandNode.attrib['type']
        if op_type == 'reg':
            registers = operandNode.text.split(',')
            try:
                allowed_registers = frozenset(( self.all_registers[reg] for reg in registers ))
            except KeyError as e:
                raise iwho.UnsupportedFeatureError(f"Unsupported register: {e}")
            constraint = self.dedup_store.get(iwho.SetConstraint, acceptable_operands=allowed_registers)
            op_schemes.append(self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written))

            if not operandNode.attrib.get('opmask', '') == '1':
                str_template += "${" + op_name + "}"
            else:
                str_template += "{${" + op_name + "}}"
                if instrNode.attrib.get('zeroing', '') == '1':
                    str_template += '{z}'
        elif op_type == 'mem':
            memoryPrefix = operandNode.attrib.get('memory-prefix', '')
            if memoryPrefix:
                str_template += memoryPrefix + ' '

            if operandNode.attrib.get('VSIB', '0') != '0':
                raise iwho.UnsupportedFeatureError("instruction with VSIB: {}".format(instrNode))
                # TODO
                str_template += '[' + operandNode.attrib.get('VSIB') + '0]'
            else:
                str_template += "${" + op_name + "}"
                width = str(operandNode.attrib.get('width'))
                constraint = self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=width)
                op_schemes.append(self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written))

            memorySuffix = operandNode.attrib.get('memory-suffix', '')
            if memorySuffix:
                str_template += ' ' + memorySuffix

        elif op_type == 'agen':
            str_template += "${" + op_name + "}"
            # agen memory operands are neither read nor written
            constraint = self.dedup_store.get(MemConstraint, unhashed_kwargs={"context": self}, width=0)
            op_schemes.append(self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

        elif op_type == 'imm':
            if instrNode.attrib.get('roundc', '') == '1':
                str_template += '{rn-sae}, '
            elif instrNode.attrib.get('sae', '') == '1':
                str_template += '{sae}, '
            str_template += "${" + op_name + "}"

            width = int(operandNode.attrib['width'])
            if operandNode.text is not None:
                imm = operandNode.text
                op = self.dedup_store.get(ImmediateOperand, width=width, value=imm)
                op_schemes.append(self.dedup_store.get(iwho.OperandScheme, fixed_operand=op, read=False, written=False))
            else:
                constraint = self.dedup_store.get(ImmConstraint, unhashed_kwargs={"context": self}, width=width)
                op_schemes.append(self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False))

        # elif op_type == 'relbr':
            # str_template = '1: ' + str_template + '1b'
            # TODO
        elif op_type == 'flags':
            for f in ["flag_AF", "flag_CF", "flag_OF", "flag_PF", "flag_SF", "flag_ZF"]:
                fval = operandNode.attrib.get(f, '')
                read = False
                written = False
                if fval == "w":
                    written = True
                elif fval == "r":
                    read = True
                elif fval == "r/w":
                    read = True
                    written = True
                elif fval == "undef":
                    written = True
                reg = self.all_registers[f]
                op_schemes.append(iwho.OperandScheme(fixed_operand=reg, read=read, written=written))

        else:
            raise iwho.UnsupportedFeatureError("unsupported operand type: {}".format(operandNode.attrib['type']))

        return op_schemes, op_name, str_template


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


