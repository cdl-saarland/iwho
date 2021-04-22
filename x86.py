
from typing import Sequence, Optional

from collections import defaultdict
import string

import iwho as iwho

from enum import Enum, auto

import logging
logger = logging.getLogger(__name__)

class X86_RegAliasClass(Enum):
    GPR_A = auto()
    GPR_B = auto()
    GPR_C = auto()
    GPR_D = auto()
    GPR_BP = auto()
    GPR_DI = auto()
    GPR_SI = auto()
    GPR_SP = auto()
    GPR_IP = auto()
    GPR_R8 = auto()
    GPR_R9 = auto()
    GPR_R10 = auto()
    GPR_R11 = auto()
    GPR_R12 = auto()
    GPR_R13 = auto()
    GPR_R14 = auto()
    GPR_R15 = auto()

    FLAG_AF = auto()
    FLAG_CF = auto()
    FLAG_OF = auto()
    FLAG_PF = auto()
    FLAG_SF = auto()
    FLAG_ZF = auto()

class X86_RegKind(Enum):
    GPR = auto()
    FLAG = auto()
    vMM = auto()

class X86_RegisterOperand(iwho.Operand):
    def __init__(self, name: str, alias_class: X86_RegAliasClass, kind: X86_RegKind, width: int):
        self.name = name
        self.alias_class = alias_class
        self.kind = kind
        self.width = width

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return "X86_RegisterOperand(name: {}, alias_class: {}, kind: {}, width: {})".format(repr(self.name), self.alias_class, self.kind, self.width)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.name == other.name

    def __hash__(self):
        return hash((self.name))


class X86_MemoryOperand(iwho.Operand):
    def __init__(self, width: int,
                segment: Optional[X86_RegisterOperand]=None,
                base: Optional[X86_RegisterOperand]=None,
                index: Optional[X86_RegisterOperand]=None,
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
        if segment is not None:
            res.append(segment)
        if base is not None:
            res.append(base)
        if index is not None:
            res.append(index)
        return res

    def __str__(self):
        # TODO
        return repr(self)

    def __repr__(self):
        res = "X86_MemoryOperand(width={}".format(self.width)
        if self.segment is not None:
            res += "segment={}, ".format(repr(self.segment))
        if self.base is not None:
            res += "base={}, ".format(repr(self.base))
        if self.index is not None:
            res += "index={}, ".format(repr(self.index))
        if self.scale is not None:
            res += "scale={}, ".format(repr(self.scale))
        if self.displacement is not None:
            res += "displacement={}, ".format(repr(self.displacement))
        if res.endswith(', '):
            res = res[-2]
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

class X86_ImmKind(Enum):
    INT = auto()
    FLOAT = auto()

class X86_ImmediateOperand(iwho.Operand):
    def __init__(self, imm_kind: X86_ImmKind, width, value):
        self.imm_kind = imm_kind
        self.width = width
        self.value = value

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return "X86_ImmediateOperand(imm_kind={}, width={}, value={})".format(self.imm_kind, self.width, repr(self.value))

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.imm_kind == other.imm_kind
                and self.width == other.width
                and self.value == other.value)

    def __hash__(self):
        return hash((self.imm_kind, self.width, self.value))


class X86_ImmConstraint(iwho.OperandConstraint):
    def __init__(self, imm_kind: X86_ImmKind, width: int):
        self.imm_kind = imm_kind
        self.width = width

    def is_valid(self, operand):
        return (isinstance(operand, X86_ImmediateOperand) and
                self.width == operand.width and
                self.imm_kind == operand.imm_kind)
        # TODO check if the value is in range

    def get_valid(self, not_in):
        # TODO
        pass

    def __str__(self):
        return "IMM({},{})".format(self.imm_kind.name, self.width)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and self.imm_kind == other.imm_kind
                and self.width == other.width)

    def __hash__(self):
        return hash((self.imm_kind, self.width))


class X86_MemConstraint(iwho.OperandConstraint):
    def __init__(self, width: int):
        self.width = width

    def is_valid(self, operand):
        return (isinstance(operand, X86_MemoryOperand) and
                self.width == operand.width)

    def get_valid(self, not_in):
        # TODO
        pass

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

    def get(self, constructor, **kwargs):
        store = self.stores[constructor]
        key = tuple(sorted(kwargs.items(), key=lambda x: x[0]))
        stored_res = store.get(key, None)
        if stored_res is not None:
            return stored_res
        new_res = constructor(**kwargs)
        store[key] = new_res
        return new_res


class X86_Context(iwho.Context):

    def __init__(self):
        self.all_registers = dict()
        self.gp_regs = []
        self.flag_regs = []

        self.insn_schemes = []

        self.dedup_store = DedupStore()

        self._add_registers()

    def _add_registers(self):
        def add_gpr_aliases(names_and_widths, alias_class):
            for n, w in names_and_widths:
                assert n not in self.all_registers.keys()
                regop = X86_RegisterOperand(name=n, alias_class=alias_class, kind=X86_RegKind.GPR, width=w)
                self.all_registers[n] = regop
                self.gp_regs.append(regop)

        add_gpr_aliases((("AH", 8), ("AL", 8), ("A", 8), ("AX", 16), ("EAX", 32), ("RAX", 64)), X86_RegAliasClass.GPR_A)
        add_gpr_aliases((("BH", 8), ("BL", 8), ("B", 8), ("BX", 16), ("EBX", 32), ("RBX", 64)), X86_RegAliasClass.GPR_B)
        add_gpr_aliases((("CH", 8), ("CL", 8), ("C", 8), ("CX", 16), ("ECX", 32), ("RCX", 64)), X86_RegAliasClass.GPR_C)
        add_gpr_aliases((("DH", 8), ("DL", 8), ("D", 8), ("DX", 16), ("EDX", 32), ("RDX", 64)), X86_RegAliasClass.GPR_D)

        add_gpr_aliases((("BPL", 8), ("BP", 16), ("EBP", 32), ("RBP", 64)), X86_RegAliasClass.GPR_BP)
        add_gpr_aliases((("DIL", 8), ("DI", 16), ("EDI", 32), ("RDI", 64)), X86_RegAliasClass.GPR_DI)
        add_gpr_aliases((("SIL", 8), ("SI", 16), ("ESI", 32), ("RSI", 64)), X86_RegAliasClass.GPR_SI)
        add_gpr_aliases((("SPL", 8), ("SP", 16), ("ESP", 32), ("RSP", 64)), X86_RegAliasClass.GPR_SP)
        add_gpr_aliases((("IP", 16), ("EIP", 32), ("RIP", 64)), X86_RegAliasClass.GPR_IP)

        add_gpr_aliases((("R8B", 8), ("R8W", 16), ("R8D", 32), ("R8", 64)), X86_RegAliasClass.GPR_R8)
        add_gpr_aliases((("R9B", 8), ("R9W", 16), ("R9D", 32), ("R9", 64)), X86_RegAliasClass.GPR_R9)
        add_gpr_aliases((("R10B", 8), ("R10W", 16), ("R10D", 32), ("R10", 64)), X86_RegAliasClass.GPR_R10)
        add_gpr_aliases((("R11B", 8), ("R11W", 16), ("R11D", 32), ("R11", 64)), X86_RegAliasClass.GPR_R11)
        add_gpr_aliases((("R12B", 8), ("R12W", 16), ("R12D", 32), ("R12", 64)), X86_RegAliasClass.GPR_R12)
        add_gpr_aliases((("R13B", 8), ("R13W", 16), ("R13D", 32), ("R13", 64)), X86_RegAliasClass.GPR_R13)
        add_gpr_aliases((("R14B", 8), ("R14W", 16), ("R14D", 32), ("R14", 64)), X86_RegAliasClass.GPR_R14)
        add_gpr_aliases((("R15B", 8), ("R15W", 16), ("R15D", 32), ("R15", 64)), X86_RegAliasClass.GPR_R15)

        # TODO vector registers, ...

        # flag registers
        def add_flag_reg(name, alias_class):
            assert name not in self.all_registers.keys()
            regop = X86_RegisterOperand(name=name, alias_class=alias_class, kind=X86_RegKind.FLAG, width=1)
            self.all_registers[name] = regop
            self.flag_regs.append(regop)

        add_flag_reg("flag_AF", X86_RegAliasClass.FLAG_AF)
        add_flag_reg("flag_CF", X86_RegAliasClass.FLAG_CF)
        add_flag_reg("flag_OF", X86_RegAliasClass.FLAG_OF)
        add_flag_reg("flag_PF", X86_RegAliasClass.FLAG_PF)
        add_flag_reg("flag_SF", X86_RegAliasClass.FLAG_SF)
        add_flag_reg("flag_ZF", X86_RegAliasClass.FLAG_ZF)


    def add_uops_info_xml(self, xml_path):

        # First, establish some names for common groups of allowed registers
        # This makes the str representation of constraints and schemes more readable
        groups = defaultdict(list)
        for k, regop in self.all_registers.items():
            if "IP" not in k:
                groups[(regop.kind, regop.width)].append(regop)

        for (kind, width), group in groups.items():
            obj = self.dedup_store.get(iwho.SetConstraint, acceptable_operands=frozenset(group))
            obj.name = "{}:{}".format(kind.name, width)

        import xml.etree.ElementTree as ET

        logger.debug("start parsing uops.info xml")
        with open(xml_path, 'r') as xml_file:
            xml_root = ET.parse(xml_file)
        logger.debug("done parsing uops.info xml")

        for instrNode in xml_root.iter('instruction'):
            # Future instruction set extensions
            if instrNode.attrib['extension'] in ['AMD_INVLPGB', 'AMX_BF16', 'AMX_INT8', 'AMX_TILE', 'CLDEMOTE', 'ENQCMD', 'HRESET', 'KEYLOCKER', 'KEYLOCKER_WIDE', 'MCOMMIT', 'MOVDIR', 'PCONFIG', 'RDPRU', 'SERIALIZE', 'SNP', 'TDX', 'TSX_LDTRK', 'UINTR', 'WAITPKG', 'WBNOINVD']:
                continue
            if any(x in instrNode.attrib['isa-set'] for x in ['BF16_', 'VP2INTERSECT']):
                continue

            str_template = instrNode.get('asm')
            mnemonic = str_template

            # TODO remove, only for testing
            if mnemonic != "ADC":
                continue

            explicit_operands = dict()
            implicit_operands = []

            first = True
            for operandNode in instrNode.iter('operand'):
                operandIdx = int(operandNode.attrib['idx'])

                if operandNode.attrib.get('suppressed', '0') == '1':
                    # TODO implicit operand
                    op_type = operandNode.attrib['type']
    #                 if op_type == 'flags':
    #                     for f in ["flag_AF", "flag_CF", "flag_OF", "flag_PF", "flag_SF", "flag_ZF"]:
    #                         fval = operandNode.attrib.get(f, '')
    #                         if fval == '':
    #                             continue
    #                         elif fval == 'r':
    #                             pass
    #                     pass
    #                 elif op_type == 'reg':
    #                     pass
    #                 elif op_type == 'mem':
    #                     pass

                    continue

                # implicit?

                if not first and not operandNode.attrib.get('opmask', '') == '1':
                    str_template += ', '
                else:
                    str_template += ' '
                    first = False

                op_name = operandNode.attrib['name']
                read = operandNode.attrib.get('r', '0') == '1'
                written = operandNode.attrib.get('w', '0') == '1'

                if operandNode.attrib['type'] == 'reg':
                    registers = operandNode.text.split(',')
                    allowed_registers = frozenset(( self.all_registers[reg] for reg in registers ))
                    constraint = self.dedup_store.get(iwho.SetConstraint, acceptable_operands=allowed_registers)
                    op_scheme = self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written)
                    explicit_operands[op_name] = op_scheme

                    if not operandNode.attrib.get('opmask', '') == '1':
                        str_template += "${" + op_name + "}"
                    else:
                        str_template += "{${" + op_name + "}}"
                        if instrNode.attrib.get('zeroing', '') == '1':
                            str_template += '{z}'
                elif operandNode.attrib['type'] == 'mem':
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
                        constraint = self.dedup_store.get(X86_MemConstraint, width=width)
                        op_scheme = self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=read, written=written)
                        explicit_operands[op_name] = op_scheme

                    memorySuffix = operandNode.attrib.get('memory-suffix', '')
                    if memorySuffix:
                        str_template += ' ' + memorySuffix
                elif operandNode.attrib['type'] == 'agen':
                    agen = instrNode.attrib['agen']
                    # address = []

                    # if 'R' in agen: address.append('RIP')
                    # if 'B' in agen: address.append('RAX')
                    # if 'IS' in agen: address.append('2*RBX')
                    # elif 'I' in agen: address.append('1*RBX')
                    # if 'D8' in agen: address.append('8')
                    # if 'D32' in agen: address.append('128')
                    #
                    # asm += ' [' + '+'.join(address) + ']'
                    str_template += "${" + op_name + "}"
                    # agen memory operands are neither read nor written
                    constraint = self.dedup_store.get(X86_MemConstraint, width=0)
                    op_scheme = self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False)
                    explicit_operands[op_name] = op_scheme
                elif operandNode.attrib['type'] == 'imm':
                    # TODO make immediate constraint, add operand
                    if instrNode.attrib.get('roundc', '') == '1':
                        str_template += '{rn-sae}, '
                    elif instrNode.attrib.get('sae', '') == '1':
                        str_template += '{sae}, '
                    str_template += "${" + op_name + "}"

                    width = int(operandNode.attrib['width'])
                    imm_kind = X86_ImmKind.INT
                    # TODO right kind?
                    if operandNode.text is not None:
                        imm = operandNode.text
                        op = self.dedup_store.get(X86_ImmediateOperand, imm_kind=imm_kind, width=width, value=imm)
                        op_scheme = self.dedup_store.get(iwho.OperandScheme, fixed_operand=op, read=False, written=False)
                    else:
                        constraint = self.dedup_store.get(X86_ImmConstraint, imm_kind=imm_kind, width=width)
                        op_scheme = self.dedup_store.get(iwho.OperandScheme, constraint=constraint, read=False, written=False)

                    explicit_operands[op_name] = op_scheme

                elif operandNode.attrib['type'] == 'relbr':
                    # str_template = '1: ' + str_template + '1b'
                    # TODO
                    raise UnsupportedFeatureError("relbr instruction")

            if not 'sae' in str_template:
                if instrNode.attrib.get('roundc', '') == '1':
                    str_template += ', {rn-sae}'
                elif instrNode.attrib.get('sae', '') == '1':
                    str_template += ', {sae}'

            str_template = string.Template(str_template)
            scheme = iwho.InsnScheme(str_template=str_template, operand_schemes=explicit_operands, implicit_operands=implicit_operands)

            self.insn_schemes.append(scheme)


    def disassemble(self, data):
        # TODO
        pass

    def assemble(self, insn_instance):
        # TODO
        pass




