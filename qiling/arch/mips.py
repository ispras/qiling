#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_MIPS64, UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from keystone import Ks, KS_ARCH_MIPS, KS_MODE_MIPS32,  KS_MODE_MIPS64, KS_MODE_BIG_ENDIAN, KS_MODE_LITTLE_ENDIAN

from qiling import Qiling
from qiling.const import QL_ENDIAN
from qiling.arch.arch import QlArch
from qiling.arch.mips_const import *

class QlArchMIPS(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_map_afpr128
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    def _archbit(self):
        if self.ql._archbit_extra != None:
            return self.ql._archbit_extra
        else:
            return self.ql.archbit

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        endian = {
            QL_ENDIAN.EB: UC_MODE_BIG_ENDIAN,
            QL_ENDIAN.EL: UC_MODE_LITTLE_ENDIAN
        }[self.ql.archendian]

        bit = {
            32: UC_MODE_MIPS32,
            64: UC_MODE_MIPS64
        }[self._archbit()]

        return Uc(UC_ARCH_MIPS, bit + endian)

    def create_disassembler(self) -> Cs:
        if self._disasm is None:
            endian = {
                QL_ENDIAN.EL : CS_MODE_LITTLE_ENDIAN,
                QL_ENDIAN.EB : CS_MODE_BIG_ENDIAN
            }[self.ql.archendian]

            bit = {
                32: CS_MODE_MIPS32,
                64: CS_MODE_MIPS64
            }[self._archbit()]

            self._disasm = Cs(CS_ARCH_MIPS, bit + endian)

        return self._disasm

    def create_assembler(self) -> Ks:
        if self._asm is None:
            endian = {
                QL_ENDIAN.EL : KS_MODE_LITTLE_ENDIAN,
                QL_ENDIAN.EB : KS_MODE_BIG_ENDIAN
            }[self.ql.archendian]

            bit = {
                32: KS_MODE_MIPS32,
                64: KS_MODE_MIPS64
            }[self._archbit()]

            self._asm = Ks(KS_ARCH_MIPS, bit + endian)

        return self._asm
