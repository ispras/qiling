#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from ctypes import Structure
from ctypes import c_uint32, c_uint16

from .base import QlBaseCoverage


# Adapted from https://www.ayrx.me/drcov-file-format
class bb_entry(Structure):
    _fields_ = [
        ("start",  c_uint32),
        ("size",   c_uint16),
        ("mod_id", c_uint16)
    ]
class QlDrCoverage(QlBaseCoverage):
    """
    Collects emulated code coverage and formats it in accordance with the DynamoRIO based
    tool drcov: https://dynamorio.org/dynamorio_docs/page_drcov.html

    The resulting output file can later be imported by coverage visualization tools such
    as Lighthouse: https://github.com/gaasedelen/lighthouse
    """

    FORMAT_NAME = "drcov"

    def __init__(self, ql):
        super().__init__()
        self.ql            = ql
        self.drcov_version = 2
        self.drcov_flavor  = 'drcov'
        self.basic_blocks  = []
        self.basic_blocks2  = []
        self.bb_callback   = None

    @staticmethod
    def block_callback(ql, address, size, self):
        for mod_id, mod in enumerate(ql.loader.images):
            if mod.base <= address <= mod.end:
                ent = bb_entry(address - mod.base, size, mod_id)
                self.basic_blocks2.append(ent)
            gg=0
            for i in range(len(self.basic_blocks)):
                if ((address - mod.base) == self.basic_blocks[i].start):
                    gg=1
            if (gg==1):
                break 
            if mod.base <= address <= mod.end:
                ent = bb_entry(address - mod.base, size, mod_id)
                self.basic_blocks.append(ent)
                break

    def activate(self):
        self.bb_callback = self.ql.hook_block(self.block_callback, user_data=self)

    def deactivate(self):
        self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file, trace_mode, text_format):
        if(text_format==False):
            with open(coverage_file, "wb") as cov:
                cov.write(f"DRCOV VERSION: {self.drcov_version}\n".encode())
                cov.write(f"DRCOV FLAVOR: {self.drcov_flavor}\n".encode())
                cov.write(f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}\n".encode())
                cov.write("Columns: id, base, end, entry, checksum, timestamp, path\n".encode())
                for mod_id, mod in enumerate(self. ql.loader.images):
                    cov.write(f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}\n".encode())
                cov.write(f"BB Table: {len(self.basic_blocks)} bbs\n".encode())
                if(trace_mode == False):
                    for bb in self.basic_blocks2:
                        cov.write(bytes(bb))   
                else:
                    for bb in self.basic_blocks:
                        cov.write(bytes(bb)) 
        else:
            with open(coverage_file, "w") as cov:
                cov.write(f"DRCOV VERSION: {self.drcov_version}\n")
                cov.write(f"DRCOV FLAVOR: {self.drcov_flavor}\n")
                cov.write(f"Module Table: version {self.drcov_version}, count {len(self.ql.loader.images)}\n")
                cov.write("Columns: id, base, end, entry, checksum, timestamp, path\n")
                for mod_id, mod in enumerate(self. ql.loader.images):
                    cov.write(f"{mod_id}, {mod.base}, {mod.end}, 0, 0, 0, {mod.path}\n")
                cov.write(f"BB Table: {len(self.basic_blocks)} bbs\n")
                cov.write("module id, start, size:\n")
                if(trace_mode == False):
                    for bb in self.basic_blocks2:
                        cov.write("module["+str(bb.mod_id)+"]: "+"0x"+format((bb.start), '014x') + ", "+str(bb.size)+'\n')
                else:
                    for bb in self.basic_blocks:
                        cov.write("module["+str(bb.mod_id)+"]: "+"0x"+format((bb.start), '014x') + ", "+str(bb.size)+'\n')
           
