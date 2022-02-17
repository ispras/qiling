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
    def __eq__(self, other):
        return (self.start==other.start and self.size==other.size and self.mod_id==other.mod_id)
    def __hash__(self):
        return (hash((self.start,self.size,self.mod_id)))

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
        self.basic_blocks  = None
        self.bb_callback   = None
        # switch - trace or coverage (list or set of blocks)
        self.trace_mode = True
        # switch - text or binary format for the list of blocks in the file
        self.text_format = False
        # sometimes we need to log all blocks, even if ostensibly they don't belong to any module
        # (they are logged as blocks of the "all-memory" module)
        self.all_memory_module = False
        self.memory_mod = None

    @staticmethod
    def block_callback(ql, address, size, self):
        images = list(ql.loader.images)
        if self.all_memory_module:
            images.append(self.memory_mod)
        for mod_id, mod in enumerate(images):
            if mod.base <= address <= mod.end:
                ent = bb_entry(address - mod.base, size, mod_id)
                if self.trace_mode:
                    self.basic_blocks.append(ent)
                else:
                    self.basic_blocks.add(ent)
                break

    def activate(self):
        if self.trace_mode:
            self.basic_blocks = list()
        else:
            self.basic_blocks = set()
        if self.all_memory_module:
            # fake module corresponding to the whole memory
            class MemoryMod:
                def __init__(self, base, end, path):
                    self.base = base
                    self.end = end
                    self.path = path
            self.memory_mod = MemoryMod(0, 0xFFFFFFFFFFFFFFFF, 'memory')
        self.bb_callback = self.ql.hook_block(self.block_callback, user_data=self)

    def deactivate(self):
        self.ql.hook_del(self.bb_callback)

    def dump_coverage(self, coverage_file):

        images = list(self.ql.loader.images)
        if self.all_memory_module:
            images.append(self.memory_mod)

        def string(s): return s if self.text_format else s.encode()

        with open(coverage_file, "w" if self.text_format else "wb") as cov:
            cov.write(string(f"DRCOV VERSION: {self.drcov_version}\n"))
            cov.write(string(f"DRCOV FLAVOR: {self.drcov_flavor}\n"))
            cov.write(string(f"Module Table: version {self.drcov_version}, count {len(images)}\n"))
            cov.write(string("Columns: id, base, end, entry, checksum, timestamp, path\n"))
            for mod_id, mod in enumerate(images):
                cov.write(string(f"{mod_id}, 0x{mod.base:016x}, 0x{mod.end:016x}, 0, 0, 0, {mod.path}\n"))
            cov.write(string(f"BB Table: {len(self.basic_blocks)} bbs\n"))
            if self.text_format:
                cov.write("module id, start, size:\n")
            for bb in self.basic_blocks:
                if self.text_format:
                    cov.write("module["+str(bb.mod_id)+"]: "+"0x"+format((bb.start), '016x') + ", "+str(bb.size)+'\n')
                else:
                    cov.write(bytes(bb))   

           
