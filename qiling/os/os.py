#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
from typing import Any, Optional, Callable, Mapping, Tuple

from qiling import Qiling
from qiling.const import QL_OS, QL_INTERCEPT, QL_OS_POSIX
from qiling.os.const import STRING, WSTRING, GUID

from .filestruct import ql_file
from .mapper import QlFsMapper
from .utils import QlOsUtils

class QlOs:
    Resolver = Callable[[int], Tuple[Any, int]]

    def __init__(self, ql: Qiling, resolvers: Mapping[Any, Resolver] = {}):
        self.ql = ql
        self.utils = QlOsUtils(ql)
        self.fcall = None
        self.fs_mapper = QlFsMapper(ql)
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.current_path = self.profile.get("MISC", "current_path")
        self.exit_code = 0
        self.services = {}
        self.elf_mem_start = 0x0

        self.user_defined_api = {
            QL_INTERCEPT.CALL : {},
            QL_INTERCEPT.ENTER: {},
            QL_INTERCEPT.EXIT : {}
        }

        if not hasattr(sys.stdin, "fileno") or not hasattr(sys.stdout, "fileno") or not hasattr(sys.stderr, "fileno"):
            # IDAPython has some hack on standard io streams and thus they don't have corresponding fds.

            self.stdin  = sys.stdin.buffer  if hasattr(sys.stdin,  "buffer") else sys.stdin
            self.stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
            self.stderr = sys.stderr.buffer if hasattr(sys.stderr, "buffer") else sys.stderr
        else:
            self.stdin  = ql_file('stdin',  sys.stdin.fileno())
            self.stdout = ql_file('stdout', sys.stdout.fileno())
            self.stderr = ql_file('stderr', sys.stderr.fileno())

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin

        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout

        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        # defult exit point
        self.exit_point = {
            16: 0xfffff,            # 20bit address lane
            32: 0x8fffffff,
            64: 0xffffffffffffffff
        }.get(self.ql.archbit, None)

        if self.ql.code:
            self.code_ram_size = int(self.profile.get("CODE", "ram_size"), 16)
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = int(self.profile.get("CODE", "entry_point"), 16)

        # default fcall paramters resolving methods
        self.resolvers = {
            STRING : lambda ptr: ptr and self.utils.read_cstring(ptr),
            WSTRING: lambda ptr: ptr and self.utils.read_wstring(ptr),
            GUID   : lambda ptr: ptr and str(self.utils.read_guid(ptr))
        }

        # let the user override default resolvers or add custom ones
        self.resolvers.update(resolvers)

        self.utils.setup_output()

    def save(self):
        return {}

    def restore(self, saved_state):
        pass

    def resolve_fcall_params(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        """Transform function call raw parameters values into meaningful ones, according to
        their assigned type.

        Args:
            params: a mapping of parameter names to their types

        Returns: a mapping of parameter names to their resolved values
        """

        # TODO: could use func.__annotations__ to resolve parameters and return type.
        #       that would require redefining all hook functions with python annotations, but
        #       also simplify hooks code (e.g. no need to do:  x = params["x"] )

        names = params.keys()
        types = params.values()
        values = self.fcall.readParams(types)
        resolved = {}

        for name, typ, val in zip(names, types, values):
            if typ in self.resolvers:
                val = self.resolvers[typ](val)

            resolved[name] = val

        return resolved

    def call(self, pc: int, func: Callable, params: Mapping[str, Any], onenter: Optional[Callable], onexit: Optional[Callable], *args, passthru: bool = False):
        # resolve params values according to their assigned types
        params = self.resolve_fcall_params(params)

        # call hooked function
        params, retval, retaddr = self.fcall.call(func, params, onenter, onexit, *args)

        # print
        self.utils.print_function(pc, func.__name__, params, retval, passthru)

        # append syscall to list
        self._call_api(func.__name__, params, retval, pc, retaddr)

        # TODO: PE_RUN is a Windows and UEFI property; move somewhere else?
        if hasattr(self, 'PE_RUN') and not self.PE_RUN:
            return retval

        if not passthru:
            self.ql.reg.arch_pc = retaddr

        return retval

    # TODO: separate this method into os-specific functionalities, instead of 'if-else'
    def set_api(self, api_name: str, intercept_function: Callable, intercept: QL_INTERCEPT):
        if self.ql.ostype == QL_OS.UEFI:
            api_name = f'hook_{api_name}'

        # BUG: workaround missing arg
        if intercept is None:
            intercept = QL_INTERCEPT.CALL

        if (self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI)) or (self.ql.ostype in (QL_OS_POSIX) and self.ql.loader.is_driver):
            self.user_defined_api[intercept][api_name] = intercept_function
        else:
            self.add_function_hook(api_name, intercept_function, intercept)

    def find_containing_image(self, pc):
        for image in self.ql.loader.images:
            if image.base <= pc < image.end:
                return image

    def stop(self):
        if self.ql.multithread:
            self.thread_management.stop() 
        else:
            self.ql.emu_stop()

    def emu_error(self):
        self.ql.log.error("\n")

        for reg in self.ql.reg.register_mapping:
            if isinstance(reg, str):
                REG_NAME = reg
                REG_VAL = self.ql.reg.read(reg)
                self.ql.log.error("%s\t:\t 0x%x" % (REG_NAME, REG_VAL))

        self.ql.log.error("\n")
        self.ql.log.error("PC = 0x%x" % (self.ql.reg.arch_pc))
        containing_image = self.find_containing_image(self.ql.reg.arch_pc)
        if containing_image:
            offset = self.ql.reg.arch_pc - containing_image.base
            self.ql.log.error(" (%s+0x%x)" % (containing_image.path, offset))
        else:
            self.ql.log.info("\n")
        self.ql.mem.show_mapinfo()

        try:
            buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
            self.ql.log.error("%r" % ([hex(_) for _ in buf]))

            self.ql.log.info("\n")
            self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
        except:
            self.ql.log.error("Error: PC(0x%x) Unreachable" % self.ql.reg.arch_pc)

    def _call_api(self, name, params, result, address, return_address):
        if name.startswith("hook_"):
            name = name[5:]

        self.utils.syscalls.setdefault(name, []).append({
            "params": params,
            "result": result,
            "address": address,
            "return_address": return_address,
            "position": self.utils.syscalls_counter
        })

        self.utils.syscalls_counter += 1