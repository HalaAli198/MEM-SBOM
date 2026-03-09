
import logging
from typing import Dict, List, Optional, Tuple

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import pe_parsing

vollog = logging.getLogger(__name__)

# Offset of interpreters.head within _PyRuntimeState, by version.
# Obtained via: p/x (int)&((_PyRuntimeState*)0)->interpreters.head
# Refs:
#https://github.com/python/cpython/blob/main/Include/internal/pycore_runtime.h
#https://github.com/python/cpython/blob/3.14/Include/internal/pycore_runtime_structs.h


PYRUNTIME_INTERP_HEAD_OFFSETS = {
    (3, 7):  0x18,
    (3, 8):  0x20,
    (3, 9):  0x20,
    (3, 10): 0x20,
    (3, 11): 0x28,
    (3, 12): 0x28,
}

# Position of runtime_state.interpreters_head in _Py_DebugOffsets
DEBUG_OFFSETS_INTERP_HEAD_POS = 0x28


# -----------------------------------------------------------------------
# Maps (major, minor) -> ISF symbol table loader parameters
# -----------------------------------------------------------------------
SYMBOL_TABLE_REGISTRY = {
    (3, 6): (
        'volatility3.framework.symbols.generic.types.python.python36_handler',
        'Python_3_6_IntermedSymbols',
        'generic/types/python',
        'python36',
    ),
    (3, 7): (
        'volatility3.framework.symbols.generic.types.python.python37_handler',
        'Python_3_7_IntermedSymbols',
        'generic/types/python',
        'python37',
    ),
    (3, 8): (
        'volatility3.framework.symbols.generic.types.python.python38_handler',
        'Python_3_8_IntermedSymbols',
        'generic/types/python',
        'python38',
    ),
    (3, 9): (
        'volatility3.framework.symbols.generic.types.python.python39_handler',
        'Python_3_9_IntermedSymbols',
        'generic/types/python',
        'python39',
    ),
    (3, 10): (
        'volatility3.framework.symbols.generic.types.python.python310_handler',
        'Python_3_10_IntermedSymbols',
        'generic/types/python',
        'python310',
    ),
    (3, 11): (
        'volatility3.framework.symbols.generic.types.python.python311_handler',
        'Python_3_11_IntermedSymbols',
        'generic/types/python',
        'python311',
    ),
    (3, 12): (
        'volatility3.framework.symbols.generic.types.python.python312_handler',
        'Python_3_12_IntermedSymbols',
        'generic/types/python',
        'python312',
    ),
    (3, 13): (
        'volatility3.framework.symbols.generic.types.python.python313_handler',
        'Python_3_13_IntermedSymbols',
        'generic/types/python',
        'python313',
    ),
    (3, 14): (
        'volatility3.framework.symbols.generic.types.python.python314_handler',
        'Python_3_14_IntermedSymbols',
        'generic/types/python',
        'python314',
    ),
}


class Py_Interpreter(interfaces.plugins.PluginInterface):
    """
    Extract loaded modules from the CPython interpreter state (Windows).

    Resolves _PyRuntime via PE symbol lookup, walks the PyInterpreterState
    linked list, and dumps every module in interpreter.modules (sys.modules).

    Returns (address, name, PyModuleObject) tuples, same shape as Py_GC
    and Py_Heap so the main plugin can merge results from all sources.
    """
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="PID of the Python process to analyze",
                element_type=int,
                optional=False,
            ),
        ]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------
    def detect_python_version(self, task):
        """
        Extract Python major.minor from loaded DLLs in the process VADs.
        Uses pe_parsing's single-process VAD scanning.

        Returns (major, minor) or None.
        """
        version = pe_parsing.detect_python_version_from_vads(self.context, task)
        if version:
            vollog.info(f"Detected Python {version[0]}.{version[1]}")
        else:
            vollog.warning("Could not detect Python version from process VADs")
        return version

    # ------------------------------------------------------------------
    # _PyRuntime resolution
    # ------------------------------------------------------------------
    def find_py_runtime_address(self, task):
        """
        Resolve _PyRuntime from the process PE image via pe_parsing.
        Operates on the SPECIFIC process only (single-process approach).
        """
        resolved = pe_parsing.find_symbol_in_process(
            self.context,
            self.config_path,
            task,
            symbol_names=["_PyRuntime"],
            module_substring="python",
        )

        runtime_addr = resolved.get("_PyRuntime")
        if runtime_addr:
            vollog.info(f"Resolved _PyRuntime at: 0x{runtime_addr:x}")
        else:
            vollog.error("Could not resolve _PyRuntime from PE symbols")

        return runtime_addr

    # ------------------------------------------------------------------
    # Interpreter head resolution
    # ------------------------------------------------------------------
    def get_interpreters_head_offset(self, version, py_runtime_addr):
        """
        Dereference _PyRuntime to get the first PyInterpreterState address.

        3.7-3.12: use hardcoded offset from PYRUNTIME_INTERP_HEAD_OFFSETS
        3.13+:    read offset from _Py_DebugOffsets (first field of _PyRuntime),
                  at debug_offsets + 0x28
        """
        key = version[:2]

        if key >= (3, 13):
            raw = self.context.layers[self.process_layer].read(
                py_runtime_addr + DEBUG_OFFSETS_INTERP_HEAD_POS, 8
            )
            offset = int.from_bytes(raw, 'little')
            vollog.debug(f"interpreters.head offset from debug_offsets: 0x{offset:x}")
        else:
            offset = PYRUNTIME_INTERP_HEAD_OFFSETS.get(key, 0x20)
            vollog.debug(f"interpreters.head offset from table: 0x{offset:x}")

        head_ptr_addr = py_runtime_addr + offset
        head_bytes = self.context.layers[self.process_layer].read(head_ptr_addr, 8)
        head_addr = int.from_bytes(head_bytes, 'little')

        if head_addr:
            vollog.info(f"Interpreter head at 0x{head_addr:x}")
        else:
            vollog.error("interpreters.head is NULL")

        return head_addr

    def _resolve_interp_head_36(self, task):
        """
        Python 3.6 has no _PyRuntime. On Windows, resolve the interpreter
        head by finding PyInterpreterState_Head in the PE export table
        and reading the global pointer it references.

        PyInterpreterState_Head() on Windows (x64) typically looks like:
            mov rax, qword ptr [rip+disp32]
            ret
        or with endbr64 prefix on newer builds.

        Falls back to scanning for the interp_head global if disassembly
        doesn't match expected patterns.
        """
        # First try to resolve the function via PE exports/PDB
        resolved = pe_parsing.find_symbol_in_process(
            self.context,
            self.config_path,
            task,
            symbol_names=["PyInterpreterState_Head", "interp_head"],
            module_substring="python",
            version=(3, 6),
        )

        # If we got interp_head directly (unlikely but possible via PDB)
        interp_head_ptr = resolved.get("interp_head")
        if interp_head_ptr:
            try:
                head_bytes = self.context.layers[self.process_layer].read(
                    interp_head_ptr, 8
                )
                interpreter_addr = int.from_bytes(head_bytes, 'little')
                if interpreter_addr and 0x10000 < interpreter_addr < 0x7FFFFFFFFFFF:
                    vollog.info(
                        f"Python 3.6: interp_head at 0x{interp_head_ptr:x} "
                        f"-> 0x{interpreter_addr:x}"
                    )
                    return interpreter_addr
            except Exception:
                pass

        # Try disassembling PyInterpreterState_Head
        func_addr = resolved.get("PyInterpreterState_Head")
        if func_addr:
            layer = self.context.layers[self.process_layer]

            # Try multiple instruction patterns
            # Pattern 1: mov rax, [rip+disp32] (no endbr64)
            # Bytes: 48 8b 05 <disp32>
            try:
                code = layer.read(func_addr, 16)

                # Check for endbr64 prefix (f3 0f 1e fa)
                if code[:4] == b'\xf3\x0f\x1e\xfa':
                    skip = 4
                else:
                    skip = 0

                # Look for mov rax, [rip+disp32]
                if code[skip:skip + 3] == b'\x48\x8b\x05':
                    disp = int.from_bytes(code[skip + 3:skip + 7], 'little', signed=True)
                    # RIP points to next instruction
                    rip = func_addr + skip + 7
                    interp_head_addr = rip + disp

                    head_bytes = layer.read(interp_head_addr, 8)
                    interpreter_addr = int.from_bytes(head_bytes, 'little')

                    if interpreter_addr and 0x10000 < interpreter_addr < 0x7FFFFFFFFFFF:
                        vollog.info(
                            f"Python 3.6: PyInterpreterState_Head disasm -> "
                            f"interp_head at 0x{interp_head_addr:x} "
                            f"-> 0x{interpreter_addr:x}"
                        )
                        return interpreter_addr

                # Pattern 2: lea rax, [rip+disp32] then mov rax, [rax]
                # Bytes: 48 8d 05 <disp32>
                if code[skip:skip + 3] == b'\x48\x8d\x05':
                    disp = int.from_bytes(code[skip + 3:skip + 7], 'little', signed=True)
                    rip = func_addr + skip + 7
                    interp_head_addr = rip + disp

                    head_bytes = layer.read(interp_head_addr, 8)
                    interpreter_addr = int.from_bytes(head_bytes, 'little')

                    if interpreter_addr and 0x10000 < interpreter_addr < 0x7FFFFFFFFFFF:
                        vollog.info(
                            f"Python 3.6: PyInterpreterState_Head lea -> "
                            f"interp_head at 0x{interp_head_addr:x} "
                            f"-> 0x{interpreter_addr:x}"
                        )
                        return interpreter_addr

            except Exception as e:
                vollog.debug(f"Error disassembling PyInterpreterState_Head: {e}")

        vollog.error("Python 3.6: Could not resolve interpreter head")
        return None

    # ------------------------------------------------------------------
    # Interpreter walking
    # ------------------------------------------------------------------
    def parse_interpreters(self, interpreter_head_addr, python_table_name):
      modules = []

      if not interpreter_head_addr:
        print("No interpreters found or invalid pointer")
        return modules

      current = self.context.object(
        object_type=python_table_name + constants.BANG + "PyInterpreterState",
        layer_name=self.process_layer,
        offset=interpreter_head_addr,
      )

      interpreter_count = 0
      seen_addrs = set()

      while current and current.vol.offset != 0:
        interpreter_count += 1
        print(f"Processing interpreter {interpreter_count} at 0x{current.vol.offset:x}")

        try:
            modules_addr = None

            # For 3.13+: use debug_offset (correct on both Windows and Linux)
            if hasattr(self, '_modules_offset') and self._modules_offset:
                raw = self.context.layers[self.process_layer].read(
                    current.vol.offset + self._modules_offset, 8
                )
                modules_addr = int.from_bytes(raw, 'little')
                print(f"DEBUG: modules from debug_offset: interp+0x{self._modules_offset:x} = 0x{modules_addr:x}")
            else:
                # For 3.12 and below: use ISF struct
                try:
                    modules_addr = current.modules
                    print(f"DEBUG: current.modules = 0x{modules_addr:x}")
                except AttributeError:
                    modules_addr = current.imports.modules
                    print(f"DEBUG: current.imports.modules = 0x{modules_addr:x}")

            print(f"DEBUG: final modules_addr = {modules_addr}")

            if modules_addr and modules_addr != 0:
                print(f"  modules dict at 0x{modules_addr:x}")
                modules_dict_obj = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyDictObject",
                    layer_name=self.process_layer,
                    offset=modules_addr,
                )
                modules_dict = modules_dict_obj.get_dict2(cur_depth=0, max_depth=100)
                print(f"  {len(modules_dict)} entries in interpreter.modules")

                for mod_name, mod_val in modules_dict.items():
                    val_type = self.get_value_type(mod_val)
                    if val_type != "module":
                        continue
                    mod_obj = mod_val.cast_to("PyModuleObject")
                    mod_dict = mod_obj.get_dict2()
                    addr = mod_obj.vol.offset
                    if addr not in seen_addrs:
                        seen_addrs.add(addr)
                        modules.append((addr, str(mod_name), mod_obj))

        except Exception as e:
            print(f"  Error processing interpreter {interpreter_count}: {e}")

        try:
            next_addr = current.next
            if not next_addr or next_addr == 0:
                break
            current = self.context.object(
                object_type=python_table_name + constants.BANG + "PyInterpreterState",
                layer_name=self.process_layer,
                offset=next_addr,
            )
        except Exception as e:
            print(f"  Error moving to next interpreter: {e}")
            break

      print(f"Total interpreters: {interpreter_count}, modules found: {len(modules)}")
      return modules

    # ------------------------------------------------------------------
    # Public API — called by Module_Extractor
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        Entry point for the main plugin. Sets up the process layer,
        resolves the interpreter head, and walks sys.modules.

        Returns list of (address, name, PyModuleObject) tuples.
        """
        task_layer = task.add_process_layer()
        self.process_layer = self.context.layers[task_layer].name

        version = self.detect_python_version(task)
        if not version:
            vollog.error("Could not detect Python version")
            return []

        key = version[:2]

        # Python 3.6: no _PyRuntime, resolve interp_head directly
        if key == (3, 6):
            interpreter_addr = self._resolve_interp_head_36(task)
            if not interpreter_addr:
                return []
            return self.parse_interpreters(interpreter_addr, python_table_name)

        # Python 3.7+: go through _PyRuntime
        py_runtime = self.find_py_runtime_address(task)
        if not py_runtime:
            vollog.error("Could not find _PyRuntime")
            return []

        interpreter_addr = self.get_interpreters_head_offset(version, py_runtime)
        if not interpreter_addr:
            vollog.error("Could not resolve interpreter head")
            return []

        vollog.info(f"_PyRuntime=0x{py_runtime:x}, interpreter_head=0x{interpreter_addr:x}")
        if key >= (3, 13) and py_runtime:
           raw = self.context.layers[self.process_layer].read(py_runtime + 0x58, 8)
           self._modules_offset = int.from_bytes(raw, 'little')
           print(f"DEBUG: modules offset from debug_offsets = 0x{self._modules_offset:x}")
        
        return self.parse_interpreters(interpreter_addr, python_table_name)

    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        """Load ISF symbol table for the detected CPython version."""
        key = version[:2]
        entry = SYMBOL_TABLE_REGISTRY.get(key)
        if not entry:
            vollog.error(
                f"No symbol table registered for Python {key[0]}.{key[1]}. "
                f"Available: {sorted(SYMBOL_TABLE_REGISTRY.keys())}"
            )
            return None

        import_path, class_name, sub_path, filename = entry
        module = __import__(import_path, fromlist=[class_name])
        symbol_class = getattr(module, class_name)

        python_table_name = symbol_class.create(
            self.context, self.config_path,
            sub_path=sub_path,
            filename=filename,
        )
        vollog.info(f"Loaded symbol table: {class_name} -> {python_table_name}")
        return python_table_name

    def _collect_data(self, processes):
        """Standalone mode: detect version, load symbols, extract modules."""
        task = next(iter(processes), None)
        if not task:
            return []

        # Windows: no task.mm check — use add_process_layer instead
        try:
            task.add_process_layer()
        except exceptions.InvalidAddressException:
            vollog.error("Cannot create process layer")
            return []

        version = self.detect_python_version(task)
        if not version:
            vollog.error("Could not detect Python version")
            return []

        python_table_name = self._load_symbol_table(version)
        if not python_table_name:
            return []

        return self.get_modules(task, python_table_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def read_cstring(self, address, max_length=256):
        """Read a null-terminated C string from the process memory layer."""
        try:
            data = self.context.layers[self.process_layer].read(
                address, max_length, pad=False
            )
            return data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        except Exception:
            return ""

    def get_value_type(self, value):
        """Get the type name string for a PyObject by reading ob_type->tp_name."""
        if value is None:
            return 'NoneType'
        if hasattr(value, 'ob_type'):
            try:
                ob_type = value.ob_type.dereference()
                tp_name_ptr = ob_type.tp_name
                type_name = self.read_cstring(tp_name_ptr)
                return type_name.split('.')[-1]
            except Exception:
                return None
        return type(value).__name__

    # ------------------------------------------------------------------
    # Volatility renderer (standalone mode)
    # ------------------------------------------------------------------
    def _generator(self, data):
        for addr, name, mod_obj in data:
            yield (0, (
                0,
                0,
                "module",
                f"0x{addr:x}",
                str(name),
            ))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(
            self.config.get("pid", None)
        )
        processes = pslist.PsList.list_processes(
            self.context,
            self.config["kernel"],
            filter_func=filter_func,
        )

        collected_data = self._collect_data(processes)

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Gen.", int),
                ("Obj_Type", str),
                ("Obj_Addr", str),
                ("Obj_Value", str),
            ],
            self._generator(collected_data),
        )
