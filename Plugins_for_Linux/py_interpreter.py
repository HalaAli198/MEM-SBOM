from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux import elf_parsing
import re

#https://github.com/python/cpython/blob/main/Include/internal/pycore_runtime.h
#https://github.com/python/cpython/blob/3.14/Include/internal/pycore_runtime_structs.h
PYRUNTIME_INTERP_HEAD_OFFSETS = {
    (3, 7):  0x10,   # PyRuntimeState.interpreters.head
    (3, 8):  0x20,   # _PyRuntimeState.interpreters.head
    (3, 9):  0x20,
    (3, 10): 0x28,
    (3, 11): 0x28,
} # 3.12+ handled dynamically via debug_offsets

class Py_Interpreter(interfaces.plugins.PluginInterface):
    """
    Py_Interpreter - Extract loaded modules from CPython interpreter state

    This plugin resolves the _PyRuntime global via ELF symbol lookup (using
    elf_parsing.py), then walks the PyInterpreterState linked list to dump
    every module registered in interpreter.modules (sys.modules).

    # Output format: list of (address, name, PyModuleObject) tuples, same shape
    # as Py_Arenas so the main plugin can merge results from all sources.
    
    """
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    
    @classmethod
    def get_requirements(cls):
      return [
        requirements.ModuleRequirement(
            name="kernel",
            description="Linux kernel",
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
        Extracts Python major.minor version from the process's loaded
        libraries (libpythonX.Y.so) or binary path (/usr/bin/pythonX.Y).
        Returns tuple like (3, 8) or None.
      """
      try:
        for vma in task.mm.get_mmap_iter():
            fname = vma.get_name(self.context, task)
            if fname and 'libpython' in fname:
                match = re.search(r'libpython(\d+)\.(\d+)', fname)
                if match:
                    return (int(match.group(1)), int(match.group(2)))
            elif fname and '/python' in fname:
                match = re.search(r'python(\d+)\.(\d+)', fname)
                if match:
                    return (int(match.group(1)), int(match.group(2)))
      except Exception:
        pass
      return None
    
    
    # ------------------------------------------------------------------
    # Symbol resolution via elf_parsing
    # ------------------------------------------------------------------

    def find_py_runtime_address(self, task):
        """
        Resolves the _PyRuntime global symbol from the Python process's
        ELF image using elf_parsing.find_symbol_in_process.

        Steps:
          1. Try libpython*.so first (shared/pyenv builds)
          2. Fall back to the python binary itself (static/system builds)

        Returns:
            int: Memory address of _PyRuntime, or None if not found.
        """
        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException:
            return None

        symbol_names = ["_PyRuntime"]

        # Strategy 1: shared library (pyenv / custom builds)
        resolved = elf_parsing.find_symbol_in_process(
            self.context, proc_layer_name, task,
            module_substring="libpython",
            symbol_names=symbol_names,
        )

        # Strategy 2: statically-linked binary (system Python)
        if not resolved or "_PyRuntime" not in resolved:
            resolved_fallback = elf_parsing.find_symbol_in_process(
                self.context, proc_layer_name, task,
                module_substring="python",
                symbol_names=symbol_names,
            )
            if resolved_fallback:
                resolved.update(resolved_fallback)

        runtime_addr = resolved.get("_PyRuntime")
        if runtime_addr:
            print(f"Resolved _PyRuntime at: 0x{runtime_addr:x}")
        else:
            print("ERROR: Could not resolve _PyRuntime from ELF symbols")
            print(f"  Symbols found: {resolved}")

        return runtime_addr
    
    
    # ------------------------------------------------------------------
    # Interpreter walking
    # ------------------------------------------------------------------

    def get_interpreters_head_offset(self, version, py_runtime_addr):
      key = version[:2]

      # 3.12+ embeds _Py_DebugOffsets as the first field of _PyRuntime.
      # runtime_state.interpreters_head sits at byte 40 within it.
      if key >= (3, 12):
        raw = self.context.layers[self.process_layer].read(py_runtime_addr + 40, 8)
        offset = int.from_bytes(raw, 'little')
        print(f"Read interpreters_head offset from debug_offsets: 0x{offset:x}")
        return offset

      # Older versions: use hardcoded table
      offset = PYRUNTIME_INTERP_HEAD_OFFSETS.get(key)
      if offset is not None:
         return offset

      print(f"WARNING: No known offset for Python {key}, falling back to 0x20")
      return 0x20
    
    
    # ------------------------------------------------------------------
    # Interpreter walking — returns [(addr, name, module_obj), ...]
    # ------------------------------------------------------------------
    def parse_interpreters(self, interpreters_head_ptr, python_table_name):
        """
        Walk the PyInterpreterState linked list starting from interpreters.head.

         For each interpreter, extracts module objects from
        interpreter.modules (the sys.modules dict).

        Returns:
            list of (address, name, PyModuleObject) tuples.
        """
        modules = []

        # Dereference the interpreters.head pointer
        try:
            head_bytes = self.context.layers[self.process_layer].read(interpreters_head_ptr, 8)
            head_addr = int.from_bytes(head_bytes, byteorder='little', signed=False)
        except exceptions.InvalidAddressException:
            head_addr = 0

        if not head_addr:
            print("No interpreters found or invalid pointer!")
            return modules

        current = self.context.object(
            object_type=python_table_name + constants.BANG + "PyInterpreterState",
            layer_name=self.process_layer,
            offset=head_addr,
        )

        interpreter_count = 0
        seen_addrs = set()  # dedup across interpreters

        while current and current.vol.offset != 0:
            interpreter_count += 1
            print(f"Processing interpreter {interpreter_count} at 0x{current.vol.offset:x}")

            try:
                # --- interpreter.modules (sys.modules) ---
                modules_addr = current.modules
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
                        addr = mod_obj.vol.offset
                        if addr not in seen_addrs:
                            seen_addrs.add(addr)
                            modules.append((addr, str(mod_name), mod_obj))

               
            except Exception as e:
                print(f"  Error processing interpreter {interpreter_count}: {e}")

            # Advance to next interpreter
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
    # Public API — called by main plugin
    # ------------------------------------------------------------------

    def get_modules(self, task, python_table_name):
        """
        High-level entry point for the main plugin.

        Args:
            task: the process task struct
            python_table_name: already-loaded symbol table name

        Returns:
            list of (address, name, PyModuleObject) tuples,
            same format as Py_Arenas.
        """
        # Set up process layer
        task_layer = task.add_process_layer()
        self.process_layer = self.context.layers[task_layer].name

        # Resolve _PyRuntime
        py_runtime = self.find_py_runtime_address(task)
        if not py_runtime:
            print("Could not find _PyRuntime — no interpreter modules available")
            return []

        # Compute interpreters.head address
        version = self.detect_python_version(task)
        if not version:
            print("Could not detect Python version")
            return []

        offset = self.get_interpreters_head_offset(version, py_runtime)
        interpreters_head = py_runtime + offset
        print(f"_PyRuntime=0x{py_runtime:x}  +0x{offset:x}  --> interpreters.head at 0x{interpreters_head:x}")

        return self.parse_interpreters(interpreters_head, python_table_name)
  
    def _collect_data(self, tasks):
        """
        Entry point when running as a standalone plugin.
        Detects version, loads symbol table, calls get_modules().
        """
        task = list(tasks)[0]
        if not task or not task.mm:
            return []

        version = self.detect_python_version(task)
        print(f"Detected Python version: {version}")

        if not version:
            print("Could not detect Python version")
            return []

        if version[:2] == (3, 8):
            from volatility3.framework.symbols.generic.types.python.sbom_dep_graph import Python_3_8_18_IntermedSymbols
            python_table_name = Python_3_8_18_IntermedSymbols.create(
                self.context, self.config_path,
                sub_path="generic/types/python",
                filename="python38",
            )
        else:
            print(f"Unsupported Python version: {version}")
            return []

        return self.get_modules(task, python_table_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    
    def read_cstring(self, address, max_length=256):
        """
        Reads a null-terminated C string from the given memory address.
        """
        try:
            data = self.context.layers[self.process_layer].read(address, max_length, pad=False)
            cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            return cstring
        except exceptions.InvalidAddressException as e:
            print(f"InvalidAddressException reading C string at {hex(address)}: {str(e)}")
            return ""
        except Exception as e:
            print(f"Error reading C string at {hex(address)}: {str(e)}")
            return ""

    
    def get_value_type(self, value):
        """
        Retrieves the type name of a given value, handling both PyObjects and primitive types.
        """
        if value is None:
            return 'NoneType'
        if hasattr(value, 'ob_type'):
            try:
                # For PyObjects, get the type name from ob_type
                ob_type = value.ob_type.dereference()
                tp_name_ptr = ob_type.tp_name
                type_name = self.read_cstring(tp_name_ptr)
                return type_name.split('.')[-1]  # Get the base type name
            except Exception as e:
                print(f"Error getting type name of PyObject: {str(e)}")
                return None
        else:
            # For primitive types, use type()
            return type(value).__name__

    

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
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func
        )

        # Collect data
        collected_data = self._collect_data(tasks)

        # Return the TreeGrid with collected data and improved formatting
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Gen.", int),
                ("Obj_Type", str),
                ("Obj_Addr", str),
                ("Obj_Value", str)
            ],
            self._generator(collected_data)
        )



