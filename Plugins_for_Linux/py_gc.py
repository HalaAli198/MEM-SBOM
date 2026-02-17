from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux import elf_parsing
import re




# This plugin walks CPython GC to  extract modules from its linked lists
# Works across 3.8-3.14 by handling three different GC layouts:
#   - 3.8:      GC state is global in _PyRuntime (not per-interpreter yet)
#   - 3.9-3.13: GC moved into PyInterpreterState, still uses generations[3]
#   - 3.14+:    generations[] replaced with young/old[0]/old[1]/permanent
#
# Returns (address, name, PyModuleObject) tuples, same shape as Py_Arenas
# and Py_Interpreter so the main plugin can merge everything.

# _PyRuntime -> interpreters.head
# Offset to dereference the interpreter linked list head from _PyRuntime.
# Got these with: p/x (int)&((_PyRuntimeState*)0)->interpreters.head
# (on 3.12+ the struct was renamed: p/x (int)&((struct pyruntimestate*)0)->interpreters.head)
# 3.13+ has _Py_DebugOffsets so we read it at runtime instead.
PYRUNTIME_INTERP_HEAD_OFFSETS = {
    (3, 7):  0x10,
    (3, 8):  0x20,
    (3, 9):  0x20,
    (3, 10): 0x20,
    (3, 11): 0x28,
    (3, 12): 0x28, 
}


# Offset of generations[0] within struct _gc_runtime_state (3.8-3.12)
# Fields before generations (identical 3.8-3.12):
#   PyObject *trash_delete_later   (8 bytes)
#   int trash_delete_nesting       (4 bytes)
#   int enabled                    (4 bytes)
#   int debug                      (4 bytes)
#   <4 bytes padding>
#   -> generations at 0x18
GC_GENERATIONS_OFFSET_IN_GC = 0x18

# Number of GC generations (constant 3.8-3.13)
NUM_GENERATIONS = 3

# Size of each gc_generation struct (3.8-3.13):
#   PyGC_Head head (16 bytes) + int threshold (4) + int count (4) = 24
GC_GENERATION_SIZE = 24


#3.14 replaced generations[] with separate lists(young, old[0], old[1], permanent):
# old is an array of 2 gc_generation_data: old[0] at 0x30, old[1] at 0x48
GC_314_YOUNG_OFFSET = 0x18
GC_314_OLD0_OFFSET = 0x30
GC_314_OLD1_OFFSET = 0x48  # 0x30 + 24 (sizeof gc_generation_data)
GC_314_PERMANENT_OFFSET = 0x60
GC_314_VISITED_SPACE_OFFSET = 0xe8


# 3.8 only: GC is global in _PyRuntime, not per-interpreter.
# _PyRuntime + 0x170 lands directly on generations[0].
PYRUNTIME_GC_GEN0_OFFSET_38 = 0x170


# 3.9-3.12: GC is per-interpreter. These are the offsets of the gc field
# inside PyInterpreterState. Got with: p/x &((PyInterpreterState*)0)->gc
INTERP_GC_OFFSETS = {
    (3, 9):  0x268,
    (3, 10): 0x268,
    (3, 11): 0x288,
    (3, 12): 0x70,
}

# Python 3.13+: gc offset read from _Py_DebugOffsets dynamically.
# _Py_DebugOffsets starts at _PyRuntime + 0x0 (confirmed 3.13 and 3.14).
# Position of interpreter_state.gc within _Py_DebugOffsets:
DEBUG_OFFSETS_GC_FIELD_POS = {
    (3, 13): 80,   # 0x50
    (3, 14): 88,   # 0x58
}
DEBUG_OFFSETS_GC_FIELD_POS_DEFAULT = 88 

# Position of runtime_state.interpreters_head within _Py_DebugOffsets
#   3.13: 0x28 
#   3.14: 0x28 
DEBUG_OFFSETS_INTERP_HEAD_POS = 0x28


# ==========================================================================
# SYMBOL TABLE REGISTRY - maps Python version to loader parameters
# ==========================================================================
SYMBOL_TABLE_REGISTRY = {
    (3, 8): (
        'volatility3.framework.symbols.generic.types.python.python38_handler',
        'Python_3_8_18_IntermedSymbols',
        'generic/types/python',
        'python38',
    ),
    (3, 9): (
        'volatility3.framework.symbols.generic.types.python.python38_handler',
        'Python_3_8_18_IntermedSymbols',
        'generic/types/python',
        'python39',
    ),
    (3, 10): (
        'volatility3.framework.symbols.generic.types.python.python38_handler',
        'Python_3_8_18_IntermedSymbols',
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
        'volatility3.framework.symbols.generic.types.python.python312_handler',
        'Python_3_12_IntermedSymbols',
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


class Py_GC(interfaces.plugins.PluginInterface):
    """Walk CPython GC lists and extract tracked objects (3.8-3.14)."""
    _version = (2, 0, 0)
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
        Extracts Python major.minor from the process's loaded libraries
        (libpythonX.Y.so) or binary path (/usr/bin/pythonX.Y).
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

      The updated find_symbol_in_process searches both libpython and
      the python binary automatically.
      """
      try:
        proc_layer_name = task.add_process_layer()
      except exceptions.InvalidAddressException:
        return None

      # find_symbol_in_process now tries libpython first, then the
      # python binary, searching both if needed
      resolved = elf_parsing.find_symbol_in_process(
        self.context, proc_layer_name, task,
        module_substring="libpython",
        symbol_names=["_PyRuntime"],
      )

      runtime_addr = resolved.get("_PyRuntime")
      if runtime_addr:
        print(f"Resolved _PyRuntime at: 0x{runtime_addr:x}")
      else:
        print("ERROR: Could not resolve _PyRuntime from ELF symbols")
        print(f"  Symbols found: {resolved}")

      return runtime_addr

    # ------------------------------------------------------------------
    # Interpreter head resolution
    # ------------------------------------------------------------------
    def get_interpreter_head_address(self, version, py_runtime_addr):
        """
        Returns the address of the first PyInterpreterState.

        Resolution:
          3.7-3.12: hardcoded offset table (PYRUNTIME_INTERP_HEAD_OFFSETS)
          3.13+:    read from _Py_DebugOffsets.runtime_state.interpreters_head
                    _Py_DebugOffsets is at _PyRuntime + 0x0 (first field)
                    interpreters_head is at debug_offsets + 0x28
        """
        key = version[:2]

        if key >= (3, 13):
            # _Py_DebugOffsets is at _PyRuntime + 0x0
            # runtime_state.interpreters_head is at debug_offsets + 0x28
            raw = self.context.layers[self.process_layer].read(
                py_runtime_addr + DEBUG_OFFSETS_INTERP_HEAD_POS, 8
            )
            offset = int.from_bytes(raw, 'little')
            print(f"  interpreters.head offset from debug_offsets: 0x{offset:x}")
        else:
            offset = PYRUNTIME_INTERP_HEAD_OFFSETS.get(key, 0x20)
            print(f"  interpreters.head offset from table: 0x{offset:x}")

        # Dereference the pointer at _PyRuntime + offset
        head_ptr_addr = py_runtime_addr + offset
        head_bytes = self.context.layers[self.process_layer].read(head_ptr_addr, 8)
        head_addr = int.from_bytes(head_bytes, 'little')

        if head_addr:
            print(f"Interpreter head at 0x{head_addr:x}")
        else:
            print("ERROR: interpreters.head is NULL")

        return head_addr

    # ------------------------------------------------------------------
    # GC base address resolution - returns _gc_runtime_state address
    # ------------------------------------------------------------------
    def find_gc_base_address(self, version, py_runtime_addr, interpreter_addr):
        """
        Returns the base address of _gc_runtime_state.

        Resolution strategy by version:
          3.8:       GC is global in _PyRuntime.
          3.9-3.12:  GC is per-interpreter, hardcoded offset.
          3.13+:     GC is per-interpreter, offset from _Py_DebugOffsets.
        """
        key = version[:2]

        # 3.8: GC lives directly in _PyRuntime (global, not per-interpreter)
        if key == (3, 8):
            gc_base = py_runtime_addr + PYRUNTIME_GC_GEN0_OFFSET_38 - GC_GENERATIONS_OFFSET_IN_GC
            print(f"Python 3.8: GC base in _PyRuntime at 0x{gc_base:x}")
            return gc_base

        # 3.13+: read gc offset from _Py_DebugOffsets dynamically
        if key >= (3, 13):
            debug_gc_pos = DEBUG_OFFSETS_GC_FIELD_POS.get(
                key, DEBUG_OFFSETS_GC_FIELD_POS_DEFAULT
            )
            # _Py_DebugOffsets is at _PyRuntime + 0x0
            raw = self.context.layers[self.process_layer].read(
                py_runtime_addr + debug_gc_pos, 8
            )
            gc_in_interp = int.from_bytes(raw, 'little')
            gc_base = interpreter_addr + gc_in_interp
            print(f"Python {key[0]}.{key[1]}: GC offset from debug_offsets = 0x{gc_in_interp:x}")
            print(f"  gc_base = interp + 0x{gc_in_interp:x} = 0x{gc_base:x}")
            return gc_base

        # 3.9-3.12: hardcoded per-version gc offset within PyInterpreterState
        gc_in_interp = INTERP_GC_OFFSETS.get(key)
        if gc_in_interp is None:
            print(f"WARNING: No GC offset for Python {key[0]}.{key[1]}")
            print(f"  Known versions: {sorted(INTERP_GC_OFFSETS.keys())}")
            return None

        gc_base = interpreter_addr + gc_in_interp
        print(f"Python {key[0]}.{key[1]}: GC base at interp + 0x{gc_in_interp:x} = 0x{gc_base:x}")
        return gc_base

    # ------------------------------------------------------------------
    # Legacy: generations[0] head address (3.8-3.13 compat wrapper)
    # ------------------------------------------------------------------
    def find_gc_generations_head(self, version, py_runtime_addr, interpreter_addr):
        """
        Returns the memory address of gc.generations[0].head.
        Only valid for 3.8-3.13. For 3.14+, use find_gc_base_address directly.
        """
        key = version[:2]
        if key >= (3, 14):
            print("Python 3.14+ uses incremental GC - use find_gc_base_address()")
            return None

        gc_base = self.find_gc_base_address(version, py_runtime_addr, interpreter_addr)
        if gc_base is None:
            return None

        gen0_addr = gc_base + GC_GENERATIONS_OFFSET_IN_GC
        print(f"  generations[0] at 0x{gen0_addr:x}")
        return gen0_addr

    # ------------------------------------------------------------------
    # Walk a single GC linked list (shared by both legacy and 3.14+)
    # ------------------------------------------------------------------
    def _walk_gc_list(self, head_addr, list_name, python_table_name,
                      gc_head_size, type_filter=None):
        """
        Walk a single PyGC_Head doubly-linked list starting from the sentinel
        at head_addr. The sentinel's _gc_next points to the first real entry.

        Each tracked object sits immediately after its PyGC_Head:
            object_addr = gc_head_addr + sizeof(PyGC_Head)

        Returns:
            list of (address, type_name, list_name, PyObject) tuples
        """
        results = []

        try:
            head_gc = self.context.object(
                object_type=python_table_name + constants.BANG + "PyGC_Head",
                layer_name=self.process_layer,
                offset=head_addr,
            )
        except Exception as e:
            print(f"  Error reading {list_name} head: {e}")
            return results

        try:
            current_offset = head_gc.get_next()
        except Exception as e:
            print(f"  Error reading _gc_next for {list_name}: {e}")
            return results

        visited = set()
        count = 0

        while current_offset != head_addr:
            if current_offset in visited or current_offset == 0:
                if current_offset in visited:
                    print(f"  Cycle detected at 0x{current_offset:x}")
                break

            visited.add(current_offset)

            try:
                obj_addr = current_offset + gc_head_size
                obj = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyObject",
                    layer_name=self.process_layer,
                    offset=obj_addr,
                )

                obj_type = obj.ob_type.dereference()
                type_name = obj_type.get_name()
                count += 1

                if type_filter is None or type_name == type_filter:
                    results.append((obj_addr, type_name, list_name, obj))

                # Advance to next GC head in the linked list
                current_gc = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyGC_Head",
                    layer_name=self.process_layer,
                    offset=current_offset,
                )
                current_offset = current_gc.get_next()

            except exceptions.InvalidAddressException:
                print(f"  Invalid address at 0x{current_offset:x}, stopping {list_name}")
                break
            except exceptions.PagedInvalidAddressException:
                print(f"  Page fault at 0x{current_offset:x}, stopping {list_name}")
                break
            except Exception as e:
                print(f"  Error at 0x{current_offset:x}: {e}")
                break

        print(f"  {list_name}: {count} tracked objects")
        return results

    # ------------------------------------------------------------------
    # GC traversal - 3.8-3.13: walks all 3 generations
    # ------------------------------------------------------------------
    def traverse_gc_legacy(self, gen0_addr, python_table_name, type_filter=None):
        """
        Walk all 3 GC generations starting from gen0_addr (Python 3.8-3.13).
        """
        gc_head_size = self.context.symbol_space.get_type(
            python_table_name + constants.BANG + "PyGC_Head"
        ).size

        results = []
        for gen_idx in range(NUM_GENERATIONS):
            gen_head_addr = gen0_addr + (gen_idx * GC_GENERATION_SIZE)
            list_name = f"generation {gen_idx}"
            print(f"{list_name} head at 0x{gen_head_addr:x}")

            results.extend(self._walk_gc_list(
                gen_head_addr, list_name, python_table_name,
                gc_head_size, type_filter
            ))

        return results

    # ------------------------------------------------------------------
    # GC traversal - 3.14+: walks young, old[0], old[1], permanent
    # ------------------------------------------------------------------
    def traverse_gc_incremental(self, gc_base_addr, python_table_name, type_filter=None):
        """
        Walk Python 3.14+ incremental GC lists.

        Layout within _gc_runtime_state:
          gc_base + 0x18: young        (gc_generation_data)
          gc_base + 0x30: old[0]       (gc_generation_data)
          gc_base + 0x48: old[1]       (gc_generation_data)
          gc_base + 0x60: permanent    (gc_generation_data)

        visited_space (at gc_base + 0xe8) tells which old[] space is currently
        the "visited" side of incremental collection.
        """
        gc_head_size = self.context.symbol_space.get_type(
            python_table_name + constants.BANG + "PyGC_Head"
        ).size

        # Read visited_space to annotate which old[] is active
        try:
            vs_raw = self.context.layers[self.process_layer].read(
                gc_base_addr + GC_314_VISITED_SPACE_OFFSET, 4
            )
            visited_space = int.from_bytes(vs_raw, 'little')
            print(f"visited_space = {visited_space}")
        except Exception:
            visited_space = -1
            print("Could not read visited_space")

        # Define the 4 GC lists to walk
        gc_lists = [
            (GC_314_YOUNG_OFFSET,     "young"),
            (GC_314_OLD0_OFFSET,      f"old[0]{' (visited)' if visited_space == 0 else ''}"),
            (GC_314_OLD1_OFFSET,      f"old[1]{' (visited)' if visited_space == 1 else ''}"),
            (GC_314_PERMANENT_OFFSET, "permanent"),
        ]

        results = []
        for offset, list_name in gc_lists:
            head_addr = gc_base_addr + offset
            print(f"{list_name} head at 0x{head_addr:x}")

            results.extend(self._walk_gc_list(
                head_addr, list_name, python_table_name,
                gc_head_size, type_filter
            ))

        return results

    # ------------------------------------------------------------------
    # Unified traverse_gc dispatcher
    # ------------------------------------------------------------------
    def traverse_gc(self, gc_addr, python_table_name,
                    type_filter=None, version=None):
        """
        Unified GC traversal - dispatches to legacy or incremental walker.

        For 3.8-3.13: gc_addr = gen0 address (legacy).
        For 3.14+:    gc_addr = gc_base address (incremental).
        """
        key = version[:2] if version else (3, 8)

        if key >= (3, 14):
            return self.traverse_gc_incremental(
                gc_addr, python_table_name, type_filter
            )
        else:
            return self.traverse_gc_legacy(
                gc_addr, python_table_name, type_filter
            )

    # ------------------------------------------------------------------
    # Internal: resolve _PyRuntime, version, interpreter, GC address
    # ------------------------------------------------------------------
    def _resolve_gc(self, task):
        """
        Common resolution pipeline used by all public APIs.

        Returns:
          (gc_addr, version) where gc_addr is:
            - gen0 address for 3.8-3.13 (legacy)
            - gc_base address for 3.14+ (incremental)
          or (None, None) on failure.
        """
        py_runtime = self.find_py_runtime_address(task)
        if not py_runtime:
            print("Could not find _PyRuntime")
            return None, None

        version = self.detect_python_version(task)
        if not version:
            print("Could not detect Python version")
            return None, None

        key = version[:2]
        print(f"Detected Python {key[0]}.{key[1]}")

        # 3.8: no interpreter needed, GC is in _PyRuntime
        # 3.9+: need interpreter address
        interpreter_addr = None
        if key != (3, 8):
            interpreter_addr = self.get_interpreter_head_address(version, py_runtime)
            if not interpreter_addr:
                print("Could not resolve interpreter head")
                return None, None

        if key >= (3, 14):
            # 3.14+: return gc_base for incremental walker
            gc_base = self.find_gc_base_address(version, py_runtime, interpreter_addr)
            return gc_base, version
        else:
            # 3.8-3.13: return gen0 address for legacy walker
            gen0_addr = self.find_gc_generations_head(version, py_runtime, interpreter_addr)
            return gen0_addr, version

    # ------------------------------------------------------------------
    # Public API - get_modules (for main plugin integration)
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        High-level entry point for the main plugin.
        Walks GC generations/lists and returns only module objects.

        Returns:
            list of (address, name, PyModuleObject) tuples,
            same format as Py_Arenas and Py_Interpreter.
        """
        task_layer = task.add_process_layer()
        self.process_layer = self.context.layers[task_layer].name

        gc_addr, version = self._resolve_gc(task)
        if not gc_addr:
            return []

        gc_objects = self.traverse_gc(
            gc_addr, python_table_name,
            type_filter='module', version=version
        )

        # Convert to standard (address, name, module_obj) format
        modules = []
        seen = set()
        for addr, type_name, list_name, obj in gc_objects:
            if addr in seen:
                continue
            seen.add(addr)
            try:
                mod_obj = obj.cast_to("PyModuleObject")
                mod_dict=mod_obj.get_dict2()
                print(mod_dict.keys())
                mod_name = mod_obj.get_name()
                modules.append((addr, str(mod_name), mod_obj))
            except Exception as e:
                print(f"  Error extracting module at 0x{addr:x}: {e}")

        print(f"GC walker found {len(modules)} unique modules")
        return modules

    # ------------------------------------------------------------------
    # Public API - get_all_objects (generic GC walker)
    # ------------------------------------------------------------------
    def get_all_objects(self, task, python_table_name, type_filter=None):
        """
        Walk GC and return all tracked objects (or filtered by type).

        Returns:
            list of (address, type_name, list_name, PyObject) tuples
        """
        task_layer = task.add_process_layer()
        self.process_layer = self.context.layers[task_layer].name

        gc_addr, version = self._resolve_gc(task)
        if not gc_addr:
            return []

        return self.traverse_gc(
            gc_addr, python_table_name,
            type_filter=type_filter, version=version
        )

    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        """
        Load the appropriate IntermedSymbols class for the detected version.
        Returns the symbol table name, or None if no table is registered.
        """
        key = version[:2]
        print(f"key: {key}")
        entry = SYMBOL_TABLE_REGISTRY.get(key)
        if not entry:
            print(f"No symbol table registered for Python {key[0]}.{key[1]}")
            print(f"  Available: {sorted(SYMBOL_TABLE_REGISTRY.keys())}")
            print(f"  Add an entry to SYMBOL_TABLE_REGISTRY in py_gc.py")
            return None

        import_path, class_name, sub_path, filename = entry
        module = __import__(import_path, fromlist=[class_name])
        symbol_class = getattr(module, class_name)

        python_table_name = symbol_class.create(
            self.context, self.config_path,
            sub_path=sub_path,
            filename=filename,
        )
        print(f"Loaded symbol table: {class_name} → {python_table_name}")
        return python_table_name

    def _collect_data(self, tasks):
        """
        Entry point when running as a standalone Volatility plugin.
        Detects version, loads symbol table, walks GC, returns modules.
        """
        task = list(tasks)[0]
        if not task or not task.mm:
            return []

        version = self.detect_python_version(task)
        print(f"Detected Python version: {version}")
        if not version:
            print("Could not detect Python version")
            return []

        python_table_name = self._load_symbol_table(version)
       
        if not python_table_name:
            return []

        return self.get_modules(task, python_table_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def read_cstring(self, address, max_length=256):
        """Reads a null-terminated C string from the process memory layer."""
        try:
            data = self.context.layers[self.process_layer].read(
                address, max_length, pad=False
            )
            return data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        except Exception:
            return ""

    def get_value_type(self, value):
        """Returns the type name for a PyObject by reading ob_type->tp_name."""
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
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func,
        )

        collected_data = self._collect_data(tasks)

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
