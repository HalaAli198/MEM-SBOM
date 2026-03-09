"""
Walk CPython's GC linked lists to extract tracked objects (Windows).

Handles three different GC layouts across Python versions:
  3.7-3.8:  GC state is global in _PyRuntime (not per-interpreter)
  3.9-3.13: GC moved into PyInterpreterState, still uses generations[3]
  3.14+:    generations[] replaced with young/old[0]/old[1]/permanent

Uses pe_parsing (single-process, direct PE export + PDB + structural scan)
to resolve _PyRuntime — mirrors the Linux elf_parsing approach.

Returns (address, name, PyModuleObject) tuples, same shape as
Py_Interpreter and Py_Heap so Module_Extractor can merge everything.
"""

import logging
from typing import Dict, List, Optional, Tuple

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import pe_parsing

vollog = logging.getLogger(__name__)


# -----------------------------------------------------------------------
# _PyRuntime -> interpreters.head offsets
# Obtained via: p/x (int)&((_PyRuntimeState*)0)->interpreters.head
# 3.13+ reads this from _Py_DebugOffsets at runtime instead.
# -----------------------------------------------------------------------
PYRUNTIME_INTERP_HEAD_OFFSETS = {
    (3, 7):  0x18,
    (3, 8):  0x20,
    (3, 9):  0x20,
    (3, 10): 0x20,
    (3, 11): 0x28,
    (3, 12): 0x28,
}


# -----------------------------------------------------------------------
# GC generation layout constants (3.8-3.13)
# -----------------------------------------------------------------------

# Offset of generations[0] within _gc_runtime_state.
# Fields before generations:
#   trash_delete_later (8) + trash_delete_nesting (4) + enabled (4)
#   + debug (4) + 4 padding = 0x18
GC_GENERATIONS_OFFSET_IN_GC = 0x18

NUM_GENERATIONS = 3


# sizeof(gc_generation) per version
GC_GENERATION_SIZES = {
    (3, 6): 32,   # PyGC_Head(24) + threshold(4) + count(4)
    (3, 7): 32,    # PyGC_Head(24) — MSVC long double = 8
}
GC_GENERATION_SIZE_DEFAULT = 24  # 3.8+: PyGC_Head(16) + threshold(4) + count(4)


# -----------------------------------------------------------------------
# 3.14 incremental GC: separate lists replaced generations[]
# Offsets within _gc_runtime_state for each list head:
# -----------------------------------------------------------------------
GC_314_YOUNG_OFFSET = 0x18
GC_314_OLD0_OFFSET = 0x30
GC_314_OLD1_OFFSET = 0x48
GC_314_PERMANENT_OFFSET = 0x60
GC_314_VISITED_SPACE_OFFSET = 0xe8


# -----------------------------------------------------------------------
# Version-specific GC location offsets
# -----------------------------------------------------------------------

# 3.7-3.8: GC lives directly in _PyRuntime (global).
# Obtained via: p/x &((_PyRuntimeState*)0)->gc.generations
PYRUNTIME_GC_GENERATIONS_OFFSET = {
    (3, 7): 0x150,
    (3, 8): 0x170,
}

# 3.9-3.12: GC is per-interpreter.
# Obtained via: p/x &((PyInterpreterState*)0)->gc
INTERP_GC_OFFSETS = {
    (3, 9):  0x268,
    (3, 10): 0x268,
    (3, 11): 0x288,
    (3, 12): 0x70,
}

# 3.13+: gc offset read from _Py_DebugOffsets at runtime.
# _Py_DebugOffsets starts at _PyRuntime + 0x0.
# Position of interpreter_state.gc within the debug offsets struct:
DEBUG_OFFSETS_GC_FIELD_POS = {
    (3, 13): 80,   # 0x50
    (3, 14): 80,   # 0x50
}

DEBUG_OFFSETS_GC_FIELD_POS_DEFAULT = 88

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


class Py_GC(interfaces.plugins.PluginInterface):
    """Walk CPython GC lists and extract tracked objects (Windows, 3.6-3.14)."""
    _version = (2, 0, 0)
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
    def get_interpreter_head_address(self, version, py_runtime_addr):
        """
        Dereference _PyRuntime to get the first PyInterpreterState.

        3.7-3.12: hardcoded offset from PYRUNTIME_INTERP_HEAD_OFFSETS
        3.13+:    read from _Py_DebugOffsets at debug_offsets + 0x28
        """
        key = version[:2]

        if key >= (3, 13):
            raw = self.context.layers[self.process_layer].read(
                py_runtime_addr + DEBUG_OFFSETS_INTERP_HEAD_POS, 8
            )
            offset = int.from_bytes(raw, 'little')
            vollog.debug(
                f"interpreters.head offset from debug_offsets: 0x{offset:x}"
            )
        else:
            offset = PYRUNTIME_INTERP_HEAD_OFFSETS.get(key, 0x20)
            vollog.debug(
                f"interpreters.head offset from table: 0x{offset:x}"
            )

        head_ptr_addr = py_runtime_addr + offset
        head_bytes = self.context.layers[self.process_layer].read(
            head_ptr_addr, 8
        )
        head_addr = int.from_bytes(head_bytes, 'little')

        if head_addr:
            vollog.info(f"Interpreter head at 0x{head_addr:x}")
        else:
            vollog.error("interpreters.head is NULL")

        return head_addr

    # ------------------------------------------------------------------
    # GC base address resolution
    # ------------------------------------------------------------------
    def find_gc_base_address(self, version, py_runtime_addr, interpreter_addr):
        """
        Locate the _gc_runtime_state struct.

        3.7-3.8:  GC is global in _PyRuntime
        3.9-3.12: GC is per-interpreter, hardcoded offset
        3.13+:    GC is per-interpreter, offset read from _Py_DebugOffsets
        """
        key = version[:2]

        # 3.7 & 3.8: GC lives directly in _PyRuntime (global)
        if key in PYRUNTIME_GC_GENERATIONS_OFFSET:
            gen_offset = PYRUNTIME_GC_GENERATIONS_OFFSET[key]
            gc_base = py_runtime_addr + gen_offset - GC_GENERATIONS_OFFSET_IN_GC
            vollog.info(
                f"Python {key[0]}.{key[1]}: "
                f"GC base in _PyRuntime at 0x{gc_base:x}"
            )
            return gc_base

        # 3.13+: read gc offset from _Py_DebugOffsets dynamically
        if key >= (3, 13):
            debug_gc_pos = DEBUG_OFFSETS_GC_FIELD_POS.get(
                key, DEBUG_OFFSETS_GC_FIELD_POS_DEFAULT
            )
            raw = self.context.layers[self.process_layer].read(
                py_runtime_addr + debug_gc_pos, 8
            )
            gc_in_interp = int.from_bytes(raw, 'little')
            gc_base = interpreter_addr + gc_in_interp
            vollog.info(
                f"Python {key[0]}.{key[1]}: "
                f"GC offset from debug_offsets = 0x{gc_in_interp:x}, "
                f"gc_base = 0x{gc_base:x}"
            )
            return gc_base

        # 3.9-3.12: hardcoded per-version gc offset within PyInterpreterState
        gc_in_interp = INTERP_GC_OFFSETS.get(key)
        if gc_in_interp is None:
            vollog.warning(
                f"No GC offset for Python {key[0]}.{key[1]}. "
                f"Known versions: {sorted(INTERP_GC_OFFSETS.keys())}"
            )
            return None

        gc_base = interpreter_addr + gc_in_interp
        vollog.info(
            f"Python {key[0]}.{key[1]}: "
            f"GC base at interp + 0x{gc_in_interp:x} = 0x{gc_base:x}"
        )
        return gc_base

    # ------------------------------------------------------------------
    # Legacy: generations[0] head address (3.6-3.13)
    # ------------------------------------------------------------------
    def find_gc_generations_head(self, version, py_runtime_addr, interpreter_addr):
        """Return address of gc.generations[0].head. Only valid for 3.6-3.13."""
        key = version[:2]
        if key >= (3, 14):
            vollog.warning(
                "Python 3.14+ uses incremental GC — "
                "use find_gc_base_address() instead"
            )
            return None

        gc_base = self.find_gc_base_address(
            version, py_runtime_addr, interpreter_addr
        )
        if gc_base is None:
            return None

        gen0_addr = gc_base + GC_GENERATIONS_OFFSET_IN_GC
        vollog.debug(f"generations[0] at 0x{gen0_addr:x}")
        return gen0_addr

    # ------------------------------------------------------------------
    # Walk a single GC linked list
    # ------------------------------------------------------------------
    def _walk_gc_list(self, head_addr, list_name, python_table_name,
                      gc_head_size, type_filter=None):
        """
        Walk a PyGC_Head doubly-linked list from the sentinel at head_addr.
        The sentinel's _gc_next points to the first real tracked object.
        Each object sits right after its PyGC_Head prefix:
            object_addr = gc_head_addr + sizeof(PyGC_Head)

        Returns list of (address, type_name, list_name, PyObject) tuples.
        """
        results = []

        try:
            head_gc = self.context.object(
                object_type=python_table_name + constants.BANG + "PyGC_Head",
                layer_name=self.process_layer,
                offset=head_addr,
            )
        except Exception as e:
            vollog.warning(f"Error reading {list_name} head: {e}")
            return results

        try:
            current_offset = head_gc.get_next()
        except Exception as e:
            vollog.warning(f"Error reading _gc_next for {list_name}: {e}")
            return results

        visited = set()
        count = 0

        while current_offset != head_addr:
            if current_offset in visited or current_offset == 0:
                if current_offset in visited:
                    vollog.debug(f"Cycle detected at 0x{current_offset:x}")
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
                vollog.debug(
                    f"Invalid address at 0x{current_offset:x}, "
                    f"stopping {list_name}"
                )
                break
            except exceptions.PagedInvalidAddressException:
                vollog.debug(
                    f"Page fault at 0x{current_offset:x}, "
                    f"stopping {list_name}"
                )
                break
            except Exception as e:
                vollog.debug(f"Error at 0x{current_offset:x}: {e}")
                break

        vollog.info(f"  {list_name}: {count} tracked objects")
        return results

    # ------------------------------------------------------------------
    # GC traversal: legacy generations (3.6-3.13)
    # ------------------------------------------------------------------
    def traverse_gc_legacy(self, gen0_addr, python_table_name,
                   type_filter=None, version=None):
      gc_head_size = self.context.symbol_space.get_type(
        python_table_name + constants.BANG + "PyGC_Head"
      ).size

      key = version[:2] if version else (3, 8)
      gen_size = GC_GENERATION_SIZES.get(key, GC_GENERATION_SIZE_DEFAULT)

      # Windows MSVC: long double = 8, so PyGC_Head = 24 for 3.6-3.7
      # ISF may report 32 (from Linux GCC where long double = 16)
      GC_HEAD_SIZE_OVERRIDES = {
        (3, 6): 24,
        (3, 7): 24,
      }
      if key in GC_HEAD_SIZE_OVERRIDES:
        gc_head_size = GC_HEAD_SIZE_OVERRIDES[key]

      results = []
      for gen_idx in range(NUM_GENERATIONS):
        gen_head_addr = gen0_addr + (gen_idx * gen_size)
        list_name = f"generation {gen_idx}"
        results.extend(self._walk_gc_list(
            gen_head_addr, list_name, python_table_name,
            gc_head_size, type_filter
        ))
      return results
    

    # ------------------------------------------------------------------
    # GC traversal: incremental (3.14+)
    # ------------------------------------------------------------------
    def traverse_gc_incremental(self, gc_base_addr, python_table_name,
                                type_filter=None):
        """
        Walk Python 3.14+ incremental GC lists:
        young, old[0], old[1], permanent.
        """
        gc_head_size = self.context.symbol_space.get_type(
            python_table_name + constants.BANG + "PyGC_Head"
        ).size

        try:
            vs_raw = self.context.layers[self.process_layer].read(
                gc_base_addr + GC_314_VISITED_SPACE_OFFSET, 4
            )
            visited_space = int.from_bytes(vs_raw, 'little')
            vollog.debug(f"visited_space = {visited_space}")
        except Exception:
            visited_space = -1
            vollog.debug("Could not read visited_space")

        gc_lists = [
            (GC_314_YOUNG_OFFSET,
             "young"),
            (GC_314_OLD0_OFFSET,
             f"old[0]{' (visited)' if visited_space == 0 else ''}"),
            (GC_314_OLD1_OFFSET,
             f"old[1]{' (visited)' if visited_space == 1 else ''}"),
            (GC_314_PERMANENT_OFFSET,
             "permanent"),
        ]

        results = []
        for offset, list_name in gc_lists:
            head_addr = gc_base_addr + offset
            vollog.info(f"{list_name} head at 0x{head_addr:x}")

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
        Dispatch to legacy (3.6-3.13) or incremental (3.14+) GC walker.
        gc_addr is gen0 address for legacy, gc_base for incremental.
        """
        key = version[:2] if version else (3, 8)

        if key >= (3, 14):
            return self.traverse_gc_incremental(
                gc_addr, python_table_name, type_filter
            )
        else:
             return self.traverse_gc_legacy(gc_addr, python_table_name, type_filter, version=version)

    # ------------------------------------------------------------------
    # Internal: resolve _PyRuntime, version, interpreter, GC address
    # ------------------------------------------------------------------
    def _resolve_gc(self, task):
        """
        Common resolution pipeline for all public APIs.
        Detects version, finds _PyRuntime, resolves interpreter and GC
        addresses.

        Returns (gc_addr, version) where gc_addr is:
          - gen0 address for 3.6-3.13
          - gc_base address for 3.14+
        Returns (None, None) on failure.
        """
        version = self.detect_python_version(task)
        if not version:
            vollog.error("Could not detect Python version")
            return None, None

        key = version[:2]
        vollog.info(f"Detected Python {key[0]}.{key[1]}")

        # 3.6: separate path, no _PyRuntime
        if key == (3, 6):
            return self._resolve_gc_36(task, version)

        # === Python 3.7+: use _PyRuntime ===
        py_runtime = self.find_py_runtime_address(task)
        if not py_runtime:
            vollog.error("Could not find _PyRuntime")
            return None, None

        # 3.7-3.8: GC is in _PyRuntime, no interpreter address needed
        # 3.9+: need interpreter address since GC moved per-interpreter
        interpreter_addr = None
        if key not in PYRUNTIME_GC_GENERATIONS_OFFSET:
            interpreter_addr = self.get_interpreter_head_address(
                version, py_runtime
            )
            if not interpreter_addr:
                vollog.error("Could not resolve interpreter head")
                return None, None

        if key >= (3, 14):
            gc_base = self.find_gc_base_address(
                version, py_runtime, interpreter_addr
            )
            return gc_base, version
        else:
            gen0_addr = self.find_gc_generations_head(
                version, py_runtime, interpreter_addr
            )
            return gen0_addr, version

    def _resolve_gc_36(self, task, version):
        """
        Python 3.6 GC resolution.

        3.6 has no _PyRuntime. The global _PyGC_generation0 points
        directly to generations[0].head. We resolve it via PE symbols
        and dereference to get gen0.
        
        Note: pe_parsing.find_symbol_in_process now operates on the
        specific task only (no global process walk).
        """
        resolved = pe_parsing.find_symbol_in_process(
            self.context,
            self.config_path,
            task,
            symbol_names=["_PyGC_generation0"],
            module_substring="python",
            version=version[:2],
        )

        gen0_ptr_addr = resolved.get("_PyGC_generation0")
        if not gen0_ptr_addr:
            vollog.error("Could not resolve _PyGC_generation0")
            return None, None

        vollog.info(f"Resolved _PyGC_generation0 at: 0x{gen0_ptr_addr:x}")

        # _PyGC_generation0 is a pointer TO gen0 when resolved via
        # PDB/exports (it's a global variable holding the address).
        # But when resolved via structural scan, it's the ADDRESS OF
        # the generations array itself. We need to detect which case.
        #
        # Heuristic: if the address is within a PE section (.data/.bss),
        # check if dereferencing it gives another valid pointer.
        # If it does, and that pointer's neighborhood looks like a
        # gc_generation array, use the dereferenced value.
        # Otherwise, use the address directly (structural scan result).
        
        try:
            gen0_bytes = self.context.layers[self.process_layer].read(
                gen0_ptr_addr, 8
            )
            potential_gen0 = int.from_bytes(gen0_bytes, 'little')
            
            # Check if this looks like a pointer to gen0
            # (the dereferenced value should be a valid heap pointer)
            if 0x10000 < potential_gen0 < 0x7FFFFFFFFFFF:
                # Try reading the gc_generation at the dereferenced address
                test = self.context.layers[self.process_layer].read(
                    potential_gen0, 24
                )
                if test is not None:
                    # Check if it looks like a gc_generation:
                    # gc_next (8), gc_prev (8), threshold (4), count (4)
                    gc_next = int.from_bytes(test[0:8], 'little')
                    threshold = int.from_bytes(test[16:20], 'little')
                    
                    # If threshold is reasonable (1-100000), this is likely
                    # the actual generations array
                    if 1 <= threshold <= 100000:
                        vollog.info(
                            f"_PyGC_generation0 is a pointer: "
                            f"0x{gen0_ptr_addr:x} -> 0x{potential_gen0:x} "
                            f"(threshold={threshold})"
                        )
                        return potential_gen0, version
            
            # Check if gen0_ptr_addr itself looks like a gc_generation
            # (structural scan case)
            direct_data = self.context.layers[self.process_layer].read(
                gen0_ptr_addr, 24
            )
            if direct_data is not None:
                direct_threshold = int.from_bytes(direct_data[16:20], 'little')
                if 1 <= direct_threshold <= 100000:
                    vollog.info(
                        f"_PyGC_generation0 is direct address: "
                        f"0x{gen0_ptr_addr:x} (threshold={direct_threshold})"
                    )
                    return gen0_ptr_addr, version
                    
        except Exception as e:
            vollog.debug(f"Error disambiguating _PyGC_generation0: {e}")

        # Fallback: try dereference first (traditional PDB/export case)
        try:
            gen0_bytes = self.context.layers[self.process_layer].read(
                gen0_ptr_addr, 8
            )
            gen0_addr = int.from_bytes(gen0_bytes, 'little')
            if gen0_addr and 0x10000 < gen0_addr < 0x7FFFFFFFFFFF:
                vollog.info(f"generations[0].head at 0x{gen0_addr:x}")
                return gen0_addr, version
        except Exception:
            pass

        # Last resort: use the address directly
        vollog.info(f"Using _PyGC_generation0 directly at 0x{gen0_ptr_addr:x}")
        return gen0_ptr_addr, version

    # ------------------------------------------------------------------
    # Public API — get_modules (for Module_Extractor)
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        Walk GC lists and return only module objects.
        Returns list of (address, name, PyModuleObject) tuples.
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

        modules = []
        seen = set()
        for addr, type_name, list_name, obj in gc_objects:
            if addr in seen:
                continue
            seen.add(addr)
            try:
                mod_obj = obj.cast_to("PyModuleObject")
                mod_dict = mod_obj.get_dict2()
                mod_name = mod_obj.get_name()
                modules.append((addr, str(mod_name), mod_obj))
            except Exception as e:
                vollog.debug(f"Error extracting module at 0x{addr:x}: {e}")

        vollog.info(f"GC walker found {len(modules)} unique modules")
        return modules

    # ------------------------------------------------------------------
    # Public API - get_all_objects (generic GC walker)
    # ------------------------------------------------------------------
    def get_all_objects(self, task, python_table_name, type_filter=None):
        """Walk GC and return all tracked objects, optionally filtered."""
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
        """Standalone mode: detect version, load symbols, walk GC."""
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
        """Get the type name for a PyObject via ob_type->tp_name."""
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
