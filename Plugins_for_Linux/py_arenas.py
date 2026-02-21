from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
import collections
from volatility3.plugins.linux import elf_parsing3
import textwrap
import dis
import types
import re
import hashlib

#==========================================================================
# SYMBOL TABLE REGISTRY - maps Python version to loader parameters
# ==========================================================================
SYMBOL_TABLE_REGISTRY = {
    (3, 6): (
        'volatility3.framework.symbols.generic.types.python.python36_handler',
        'Python_3_6_15_IntermedSymbols',
        'generic/types/python',
        'python36',
    ),
    (3, 7): (
        'volatility3.framework.symbols.generic.types.python.python37_handler',
        'Python_3_7_17_IntermedSymbols',
        'generic/types/python',
        'python37',
    ),
    (3, 8): (
        'volatility3.framework.symbols.generic.types.python.python38_handler',
        'Python_3_8_18_IntermedSymbols',
        'generic/types/python',
        'python38',
    ),
    (3, 9): (
        'volatility3.framework.symbols.generic.types.python.python39_handler',
        'Python_3_8_18_IntermedSymbols',
        'generic/types/python',
        'python39',
    ),
    (3, 10): (
        'volatility3.framework.symbols.generic.types.python.python310_handler',
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

class Py_Arenas(interfaces.plugins.PluginInterface):
    """
    Walks CPython's obmalloc arena/pool/block hierarchy to extract
    live Python objects directly from the allocator structures.

    CPython allocates small objects (<= 512 bytes) through a 3-level system:
      arenas (256KB chunks) → pools (4KB pages) → blocks (fixed-size slots)

    This plugin resolves the 'arenas' array via ELF symbol lookup (elf_parsing.py required),
    iterates each arena's pools, and scans allocated blocks for valid
    PyObject headers. Currently focused on extracting module objects
    for dependency/SBOM generation.
    """ 
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
    _modules = []
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
    
    def get_arena_addresses(self, task):
      """
      Resolves the `arenas` and `maxarenas` global variables from the
      Python process's ELF symbols. These are internal to CPython's
      obmalloc.c and hold the base pointer to the arena_object array
      and the current array capacity.

      Strategy:
      1. Try libpython*.so (shared/pyenv builds)
      2. Fall back to the python binary itself (static/system builds)
      3. If maxarenas symbol not found, probe the arena array forward
         until we hit consecutive zero-address entries (end of array)
      """
      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]

        symbols_needed = [
            "arenas",
            "maxarenas",
            "usable_arenas",
            "narenas_currently_allocated",
            "narenas_highwater",
        ]

        # Try shared library first (pyenv/custom builds)
        resolved = elf_parsing3.find_symbol_in_process(
            self.context, proc_layer_name, task,
            module_substring="libpython",
            symbol_names=symbols_needed,
        )

        # Fall back to main binary (system Python, statically linked)
        if not resolved or "arenas" not in resolved:
            resolved_fallback = elf_parsing3.find_symbol_in_process(
                self.context, proc_layer_name, task,
                module_substring="python",
                symbol_names=symbols_needed,
            )
            for k, v in resolved_fallback.items():
                if k not in resolved:
                    resolved[k] = v

        ARENAS_ADDR = resolved.get("arenas")
        MAXARENAS_ADDR = resolved.get("maxarenas")

        if ARENAS_ADDR is None:
            print("ERROR: Could not resolve 'arenas' symbol from ELF")
            print(f"  Symbols found: {resolved}")
            return None, None

        print(f"Resolved arenas symbol at: 0x{ARENAS_ADDR:x}")
        if MAXARENAS_ADDR:
            print(f"Resolved maxarenas symbol at: 0x{MAXARENAS_ADDR:x}")

        for name in ["usable_arenas", "narenas_currently_allocated", "narenas_highwater"]:
            if name in resolved:
                print(f"Resolved {name} at: 0x{resolved[name]:x}")

        # Dereference: arenas is a pointer to the arena_object array
        arenas_ptr_bytes = curr_layer.read(ARENAS_ADDR, 8)
        arenas_ptr = int.from_bytes(arenas_ptr_bytes, byteorder='little', signed=False)
        print(f"Arenas pointer value: 0x{arenas_ptr:x}")

        if not curr_layer.is_valid(arenas_ptr, 8):
            print(f"ERROR: Arena pointer 0x{arenas_ptr:x} points to invalid memory!")
            return None, None

        if MAXARENAS_ADDR:
            maxarenas_bytes = curr_layer.read(MAXARENAS_ADDR, 4)
            maxarenas_count = int.from_bytes(maxarenas_bytes, byteorder='little', signed=False)
            print(f"Maxarenas count (from symbol): {maxarenas_count}")
        else:
            # Symbol missing (common in 3.7 debug/LTO builds) — probe instead
            maxarenas_count = self._probe_maxarenas(curr_layer, arenas_ptr)
            print(f"Maxarenas count (probed): {maxarenas_count}")

        return arenas_ptr, maxarenas_count

      except Exception as e:
        print(f"Error reading arena addresses: {e}")
        import traceback
        traceback.print_exc()
        return None, None

    
    
    
    def _probe_maxarenas(self, curr_layer, arenas_ptr, arena_obj_size=48):
      """
      Scan the arena_object array forward to find its true size.
      Each entry is 48 bytes; the first 8 bytes are the arena's mmap base
      address (0 if never used). We stop after 3 consecutive zeros or
      unreadable memory.
      """
      ARENA_OBJ_SIZE = 48
      MAX_PROBE = 256          # 256 arenas = 64MB, way more than typical
      ZERO_STOP_THRESHOLD = 3  # consecutive empty slots before we quit

      count = 0
      consecutive_zeros = 0

      for i in range(MAX_PROBE):
        offset = arenas_ptr + (i * arena_obj_size)

        if not curr_layer.is_valid(offset, arena_obj_size):
            break

        addr = int.from_bytes(curr_layer.read(offset, 8), 'little')

        if addr == 0:
            consecutive_zeros += 1
            count += 1
            if consecutive_zeros >= ZERO_STOP_THRESHOLD:
                count -= consecutive_zeros  # trim trailing empties
                break
        else:
            consecutive_zeros = 0
            count += 1

      if count == 0:
        print("  WARNING: Probe found 0 arenas, falling back to 16")
        count = 16

      return count
    
    def validate_arena(self, arena_obj, layer_name):
      """
        Sanity checks on an arena_object to skip free/corrupted entries.
        A valid active arena should have:
          - Non-null base address
          - pool_address > address (pools start after alignment padding)
          - pool_address pointing to readable memory
          - Reasonable gap between address and pool_address (64KB-512KB)
      """ 
      
      if int(arena_obj.address) == 0:
        return False
    
      pool_addr = int(arena_obj.pool_address)
      arena_addr = int(arena_obj.address)
    
      if pool_addr <= arena_addr:
        return False
        

      curr_layer = self.context.layers[layer_name]
      if not curr_layer.is_valid(pool_addr, 48):
        print(f"    Pool address 0x{pool_addr:x} is not in valid memory")
        return False
     
      # Pool start should be within the 256KB arena, accounting for alignment  
      diff = pool_addr - arena_addr
      if diff < 0x1000 or diff > 0x80000:
        return False
        
      return True
   
   
    def debug_pool_addresses(self, task, arena_obj, arena_idx, ntotalpools, python_table_name):
      """Debug pool address calculations"""
      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        arena_address = int(arena_obj.address)
        pool_address = int(arena_obj.pool_address)

        # FIX: same carved-pool logic
        num_carved = (pool_address - arena_address) // 4096
        if num_carved <= 0 or num_carved > ntotalpools:
            num_carved = ntotalpools

        print(f"\n=== ARENA {arena_idx} POOL DEBUG ===")
        print(f"  address=0x{arena_address:x} pool_address=0x{pool_address:x} carved={num_carved}")

        for pool_idx in range(num_carved):
            pool_offset = arena_address + (pool_idx * 4096)
            if not curr_layer.is_valid(pool_offset, 48):
                print(f"  Pool {pool_idx} (0x{pool_offset:x}): INVALID memory")
                continue

            pool_obj = self.context.object(
                object_type=python_table_name + constants.BANG + "pool_header",
                layer_name=proc_layer_name,
                offset=pool_offset)

            szidx = int(pool_obj.szidx)
            nextoffset = int(pool_obj.nextoffset)
            arenaindex = int(pool_obj.arenaindex)

            if szidx > 0 and szidx <= 64:
                print(f"  Pool {pool_idx} (0x{pool_offset:x}): szidx={szidx} "
                      f"nextoffset={nextoffset} arenaindex={arenaindex}")
            elif szidx == 0:
                print(f"  Pool {pool_idx} (0x{pool_offset:x}): FREE")
            else:
                print(f"  Pool {pool_idx} (0x{pool_offset:x}): INVALID szidx={szidx}")
                
      except Exception as e:
        print(f"Pool debug error: {e}")

   
    def is_valid_pyobject_header(self, refcnt, type_ptr, curr_layer):
      """
      Validates a candidate PyObject header (ob_refcnt + ob_type).
      Also peeks at the type object to confirm it looks sane.
      Uses ob_refcnt_offset for debug builds when reading the type object.
      """
      if refcnt < 1 or refcnt > 1000000:
        return False

      if type_ptr < 0x1000 or not curr_layer.is_valid(type_ptr, 8):
        return False

      try:
        ob_refcnt_offset = getattr(self, '_ob_refcnt_offset', 0)

        # Read the type object's own header (with debug offset if needed)
        type_header = curr_layer.read(type_ptr + ob_refcnt_offset, 16)
        type_refcnt = int.from_bytes(type_header[0:8], 'little')
        type_type_ptr = int.from_bytes(type_header[8:16], 'little')

        if type_refcnt < 1 or type_refcnt > 10000000:
            return False
        if type_type_ptr < 0x1000:
            return False

        return True
      except Exception:
        return False
    
    def estimate_object_size(self, obj_candidate, obj_type):
      """
        Returns a rough size indicator: 'var(N)' for variable-length
        objects (str, list, tuple, bytes) where N is ob_size, or 'fixed'.
      """
      try:
        if hasattr(obj_candidate, 'ob_size'):
            ob_size = int(obj_candidate.ob_size)
            return f"var({ob_size})"
        else:
            return "fixed"
      except:
        return "unknown"
    
    
   
     
    
    def extract_pool_objects(self, task, pool_obj, pool_info, python_table_name):
      """
      Scans allocated blocks in a pool for module objects.
      Skips freelist blocks and blocks past nextoffset.

      DIAGNOSTIC VERSION: tracks objects at each pipeline stage.
      """
      modules = []
      # --- Diagnostic counters ---
      diag = {
        'blocks_scanned': 0,
        'blocks_skipped_free': 0,
        'blocks_skipped_unreadable': 0,
        'blocks_past_end': 0,
        'valid_header': 0,
        'invalid_header': 0,
        'type_resolved': 0,
        'type_failed': 0,
        'type_names': {},       # type_name -> count
        'module_cast_ok': 0,
        'module_cast_fail': 0,
        'module_name_ok': 0,
      }

      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        block_size = pool_info['block_size']
        if not isinstance(block_size, int) or block_size <= 0:
            return [], diag

        pool_base = pool_obj.vol.offset
        pool_header_size = getattr(self, '_pool_header_size', 48)
        pool_data_start = pool_base + pool_header_size
        nextoffset = pool_info['nextoffset']
        allocated_region_end = pool_base + nextoffset

        # Walk the freelist
        free_blocks = set()
        freeblock_addr = pool_info.get('freeblock_addr', 0)
        max_free = (4096 - 48) // block_size

        while freeblock_addr != 0:
            if freeblock_addr < pool_data_start or freeblock_addr >= pool_base + 4096:
                break
            if (freeblock_addr - pool_data_start) % block_size != 0:
                break
            if freeblock_addr in free_blocks:
                break
            if not curr_layer.is_valid(freeblock_addr, 8):
                break
            free_blocks.add(freeblock_addr)
            if len(free_blocks) > max_free:
                break
            try:
                next_ptr_bytes = curr_layer.read(freeblock_addr, 8)
                freeblock_addr = int.from_bytes(next_ptr_bytes, byteorder='little')
            except Exception:
                break

        if not hasattr(self, '_ob_refcnt_offset'):
            try:
                pyobj_type = self.context.symbol_space.get_type(
                    python_table_name + constants.BANG + "PyObject"
                )
                self._ob_refcnt_offset = pyobj_type.relative_child_offset('ob_refcnt')
            except Exception:
                self._ob_refcnt_offset = 0
            print(f"  ob_refcnt offset from ISF: {self._ob_refcnt_offset}")
        ob_refcnt_offset = self._ob_refcnt_offset

        max_blocks = (4096 - 48) // block_size
        for block_idx in range(max_blocks):
            block_offset = pool_data_start + (block_idx * block_size)

            if block_offset >= allocated_region_end:
                diag['blocks_past_end'] += 1
                continue  # changed from break to continue for counting
            if block_offset in free_blocks:
                diag['blocks_skipped_free'] += 1
                continue
            if not curr_layer.is_valid(block_offset + ob_refcnt_offset, 16):
                diag['blocks_skipped_unreadable'] += 1
                continue

            diag['blocks_scanned'] += 1

            try:
                header_data = curr_layer.read(block_offset + ob_refcnt_offset, 16)
                if len(header_data) < 16:
                    diag['invalid_header'] += 1
                    continue

                refcnt = int.from_bytes(header_data[0:8], byteorder='little')
                type_ptr = int.from_bytes(header_data[8:16], byteorder='little')

                if not self.is_valid_pyobject_header(refcnt, type_ptr, curr_layer):
                    diag['invalid_header'] += 1
                    continue

                diag['valid_header'] += 1

                obj_candidate = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyObject",
                    layer_name=proc_layer_name,
                    offset=block_offset
                )

                try:
                    type_name = obj_candidate.get_type_name()
                except Exception as e:
                    diag['type_failed'] += 1
                    continue

                diag['type_resolved'] += 1
                diag['type_names'][type_name] = diag['type_names'].get(type_name, 0) + 1

                if type_name != 'module':
                    continue

                # --- Module found! Try to cast and get name ---
                try:
                    module_obj = obj_candidate.cast_to("PyModuleObject")
                    diag['module_cast_ok'] += 1
                except Exception as e:
                    diag['module_cast_fail'] += 1
                    # Still record it with unknown name
                    modules.append((block_offset, "<cast_failed>", None))
                    continue

                try:
                    mod_name = module_obj.get_name()
                    diag['module_name_ok'] += 1
                except Exception:
                    mod_name = "<unknown>"

                modules.append((block_offset, mod_name, module_obj))

            except Exception:
                continue

        return modules, diag

      except Exception as e:
        print(f"Pool extraction error: {e}")
        return [], diag


    
    def comprehensive_memory_analysis(self, task, python_table_name):
      """
      Main analysis loop with full diagnostics.
      """

      arenas_ptr, maxarenas_count = self.get_arena_addresses(task)
      modules = []
      if not arenas_ptr or not maxarenas_count:
        print("Failed to retrieve arena information")
        return []

      print(f"\n=== ARENA ANALYSIS ===")

      # Global diagnostic accumulators
      global_types = {}
      global_diag = {
        'total_pools': 0,
        'active_pools': 0,
        'total_blocks_scanned': 0,
        'total_valid_headers': 0,
        'total_type_resolved': 0,
        'total_type_failed': 0,
        'total_modules': 0,
      }

      for arena_idx in range(maxarenas_count):
        arena_offset = arenas_ptr + (arena_idx * 48)

        try:
            proc_layer_name = task.add_process_layer()
            curr_layer = self.context.layers[proc_layer_name]

            if not curr_layer.is_valid(arena_offset, 48):
                break

            arena_obj = self.context.object(
                object_type=python_table_name + constants.BANG + "arena_object",
                layer_name=proc_layer_name,
                offset=arena_offset)

            if not self.validate_arena(arena_obj, proc_layer_name):
                print(f"  Arena {arena_idx}: invalid/free — skipping")
                continue

            arena_address = int(arena_obj.address)
            pool_address = int(arena_obj.pool_address)
            nfreepools = int.from_bytes(curr_layer.read(arena_offset + 16, 4), 'little')
            ntotalpools = int.from_bytes(curr_layer.read(arena_offset + 20, 4), 'little')

            num_carved = (pool_address - arena_address) // 4096
            if num_carved <= 0 or num_carved > ntotalpools:
                num_carved = ntotalpools

            print(f"\n  Arena {arena_idx}: address=0x{arena_address:x} pool_address=0x{pool_address:x}")
            print(f"    ntotalpools={ntotalpools} nfreepools={nfreepools} carved={num_carved}")

            for pool_idx in range(num_carved):
                pool_offset = arena_address + (pool_idx * 4096)
                global_diag['total_pools'] += 1
                try:
                    pool_obj = self.context.object(
                        object_type=python_table_name + constants.BANG + "pool_header",
                        layer_name=proc_layer_name,
                        offset=pool_offset)

                    if pool_obj.is_pool_active():
                        global_diag['active_pools'] += 1
                        pool_info = pool_obj.get_pool_info()
                        print(f"    Pool {pool_idx}: ACTIVE szidx={pool_info['size_class']} "
                              f"block_size={pool_info['block_size']} "
                              f"allocated={pool_info['allocated_blocks']}")

                        pool_modules, diag = self.extract_pool_objects(
                            task, pool_obj, pool_info, python_table_name)

                        if pool_modules:
                            print(f"      → Found {len(pool_modules)} module(s): "
                                  f"{[m[1] for m in pool_modules]}")
                        modules.extend(pool_modules)

                        # Accumulate global stats
                        global_diag['total_blocks_scanned'] += diag['blocks_scanned']
                        global_diag['total_valid_headers'] += diag['valid_header']
                        global_diag['total_type_resolved'] += diag['type_resolved']
                        global_diag['total_type_failed'] += diag['type_failed']
                        global_diag['total_modules'] += len(pool_modules)

                        for tn, cnt in diag['type_names'].items():
                            global_types[tn] = global_types.get(tn, 0) + cnt

                        # Per-pool detail only if something interesting
                        if diag['valid_header'] > 0:
                            print(f"      [DIAG] scanned={diag['blocks_scanned']} "
                                  f"free={diag['blocks_skipped_free']} "
                                  f"past_end={diag['blocks_past_end']} "
                                  f"hdr_ok={diag['valid_header']} "
                                  f"hdr_bad={diag['invalid_header']} "
                                  f"type_ok={diag['type_resolved']} "
                                  f"type_fail={diag['type_failed']}")
                            if diag['type_names']:
                                top = sorted(diag['type_names'].items(), key=lambda x: -x[1])[:5]
                                print(f"      [TYPES] {', '.join(f'{n}:{c}' for n, c in top)}")

                except Exception as e:
                    print(f"    Pool {pool_idx}: Error - {e}")

        except Exception as e:
            print(f"  Error reading arena {arena_idx}: {e}")

      # ===== GLOBAL SUMMARY =====
      print(f"\n{'='*60}")
      print(f"=== DIAGNOSTIC SUMMARY ===")
      print(f"{'='*60}")
      print(f"  Total pools checked:     {global_diag['total_pools']}")
      print(f"  Active pools:            {global_diag['active_pools']}")
      print(f"  Blocks scanned:          {global_diag['total_blocks_scanned']}")
      print(f"  Valid PyObject headers:   {global_diag['total_valid_headers']}")
      print(f"  Type resolution success: {global_diag['total_type_resolved']}")
      print(f"  Type resolution FAILED:  {global_diag['total_type_failed']}")
      print(f"  Modules found:           {global_diag['total_modules']}")
      print(f"")
      if global_types:
        print(f"  === TYPE DISTRIBUTION (top 20) ===")
        sorted_types = sorted(global_types.items(), key=lambda x: -x[1])
        for tn, cnt in sorted_types[:20]:
            marker = " <<<" if tn == "module" else ""
            print(f"    {tn:30s} {cnt:6d}{marker}")
        if len(sorted_types) > 20:
            others = sum(c for _, c in sorted_types[20:])
            print(f"    {'(others)':30s} {others:6d}")
        print(f"    {'TOTAL':30s} {sum(global_types.values()):6d}")
      print(f"\n=== TOTAL MODULES FOUND: {len(modules)} ===")
      return modules
   
    def get_pool_info(self):
      """Returns a dict of pool metadata including block size, allocation counts, and freelist head."""
      block_size = self.get_block_size()
      ref_count = self.get_ref_count()
    
      if isinstance(block_size, int) and block_size > 0:
        pool_header_size = getattr(self, '_pool_header_size', 48)# pool page minus header
        usable_space = 4096 - pool_header_size
        max_free = usable_space // block_size
        max_blocks = usable_space // block_size
       
        utilization = (ref_count / max_blocks * 100) if max_blocks > 0 else 0
      else:
        max_blocks = "Unknown"
        utilization = "Unknown"
    
    
      try:
        freeblock_val = int(self.member('freeblock'))
      except Exception:
        freeblock_val = 0
    
      return {
        'block_size': block_size,
        'allocated_blocks': ref_count,
        'max_blocks': max_blocks,
        'utilization_percent': utilization,
        'arena_index': int(self.arenaindex),
        'size_class': int(self.szidx),
        'nextoffset': int(self.nextoffset),
        'maxnextoffset': int(self.maxnextoffset),
        'freeblock_addr': freeblock_val
      }
   
    
    def _load_symbol_table(self, version):
      key = version[:2]
      entry = SYMBOL_TABLE_REGISTRY.get(key)
      if not entry:
         print(f"No symbol table registered for Python {key[0]}.{key[1]}")
         print(f"  Available: {sorted(SYMBOL_TABLE_REGISTRY.keys())}")
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
        Entry point for data collection. Detects Python version,
        loads the matching symbol table, and runs arena analysis.
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
        task_layer = task.add_process_layer()
        curr_layer = self.context.layers[task_layer]
        self.process_layer = curr_layer.name
        modules = self.comprehensive_memory_analysis(task, python_table_name)
     
        self._modules = modules
        return modules

   
    
    
    
    
    def parse_dist_info(self,entries):
      """
      Parses .dist-info directory names to extract (package, version) tuples.
      e.g. 'requests-2.28.1.dist-info' → ('requests', '2.28.1')
      """
      packages = []
      for entry in entries:
        if isinstance(entry, str) and '.dist-info' in entry:
            pattern = r'([\w\.-]+?)-([\d\.\w]+)\.dist-info'
            match = re.match(pattern, entry)
            if match:
                package_name = match.group(1)
                version = match.group(2)
                packages.append((package_name, version))
      
      return packages
    
    
    
    
    def read_cstring(self, address, max_length=256):
        """Reads a null-terminated C string from the process memory layer."""
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
        Returns the Python type name for a PyObject by reading ob_type->tp_name.
        Falls back to Python's type() for non-PyObject values.
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


   
    

    @staticmethod
    def sanitize_value(value):
        if isinstance(value, str):
            return value.replace('\n', '\\n')
        return value

    def _generator(self, data):
      for addr, name, module_obj in data:
        yield (0, (
            0,
            0,
            "module",
            f"0x{addr:x}",
            str(name)
        ))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func
        )

      
        collected_data = self._collect_data(tasks)

        
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



