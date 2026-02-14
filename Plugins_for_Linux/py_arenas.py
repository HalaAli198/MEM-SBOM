from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
import collections
from volatility3.plugins.linux import elf_parsing
import textwrap
import dis
import types
import re
import hashlib
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
          3. Handle LTO-renamed variants (e.g. arenas.lto_priv)
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
        # Try shared library first — pyenv and custom builds link libpython
        resolved = elf_parsing.find_symbol_in_process(
            self.context, proc_layer_name, task,
            module_substring="libpython",
            symbol_names=symbols_needed,
        )
        
        # System Python (e.g. Ubuntu's /usr/bin/python3.8) is statically linked
        if not resolved or "arenas" not in resolved:
            resolved_fallback = elf_parsing.find_symbol_in_process(
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
        
        if MAXARENAS_ADDR is None:
            print("WARNING: Could not resolve 'maxarenas', will estimate from arena data")
        
        print(f"Resolved arenas symbol at: 0x{ARENAS_ADDR:x}")
        if MAXARENAS_ADDR:
            print(f"Resolved maxarenas symbol at: 0x{MAXARENAS_ADDR:x}")
        
       
        for name in ["usable_arenas", "narenas_currently_allocated", "narenas_highwater"]:
            if name in resolved:
                print(f"Resolved {name} at: 0x{resolved[name]:x}")
        
        # Dereference: arenas is a pointer to the arena_object array-
        arenas_ptr_bytes = curr_layer.read(ARENAS_ADDR, 8)
        arenas_ptr = int.from_bytes(arenas_ptr_bytes, byteorder='little', signed=False)
        print(f"Arenas pointer value: 0x{arenas_ptr:x}")
        
        if MAXARENAS_ADDR:
            maxarenas_bytes = curr_layer.read(MAXARENAS_ADDR, 4)
            maxarenas_count = int.from_bytes(maxarenas_bytes, byteorder='little', signed=False)
        else:
            maxarenas_count = 16  # Conservative default
            print(f"Using default maxarenas: {maxarenas_count}")
        
        print(f"Maxarenas count: {maxarenas_count}")
        
        if not curr_layer.is_valid(arenas_ptr, 8):
            print(f"ERROR: Arena pointer 0x{arenas_ptr:x} points to invalid memory!")
            return None, None
        
        return arenas_ptr, maxarenas_count
        
      except Exception as e:
        print(f"Error reading arena addresses: {e}")
        import traceback
        traceback.print_exc()
        return None, None
    
    
    
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
      if diff < 0x10000 or diff > 0x80000:
        return False
        
      return True
   
   
    def debug_pool_addresses(self, task, arena_obj, arena_idx, ntotalpools, python_table_name):
      """Debug pool address calculations with correct structure"""
      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        arena_address = int(arena_obj.address)
        print(f"\n=== ARENA {arena_idx} ADDRESS DEBUGGING ===")
        print(f"Arena address: 0x{arena_address:x}")
            
        # Check if arena+256KB is valid (expected end of arena)
        alt_pool_addr = arena_address + 0x40000
        print(f" pool addr (arena + 256KB): 0x{alt_pool_addr:x}")
        if curr_layer.is_valid(alt_pool_addr, 48):
            print(f" pool address is VALID memory")
        else:
            print(f" pool address is INVALID memory")
            
        #  arena address itself as first pool
        print(f"Testing arena address as pool: 0x{arena_address:x}")
        if curr_layer.is_valid(arena_address, 48):
            print(f"Arena address is VALID for pool data")
            arena_data = curr_layer.read(arena_address, 48)
          
        else:
            print(f"Arena address is INVALID for pool data")

        # Walk each 4KB pool and dump its header fields
        # Pool header layout (48 bytes):
        #   [0:4]   ref.count (ob_refcnt union)
        #   [8:16]  freeblock ptr
        #   [16:24] nextpool ptr
        #   [24:32] prevpool ptr
        #   [32:36] arenaindex
        #   [36:40] szidx (size class index)
        #   [40:44] nextoffset
        #   [44:48] maxnextoffset
        for pool_idx in range(ntotalpools):
            pool_offset = arena_address + (pool_idx * 4096)
           # print(f"\nPool {pool_idx} (0x{pool_offset:x}):")
            pool_offset_alt = arena_address + (pool_idx * 4096)
          # print(f"  Original calc: 0x{pool_offset_original:x}")
            #print(f"  pool address calc: 0x{pool_offset_alt:x}")
            if curr_layer.is_valid(pool_offset_alt, 48):
                   pool_bytes = curr_layer.read(pool_offset, 48)
                   szidx = int.from_bytes(pool_bytes[36:40], byteorder='little')
                   nextoffset = int.from_bytes(pool_bytes[40:44], byteorder='little')
                   #print(f"Size index={szidx}, Next offset={nextoffset}")

            if curr_layer.is_valid(pool_offset, 48):
                # Read pool header - 48 bytes total
                pool_bytes = curr_layer.read(pool_offset, 48)
                ref_count = int.from_bytes(pool_bytes[0:4], byteorder='little') 
                freeblock = int.from_bytes(pool_bytes[8:16], byteorder='little')
                nextpool = int.from_bytes(pool_bytes[16:24], byteorder='little')
                prevpool = int.from_bytes(pool_bytes[24:32], byteorder='little')
                arenaindex = int.from_bytes(pool_bytes[32:36], byteorder='little')
                szidx = int.from_bytes(pool_bytes[36:40], byteorder='little')     
                nextoffset = int.from_bytes(pool_bytes[40:44], byteorder='little')
                maxnextoffset = int.from_bytes(pool_bytes[44:48], byteorder='little')
               
                # CPython size classes: szidx maps to block sizes 8, 16, 24, ... up to 512
                # szidx=0 means pool is free, >64 is invalid
                if szidx > 0 and szidx <= 64:  # Valid size class range
                    
                    size_classes = [8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
                                  144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 
                                  480, 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1152, 1280, 1408, 
                                  1536, 1664, 1792, 1920, 2048, 2304, 2560, 2816, 3072, 3328, 3584, 
                                  3840, 4096, 4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192]
                    
                    if szidx <= len(size_classes):
                        block_size = size_classes[szidx - 1]
                     
                elif szidx == 0:
                    print(f"  → Free pool (size index 0)")
                else:
                    print(f"Invalid size class {szidx}")
              
            else:
                print(f"Invalid memory address")
                
      except Exception as e:
        print(f"Pool debug error: {e}")

   
    def is_valid_pyobject_header(self, refcnt, type_ptr, curr_layer):
      """
      Checks whether a block's first 16 bytes look like a valid PyObject.
      We validate ob_refcnt range and then peek at the type object itself
      to confirm it has a sane refcount and a valid tp_type pointer.
      This filters out most garbage blocks.
      """
      
      if refcnt < 1 or refcnt > 1000000:  
        return False
        
      
      if type_ptr < 0x1000 or not curr_layer.is_valid(type_ptr, 8):
        return False
    
   
      try:
        type_data = curr_layer.read(type_ptr, 16)
        type_refcnt = int.from_bytes(type_data[0:8], 'little')
        type_type_ptr = int.from_bytes(type_data[8:16], 'little')
        if type_refcnt < 1 or type_refcnt > 10000000:
            return False
            
        # ob_type of a type object points to PyType_Type (or a metaclass)
        if type_type_ptr < 0x1000:
            return False
            
        return True
      except Exception:
        return False
   
    def get_python_object_info(self, obj_candidate, block_size, block_idx):
      """Extracts type, refcount, and value from a PyObject for reporting."""
      try:
        obj_type = obj_candidate.get_type_name()
        refcnt = int(obj_candidate.ob_refcnt)
        address = obj_candidate.vol.offset
        
        try:
            obj_value = obj_candidate.get_value(cur_depth=0, max_depth=1)
            value_str = str(obj_value)
            if len(value_str) > 100:
                value_str = value_str[:100] + "..."
        except Exception:
            obj_value = f"<{obj_type} object>"
            value_str = obj_value
        
        return {
            'block_index': block_idx,
            'address': hex(address),
            'type': obj_type,
            'obj': obj_candidate,
            'refcnt': refcnt,
            'value': value_str,
            'block_size': block_size,
            'size_estimate': self.estimate_object_size(obj_candidate, obj_type)
        }
        
      except Exception:
        return None
    
    
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
      Scans all allocated blocks within a single pool for module objects.

      For each block:
          1. Skip blocks on the freelist (linked via freeblock pointers)
          2. Skip blocks past nextoffset (never-allocated region)
          3. Validate the first 16 bytes as a PyObject header
          4. Cast to PyObject and check type — only keep 'module' objects
          5. Extract module name via PyModuleObject

      Returns list of (address, name, module_obj) tuples.
      """
     
      modules = []
      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        block_size = pool_info['block_size']
        if not isinstance(block_size, int) or block_size <= 0:
            return []

        pool_base = pool_obj.vol.offset
        pool_data_start = pool_base + 48 # skip pool_header (48 bytes)
        nextoffset = pool_info['nextoffset']
        allocated_region_end = pool_base + nextoffset
        
        # Build the set of free block addresses by walking the freelist 
        free_blocks = set()
        freeblock_addr = pool_info.get('freeblock_addr', 0)
        max_free = (4096 - 48) // block_size

        while freeblock_addr != 0:
            if freeblock_addr < pool_data_start or freeblock_addr >= pool_base + 4096:
                break
            if (freeblock_addr - pool_data_start) % block_size != 0:
                break # not aligned to block boundary — corrupted
            if freeblock_addr in free_blocks:
                break # cycle detected
            if not curr_layer.is_valid(freeblock_addr, 8):
                break
            free_blocks.add(freeblock_addr)
            if len(free_blocks) > max_free:
                break  # more free blocks than possible — bail
            try:
                next_ptr_bytes = curr_layer.read(freeblock_addr, 8)
                freeblock_addr = int.from_bytes(next_ptr_bytes, byteorder='little')
            except Exception:
                break
        
        # Iterate each block slot in the pool
        max_blocks = (4096 - 48) // block_size
        for block_idx in range(max_blocks):
            block_offset = pool_data_start + (block_idx * block_size)
            if block_offset >= allocated_region_end:
                break # past the high-water mark
            if block_offset in free_blocks:
                continue # on freelist, skip
            if not curr_layer.is_valid(block_offset, 16):
                continue
            try:
                # Read ob_refcnt (8 bytes) + ob_type pointer (8 bytes)
                header_data = curr_layer.read(block_offset, 16)
                if len(header_data) < 16:
                    continue
                refcnt = int.from_bytes(header_data[0:8], byteorder='little')
                type_ptr = int.from_bytes(header_data[8:16], byteorder='little')
                if not self.is_valid_pyobject_header(refcnt, type_ptr, curr_layer):
                    continue

                obj_candidate = self.context.object(
                    object_type=python_table_name + constants.BANG + "PyObject",
                    layer_name=proc_layer_name,
                    offset=block_offset
                )

                try:
                    type_name = obj_candidate.get_type_name()
                except Exception:
                    continue
                
                # We only care about module objects for SBOM/dependency extraction
                if type_name != 'module':
                    continue

                module_obj = obj_candidate.cast_to("PyModuleObject")
                try:
                    mod_name = module_obj.get_name()
                except Exception:
                    mod_name = "<unknown>"

                modules.append((block_offset, mod_name, module_obj))

            except Exception:
                continue

        return modules

      except Exception as e:
        print(f"Pool extraction error: {e}")
        return []


    
    def comprehensive_memory_analysis(self, task, python_table_name):
      """
      Main analysis loop: resolves arena addresses, then walks
      arenas → pools → blocks to find all module objects.

      Each arena_object is 48 bytes with layout:
          [0:8]   address       — base of the 256KB mmap'd region
          [8:16]  pool_address  — first usable pool (aligned)
          [16:20] nfreepools
          [20:24] ntotalpools
          [24:32] freepools     — head of free pool linked list
          [32:48] nextarena/prevarena pointers (doubly-linked list)
      """
      
      arenas_ptr, maxarenas_count = self.get_arena_addresses(task)
      modules = []
      if not arenas_ptr or not maxarenas_count:
        print("Failed to retrieve arena information")
        return
    
      print(f"\n=== DEBUGGING ARENA STRUCTURE READING ===")
    
      for arena_idx in range(maxarenas_count):  
        arena_offset = arenas_ptr + (arena_idx * 48)
        
        print(f"\nArena {arena_idx} Debug:")
        print(f"  Calculated offset: 0x{arena_offset:x}")
        
        try:
            proc_layer_name = task.add_process_layer()
            curr_layer = self.context.layers[proc_layer_name]
            # arena_object structs are contiguous — 48 bytes each
            raw_arena_bytes = curr_layer.read(arena_offset, 48)
            
           
            
            # Manual field parsing for verification
            arena_addr = int.from_bytes(raw_arena_bytes[0:8], byteorder='little')
            pool_addr = int.from_bytes(raw_arena_bytes[8:16], byteorder='little')
            nfreepools = int.from_bytes(raw_arena_bytes[16:20], byteorder='little')
            ntotalpools = int.from_bytes(raw_arena_bytes[20:24], byteorder='little')
            freepools_ptr = int.from_bytes(raw_arena_bytes[24:32], byteorder='little')
            
           
            print(f"    Arena address: 0x{arena_addr:x}")
            print(f"    Pool address: 0x{pool_addr:x}")
            print(f"    Free pools: {nfreepools}")
            print(f"    Total pools: {ntotalpools}")
            print(f"    Free pools ptr: 0x{freepools_ptr:x}")
            
            # Verify addresses make sense
            if arena_addr != 0:
                addr_diff = abs(arena_addr - pool_addr)
                expected_diff = 256 * 1024   # 256KB arena size
                print(f"    Address difference: 0x{addr_diff:x} (expected ~0x{expected_diff:x})")
                
                if addr_diff > expected_diff * 2:
                    print(f"    WARNING: Address difference too large!")
                
                
                if not curr_layer.is_valid(arena_addr, 8):
                    print(f"    ERROR: Arena address 0x{arena_addr:x} is invalid!")
                if not curr_layer.is_valid(pool_addr, 8):
                    print(f"    ERROR: Pool address 0x{pool_addr:x} is invalid!")
            
            # Also verify via the Volatility type overlay
            arena_obj = self.context.object(
                object_type=python_table_name + constants.BANG + "arena_object",
                layer_name=proc_layer_name,
                offset=arena_offset)
          
          
            print(f"\n=== ARENA {arena_idx} STRUCTURE VERIFICATION ===")
            print(f"Raw arena structure (48 bytes):")
            arena_bytes = curr_layer.read(arena_offset, 48)
            print(f"  Bytes 0-8 (address): {arena_bytes[0:8].hex()}")
            pool_addr_interpreted = int.from_bytes(arena_bytes[0:8], byteorder='little')
            print(f"    → Interpreted: 0x{pool_addr_interpreted:x}")
            print(f"  Bytes 8-16 (pool_address): {arena_bytes[8:16].hex()}")
            pool_addr_interpreted = int.from_bytes(arena_bytes[8:16], byteorder='little')
            print(f"    → Interpreted: 0x{pool_addr_interpreted:x}")
            print(f"  Bytes 16-20 (nfreepools): {arena_bytes[16:20].hex()}")
            print(f"  Bytes 20-24 (ntotalpools): {arena_bytes[20:24].hex()}")
            print(f"  Bytes 24-32 (freepools): {arena_bytes[24:32].hex()}")
            if not self.validate_arena(arena_obj, proc_layer_name):
                print(f"  Arena {arena_idx} is invalid/corrupted - skipping")
                continue
            self.debug_pool_addresses(task, arena_obj, arena_idx, ntotalpools, python_table_name)
            print(f"  Structure-based reading:")
            print(f"    Arena address: 0x{int(arena_obj.address):x}")
            print(f"    Pool address: 0x{int(arena_obj.pool_address):x}")
            print(f"    Active: {arena_obj.is_active()}")
            print(f"\n ------------- EXTRACTING OBJECTS FROM ARENA {arena_idx} -------------")
            arena_address=int(arena_obj.address) 
            for pool_idx in range(ntotalpools):
                pool_offset = arena_address + (pool_idx * 4096)
                try:
                  pool_obj = self.context.object(object_type=python_table_name + constants.BANG + "pool_header",layer_name=proc_layer_name,offset=pool_offset)
                  if pool_obj.is_pool_active():
                     pool_info = pool_obj.get_pool_info()
                     pool_modules = self.extract_pool_objects(task, pool_obj, pool_info, python_table_name)
                     modules.extend(pool_modules)
                  else:
                     print(f"\n  Pool {pool_idx}: INACTIVE/FREE")
            
                except Exception as e:
                    print(f"\n  Pool {pool_idx}: Error - {e}")
            print("*"*100)
        except Exception as e:
            print(f"  Error reading arena {arena_idx}: {e}")

      return modules
   
    def get_pool_info(self):
      """Returns a dict of pool metadata including block size, allocation counts, and freelist head."""
      block_size = self.get_block_size()
      ref_count = self.get_ref_count()
    
      if isinstance(block_size, int) and block_size > 0:
        usable_space = 4096 - 48 # pool page minus header
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
        collected_data=[]
        if version and version[:2] == (3, 8):
           from volatility3.framework.symbols.generic.types.python.sbom_dep_graph import Python_3_8_18_IntermedSymbols
           python_table_name = Python_3_8_18_IntermedSymbols.create(self.context, self.config_path, sub_path="generic/types/python", filename="python-3_8-x64_2")
      
        else:
           print(f"Unsupported Python version: {version}")
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



