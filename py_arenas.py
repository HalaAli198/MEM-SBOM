from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
import collections
from volatility3.plugins.linux import elf_parsing
from volatility3.framework.symbols.generic.types.python.sbom2_3_8_18_new import Python_3_8_18_IntermedSymbols
import textwrap
import dis
import types
import re
import hashlib
class Py_Arenas(interfaces.plugins.PluginInterface):
    """
    Identifies Python objects in a process memory dump for Python 3.8
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
    

    def get_arena_addresses(self, task):
      """
      Automatically locate the arenas pointer and maxarenas count
      by resolving ELF symbols from the Python binary/library in memory.
    
      Replaces the old hardcoded approach:
        ARENAS_ADDR = 0x93cc08    # ← no longer needed
        MAXARENAS_ADDR = 0x93cbf0  # ← no longer needed
    
      Resolution strategy:
        1. Find libpython*.so or statically-linked python binary in VMAs
        2. Parse ELF section headers for .symtab (static symbols)
        3. Fall back to .dynsym (dynamic symbols)
        4. Fall back to LTO-renamed variants (e.g. arenas.lto_priv)
      """
      try:
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        
        # --- Resolve symbol addresses automatically ---
        # Try libpython first (shared library build, e.g. pyenv Python 3.11)
        # Then fall back to the main python binary (statically linked, e.g. system Python 3.8)
        symbols_needed = [
            "arenas",
            "maxarenas",
            "usable_arenas",
            "narenas_currently_allocated",
            "narenas_highwater",
        ]
        
        resolved = elf_parsing.find_symbol_in_process(
            self.context, proc_layer_name, task,
            module_substring="libpython",
            symbol_names=symbols_needed,
        )
        
        # If libpython wasn't found, try the main binary
        if not resolved or "arenas" not in resolved:
            resolved_fallback = elf_parsing.find_symbol_in_process(
                self.context, proc_layer_name, task,
                module_substring="python",
                symbol_names=symbols_needed,
            )
            # Merge, preferring any results we already had
            for k, v in resolved_fallback.items():
                if k not in resolved:
                    resolved[k] = v
        
        # --- Check that we found the critical symbols ---
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
        
        # Log any bonus symbols we found (useful for future use)
        for name in ["usable_arenas", "narenas_currently_allocated", "narenas_highwater"]:
            if name in resolved:
                print(f"Resolved {name} at: 0x{resolved[name]:x}")
        
        # --- Read the actual values from the resolved addresses ---
        arenas_ptr_bytes = curr_layer.read(ARENAS_ADDR, 8)
        arenas_ptr = int.from_bytes(arenas_ptr_bytes, byteorder='little', signed=False)
        print(f"Arenas pointer value: 0x{arenas_ptr:x}")
        
        if MAXARENAS_ADDR:
            maxarenas_bytes = curr_layer.read(MAXARENAS_ADDR, 4)
            maxarenas_count = int.from_bytes(maxarenas_bytes, byteorder='little', signed=False)
        else:
            # Fallback: estimate maxarenas by walking arena_object array
            # until we hit an invalid entry (crude but works)
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
            
        #  alternative calculation: arena + 256KB
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
            # Read what's actually at arena address
            arena_data = curr_layer.read(arena_address, 48)
          #  print(f"Data at arena address: {arena_data.hex()}")
        else:
            print(f"Arena address is INVALID for pool data")

        # Check first few pools with CORRECT pool header layout
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
               # print(f"  Raw header: {pool_bytes.hex()}")
                ref_count = int.from_bytes(pool_bytes[0:4], byteorder='little')  # First 4 bytes of union
                freeblock = int.from_bytes(pool_bytes[8:16], byteorder='little')
                nextpool = int.from_bytes(pool_bytes[16:24], byteorder='little')
                prevpool = int.from_bytes(pool_bytes[24:32], byteorder='little')
                arenaindex = int.from_bytes(pool_bytes[32:36], byteorder='little')
                szidx = int.from_bytes(pool_bytes[36:40], byteorder='little')      # CORRECT OFFSET!
                nextoffset = int.from_bytes(pool_bytes[40:44], byteorder='little')
                maxnextoffset = int.from_bytes(pool_bytes[44:48], byteorder='little')
                '''
                print(f"  Ref count: {ref_count}")
                print(f"  Free block: 0x{freeblock:x}")
                print(f"  Next pool: 0x{nextpool:x}")
                print(f"  Prev pool: 0x{prevpool:x}")
                print(f"  Arena index: {arenaindex}")
                print(f"  Size index: {szidx}")
                print(f"  Next offset: {nextoffset}")
                print(f"  Max next offset: {maxnextoffset}")
                '''
                # Validate size class
                if szidx > 0 and szidx <= 64:  # Valid size class range
                    #    print(f"  Valid size class {szidx}")
                    
                    # Calculate block size for this size class
                    size_classes = [8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
                                  144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 
                                  480, 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1152, 1280, 1408, 
                                  1536, 1664, 1792, 1920, 2048, 2304, 2560, 2816, 3072, 3328, 3584, 
                                  3840, 4096, 4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192]
                    
                    if szidx <= len(size_classes):
                        block_size = size_classes[szidx - 1]
                      #  print(f"  Block size: {block_size} bytes")
                       # print(f"  Max blocks per pool: {(4096-48)//block_size}")
                elif szidx == 0:
                    print(f"  → Free pool (size index 0)")
                else:
                    print(f"Invalid size class {szidx}")
                #print("===============================================")   
            else:
                print(f"Invalid memory address")
                
      except Exception as e:
        print(f"Pool debug error: {e}")

   
    def is_valid_pyobject_header(self, refcnt, type_ptr, curr_layer):
      """Improved PyObject header validation"""
      # Allow reference count of 1 (very common for new objects)
      if refcnt < 1 or refcnt > 1000000:  # More reasonable upper bound
        return False
        
      # Type pointer should be in valid memory and reasonable range
      if type_ptr < 0x1000 or not curr_layer.is_valid(type_ptr, 8):
        return False
    
      # Additional validation: try to read the type object
      try:
        type_data = curr_layer.read(type_ptr, 16)
        type_refcnt = int.from_bytes(type_data[0:8], 'little')
        type_type_ptr = int.from_bytes(type_data[8:16], 'little')
        
        # Type objects should have reasonable reference counts
        if type_refcnt < 1 or type_refcnt > 10000000:
            return False
            
        # Type of type should be valid (often points to type or metatype)
        if type_type_ptr < 0x1000:
            return False
            
        return True
      except Exception:
        return False
   
    def get_python_object_info(self, obj_candidate, block_size, block_idx):
      """Extract detailed information from a Python object"""
      try:
        # Get basic object info
        obj_type = obj_candidate.get_type_name()
        refcnt = int(obj_candidate.ob_refcnt)
        address = obj_candidate.vol.offset
        
        # Try to get object value (with safety limits)
        try:
            obj_value = obj_candidate.get_value(cur_depth=0, max_depth=1)
            
            # Truncate long values
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
            'obj':obj_candidate,
            'refcnt': refcnt,
            'value': value_str,
            'block_size': block_size,
            'size_estimate': self.estimate_object_size(obj_candidate, obj_type)
        }
        
      except Exception as e:
        return None
    
    
    def estimate_object_size(self, obj_candidate, obj_type):
      """Estimate the actual size of the Python object"""
      try:
        if hasattr(obj_candidate, 'ob_size'):
            # Variable-size objects (str, list, tuple, etc.)
            ob_size = int(obj_candidate.ob_size)
            return f"var({ob_size})"
        else:
            # Fixed-size objects
            return "fixed"
      except:
        return "unknown"
    
    
    def print_object_summary(self, obj_info, block_idx):
      """Print a summary of an extracted object"""
    #  print(f"      Block {block_idx}: {obj_info['type']} "
    #      f"(ref={obj_info['refcnt']}) = {obj_info['value'][:50]}{'...' if len(obj_info['value']) > 50 else ''}")

      # Special handling for module objects
     
      #print(f"obj_info['type']: {obj_info['type']}")
      if obj_info['type'] == 'module':
        print("MODULE DETECTED! Analyzing...")
        try:
            obj = obj_info['obj']  # Get the stored object
            module_obj = obj.cast_to("PyModuleObject")  
            module_name = module_obj.get_name()
            print(f"        Module name: {module_name}")
            
            # Try to get module dictionary
            try:
                module_dict = module_obj.get_dict2()
                if isinstance(module_dict, dict):
                    print(f"        Module attributes: {len(module_dict)}")
                    
                    # Show key attributes
                    for attr in ['__name__', '__file__', '__package__']:
                        if attr in module_dict:
                            attr_value = str(module_dict[attr])[:50]
                            print(f"        {attr}: {attr_value}")
                else:
                    print(f"        Module dict: {type(module_dict)}")
            except Exception as e:
                print(f"        Error reading module dict: {e}")
                
        except Exception as e:
            print(f"        Error analyzing module: {e}")
      
      elif  obj_info['type'] == 'NoneType':
          obj = obj_info['obj']
          print("None DETECTED! Analyzing...")
          mod_dict=obj.get_value()
          print(f"obj.value(): {mod_dict}")
          if not mod_dict:
              print(f"error with None")
          vtype = self.get_value_type(mod_dict)
          if vtype !="str":
             print(f"None dict {mod_dict.get_dict2()}")
    
    
    
    def summarize_object_types(self, objects):
      """Print a summary of object types found"""
      if not objects:
        return
        
      # Count object types
      type_counts = {}
      for obj in objects:
        obj_type = obj['type']
        type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
    
     # print(f"Object type summary:")
      #for obj_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
      #  print(f"      • {obj_type}: {count}")
    
    
    def extract_pool_objects(self, task, pool_obj, pool_info, python_table_name):
      objects = []
      valid_objects = 0
      blocks_scanned = 0
      try:
        
        proc_layer_name = task.add_process_layer()
        curr_layer = self.context.layers[proc_layer_name]
        block_size = pool_info['block_size']
        if not isinstance(block_size, int) or block_size <= 0:
            return []
        pool_data_start = pool_obj.vol.offset + 48
        allocated_blocks = pool_info['allocated_blocks']
        nextoffset = pool_info['nextoffset']
        #print(f"    Pool: 0x{pool_obj.vol.offset:x}, Block size: {block_size}")
        #print(f"    Allocated blocks: {allocated_blocks}, Next offset: {nextoffset}")
        allocated_region_size = nextoffset - 48  # Subtract header size
        max_allocated_blocks = allocated_region_size // block_size
        for block_idx in range(min(max_allocated_blocks, allocated_blocks)):
            blocks_scanned += 1
            block_offset = pool_data_start + (block_idx * block_size)
            if not curr_layer.is_valid(block_offset, block_size):
                 continue
            if block_offset >= (pool_obj.vol.offset + nextoffset):
                break
            try:
                # Read potential PyObject header
                header_data = curr_layer.read(block_offset, 16)
                
                if len(header_data) >= 16:
                    refcnt = int.from_bytes(header_data[0:8], byteorder='little')
                    type_ptr = int.from_bytes(header_data[8:16], byteorder='little')
                    
                    # More permissive validation - even refcnt=0 might be valid in some cases
                    if self.is_valid_pyobject_header(refcnt, type_ptr, curr_layer):
                        
                        try:
                            obj_candidate = self.context.object(
                                object_type=python_table_name + constants.BANG + "PyObject",
                                layer_name=proc_layer_name,
                                offset=block_offset
                            )
                            
                            obj_info = self.get_python_object_info(obj_candidate, block_size, block_idx)
                            
                            if obj_info:
                                objects.append(obj_info)
                                valid_objects += 1
                                self.print_object_summary(obj_info, block_idx)
                                # Show first few objects for debugging
                                #if valid_objects <= 5:
                                   # self.print_object_summary(obj_info, block_idx)
                            
                           
                            
                        except Exception as e:
                            # Failed to interpret as PyObject
                            pass
                            
            except Exception as e:
                # Failed to read block
                pass
        
       # print(f"Extraction complete: {valid_objects}/{blocks_scanned} valid objects found")
        if objects:  # Only summarize if we have objects
            self.summarize_object_types(objects)
        
        return objects
        
      except Exception as e:
        print(f"Pool extraction error: {e}")
        return []


    
    def comprehensive_memory_analysis(self, task, python_table_name):
      arenas_ptr, maxarenas_count = self.get_arena_addresses(task)
    
      if not arenas_ptr or not maxarenas_count:
        print("Failed to retrieve arena information")
        return
    
      print(f"\n=== DEBUGGING ARENA STRUCTURE READING ===")
    
      for arena_idx in range(maxarenas_count):  
        arena_offset = arenas_ptr + (arena_idx * 48)
        
        print(f"\nArena {arena_idx} Debug:")
        print(f"  Calculated offset: 0x{arena_offset:x}")
        
        try:
            # Read raw arena bytes first
            proc_layer_name = task.add_process_layer()
            curr_layer = self.context.layers[proc_layer_name]
            raw_arena_bytes = curr_layer.read(arena_offset, 48)
            
            #print(f"  Raw arena bytes: {raw_arena_bytes[:32].hex()}...")
            
            # Parse key fields manually
            arena_addr = int.from_bytes(raw_arena_bytes[0:8], byteorder='little')
            pool_addr = int.from_bytes(raw_arena_bytes[8:16], byteorder='little')
            nfreepools = int.from_bytes(raw_arena_bytes[16:20], byteorder='little')
            ntotalpools = int.from_bytes(raw_arena_bytes[20:24], byteorder='little')
            freepools_ptr = int.from_bytes(raw_arena_bytes[24:32], byteorder='little')
            
           #print(f"  Manual parsing:")
            print(f"    Arena address: 0x{arena_addr:x}")
            print(f"    Pool address: 0x{pool_addr:x}")
            print(f"    Free pools: {nfreepools}")
            print(f"    Total pools: {ntotalpools}")
            print(f"    Free pools ptr: 0x{freepools_ptr:x}")
            
            # Verify addresses make sense
            if arena_addr != 0:
                addr_diff = abs(arena_addr - pool_addr)
                expected_diff = 256 * 1024  # 256KB
                print(f"    Address difference: 0x{addr_diff:x} (expected ~0x{expected_diff:x})")
                
                if addr_diff > expected_diff * 2:
                    print(f"    WARNING: Address difference too large!")
                
                # Check if addresses are in valid memory ranges
                if not curr_layer.is_valid(arena_addr, 8):
                    print(f"    ERROR: Arena address 0x{arena_addr:x} is invalid!")
                if not curr_layer.is_valid(pool_addr, 8):
                    print(f"    ERROR: Pool address 0x{pool_addr:x} is invalid!")
            
            # Now try using your arena_object structure
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
                     objects = self.extract_pool_objects(task, pool_obj, pool_info, python_table_name)
                  else:
                     print(f"\n  Pool {pool_idx}: INACTIVE/FREE")
            
                except Exception as e:
                    print(f"\n  Pool {pool_idx}: Error - {e}")
            print("*"*100)
        except Exception as e:
            print(f"  Error reading arena {arena_idx}: {e}")

    
   
   
   
    def _collect_data(self, tasks):
        collected_data=[]
        python_table_name = Python_3_8_18_IntermedSymbols.create(
            self.context, self.config_path, sub_path="generic/types/python", filename="python-3_8-x64_2"
        )

        task = list(tasks)[0]
        if not task or not task.mm:
            return []
        task_layer = task.add_process_layer()
        curr_layer = self.context.layers[task_layer]
        self.process_layer = curr_layer.name 
        self.comprehensive_memory_analysis(task, python_table_name)
      
        return collected_data

   
    
    
    
    
    def parse_dist_info(self,entries):
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


   
    

    @staticmethod
    def sanitize_value(value):
        if isinstance(value, str):
            return value.replace('\n', '\\n')
        return value

    def _generator(self, data):
        for item in data:
            pid, generation, obj_type, obj_address, obj_value = item
            obj_value = self.sanitize_value(obj_value)

            # Wrap long lines
            wrapped_value = textwrap.wrap(str(obj_value), width=80)

            # Yield the first line
            yield (0, (
                pid,
                generation,
                f"{obj_type:<20}",
                f"{obj_address:<20}",
                wrapped_value[0] if wrapped_value else ""
            ))

            # Yield continuation lines if any
            for line in wrapped_value[1:]:
                yield (1, (
                    pid,  # Keep the same PID for continuation lines
                    generation,
                    "",
                    "",
                    line
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



