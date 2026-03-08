from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux import elf_parsing
import re



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
# 3.13+: offset is read from _Py_DebugOffsets at runtime (see below)
DEBUG_OFFSETS_INTERP_HEAD_POS = 0x28

# Maps (major, minor) -> ISF symbol table loader parameters
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

class Py_Interpreter(interfaces.plugins.PluginInterface):
    """
    Extract loaded modules from the CPython interpreter state.

    Resolves _PyRuntime via ELF symbol lookup, walks the PyInterpreterState
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
      Extract Python major.minor from libpythonX.Y.so or /usr/bin/pythonX.Y
      in the process VMA list. Returns (major, minor) or None.
      """
      try:
        for vma in task.mm.get_vma_iter():
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
    #  _PyRuntime resolution
    # ------------------------------------------------------------------
    def find_py_runtime_address(self, task):
      """
      Resolve the _PyRuntime symbol from the process ELF image.
      Uses elf_parsing which searches both libpython and the python
      binary (handles both dynamic and static builds).
      """
      try:
        proc_layer_name = task.add_process_layer()
      except exceptions.InvalidAddressException:
        return None

     
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
            print(f"  interpreters.head offset from debug_offsets: 0x{offset:x}")
        else:
            offset = PYRUNTIME_INTERP_HEAD_OFFSETS.get(key, 0x20)
            print(f"  interpreters.head offset from table: 0x{offset:x}")

       
        head_ptr_addr = py_runtime_addr + offset
        head_bytes = self.context.layers[self.process_layer].read(head_ptr_addr, 8)
        head_addr = int.from_bytes(head_bytes, 'little')

        if head_addr:
            print(f"Interpreter head at 0x{head_addr:x}")
        else:
            print("ERROR: interpreters.head is NULL")

        return head_addr

    
    def _resolve_interp_head_36(self, task, task_layer):
      """
      Python 3.6 has no _PyRuntime. Instead, resolve the interpreter head
      by disassembling PyInterpreterState_Head(), which is just:
          endbr64
          mov rax, [rip + disp32]
          ret
      We read the RIP-relative displacement to find the global pointer.
      """
      resolved = elf_parsing.find_symbol_in_process(
        self.context, task_layer, task,
        module_substring="libpython",
        symbol_names=["PyInterpreterState_Head"],
      )
      func_addr = resolved.get("PyInterpreterState_Head")
      if not func_addr:
        print("Could not resolve PyInterpreterState_Head")
        return None

      layer = self.context.layers[self.process_layer]
      # Skip endbr64 (4 bytes), read mov rax,[rip+disp32] (7 bytes)
      code = layer.read(func_addr + 4, 7)
      if code[:3] != b'\x48\x8b\x05':
        print(f"Unexpected instruction at PyInterpreterState_Head+4: {code[:3].hex()}")
        return None

      disp = int.from_bytes(code[3:7], 'little', signed=True)
      # RIP at the next instruction = func_addr + 4 + 7 = func_addr + 11
      interp_head_addr = func_addr + 11 + disp
      head_bytes = layer.read(interp_head_addr, 8)
      interpreter_addr = int.from_bytes(head_bytes, 'little')
      print(f"Python 3.6: PyInterpreterState_Head -> interp_head at 0x{interp_head_addr:x} -> 0x{interpreter_addr:x}")
      return interpreter_addr
    
    # ------------------------------------------------------------------
    # Interpreter walking 
    # ------------------------------------------------------------------
    def parse_interpreters(self, interpreter_head_addr, python_table_name):
        """
        Walk the PyInterpreterState linked list starting from interpreters.head.
        For each interpreter, extract module objects from interpreter.modules
        (the sys.modules dict).

        Returns list of (address, name, PyModuleObject) tuples.
        """
        modules = []

        # Dereference the interpreters.head pointer
        if not interpreter_head_addr:
            print("No interpreters found or invalid pointer!")
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
                # interpreter.modules is the sys.modules dict
                # 3.12+ moved it into the imports sub-struct
                try:
                    modules_addr = current.modules
                except AttributeError:
                    modules_addr = current.imports.modules
               
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
                        mod_dict=mod_obj.get_dict2()
                        #print(mod_dict.keys())
                        addr = mod_obj.vol.offset
                        if addr not in seen_addrs:
                            seen_addrs.add(addr)
                            modules.append((addr, str(mod_name), mod_obj))

               
            except Exception as e:
                print(f"  Error processing interpreter {interpreter_count}: {e}")

            
            # Follow the linked list
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
    # Public API  — called by Module_Extractor
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
            print("Could not detect Python version")
            return []

        key = version[:2]
        
        # Python 3.6: no _PyRuntime, resolve interp_head directly
        if key == (3, 6):
           interpreter_addr = self._resolve_interp_head_36(task, task_layer)
           if not interpreter_addr:
              return []
           return self.parse_interpreters(interpreter_addr, python_table_name)

        
        # Python 3.7+: go through _PyRuntime
        py_runtime = self.find_py_runtime_address(task)
        if not py_runtime:
            print("Could not find _PyRuntime - no interpreter modules available")
            return []

        interpreter_addr = self.get_interpreters_head_offset(version, py_runtime)
        if not interpreter_addr:
            print("Could not resolve interpreter head")
            return []
        print(f"_PyRuntime=0x{py_runtime:x}, interpreter_head=0x{interpreter_addr:x}")

        return self.parse_interpreters(interpreter_addr, python_table_name)
  
    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        
        """Load ISF symbol table for the detected CPython version."""
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
        """Standalone mode: detect version, load symbols, extract modules."""
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
        """Read a null-terminated C string from the process memory layer."""
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
        """Get the type name string for a PyObject by reading ob_type->tp_name."""
        if value is None:
            return 'NoneType'
        if hasattr(value, 'ob_type'):
            try:
                
                ob_type = value.ob_type.dereference()
                tp_name_ptr = ob_type.tp_name
                type_name = self.read_cstring(tp_name_ptr)
                return type_name.split('.')[-1]  # Get the base type name
            except Exception as e:
                print(f"Error getting type name of PyObject: {str(e)}")
                return None
        else:
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



