from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
import re
import dis
import hashlib
import json
from typing import Dict, Set, List, Tuple, Optional


class Dependency_Generator:
    """
    Generate a dependency graph from Python process memory.

    Analyzes application and third-party modules extracted by MEM_SBOM /
    Module_Extractor + Module_Classifier, then inspects each module's dict
    components and function bytecode to discover which other modules they
    depend on.

    Sources of dependency evidence:
      1. Direct module references in module/class dicts
      2. IMPORT_NAME / IMPORT_FROM bytecode opcodes in functions
      3. Module of called functions resolved via func_module_obj
      4. Module of called functions resolved via chained LOAD_GLOBAL →
         LOAD_ATTR into module dicts
      5. Module references in func_globals (even without CALL)
      6. All of the above applied recursively to inner functions
         (unlimited nesting depth)
    """

    def __init__(self, python_version: Tuple[int, int] = (3, 8)):
        self._analyzed_addrs: Set[int] = set()
        self._python_version = python_version

    # ------------------------------------------------------------------
    # Low-level helper
    # ------------------------------------------------------------------
    @staticmethod
    def _get_type_name(value) -> Optional[str]:
        """Get type name using PyObject's own ob_type pointer."""
        if value is None:
            return 'NoneType'
        try:
            return value.ob_type.dereference().get_name()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Bytecode → instruction list + inner code objects
    # ------------------------------------------------------------------
    def _process_code(self, code_obj):
        """
        Disassemble a code object into a flat list of "OPNAME arg" strings
        and recurse into nested code objects (inner functions).

        Returns (instructions: List[str], inner_codes: Dict[str, Tuple])
            where each inner entry is (instructions, inner_codes, code_obj).
        """
         
        from volatility3.plugins.linux.bytecode_decoder import decode_code_object
        return decode_code_object(code_obj, self._python_version)

    
    def _resolve_pyobject(self, obj):
        if hasattr(obj, 'ob_type') and hasattr(obj, 'get_value'):
            try:
                name = obj.ob_type.dereference().get_name()
                ptype = obj.get_type(name)
                if ptype == "PyTupleObject":
                    items = obj.get_value()
                    if isinstance(items, (list, tuple)):
                        return tuple(self._resolve_pyobject(i) for i in items)
                return obj.get_value()
            except Exception:
                return str(obj)
        return obj

    # ------------------------------------------------------------------
    # Extract IMPORT_NAME / IMPORT_FROM from bytecode
    # ------------------------------------------------------------------
    def _extract_imports_from_bytecode(self, instructions: List[str]) -> Set[str]:
        """
        Walk the instruction list and collect every IMPORT_NAME target.
        Also pairs IMPORT_FROM with the preceding IMPORT_NAME to produce
        fully-qualified names.
        """
        imports: Set[str] = set()
        last_import_name: Optional[str] = None

        for raw in instructions:
            parts = raw.split(' ', 1)
            opcode = parts[0]
            arg    = parts[1].strip() if len(parts) > 1 else ''

            if opcode == "IMPORT_NAME" and arg and not arg.startswith('<'):
                last_import_name = arg
                imports.add(arg)
            elif opcode == "IMPORT_FROM" and arg and not arg.startswith('<'):
                if last_import_name:
                    imports.add(f"{last_import_name}.{arg}")
                else:
                    imports.add(arg)
            else:
                if opcode not in ("IMPORT_STAR",):
                    last_import_name = None

        return imports

    # ------------------------------------------------------------------
    # Extract function-call targets with deep resolution
    # ------------------------------------------------------------------
    def _extract_call_modules(self, instructions: List[str],
                              func_globals_dict: dict, parent_name: str = "") -> Set[str]:
        """
        Walk bytecode to find CALL sites preceded by LOAD_GLOBAL →
        LOAD_ATTR / LOAD_METHOD chains.

        For each call site:
          - If the base resolves to a module, record the module name AND
            try to resolve the called attribute inside the module dict to
            get the actual function's func_module (handles re-exports).
          - If the base resolves to a function, extract its func_module.
          - For chained access (a.b.c()), resolve intermediate modules.
        """
        modules: Set[str] = set()
        load_stack: List[str] = []

        for raw in instructions:
            parts = raw.split(' ', 1)
            opcode = parts[0]
            arg    = parts[1].strip() if len(parts) > 1 else ''

            if opcode in ("LOAD_GLOBAL", "LOAD_NAME"):
                load_stack = [arg] if arg and not arg.isdigit() else []

            elif opcode in ("LOAD_ATTR", "LOAD_METHOD"):
                if load_stack and arg and not arg.isdigit():
                    load_stack.append(arg)

            elif opcode in ("CALL_FUNCTION", "CALL_METHOD", "CALL",
                            "CALL_FUNCTION_KW", "CALL_FUNCTION_EX"):
                if load_stack and func_globals_dict:
                    base = load_stack[0]
                    if base == '__import__' and len(load_stack) == 1:
                       # Look back for the LOAD_CONST that has the module name
                       idx = instructions.index(raw) if raw in instructions else -1
                       if idx > 0:
                          prev = instructions[idx - 1]
                          prev_parts = prev.split(' ', 1)
                          if prev_parts[0] == "LOAD_CONST" and len(prev_parts) > 1:
                             mod_name = prev_parts[1].strip().strip("'\"")
                             if mod_name and not mod_name.startswith('<'):
                                top = mod_name.split('.')[0]
                                if top != parent_name:
                                   modules.add(top)
        
                    elif base in func_globals_dict:
                        base_obj  = func_globals_dict[base]
                        base_type = self._get_type_name(base_obj)

                        if base_type == "module":
                            # Record the module itself
                            if base != parent_name:
                               modules.add(base)

                            # Deep resolve: look up the called attribute
                            # inside the module dict to find the actual
                            # function's owning module (handles re-exports)
                            if len(load_stack) >= 2:
                                modules |= self._resolve_chained_call(
                                    base_obj, load_stack[1:])

                        elif base_type in ("function", "generator",
                                           "coroutine", "async_generator"):
                            # Single function call: get its func_module
                            mod_name = self._get_func_module_name(base_obj)
                            if mod_name:
                                modules.add(mod_name.split('.')[0])

                        elif base_type == "type":
                            # Class instantiation: check __module__
                            try:
                                type_obj = base_obj.cast_to("PyTypeObject")
                                dict_ptr = type_obj.tp_dict
                                if dict_ptr and int(dict_ptr) != 0:
                                    dict_obj = dict_ptr.dereference()
                                    if self._get_type_name(dict_obj) == "dict":
                                        cls_dict = dict_obj.cast_to("PyDictObject").get_dict2()
                                        if '__module__' in cls_dict:
                                            mod_name = cls_dict['__module__'].get_value()
                                            if mod_name:
                                                modules.add(mod_name.split('.')[0])
                            except Exception:
                                pass

                load_stack = []

            elif opcode in ("STORE_FAST", "STORE_GLOBAL", "STORE_NAME",
                            "POP_TOP"):
                load_stack = []

        return modules

    def _resolve_chained_call(self, module_obj, attr_chain: List[str]) -> Set[str]:
        """
        Given a module object and an attribute chain like ['sub', 'func'],
        resolve step by step. At each step, if we land on a module, record
        it. If we land on a function, extract its func_module.

        This handles cases like:
          os.path.join()     → discovers 'posixpath' via func_module
          urllib3.util.retry → discovers intermediate modules
        """
        modules: Set[str] = set()
        current = module_obj

        for i, attr in enumerate(attr_chain):
            try:
                current_type = self._get_type_name(current)

                if current_type == "module":
                    mod = current.cast_to("PyModuleObject")
                    mod_dict = mod.get_dict2()

                    if attr not in mod_dict:
                        break

                    current = mod_dict[attr]
                    next_type = self._get_type_name(current)

                    if next_type == "module":
                        try:
                            sub_mod = current.cast_to("PyModuleObject")
                            sub_name = sub_mod.get_name()
                            if sub_name:
                                modules.add(sub_name.split('.')[0])
                        except Exception:
                            pass

                    elif next_type in ("function", "generator",
                                       "coroutine", "async_generator"):
                        mod_name = self._get_func_module_name(current)
                        if mod_name:
                            modules.add(mod_name.split('.')[0])
                        break  # function is the terminal call target

                    elif next_type == "type":
                        # Class — if this is the last in the chain it's
                        # an instantiation; check __module__
                        if i == len(attr_chain) - 1:
                            try:
                                type_obj = current.cast_to("PyTypeObject")
                                dict_ptr = type_obj.tp_dict
                                if dict_ptr and int(dict_ptr) != 0:
                                    dict_obj = dict_ptr.dereference()
                                    if self._get_type_name(dict_obj) == "dict":
                                        cls_dict = dict_obj.cast_to("PyDictObject").get_dict2()
                                        if '__module__' in cls_dict:
                                            mn = cls_dict['__module__'].get_value()
                                            if mn:
                                                modules.add(mn.split('.')[0])
                            except Exception:
                                pass
                        break
                    else:
                        break  # can't resolve further
                else:
                    break
            except Exception:
                break

        return modules

    def _get_func_module_name(self, obj) -> Optional[str]:
        """Extract func_module_obj.get_value() from a function-like object."""
        try:
            func_obj = obj.cast_to("PyFunctionObject")
            func_module = func_obj.func_module_obj
            if func_module:
                return func_module.get_value()
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Analyse a single callable (function / method / classmethod / …)
    # ------------------------------------------------------------------
    def _analyse_callable(self, func_obj, known_modules: Set[str],parent_name: str = "") -> Set[str]:
        """
        Given a PyFunctionObject, disassemble its code + inner functions
        and return the set of module-level dependencies discovered from
        both IMPORT opcodes, CALL chains, and func_module resolution.
        """
        # Dedup by address to avoid re-analyzing the same function
        try:
            addr = int(func_obj.vol.offset)
            if addr in self._analyzed_addrs:
                return set()
            self._analyzed_addrs.add(addr)
        except Exception:
            pass

        deps: Set[str] = set()
        try:
            # Get function metadata
            func_globals_obj  = func_obj.func_globals_obj
            func_globals      = func_globals_obj.cast_to("PyDictObject")
            func_globals_dict = func_globals.get_dict2()

            # Record the function's own module
            func_module_name = self._get_func_module_name(func_obj)
            # (We don't add func_module_name to deps because that's
            #  typically the module we're currently analyzing.)

            # Disassemble
            code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
            instructions, inner_codes = self._process_code(code_obj)

            # 1) IMPORT_NAME / IMPORT_FROM
            deps |= self._extract_imports_from_bytecode(instructions)

            # 2) CALL chains with deep module resolution
            deps |= self._extract_call_modules(instructions, func_globals_dict, parent_name)

            # 3) Any name in func_globals that is a module and appears in
            #    LOAD_GLOBAL instructions → the function accesses it
            for raw in instructions:
                parts = raw.split(' ', 1)
                if parts[0] == "LOAD_GLOBAL" and len(parts) > 1:
                    name = parts[1].strip()
                    if name in func_globals_dict:
                        obj_type = self._get_type_name(func_globals_dict[name])
                        if obj_type == "module":
                           if name != parent_name: 
                              deps.add(name)

            # 4) Scan ALL module-type entries in func_globals
            #    (catches imports that the function has access to even
            #     if not directly referenced in *this* function's bytecode)
            for gname, gval in func_globals_dict.items():
                if gname.startswith('__'):
                    continue
                gtype = self._get_type_name(gval)
                if gtype == "module" and gname != parent_name:
                    deps.add(gname)

            # 5) Recurse into inner functions (unlimited depth)
            deps |= self._collect_inner_deps(inner_codes, func_globals_dict, parent_name)

        except Exception as e:
            print(f"    _analyse_callable error: {e}")

        return deps

    def _collect_inner_deps(self, inner_codes: dict,
                            func_globals_dict: dict, parent_name: str = "") -> Set[str]:
        """
        Recursively collect dependencies from inner function code objects.
        Handles arbitrary nesting depth.
        """
        deps: Set[str] = set()

        for _key, (inner_instrs, inner_nested, _code_obj) in inner_codes.items():
            # Imports from this inner function
            deps |= self._extract_imports_from_bytecode(inner_instrs)
            # Call targets from this inner function
            deps |= self._extract_call_modules(inner_instrs, func_globals_dict, parent_name)
            # LOAD_GLOBAL → module in globals
            for raw in inner_instrs:
                parts = raw.split(' ', 1)
                if parts[0] == "LOAD_GLOBAL" and len(parts) > 1:
                    name = parts[1].strip()
                    if name in func_globals_dict:
                        obj_type = self._get_type_name(func_globals_dict[name])
                        if obj_type == "module" and name != parent_name:
                            deps.add(name)

            # Recurse deeper
            if inner_nested:
                deps |= self._collect_inner_deps(inner_nested, func_globals_dict, parent_name)

        return deps

    # ------------------------------------------------------------------
    # Unwrap descriptor → PyFunctionObject
    # ------------------------------------------------------------------
    def _unwrap_to_func(self, v, vtype: str):
        """
        Given a dict value and its type string, try to return the
        underlying PyFunctionObject (or None).
        For properties, returns the first non-null accessor.
        """
        try:
            if vtype in ("function", "generator", "coroutine", "async_generator"):
                return v.cast_to("PyFunctionObject")

            elif vtype == "method":
                im_obj = v.cast_to("PyMethodObject")
                im_func = im_obj.im_func.dereference()
                if self._get_type_name(im_func) == "function":
                    return im_func.cast_to("PyFunctionObject")

            elif vtype == "classmethod":
                cm = v.cast_to("classmethod")
                c = cm.cm_callable.dereference()
                if self._get_type_name(c) == "function":
                    return c.cast_to("PyFunctionObject")

            elif vtype == "staticmethod":
                sm = v.cast_to("staticmethod")
                c = sm.sm_callable.dereference()
                if self._get_type_name(c) == "function":
                    return c.cast_to("PyFunctionObject")

            elif vtype == "property":
                # Return first accessor; caller handles all accessors
                prop = v.cast_to("PyPropertyObject")
                for accessor in ('fget', 'fset', 'fdel'):
                    ptr = getattr(prop, accessor, None)
                    if ptr and int(ptr) != 0:
                        obj = ptr.dereference()
                        if self._get_type_name(obj) == "function":
                            return obj.cast_to("PyFunctionObject")
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Get ALL function objects from a property (all accessors)
    # ------------------------------------------------------------------
    def _get_all_property_funcs(self, v) -> List:
        """Return list of PyFunctionObjects from all property accessors."""
        funcs = []
        try:
            prop = v.cast_to("PyPropertyObject")
            for accessor in ('fget', 'fset', 'fdel'):
                ptr = getattr(prop, accessor, None)
                if ptr and int(ptr) != 0:
                    obj = ptr.dereference()
                    if self._get_type_name(obj) == "function":
                        funcs.append(obj.cast_to("PyFunctionObject"))
        except Exception:
            pass
        return funcs

    # ------------------------------------------------------------------
    # Analyse one module dict (top-level or class dict)
    # ------------------------------------------------------------------
    _SKIP_KEYS = frozenset([
        '__name__', '__doc__', '__path__', '__file__', '__cached__',
        '__builtins__', '__package__', '__loader__', '__spec__',
        '__getattr__', '__all__',
        'version', '__version__', 'VERSION', '__VERSION__',
        '_version', 'version_short', 'version_info',
        '__version_info__', 'VERSION_INFO', '__VERSION_INFO__',
    ])

    def _analyse_dict(self, mod_dict: dict, known_modules: Set[str], parent_name: str = "",
                      depth: int = 0, max_depth: int = 2) -> Set[str]:
        """
        Walk a module / class dict and collect dependency module names.

        Sources of evidence:
        1. Dict values that ARE modules (direct reference).
        2. Function bytecode (imports + call targets + func_module).
        3. Class tp_dict → recurse.
        """
        deps: Set[str] = set()
        if depth >= max_depth:
            return deps

        for k, v in mod_dict.items():
            if k in self._SKIP_KEYS:
                continue

            vtype = self._get_type_name(v)
            if vtype is None:
                continue

            # --- 1) Direct module reference in dict -----------------------
            if vtype == "module":
                try:
                    mod_o = v.cast_to("PyModuleObject")
                    dep_name = mod_o.get_name()
                    if dep_name:
                        top_level = dep_name.split('.')[0]
                        if top_level != parent_name:
                           deps.add(top_level)
                except Exception:
                    pass
                continue  # don't recurse into foreign modules here

            # --- 2) Callable types ----------------------------------------
            if vtype == "property":
                # Analyze ALL property accessors, not just the first one
                for func_obj in self._get_all_property_funcs(v):
                    deps |= self._analyse_callable(func_obj, known_modules, parent_name)
                continue

            func_obj = self._unwrap_to_func(v, vtype)
            if func_obj is not None:
                deps |= self._analyse_callable(func_obj, known_modules, parent_name)
                continue

            # --- 3) Class types → recurse into tp_dict --------------------
            if vtype in ("type", "ABCMeta", "EnumMeta", "StructMeta") or \
               (isinstance(vtype, str) and vtype.endswith("Meta")):
                try:
                    type_obj = v.cast_to("PyTypeObject")
                    dict_ptr = type_obj.tp_dict
                    if dict_ptr and int(dict_ptr) != 0:
                        dict_obj = dict_ptr.dereference()
                        if self._get_type_name(dict_obj) == "dict":
                            class_dict = dict_obj.cast_to("PyDictObject").get_dict2()
                            deps |= self._analyse_dict(class_dict, known_modules,  parent_name,depth + 1, max_depth)
                except Exception:
                    pass

        return deps

    # ------------------------------------------------------------------
    # Normalise a raw dependency name to its top-level parent
    # ------------------------------------------------------------------
    @staticmethod
    def _normalise(name: str) -> str:
        """'urllib3.util.retry' → 'urllib3'"""
        return name.split('.')[0] if name else name

    # ------------------------------------------------------------------
    # Public entry: build full graph
    # ------------------------------------------------------------------
    def build_dependency_graph(
        self,
        classified: dict,       # from Module_Classifier
        grouped: dict,          # parent → [(addr, name, src, pid, comm, obj), …]
    ) -> Dict[str, List[str]]:
        """
        For every *application* and *third-party* parent module, analyse
        its dict (and children dicts) and return:

            { parent_name: sorted([dep1, dep2, …]), … }

        where each dep is the top-level parent of a discovered import /
        call target.
        """
        # Set of ALL known top-level module names (for filtering)
        all_known: Set[str] = set()
        #for cat in classified.values():
            #all_known |= set(cat.keys())
        for cat in ('application', 'third-party'):
            all_known |= set(classified.get(cat, {}).keys())
       
        graph: Dict[str, List[str]] = {}
        
        for category in ('application', 'third-party'):
            #for category in classified:
            for parent, entries in classified.get(category, {}).items():
                # Reset per-module dedup so different modules can
                # discover the same function independently
                self._analyzed_addrs.clear()

                print(f"\n  Analysing [{category}] {parent} "
                      f"({len(entries)} sub-module(s)) …")

                raw_deps: Set[str] = set()

                for entry in entries:
                    _addr, name, _src, _pid, _comm, mod_obj = entry
                    try:
                        module_obj = mod_obj.cast_to("PyModuleObject")
                        mod_dict   = module_obj.get_dict2()
                    except Exception as e:
                        print(f"    Could not read dict of {name}: {e}")
                        continue

                    entry_deps = self._analyse_dict(mod_dict, all_known, parent_name=parent)
                    raw_deps |= entry_deps

                    print(f"    {name}: {len(entry_deps)} raw deps")

                # Normalise to top-level parents and remove self-references
                normalised = {
                    self._normalise(d) for d in raw_deps
                } - {parent}

                # Keep only deps that are themselves known modules
                normalised = {d for d in normalised if d in all_known}

                graph[parent] = sorted(normalised)

                print(f"    → {len(normalised)} dependencies: "
                      f"{', '.join(sorted(normalised)) or '(none)'}")

        return graph
