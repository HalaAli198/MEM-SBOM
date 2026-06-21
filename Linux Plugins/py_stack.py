from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
import re


# Runtime call-stack walker for Python processes (CPython 3.6 - 3.14).
#
# Walks every thread's frame chain and attributes each frame to the module whose
# code is running in it, by reading f_globals['__name__'] (a frame's globals IS
# the defining module's __dict__).
#
# This is NOT a coverage scanner. py_interpreter / py_gc / py_heap answer "what
# module objects exist in memory"; this answers "which modules' code was actually
# executing at acquisition time" - a runtime-execution evidence signal the static
# scanners can't produce. It surfaces only the modules with a live frame, so it
# OVERLAYS the others (a +stack source tag in the SBOM) rather than competing on
# coverage.
#
# get_modules() returns (address, name, PyModuleObject) tuples - same shape as the
# other three plugins - so Module_Extractor merges it with zero new logic. The
# PyModuleObject is the real object resolved from sys.modules (not the frame's
# globals dict), so downstream consumers (dependency_generator) keep working.
#
# ----------------------------------------------------------------------------
# Frame model by version (the 3.11 reimplementation is the reason for dispatch):
#
#   3.6-3.10  classic   tstate.frame -> PyFrameObject, walk f_back.
#                       Heap-allocated PyObject frames. code in f_code.
#
#   3.11-3.12 cframe    tstate.cframe -> _PyCFrame.current_frame ->
#                       _PyInterpreterFrame, walk .previous. Lightweight structs
#                       on a per-thread datastack (NOT PyObjects). code in f_code,
#                       globals in f_globals (or via f_func -> func_globals).
#
#   3.13-3.14 current   cframe removed; tstate.current_frame -> _PyInterpreterFrame
#                       directly, walk .previous. f_code renamed f_executable;
#                       func ptr is f_funcobj.
#
# Interpreter-head resolution (3.6 disasm / 3.7-3.12 offsets / 3.13+ debug
# offsets) is delegated to Py_Interpreter, the canonical implementation here, to
# avoid drift.
#
# ISF dependency: for 3.11+ the symbol table must define the _PyInterpreterFrame
# struct (and _PyCFrame for 3.11/3.12) plus the PyThreadState.cframe /
# current_frame fields. If a field/struct is missing the walk degrades to empty
# for that version and prints one actionable diagnostic rather than guessing
# offsets.
# ----------------------------------------------------------------------------


# Which traversal strategy each version uses.
FRAME_MODEL = {
    (3, 6): 'classic',  (3, 7): 'classic',  (3, 8): 'classic',
    (3, 9): 'classic',  (3, 10): 'classic',
    (3, 11): 'cframe',  (3, 12): 'cframe',
    (3, 13): 'current', (3, 14): 'current',
}

# Defensive cap on chain length (cyclic/garbage protection).
MAX_FRAMES = 10000


class Py_Stack(interfaces.plugins.PluginInterface):
    """Walk Python thread call stacks and attribute frames to modules (3.6-3.14)."""
    _version = (1, 2, 0)
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
            requirements.BooleanRequirement(
                name="dump",
                description="Dump per-thread call chains to text files",
                default=False,
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------
    def detect_python_version(self, task):
        """Extract Python major.minor from libpythonX.Y.so or /usr/bin/pythonX.Y."""
        try:
            for vma in task.mm.get_vma_iter():
                fname = vma.get_name(self.context, task)
                if not fname:
                    continue
                if 'libpython' in fname:
                    m = re.search(r'libpython(\d+)\.(\d+)', fname)
                    if m:
                        return (int(m.group(1)), int(m.group(2)))
                elif '/python' in fname:
                    m = re.search(r'python(\d+)\.(\d+)', fname)
                    if m:
                        return (int(m.group(1)), int(m.group(2)))
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Object construction helper (works for PyObjects AND raw structs)
    # ------------------------------------------------------------------
    def _obj(self, type_name, addr):
        return self.context.object(
            object_type=self._py_table + constants.BANG + type_name,
            layer_name=self.process_layer,
            offset=addr,
        )

    def _note_missing(self, msg):
        """Print an ISF-gap diagnostic once per unique message."""
        if not hasattr(self, '_notes'):
            self._notes = set()
        if msg not in self._notes:
            self._notes.add(msg)
            print(f"  py_stack ISF note: {msg}")

    def _read_ptr_field(self, struct_obj, field_name):
        """Read a pointer field, handling union types by raw 8-byte read."""
        try:
            val = getattr(struct_obj, field_name)
            try:
                return int(val)
            except TypeError:
                off = struct_obj.vol.members[field_name][0]
                raw = self.context.layers[self.process_layer].read(
                    struct_obj.vol.offset + off, 8)
                return int.from_bytes(raw, 'little')
        except (AttributeError, KeyError):
            return 0
    
    @staticmethod
    def _as_str(val):
        """A get_dict2 value is a PyObject wrapper; materialise it to a str."""
        if val is None:
            return None
        if isinstance(val, str):
            return val
        try:
            if hasattr(val, 'get_value'):
                v = val.get_value()
                return v if isinstance(v, str) else (str(v) if v is not None else None)
        except Exception:
            pass
        return None

    @staticmethod
    def _type_name(value):
        if value is None:
            return None
        try:
            return value.ob_type.dereference().get_name().split('.')[-1]
        except Exception:
            return None

    # ------------------------------------------------------------------
    # sys.modules -> {name: PyModuleObject}
    # ------------------------------------------------------------------
    def _build_module_map(self, interp):
        name_to_mod = {}
        try:
            try:
                modules_addr = int(interp.modules)
            except AttributeError:
                modules_addr = int(interp.imports.modules)   # 3.12+
            if not modules_addr:
                return name_to_mod
            modules_dict = self._obj("PyDictObject", modules_addr).get_dict2(
                cur_depth=0, max_depth=100
            )
            for mod_name, mod_val in modules_dict.items():
                if self._type_name(mod_val) != "module":
                    continue
                try:
                    name_to_mod[str(mod_name)] = mod_val.cast_to("PyModuleObject")
                except Exception:
                    continue
        except Exception as e:
            print(f"  Could not read sys.modules: {e}")
        print(f"  sys.modules map: {len(name_to_mod)} module objects resolved")
        return name_to_mod

    # ------------------------------------------------------------------
    # Read (__name__, __file__) from a globals dict address
    # ------------------------------------------------------------------
    def _name_file_from_globals(self, g_addr):
        if not g_addr:
            return None, None
        try:
            g = self._obj("PyDictObject", g_addr).get_dict2(cur_depth=0, max_depth=2)
        except Exception:
            return None, None
        if not isinstance(g, dict):
            return None, None
        return self._as_str(g.get('__name__')), self._as_str(g.get('__file__'))

    # ------------------------------------------------------------------
    # CLASSIC frame model (3.6 - 3.10): PyFrameObject linked by f_back
    # ------------------------------------------------------------------
    def _classic_code_info(self, frame):
        funcname, filename, firstline = "<unknown>", "<unknown>", 0
        try:
            code_addr = int(frame.f_code)
            if not code_addr:
                return funcname, filename, firstline
            code_obj = self._obj("PyCodeObject", code_addr)
            try:
                funcname = code_obj.co_name.dereference().get_value() or funcname
            except Exception:
                pass
            try:
                filename = code_obj.co_filename.dereference().get_value() or filename
            except Exception:
                pass
            try:
                firstline = int(code_obj.co_firstlineno)
            except Exception:
                pass
        except Exception:
            pass
        return funcname, filename, firstline

    def _walk_classic(self, frame_addr, module_map):
        frames, seen = [], set()
        current = self._obj("PyFrameObject", frame_addr)
        guard = 0
        while current and int(current.vol.offset) != 0 and guard < MAX_FRAMES:
            guard += 1
            off = int(current.vol.offset)
            if off in seen:
                break
            seen.add(off)

            funcname, filename, firstline = self._classic_code_info(current)
            try:
                g_addr = int(current.f_globals)
            except Exception:
                g_addr = 0
            mod_name, mod_file = self._name_file_from_globals(g_addr)
            # NOTE: on 3.10, f_lineno is only accurate when tracing is active;
            # in a memory snapshot it may hold a stale value. We report whatever
            # is stored and fall back to firstlineno in the renderer.
            try:
                lineno = int(current.f_lineno)
            except Exception:
                lineno = 0

            frames.append(self._frame_record(
                off, mod_name, mod_file, module_map,
                funcname, filename, lineno, firstline))

            try:
                back = int(current.f_back)
            except Exception:
                break
            if not back:
                break
            current = self._obj("PyFrameObject", back)
        return frames

    # ------------------------------------------------------------------
    # INTERNAL frame model (3.11 - 3.14): _PyInterpreterFrame on datastack
    # ------------------------------------------------------------------
    def _interp_globals_addr(self, frame):
        """Globals dict address: direct f_globals, else via the function object."""
        try:
            a = self._read_ptr_field(frame, 'f_globals')
            if a:
                return a
        except Exception:
            pass
        # fallback: f_funcobj (3.12+) / f_func (3.11) -> PyFunctionObject.func_globals
        for fld in ('f_funcobj', 'f_func'):
            try:
                fa = self._read_ptr_field(frame, fld)
                if not fa:
                    continue
                func = self._obj("PyFunctionObject", fa)
                ga = int(func.func_globals)
                if ga:
                    return ga
            except Exception:
                continue
        return 0

    def _interp_code_info(self, frame, code_field):
        funcname, filename, firstline = "<unknown>", "<unknown>", 0
        addr = 0
        for fld in (code_field, 'f_executable', 'f_code'):
            try:
                addr = self._read_ptr_field(frame, fld)
                if addr:
                    break
            except Exception:
                addr = 0
        if not addr:
            for fld in ('f_funcobj', 'f_func'):
                try:
                    fa = self._read_ptr_field(frame, fld)
                    if not fa:
                        continue
                    func = self._obj("PyFunctionObject", fa)
                    addr = int(func.func_code)
                    if addr:
                        break
                except Exception:
                    continue
        if not addr:
            return funcname, filename, firstline
        try:
            code_obj = self._obj("PyCodeObject", addr)
            try:
                funcname = code_obj.co_name.dereference().get_value() or funcname
            except Exception:
                pass
            try:
                filename = code_obj.co_filename.dereference().get_value() or filename
            except Exception:
                pass
            try:
                firstline = int(code_obj.co_firstlineno)
            except Exception:
                pass
        except Exception:
            pass
        return funcname, filename, firstline

    def _walk_internal(self, top_addr, module_map, code_field):
   
        frames, seen = [], set()
        cur = top_addr
        guard = 0
        while cur and guard < MAX_FRAMES:
            guard += 1
            if cur in seen:
                break
            seen.add(cur)

            frame = self._obj("_PyInterpreterFrame", cur)
            funcname, filename, firstline = self._interp_code_info(frame, code_field)
            g_addr = self._interp_globals_addr(frame)
            mod_name, mod_file = self._name_file_from_globals(g_addr)

            # The C entry/sentinel frame has neither Python globals nor a code
            # object - that's our signal to stop the walk cleanly.
            if funcname == "<unknown>" and filename == "<unknown>":
                break

            frames.append(self._frame_record(
                cur, mod_name, mod_file, module_map,
                funcname, filename, 0, firstline))

            try:
                prev = int(frame.previous)
            except Exception as e:
                self._note_missing(f"_PyInterpreterFrame.previous unreadable: {e}")
                break
            if not prev:
                break
            cur = prev
        return frames

    # ------------------------------------------------------------------
    # Shared frame-record builder
    # ------------------------------------------------------------------
    def _frame_record(self, frame_addr, mod_name, mod_file, module_map,
                      funcname, filename, lineno, firstline):
        return {
            "frame_addr": frame_addr,
            "module": mod_name,
            "module_file": mod_file,
            "module_obj": module_map.get(mod_name) if mod_name else None,
            "funcname": funcname,
            "filename": filename,
            "lineno": lineno,
            "firstlineno": firstline,
        }

    # ------------------------------------------------------------------
    # Top-frame retrieval per model
    # ------------------------------------------------------------------
    def _top_frame(self, tstate, model):
        """Return (addr, kind) where kind is 'classic' or 'internal'."""
        if model == 'classic':
            try:
                return int(tstate.frame), 'classic'
            except Exception as e:
                self._note_missing(f"PyThreadState.frame unreadable: {e}")
                return 0, None

        if model == 'cframe':                       # 3.11 / 3.12
            try:
                ca = int(tstate.cframe)
                if not ca:
                    return 0, None
                cf = self._obj("_PyCFrame", ca)
                return int(cf.current_frame), 'internal'
            except Exception as e:
                self._note_missing(
                    f"PyThreadState.cframe / _PyCFrame.current_frame unreadable "
                    f"(add _PyCFrame to the ISF?): {e}")
                return 0, None

        if model == 'current':                      # 3.13 / 3.14
            try:
                return int(tstate.current_frame), 'internal'
            except Exception as e:
                self._note_missing(f"PyThreadState.current_frame unreadable: {e}")
                return 0, None

        return 0, None

    # ------------------------------------------------------------------
    # Interpreter + thread traversal
    # ------------------------------------------------------------------
    def _walk_threads(self, interp_head_addr):
        """
        Walk interpreters -> thread states -> frame chains.

        Returns:
          thread_records: [(interp_idx, thread_idx, thread_id, [frame dicts])]
          module_objs:    {addr: (addr, name, PyModuleObject)}  for get_modules()
        """
        thread_records = []
        module_objs = {}

        model = FRAME_MODEL.get(self._version_key)
        if model is None:
            print(f"py_stack: no frame model for Python "
                  f"{self._version_key[0]}.{self._version_key[1]}")
            return thread_records, module_objs

        code_field = 'f_executable' if self._version_key >= (3, 13) else 'f_code'

        interp = self._obj("PyInterpreterState", interp_head_addr)
        interp_idx = 0

        while interp and int(interp.vol.offset) != 0:
            module_map = self._build_module_map(interp)

            # 3.6-3.11: interp->tstate_head
            # 3.12+:    interp->threads.head  (struct reorganisation)
            tstate_addr = 0
            try:
                tstate_addr = int(interp.tstate_head)
            except (AttributeError, exceptions.InvalidAddressException):
                pass
            if not tstate_addr:
                try:
                    tstate_addr = int(interp.threads.head)
                except (AttributeError, exceptions.InvalidAddressException):
                    pass
            if not tstate_addr:
                self._note_missing(
                    "PyInterpreterState.tstate_head / threads.head both unreadable "
                    "(ISF may be missing the field)")
            print(f"  interp[{interp_idx}] tstate_head -> 0x{tstate_addr:x}")

            thread_idx = 0
            while tstate_addr:
                tstate = self._obj("PyThreadState", tstate_addr)
                try:
                    thread_id = int(tstate.thread_id)
                except Exception:
                    thread_id = 0

                top, kind = self._top_frame(tstate, model)
                print(f"    thread[{thread_idx}] id=0x{thread_id:x}  "
                      f"top_frame={'0x{:x}'.format(top) if top else 'None'}  "
                      f"kind={kind}")
                if top:
                    if kind == 'classic':
                        frames = self._walk_classic(top, module_map)
                    else:
                        frames = self._walk_internal(top, module_map, code_field)

                    mods_in_thread = sorted({
                        f["module"] for f in frames if f["module"]})
                    print(f"    thread[{thread_idx}] {len(frames)} frames  "
                          f"modules={mods_in_thread or '(none)'}")
                    for depth, f in enumerate(frames):
                        print(f"      [{depth}] {f['funcname']:30s}  "
                              f"mod={f['module'] or '?':20s}  "
                              f"file={f['filename']}:{f['lineno'] or f['firstlineno']}")

                    if frames:
                        thread_records.append(
                            (interp_idx, thread_idx, thread_id, frames))
                        for f in frames:
                            mod_obj = f["module_obj"]
                            if mod_obj is None:
                                continue
                            addr = int(mod_obj.vol.offset)
                            if addr not in module_objs:
                                module_objs[addr] = (addr, f["module"], mod_obj)

                try:
                    tstate_addr = int(tstate.next)
                except Exception:
                    tstate_addr = 0
                thread_idx += 1

            try:
                next_addr = int(interp.next)
            except Exception:
                next_addr = 0
            if not next_addr:
                break
            interp = self._obj("PyInterpreterState", next_addr)
            interp_idx += 1

        print(f"py_stack: walk complete — {len(thread_records)} threads with frames, "
              f"{len(module_objs)} unique modules on stack")
        return thread_records, module_objs

    # ------------------------------------------------------------------
    # Setup: process layer + interpreter head (head resolution delegated)
    # ------------------------------------------------------------------
    def _prepare(self, task, python_table_name):
        """Resolve process layer + interpreter head. Returns head addr or None."""
        from volatility3.plugins.linux.py_interpreter import Py_Interpreter

        task_layer = task.add_process_layer()
        self.process_layer = self.context.layers[task_layer].name
        self._py_table = python_table_name

        version = self.detect_python_version(task)
        if not version:
            print("py_stack: could not detect Python version")
            return None
        self._version_key = version[:2]
        model = FRAME_MODEL.get(self._version_key)
        print(f"py_stack: detected Python {version[0]}.{version[1]}  "
              f"frame_model={model or 'UNSUPPORTED'}")

        if self._version_key not in FRAME_MODEL:
            print(f"py_stack: Python {version[0]}.{version[1]} not supported")
            return None

        # Delegate _PyRuntime / interpreter-head resolution to the canonical
        # implementation so 3.6 (disasm), 3.7-3.12 (offsets) and 3.13+ (debug
        # offsets) all work without duplicating that logic here.
        pi = Py_Interpreter(self.context, self.config_path)
        pi.process_layer = self.process_layer

        if self._version_key == (3, 6):
            head = pi._resolve_interp_head_36(task, self.process_layer)
        else:
            py_runtime = pi.find_py_runtime_address(task)
            if not py_runtime:
                print("py_stack: could not resolve _PyRuntime")
                return None
            head = pi.get_interpreters_head_offset(version, py_runtime)

        print(f"py_stack: interpreter head -> "
              f"{'0x{:x}'.format(head) if head else 'None'}")
        return head or None

    # ------------------------------------------------------------------
    # Public API — called by Module_Extractor (runtime-execution overlay)
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        Return (address, name, PyModuleObject) tuples for every module with a
        live frame on any thread's stack. Same shape as py_interpreter / py_gc /
        py_heap so Module_Extractor merges it as a 'stack' source.
        """
        head = self._prepare(task, python_table_name)
        if not head:
            return []
        _records, module_objs = self._walk_threads(head)
        modules = list(module_objs.values())
        print(f"py_stack: {len(modules)} modules seen executing on the stack")
        return modules

    def get_call_stacks(self, task, python_table_name):
        """Rich per-thread frame data for the standalone / forensic view."""
        head = self._prepare(task, python_table_name)
        if not head:
            return []
        records, _module_objs = self._walk_threads(head)
        return records

    # ------------------------------------------------------------------
    # Optional dump of per-thread call chains
    # ------------------------------------------------------------------
    def _dump_chains(self, pid, records):
        for interp_idx, thread_idx, thread_id, frames in records:
            fname = f"pystack_{pid}_interp{interp_idx}_thread{thread_idx}.txt"
            try:
                with open(fname, 'w') as fh:
                    fh.write(f"PID {pid}  interpreter {interp_idx}  "
                             f"thread {thread_idx}  (thread_id 0x{thread_id:x})\n")
                    fh.write("=" * 60 + "\n\n")
                    for depth, f in enumerate(reversed(frames)):  # oldest -> newest
                        short = f["filename"].split('/')[-1] if '/' in f["filename"] else f["filename"]
                        mod = f["module"] or "?"
                        line = f["lineno"] or f["firstlineno"]
                        fh.write(f"#{depth}  {f['funcname']}  [{mod}]  {short}:{line}\n")
                print(f"  wrote {fname}")
            except Exception as e:
                print(f"  error writing {fname}: {e}")

    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        from volatility3.plugins.linux.py_interpreter import SYMBOL_TABLE_REGISTRY
        key = version[:2]
        entry = SYMBOL_TABLE_REGISTRY.get(key)
        if not entry:
            print(f"No symbol table registered for Python {key[0]}.{key[1]}")
            return None
        import_path, class_name, sub_path, filename = entry
        module = __import__(import_path, fromlist=[class_name])
        symbol_class = getattr(module, class_name)
        table_name = symbol_class.create(
            self.context, self.config_path, sub_path=sub_path, filename=filename,
        )
        print(f"Loaded symbol table: {class_name} -> {table_name}")
        return table_name

    def _collect_data(self, tasks):
        task = list(tasks)[0]
        if not task or not task.mm:
            return []

        version = self.detect_python_version(task)
        if not version:
            print("Could not detect Python version")
            return []
        print(f"Detected Python {version[0]}.{version[1]}")

        table_name = self._load_symbol_table(version)
        if not table_name:
            return []

        records = self.get_call_stacks(task, table_name)

        if self.config.get("dump", False):
            self._dump_chains(int(task.pid), records)

        executing = sorted({
            f["module"] for _, _, _, frames in records
            for f in frames if f["module"]
        })
        print(f"\nModules executing on the stack ({len(executing)}): "
              f"{', '.join(executing) or '(none)'}")

        rows = []
        for interp_idx, thread_idx, thread_id, frames in records:
            for depth, f in enumerate(reversed(frames)):   # oldest -> newest
                short = f["filename"].split('/')[-1] if '/' in f["filename"] else f["filename"]
                rows.append((
                    int(task.pid),
                    thread_idx,
                    depth,
                    f["module"] or "<unknown>",
                    f["funcname"],
                    short,
                    f["lineno"] or f["firstlineno"],
                ))
        return rows

    def _generator(self, rows):
        for pid, thread_idx, depth, module, func, fileshort, lineno in rows:
            yield (0, (
                pid,
                f"{thread_idx}",
                f"{depth}",
                str(module),
                str(func),
                str(fileshort),
                int(lineno),
            ))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=filter_func,
        )
        rows = self._collect_data(tasks)

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Thread", str),
                ("Frame", str),
                ("Module", str),
                ("Function", str),
                ("File", str),
                ("Line", int),
            ],
            self._generator(rows),
        )
