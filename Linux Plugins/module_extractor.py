from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
import re



# Application-level Python module extractor.
#
# Given a root PID, finds all descendant processes, identifies which
# ones are Python, runs py_interpreter + py_gc + py_heap on each, and
# produces a unified deduplicated module list for the whole application.
#
# Two-level deduplication:
#   1) Per-process: merge by ADDRESS (same address = same object in memory)
#   2) Cross-process: merge by NAME (forked workers share modules via COW
#      but at different virtual addresses)

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



class Module_Extractor(interfaces.plugins.PluginInterface):
    """Extract Python modules from an application and all its child processes."""
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
                description="Root PID of the application",
                element_type=int,
                optional=False,
            ),
            requirements.BooleanRequirement(
                name="skip_interp",
                description="Skip interpreter (sys.modules) extraction",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="skip_gc",
                description="Skip GC linked list walking",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="skip_heap",
                description="Skip heap scanning (slowest)",
                default=False,
                optional=True,
            ),
        ]
    # ------------------------------------------------------------------
    # Process tree discovery
    # ------------------------------------------------------------------
    def _build_children_map(self, all_tasks):
        """Build pid -> {child_pids} map from the full task list."""
        tasks_by_pid = {}
        children = {}

        for task in all_tasks:
            pid = task.pid
            tasks_by_pid[pid] = task

            if task.is_thread_group_leader:
                ppid = task.get_parent_pid()
            else:
                ppid = task.tgid

            children.setdefault(ppid, set()).add(pid)

        return tasks_by_pid, children

    def _collect_descendants(self, root_pid, tasks_by_pid, children_map):
        """BFS from root_pid, returns all descendant tasks including root."""
        result = []
        queue = [root_pid]
        visited = set()

        while queue:
            pid = queue.pop(0)
            if pid in visited:
                continue
            visited.add(pid)

            task = tasks_by_pid.get(pid)
            if task:
                result.append(task)

            for child_pid in sorted(children_map.get(pid, set())):
                if child_pid not in visited:
                    queue.append(child_pid)

        return result

    # ------------------------------------------------------------------
    # Python detection
    # ------------------------------------------------------------------
    def _detect_python_version(self, task):
        """
        Check VMA paths for libpythonX.Y.so or /usr/bin/pythonX.Y.
        Returns (major, minor) or None if the process isn't Python.
        """
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
    # Symbol table loading (cached per version)
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        """Load ISF symbol table for the given CPython version. Cached."""
        key = version[:2]
        if key in self._symbol_table_cache:
            return self._symbol_table_cache[key]

        entry = SYMBOL_TABLE_REGISTRY.get(key)
        if not entry:
            print(f"No symbol table for Python {key[0]}.{key[1]}")
            return None

        import_path, class_name, sub_path, filename = entry
        module = __import__(import_path, fromlist=[class_name])
        symbol_class = getattr(module, class_name)

        table_name = symbol_class.create(
            self.context, self.config_path,
            sub_path=sub_path,
            filename=filename,
        )
        self._symbol_table_cache[key] = table_name
        return table_name

    # ------------------------------------------------------------------
    # Per-process: run all 3 scanners, merge by ADDRESS, print results
    # ------------------------------------------------------------------
    def _extract_modules_for_process(self, task, python_table_name):
        """
        Run py_interpreter, py_gc, py_heap on one process and merge
        results by address. Within one process, same address = same object.

        Returns dict: {addr: [addr, name, sources_set, mod_obj]}
        """
        from volatility3.plugins.linux.py_gc import Py_GC
        from volatility3.plugins.linux.py_heap import Py_Heap
        from volatility3.plugins.linux.py_interpreter import Py_Interpreter

        pid = task.pid
        comm = utility.array_to_string(task.comm)

        # addr -> (addr, name, set_of_sources, mod_obj)
        merged = {}

        def _merge_results(modules, source_tag):
            """Merge a list of (addr, name, mod_obj) into the combined dict."""
            count_new = 0
            for addr, name, mod_obj in modules:
                if addr in merged:
                    # same object, just record that another source also found it
                    merged[addr][2].add(source_tag)
                else:
                    merged[addr] = [addr, name, {source_tag}, mod_obj]
                    count_new += 1
            return count_new

        # --- 1. Interpreter (sys.modules - fastest, most authoritative) ---
        interp_count = 0
        if not self.config.get("skip_interp", False):
          try:
            interp_plugin = Py_Interpreter(self.context, self.config_path)
            interp_modules = interp_plugin.get_modules(task, python_table_name)
            interp_count = _merge_results(interp_modules, 'interp')
            print(f"    interpreter: {len(interp_modules)} found, {interp_count} new")
          except Exception as e:
            print(f"    interpreter error: {e}")

        # --- 2. GC walker (catches GC-tracked objects not in sys.modules) ---
        gc_count = 0
        if not self.config.get("skip_gc", False):
          try:
            gc_plugin = Py_GC(self.context, self.config_path)
            gc_modules = gc_plugin.get_modules(task, python_table_name)
            gc_count = _merge_results(gc_modules, 'gc')
            print(f"    gc: {len(gc_modules)} found, {gc_count} new")
          except Exception as e:
            print(f"    gc error: {e}")

        # --- 3. Heap scanner (brute force, catches untracked/unlinked objects) ---
        
        heap_count = 0
        if not self.config.get("skip_heap", False):
            try:
                heap_plugin = Py_Heap(self.context, self.config_path)
                heap_modules = heap_plugin.get_modules(task, python_table_name)
                heap_count = _merge_results(heap_modules, 'heap')
                print(f"    heap: {len(heap_modules)} found, {heap_count} new")
            except Exception as e:
                print(f"    heap error: {e}")

        
        print(f"\n  --- PID {pid} ({comm}) combined ---")
        print(f"  unique addresses: {len(merged)}")
        for addr in sorted(merged.keys()):
            _, name, sources, _ = merged[addr]
            src_str = '+'.join(sorted(sources))
            print(f"    0x{addr:x}  {name:40s}  [{src_str}]")

        return merged

    # ------------------------------------------------------------------
    # Main collection logic
    # ------------------------------------------------------------------
    def _collect_all(self):
        self._symbol_table_cache = {}

        # Build parent->children map from all tasks
        all_tasks = list(pslist.PsList.list_tasks(
            self.context,
            self.config["kernel"],
            filter_func=lambda _: False,
        ))
        tasks_by_pid, children_map = self._build_children_map(all_tasks)

        root_pids = self.config.get("pid", [])
        if not root_pids:
            print("ERROR: --pid is required")
            return []

        # Walk the process tree from each root PID
        target_tasks = []
        for root_pid in root_pids:
            if root_pid not in tasks_by_pid:
                print(f"WARNING: PID {root_pid} not found in task list")
                continue
            descendants = self._collect_descendants(root_pid, tasks_by_pid, children_map)
            target_tasks.extend(descendants)

        # Dedup (a PID could appear under multiple roots)
        seen_pids = set()
        unique_tasks = []
        for t in target_tasks:
            if t.pid not in seen_pids:
                seen_pids.add(t.pid)
                unique_tasks.append(t)

        # Show the tree we discovered
        print(f"\n{'='*60}")
        print(f"PROCESS TREE ({len(unique_tasks)} processes)")
        print(f"{'='*60}")
        for t in unique_tasks:
            comm = utility.array_to_string(t.comm)
            ppid = t.get_parent_pid()
            print(f"  PID {t.pid:6d}  PPID {ppid:6d}  {comm}")

        # ---- Phase 1: per-process extraction ----
        # Run all 3 scanners on each Python process, merge by address
        per_process = {}  # pid -> (comm, {addr: [addr, name, sources, mod_obj]})
        python_count = 0

        for task in unique_tasks:
            if not task.mm:
                continue

            version = self._detect_python_version(task)
            if not version:
                comm = utility.array_to_string(task.comm)
                print(f"\n  PID {task.pid} ({comm}): not Python, skipping")
                continue

            python_count += 1
            comm = utility.array_to_string(task.comm)
            print(f"\n{'='*60}")
            print(f"PID {task.pid} ({comm}) - Python {version[0]}.{version[1]}")
            print(f"{'='*60}")

            table_name = self._load_symbol_table(version)
            if not table_name:
                continue

            process_modules = self._extract_modules_for_process(task, table_name)
            per_process[task.pid] = (comm, process_modules)

        # --- Phase 2: cross-process merge by name ---
        # Forked workers have the same modules at different virtual addresses
        # (COW pages), so we dedup by module name across all processes.
        global_modules = {}  # name -> (addr, name, sources_str, pid, comm, mod_obj)

        for pid, (comm, addr_map) in per_process.items():
            for addr, (_, name, sources, mod_obj) in addr_map.items():
                if name not in global_modules:
                    src_str = '+'.join(sorted(sources))
                    global_modules[name] = (addr, name, src_str, pid, comm, mod_obj)

        # Print cross-process summary
        print(f"\n{'='*60}")
        print(f"CROSS-PROCESS MERGE")
        print(f"{'='*60}")
        for pid, (comm, addr_map) in per_process.items():
            print(f"  PID {pid:6d} ({comm}): {len(addr_map)} modules")

        print(f"\n{'='*60}")
        print(f"FINAL DEDUPLICATED MODULES ({len(global_modules)} unique)")
        print(f"{'='*60}")
        for name in sorted(global_modules.keys()):
            addr, _, src_str, pid, comm, _ = global_modules[name]
            print(f"  {name:40s}  [{src_str:12s}]  PID {pid} ({comm})")

        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        print(f"  Total processes in tree:  {len(unique_tasks)}")
        print(f"  Python processes scanned: {python_count}")
        print(f"  Unique modules (final):   {len(global_modules)}")

        return list(global_modules.values())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_all_modules(self):
        """Returns deduplicated (addr, name, sources, pid, comm, mod_obj) list."""
        return self._collect_all()

    # ------------------------------------------------------------------
    # Volatility renderer
    # ------------------------------------------------------------------
    def _generator(self, data):
        for addr, name, sources, pid, comm, mod_obj in data:
            yield (0, (
                pid,
                comm,
                sources,
                f"0x{addr:x}",
                str(name),
            ))

    def run(self):
        collected = self._collect_all()

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Source", str),
                ("Address", str),
                ("Module", str),
            ],
            self._generator(collected),
        )
