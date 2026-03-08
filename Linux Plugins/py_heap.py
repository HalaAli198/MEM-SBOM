from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux.proc import Maps
from volatility3.plugins.linux import elf_parsing
import struct
import re


# Brute-force heap scanner for Python objects.
# Walks r/w memory regions looking for valid PyObject headers.
# Slower than GC walking but catches objects not tracked by GC.
#
# Returns (address, name, PyModuleObject) tuples so the main plugin
# can merge results from all discovery methods.

# Symbol table registry - maps (major, minor) to ISF loader parameters.
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

# Sane upper bounds to avoid chasing garbage pointers.
# refcount > 1M is almost certainly not a real object.
MAX_REASONABLE_REFCOUNT = 1_000_000

# md_dict.ma_used sanity bound - even huge apps rarely exceed this
MAX_DICT_USED = 100_000

# Cap per-region scan to avoid spending forever on giant anon mappings.
# Head + tail scan for anything larger.
MAX_REGION_SCAN_BYTES = 100 * 1024 * 1024  # 100 MB

# Alignment - CPython allocates all PyObjects on 8-byte boundaries
PTR_SIZE = 8


class Py_Heap(interfaces.plugins.PluginInterface):
    """Scan heap/anon regions for Python objects (3.6-3.14)."""
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
        """Extract Python major.minor from libpythonX.Y.so or binary path."""
        try:
            for vma in task.mm.get_mmap_iter():
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
    # Symbol table loading
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        """Load ISF symbol table for the detected CPython version."""
        key = version[:2]
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
        print(f"Loaded symbol table: {class_name} -> {table_name}")
        return table_name

    # ------------------------------------------------------------------
    # Memory region enumeration
    # ------------------------------------------------------------------
    def _get_scannable_regions(self, task):
        """Collect r/w VMAs: heap, anon, libpython, python binary."""
        regions = []
        for vma in Maps.list_vmas(task):
            flags = vma.get_protection()
            if 'r' not in flags or 'w' not in flags:
                continue

            path = vma.get_name(self.context, task) or ''

            # heap, anon, libpython, python binary - all fair game
            is_interesting = (
                path == '[heap]'
                or path == 'Anonymous Mapping'
                or not path
                or '.so' in path
                or 'python' in path.lower()
            )
            if not is_interesting:
                continue

            start = vma.vm_start
            end = vma.vm_end
            regions.append({
                'start': start,
                'end': end,
                'size': end - start,
                'flags': flags,
                'path': path or 'Anonymous',
            })

        return regions

    # ------------------------------------------------------------------
    # PyObject header validation
    # ------------------------------------------------------------------
    def _is_valid_header(self, refcnt, type_ptr, layer):
        """Quick sanity check: positive refcount + readable type pointer."""
        if refcnt < 1 or refcnt > MAX_REASONABLE_REFCOUNT:
            return False
        # type pointer must be in mapped, readable memory
        if type_ptr < 0x1000:
            return False
        return layer.is_valid(type_ptr, PTR_SIZE)

    def _extract_type_name(self, type_ptr, layer):
        """Read tp_name from PyTypeObject. Returns short name or None."""
        try:
            if not layer.is_valid(type_ptr, 64):
                return None

            pytype = self.context.object(
                object_type=self._py_table + constants.BANG + "PyTypeObject",
                layer_name=layer.name,
                offset=type_ptr,
            )
            name = pytype.get_name()
            if name and isinstance(name, str) and len(name) < 100 and name.isprintable():
                # strip module prefix: 'builtins.int' -> 'int'
                return name.split('.')[-1]
        except (exceptions.InvalidAddressException,
                exceptions.PagedInvalidAddressException):
            pass
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Module-specific validation
    # ------------------------------------------------------------------
    def _validate_module(self, addr, layer):
        """Check md_dict is a readable PyDictObject with sane ma_used."""
        try:
            mod = self.context.object(
                object_type=self._py_table + constants.BANG + "PyModuleObject",
                layer_name=layer.name,
                offset=addr,
            )
            md_dict_ptr = int(mod.md_dict)
            if md_dict_ptr < 0x1000 or not layer.is_valid(md_dict_ptr, 24):
                return False

            d = self.context.object(
                object_type=self._py_table + constants.BANG + "PyDictObject",
                layer_name=layer.name,
                offset=md_dict_ptr,
            )
            used = int(d.ma_used)
            return 0 <= used <= MAX_DICT_USED
        except Exception:
            return False

    def _extract_module_info(self, addr, layer):
        """Build module metadata from a validated PyModuleObject."""
        info = {
            'address': addr,
            'name': 'Unknown',
            'file': 'Unknown',
            'version': 'Unknown',
            'package': 'Unknown',
        }
        try:
            mod = self.context.object(
                object_type=self._py_table + constants.BANG + "PyObject",
                layer_name=layer.name,
                offset=addr,
            ).cast_to("PyModuleObject")

            try:
                n = mod.get_name()
                if n:
                    info['name'] = str(n)
            except Exception:
                pass

            # dig into md_dict for __file__, __version__, __package__
            try:
                d = mod.get_dict2(cur_depth=0, max_depth=8)
                if isinstance(d, dict):
                    for key in ('__name__', '__file__', '__version__', '__package__'):
                        val = d.get(key)
                        try:
                            if val is not None and hasattr(val, 'get_value'):
                                val = val.get_value()
                            if val is not None:
                                info[key.strip('_')] = str(val)
                        except Exception:
                            continue
            except Exception:
                pass

        except Exception as e:
            print(f"  Error extracting module at 0x{addr:x}: {e}")

        return info

    # ------------------------------------------------------------------
    # Core scanner - walks a single memory region looking for modules
    # ------------------------------------------------------------------
    def _scan_region(self, task, region, type_filter=None):
        """
        Linear scan at 8-byte alignment looking for PyObject headers.
        Caches type_ptr -> name so we resolve each unique type only once.
        """
        proc_layer_name = task.add_process_layer()
        layer = self.context.layers[proc_layer_name]

        start = region['start']
        end = region['end']
        results = []

        # Cache: type_ptr -> type_name (or None for garbage pointers)
        type_cache = {}
        # Cache: set of type_ptrs known to be 'module'
        module_type_ptrs = set()

        scan_count = 0
        addr = start

        while addr < end - 16:
            try:
                header = layer.read(addr, 16)
            except Exception:
                addr += PTR_SIZE
                continue

            refcnt = int.from_bytes(header[0:8], 'little')
            type_ptr = int.from_bytes(header[8:16], 'little')

            if not self._is_valid_header(refcnt, type_ptr, layer):
                addr += PTR_SIZE
                continue

            # Resolve type name (cached)
            if type_ptr in type_cache:
                type_name = type_cache[type_ptr]
            else:
                type_name = self._extract_type_name(type_ptr, layer)
                type_cache[type_ptr] = type_name

            if type_name is None:
                addr += PTR_SIZE
                continue

            # Apply filter if caller only wants specific types
            if type_filter and type_name != type_filter:
                addr += PTR_SIZE
                scan_count += 1
                continue

            # For modules, do extra validation to weed out false positives
            if type_name == 'module':
                module_type_ptrs.add(type_ptr)
                if self._validate_module(addr, layer):
                    info = self._extract_module_info(addr, layer)
                    results.append((addr, type_name, info))
            else:
                results.append((addr, type_name, {
                    'address': addr,
                    'refcnt': refcnt,
                }))

            scan_count += 1
            addr += PTR_SIZE

        return results

    # ------------------------------------------------------------------
    # Public API - get_modules
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        Scan heap/anon regions for module objects.
        Returns list of (address, name, PyModuleObject) tuples.
        """
        proc_layer_name = task.add_process_layer()
        self.process_layer = self.context.layers[proc_layer_name].name
        self._py_table = python_table_name

        regions = self._get_scannable_regions(task)
        if not regions:
            print("No scannable regions found")
            return []

        print(f"Heap scanner: {len(regions)} regions to scan")

        modules = []
        seen_addrs = set()

        for region in regions:
            # Split oversized regions into head+tail chunks
            scan_targets = self._split_region(region)

            for target in scan_targets:
                hits = self._scan_region(task, target, type_filter='module')

                for addr, type_name, info in hits:
                    if addr in seen_addrs:
                        continue
                    seen_addrs.add(addr)

                    # Build the actual PyModuleObject for the caller
                    try:
                        layer = self.context.layers[self.process_layer]
                        mod_obj = self.context.object(
                            object_type=python_table_name + constants.BANG + "PyObject",
                            layer_name=self.process_layer,
                            offset=addr,
                        ).cast_to("PyModuleObject")

                        mod_name = info.get('name', 'Unknown')
                        modules.append((addr, str(mod_name), mod_obj))
                    except Exception as e:
                        print(f"  Error casting module at 0x{addr:x}: {e}")

        print(f"Heap scanner found {len(modules)} unique modules")
        return modules

    # ------------------------------------------------------------------
    # Public API - get_all_objects (generic scanner)
    # ------------------------------------------------------------------
    def get_all_objects(self, task, python_table_name, type_filter=None):
        """Scan heap for all objects, optionally filtered by type name."""
        proc_layer_name = task.add_process_layer()
        self.process_layer = self.context.layers[proc_layer_name].name
        self._py_table = python_table_name

        regions = self._get_scannable_regions(task)
        if not regions:
            return []

        all_results = []
        seen = set()

        for region in regions:
            for target in self._split_region(region):
                hits = self._scan_region(task, target, type_filter=type_filter)
                for addr, tname, info in hits:
                    if addr not in seen:
                        seen.add(addr)
                        all_results.append((addr, tname, info))

        return all_results

    # ------------------------------------------------------------------
    # Region splitting for oversized VMAs
    # ------------------------------------------------------------------
    def _split_region(self, region):
        """Split oversized regions into head+tail chunks."""
        if region['size'] <= MAX_REGION_SCAN_BYTES:
            return [region]

        head = {
            'start': region['start'],
            'end': region['start'] + MAX_REGION_SCAN_BYTES,
            'size': MAX_REGION_SCAN_BYTES,
            'flags': region['flags'],
            'path': region['path'] + ' (head)',
        }
        tail = {
            'start': region['end'] - MAX_REGION_SCAN_BYTES,
            'end': region['end'],
            'size': MAX_REGION_SCAN_BYTES,
            'flags': region['flags'],
            'path': region['path'] + ' (tail)',
        }
        print(f"  Splitting oversized region ({region['size']:,} bytes) into head+tail")
        return [head, tail]

    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _collect_data(self, tasks):
        """Standalone mode: detect version, load symbols, scan for modules."""
        task = list(tasks)[0]
        if not task or not task.mm:
            return []

        version = self.detect_python_version(task)
        if not version:
            print("Could not detect Python version")
            return []

        print(f"Detected Python {version[0]}.{version[1]}")

        self._py_table = self._load_symbol_table(version)
        if not self._py_table:
            return []

        return self.get_modules(task, self._py_table)

    def _generator(self, data):
        for addr, name, mod_obj in data:
            yield (0, (
                0,
                "heap",
                f"0x{addr:x}",
                "module",
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
                ("Region", str),
                ("Address", str),
                ("Type", str),
                ("Name", str),
            ],
            self._generator(collected_data),
        )
