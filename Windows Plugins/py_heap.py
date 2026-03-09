
import logging
from typing import Dict, List, Optional, Tuple

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import pe_parsing

vollog = logging.getLogger(__name__)

# Brute-force heap scanner for Python objects.
#
# Walks r/w memory regions at 8-byte alignment looking for valid PyObject
# headers (ob_refcnt + ob_type). Slower than GC walking but catches objects
# not tracked by GC — deleted modules, unlinked objects, etc.
#
# Returns (address, name, PyModuleObject) tuples, same shape as
# Py_Interpreter and Py_GC so Module_Extractor can merge everything.


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

# Refcount > 1M is almost certainly garbage, not a real object
MAX_REASONABLE_REFCOUNT = 1_000_000

# md_dict.ma_used sanity bound — even huge apps rarely exceed this
MAX_DICT_USED = 100_000

# Cap per-region scan to avoid spending forever on giant mappings.
# Anything larger gets split into head + tail chunks.
MAX_REGION_SCAN_BYTES = 100 * 1024 * 1024  # 100 MB

# CPython allocates all PyObjects on 8-byte boundaries
PTR_SIZE = 8


class Py_Heap(interfaces.plugins.PluginInterface):
    """Scan heap/private memory regions for Python objects (Windows, 3.6-3.14)."""
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
    # Symbol table loading
    # ------------------------------------------------------------------
    def _load_symbol_table(self, version):
        """Load ISF symbol table for the detected CPython version."""
        key = version[:2]
        entry = SYMBOL_TABLE_REGISTRY.get(key)
        if not entry:
            vollog.error(f"No symbol table for Python {key[0]}.{key[1]}")
            return None

        import_path, class_name, sub_path, filename = entry
        module = __import__(import_path, fromlist=[class_name])
        symbol_class = getattr(module, class_name)

        table_name = symbol_class.create(
            self.context, self.config_path,
            sub_path=sub_path,
            filename=filename,
        )
        vollog.info(f"Loaded symbol table: {class_name} -> {table_name}")
        return table_name

    # ------------------------------------------------------------------
    # Memory region enumeration (Windows VADs)
    # ------------------------------------------------------------------
    def _get_scannable_regions(self, task):
      """
      Collect r/w VADs worth scanning: private memory, heap,
      and python DLL regions.
      """
      regions = []

      # Windows VAD protection constants (from _MMVAD_FLAGS.Protection)
      # 4 = READWRITE, 5 = WRITECOPY, 6 = EXECUTE_READWRITE, 7 = EXECUTE_WRITECOPY
      RW_PROTECTIONS = {4, 5, 6, 7}

      try:
        for vad in task.get_vad_root().traverse():
            try:
                start = vad.get_start()
                end = vad.get_end()
                size = end - start

                # Skip tiny or impossibly large regions
                if size < 0x1000 or size > 512 * 1024 * 1024:
                    continue

                # We need at least read+write access
                protect = int(vad.Protection)
                if protect not in RW_PROTECTIONS:
                    continue

                # Get the file path if this is a mapped file
                try:
                    file_path = vad.get_file_name()
                except Exception:
                    file_path = None

                path_str = str(file_path) if file_path else "Private"

                # Treat "N/A" as private/anonymous memory
                is_private = (file_path is None or path_str == "N/A")

                # heap, anon, python DLLs - all fair game
                is_interesting = (
                    is_private
                    or 'python' in path_str.lower()
                )

                if not is_interesting:
                    continue

                if is_private:
                    path_str = "Private"

                regions.append({
                    'start': start,
                    'end': end,
                    'size': size,
                    'flags': str(protect),
                    'path': path_str,
                })

            except Exception as e:
                vollog.debug(f"Error processing VAD entry: {e}")
                continue

      except Exception as e:
        vollog.warning(f"Error traversing VAD tree: {e}")

      return regions

    # ------------------------------------------------------------------
    # PyObject header validation
    # ------------------------------------------------------------------
    def _is_valid_header(self, refcnt, type_ptr, layer):
        """Sanity check: positive refcount within bounds + readable type pointer."""
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
        """
        Extra validation for module candidates: check that md_dict is
        a readable PyDictObject with a sane ma_used count.
        """
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
        """Pull name, __file__, __version__, __package__ from a validated module."""
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
            vollog.debug(f"Error extracting module at 0x{addr:x}: {e}")

        return info

    # ------------------------------------------------------------------
    # Core scanner — walks a single memory region at 8-byte alignment
    # ------------------------------------------------------------------
    def _scan_region(self, task, region, type_filter=None):
        """
        Linear scan looking for PyObject headers (ob_refcnt, ob_type).
        type_ptr -> name is cached so each unique type is resolved once.
        """
        layer = self.context.layers[self.process_layer]

        start = region['start']
        end = region['end']
        results = []

        type_cache = {}  # type_ptr -> type_name (or None)

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

            if type_ptr in type_cache:
                type_name = type_cache[type_ptr]
            else:
                type_name = self._extract_type_name(type_ptr, layer)
                type_cache[type_ptr] = type_name

            if type_name is None:
                addr += PTR_SIZE
                continue

            if type_filter and type_name != type_filter:
                addr += PTR_SIZE
                scan_count += 1
                continue

            if type_name == 'module':
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
    # Public API — get_modules (for Module_Extractor)
    # ------------------------------------------------------------------
    def get_modules(self, task, python_table_name):
        """
        Scan heap/private regions for module objects.
        Returns list of (address, name, PyModuleObject) tuples.
        """
        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException:
            vollog.error("Cannot create process layer")
            return []

        self.process_layer = self.context.layers[proc_layer_name].name
        self._py_table = python_table_name

        regions = self._get_scannable_regions(task)
        if not regions:
            vollog.warning("No scannable regions found")
            return []

        vollog.info(f"Heap scanner: {len(regions)} regions to scan")

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
                        mod_obj = self.context.object(
                            object_type=python_table_name + constants.BANG + "PyObject",
                            layer_name=self.process_layer,
                            offset=addr,
                        ).cast_to("PyModuleObject")

                        mod_name = info.get('name', 'Unknown')
                        modules.append((addr, str(mod_name), mod_obj))
                    except Exception as e:
                        vollog.debug(f"Error casting module at 0x{addr:x}: {e}")

        vollog.info(f"Heap scanner found {len(modules)} unique modules")
        return modules

    # ------------------------------------------------------------------
    # Public API — get_all_objects (generic scanner)
    # ------------------------------------------------------------------
    def get_all_objects(self, task, python_table_name, type_filter=None):
        """Scan heap for all objects, optionally filtered by type name."""
        try:
            proc_layer_name = task.add_process_layer()
        except exceptions.InvalidAddressException:
            vollog.error("Cannot create process layer")
            return []

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
    # Region splitting for oversized VADs
    # ------------------------------------------------------------------
    def _split_region(self, region):
        """
        Split regions larger than MAX_REGION_SCAN_BYTES into head + tail
        chunks. Most Python objects live near the start or end of large
        private memory regions.
        """
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
        vollog.info(f"Splitting oversized region ({region['size']:,} bytes) into head+tail")
        return [head, tail]

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

    # ------------------------------------------------------------------
    # Standalone execution
    # ------------------------------------------------------------------
    def _collect_data(self, processes):
        """Standalone mode: detect version, load symbols, scan for modules."""
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

        vollog.info(f"Detected Python {version[0]}.{version[1]}")

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
                ("Region", str),
                ("Address", str),
                ("Type", str),
                ("Name", str),
            ],
            self._generator(collected_data),
        )
