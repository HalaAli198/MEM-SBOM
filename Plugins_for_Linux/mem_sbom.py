from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
import re


# MEM-SBOM: Software Bill of Materials from memory.
#
# Step 1: Use Module_Extractor to get all loaded Python modules across
#          the process tree.
# Step 2: Find the 'sys' module, extract sys.path_importer_cache,
#          parse .dist-info/.egg-info entries for installed package
#          names and versions.
#
# Usage:
#   vol.py -f dump.vmem linux.mem_sbom.MEM_SBOM --pid 22162


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


class MEM_SBOM(interfaces.plugins.PluginInterface):
    """Generate Software Bill of Materials from Python process memory."""
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
    # Helpers
    # ------------------------------------------------------------------
    def read_cstring(self, address, max_length=256):
        """Read a null-terminated C string from process memory."""
        try:
            data = self.context.layers[self._proc_layer].read(
                address, max_length, pad=False
            )
            return data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        except Exception:
            return ""

    def get_value_type(self, value):
        """Get the type name string for a PyObject."""
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
    # Parse .dist-info / .egg-info entries from path cache
    # ------------------------------------------------------------------
    def parse_dist_info(self, entries):
        """
        Parse .dist-info and .egg-info directory names from the
        FileFinder._path_cache set to extract (package_name, version).

        Examples:
          'requests-2.28.1.dist-info'  -> ('requests', '2.28.1')
          'Flask-2.3.0-py3.9.egg-info' -> ('Flask', '2.3.0')
        """
        packages = []

        for entry in entries:
            if not isinstance(entry, str):
                continue
            if '.dist-info' not in entry and '.egg-info' not in entry:
                continue

            patterns = [
                # package-1.2.3-py3.9.egg-info or package-1.2.3-py3.9-linux.egg-info
                r'([\w\.-]+?)-([\d\.\w\+\-]+?)(?:-py[\d\.]+)?(?:-[\w]+)?\.(dist-info|egg-info)',
                # package-1.2.3.dist-info (standard)
                r'([\w\.-]+?)-([\d\.\w\+\-]+)\.(dist-info|egg-info)',
                # package.dist-info (no version)
                r'([\w\.-]+?)\.(dist-info|egg-info)',
            ]

            for pattern in patterns:
                match = re.match(pattern, entry)
                if match:
                    package_name = match.group(1)
                    version = match.group(2) if len(match.groups()) >= 3 else "unknown"
                    packages.append((package_name, version))
                    break

        return packages

    # ------------------------------------------------------------------
    # Extract installed packages from sys.path_importer_cache
    # ------------------------------------------------------------------
    def extract_installed_packages(self, sys_mod_dict):
      if 'path_importer_cache' not in sys_mod_dict:
        print("  sys.path_importer_cache not found")
        return []

      path_cache_obj = sys_mod_dict['path_importer_cache']
      path_cache_dict = path_cache_obj.get_value()

      all_packages = []

      for key, value in path_cache_dict.items():
        if 'site-packages' not in key and 'dist-packages' not in key:
            continue

        print(f"  Scanning: {key}")

        try:
            finder_dict = value.get_value()

            if '_path_cache' not in finder_dict:
                print(f"    No _path_cache found")
                continue

            path_cache_set_obj = finder_dict['_path_cache'].cast_to("PySetObject")
            cache_entries = path_cache_set_obj.get_value()
            packages = self.parse_dist_info(cache_entries)
            for pkg_name, pkg_version in packages:
                all_packages.append((pkg_name, pkg_version, key))

            print(f"    Found {len(packages)} packages")

        except Exception as e:
            print(f"    Error processing {key}: {e}")
            continue

      return all_packages

    # ------------------------------------------------------------------
    # Find sys module from the extracted module list
    # ------------------------------------------------------------------
    def find_sys_module(self, modules):
        """
        Find the 'sys' module in the extracted module list and return
        its dict (mod_obj.get_dict2()).

        modules: list of (addr, name, sources_str, pid, comm, mod_obj)
        Returns: dict or None
        """
        for addr, name, sources, pid, comm, mod_obj in modules:
            if name == 'sys':
                print(f"  Found sys module at 0x{addr:x} (PID {pid}, {comm})")
                try:
                    # We need the process layer set up for read_cstring etc.
                    # The mod_obj is already in the right layer context.
                    module_obj = mod_obj.cast_to("PyModuleObject")
                    mod_dict = module_obj.get_dict2()
                    return mod_dict
                except Exception as e:
                    print(f"  Error reading sys module dict: {e}")
                    return None

        print("  WARNING: sys module not found in extracted modules")
        return None

    def group_modules_by_parent(self, all_modules):
      """
      Group modules by their top-level parent.
      e.g. json.decoder, json.encoder, json.scanner → json
         collections.abc → collections
         sqlite3.dbapi2 → sqlite3
    
      Returns: {parent_name: [(addr, name, sources, pid, comm, mod_obj), ...]}
      """
      groups = {}

      for mod_tuple in all_modules:
        addr, name, sources, pid, comm, mod_obj = mod_tuple
        # Get top-level parent: first component before '.'
        parent = name.split('.')[0]

        if parent not in groups:
            groups[parent] = []
        groups[parent].append(mod_tuple)

      return groups
    
    # ------------------------------------------------------------------
    # Main logic
    # ------------------------------------------------------------------
    def _collect_all(self):
        from volatility3.plugins.linux.module_extractor import Module_Extractor

        # ----------------------------------------------------------
        # Step 1: Extract all modules via Module_Extractor
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 1: Extracting modules via Module_Extractor")
        print(f"{'='*60}")

        extractor = Module_Extractor(self.context, self.config_path)
        all_modules = extractor.get_all_modules()

        print(f"\n  Module_Extractor returned {len(all_modules)} unique modules")

        if not all_modules:
            print("  ERROR: No modules extracted")
            return [], []

        # ----------------------------------------------------------
        # Step 2: Find sys module → parse path_importer_cache
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 2: Parsing sys.path_importer_cache")
        print(f"{'='*60}")

        sys_dict = self.find_sys_module(all_modules)

        installed_packages = []
        if sys_dict:
            installed_packages = self.extract_installed_packages(sys_dict)

            # Dedup by normalized (name, version)
            seen = set()
            deduped = []
            for pkg_name, pkg_version, source_path in installed_packages:
                key = (pkg_name.lower().replace('-', '_'), pkg_version)
                if key not in seen:
                    seen.add(key)
                    deduped.append((pkg_name, pkg_version, source_path))
            installed_packages = sorted(deduped, key=lambda x: x[0].lower())

        
        # ----------------------------------------------------------
        # Step 3: Group modules by parent
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("MODULE GROUPING BY PARENT")
        print(f"{'='*60}")

        grouped = self.group_modules_by_parent(all_modules)

        for parent in sorted(grouped.keys()):
            children = grouped[parent]
            if len(children) == 1 and children[0][1] == parent:
                # Standalone module, no sub-modules
                print(f"  {parent}")
            else:
                child_names = sorted([c[1] for c in children])
                print(f"  {parent}")
                for child in child_names:
                    if child != parent:
                        print(f"    └─ {child}")

        print(f"\n  Top-level modules: {len(grouped)}")
        print(f"  Total modules:     {len(all_modules)}")
        # ----------------------------------------------------------
        # Print results
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print(f"INSTALLED PACKAGES from path_importer_cache ({len(installed_packages)})")
        print(f"{'='*60}")
        for pkg_name, pkg_version, source_path in installed_packages:
            print(f"  {pkg_name:40s}  {pkg_version:15s}  {source_path}")

        print(f"\n{'='*60}")
        print(f"LOADED MODULES from memory ({len(all_modules)})")
        print(f"{'='*60}")
        for addr, name, sources, pid, comm, mod_obj in sorted(all_modules, key=lambda x: x[1]):
            print(f"  {name:40s}  [{sources:12s}]  PID {pid} ({comm})")

        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        print(f"  Loaded modules (from memory):     {len(all_modules)}")
        print(f"  Installed packages (from cache):   {len(installed_packages)}")

        return all_modules, installed_packages

    # ------------------------------------------------------------------
    # Volatility renderer
    # ------------------------------------------------------------------
    def _generator(self, installed_packages):
        for pkg_name, pkg_version, source_path in installed_packages:
            yield (0, (
                str(pkg_name),
                str(pkg_version),
                str(source_path),
            ))

    def run(self):
        all_modules, installed_packages = self._collect_all()

        return renderers.TreeGrid(
            [
                ("Package", str),
                ("Version", str),
                ("Source", str),
            ],
            self._generator(installed_packages),
        )
