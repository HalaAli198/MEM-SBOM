# MEM-SBOM: Software Bill of Materials from memory.
#
# Pipeline:
#   1. Module_Extractor: extract all loaded Python modules across the process tree
#   2. Find 'sys' module, parse sys.path_importer_cache for installed packages
#   3. Group and classify modules (application / third-party / stdlib)
#   4. Extract version info from module dicts
#   5. Resolve pip package names → import names via PyPI
#   6. Fill unknown versions from installed package metadata
#   7. Generate dependency graph (optional, --dep flag)
#   8. Write CycloneDX 1.5 SBOM JSON

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
import re
import json
import uuid
from datetime import datetime

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
            requirements.BooleanRequirement(
                name="dep",
                description="Generate dependency graph",
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
      """Walk sys.path_importer_cache entries for site-packages/dist-packages
      directories and extract package names + versions from .dist-info/.egg-info."""
     
      if 'path_importer_cache' not in sys_mod_dict:
        print("  sys.path_importer_cache not found")
        return []

      path_cache_obj = sys_mod_dict['path_importer_cache']
      path_cache_dict = path_cache_obj.get_value()

      all_packages = []

      for key, value in path_cache_dict.items():
        if 'site-packages' not in key and 'dist-packages' not in key:
            continue

        #print(f"  Scanning: {key}")

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

            #print(f"    Found {len(packages)} packages")

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
        its dict.

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
    
    def generate_mem_sbom(self, package_versions, dep_graph, main_app_name):
      """
      Generate CycloneDX 1.5 SBOM for application + third-party packages.
    
      package_versions: {parent_name: (version, path, category)}
      dep_graph:        {parent_name: [dep_name, ...]} or {}
      """
      components = []
      bom_ref_map = {}

      for parent_name, (version, path, category) in package_versions.items():
        # Only application + third-party
        if category not in ('application', 'third-party'):
            continue

        clean_version = version if version != "unknown" else "0.0.0"
        bom_ref = (
            f"{parent_name.replace('.', '_').replace('-', '_')}-"
            f"{clean_version.replace('.', '_')}"
        )
        bom_ref_map[parent_name] = bom_ref

        if '.' in parent_name:
            pypi_name = parent_name.replace('.', '-').lower()
        else:
            pypi_name = parent_name.replace('_', '-').lower()

        purl = f"pkg:pypi/{pypi_name}@{clean_version}"

        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": parent_name,
            "version": clean_version,
            "purl": purl,
            "scope": "required",
            "properties": [
                {"name": "classification", "value": category},
                {"name": "extracted_from", "value": "memory"},
            ],
        }

        if path and path != "None":
            component["properties"].append({"name": "file_path", "value": path})
            component["evidence"] = {"occurrences": [{"location": path}]}

        if version == "unknown":
            component["properties"].append({"name": "version_detection", "value": "failed"})
            component["purl"] = f"pkg:pypi/{pypi_name}"

        components.append(component)

      # --- Dependencies ---
      dependencies = []

      if dep_graph:
        for parent_name, dep_list in dep_graph.items():
            ref = bom_ref_map.get(parent_name)
            if not ref:
                continue
            depends_on = [
                bom_ref_map[d] for d in dep_list if d in bom_ref_map
            ]
            dependencies.append({"ref": ref, "dependsOn": depends_on})
        # Empty entries for components not in dep_graph
        referenced = {d["ref"] for d in dependencies}
        for comp in components:
            if comp["bom-ref"] not in referenced:
                dependencies.append({"ref": comp["bom-ref"], "dependsOn": []})
      else:
        for comp in components:
            dependencies.append({"ref": comp["bom-ref"], "dependsOn": []})

      timestamp = datetime.utcnow().isoformat() + "Z"

      sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "name": "MEM-SBOM",
                "version": "1.0.0",
            }],
            "component": {
                "type": "application",
                "name": main_app_name,
                "description": "Python application analyzed from memory dump",
            },
            "properties": [
                {"name": "extraction_method", "value": "memory_analysis"},
                {"name": "total_components", "value": str(len(components))},
                {"name": "dependency_graph_enabled", "value": str(bool(dep_graph))},
            ],
        },
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": [],
      }

      return sbom
    
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
        
        print(f"\n{'='*60}")
        print(f"INSTALLED PACKAGES from path_importer_cache ({len(installed_packages)})")
        print(f"{'='*60}")
        for pkg_name, pkg_version, source_path in installed_packages:
            print(f"  {pkg_name:40s}  {pkg_version:15s}  {source_path}")

        print(f"\n{'='*60}")
        print("SUMMARY")
        print(f"{'='*60}")
        print(f"  Installed packages (from cache):   {len(installed_packages)}")
        # ----------------------------------------------------------
        # Step 3: Group modules by parent and  classify parent modules
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 3: Module grouping by parent")
        print(f"{'='*60}")
        
        grouped = self.group_modules_by_parent(all_modules)
        
        print(f"\n{'='*60}")
        print("STEP 3: Module classification")
        print(f"{'='*60}")
        from volatility3.plugins.linux.module_classifier import Module_Classifier

        classifier = Module_Classifier()
        classified = {
            'application': {},
            'internal': {},
            'stdlib': {},
            'third-party': {},
        }

        for parent, entries in grouped.items():
            # Find the actual parent entry for path extraction
            parent_entry = None
            for entry in entries:
                if entry[1] == parent:
                    parent_entry = entry
                    break
            if parent_entry is None:
                parent_entry = entries[0]

            module_path = classifier._extract_path(parent_entry[5])
            category = classifier.classify(parent, module_path)
            classified[category][parent] = entries
        module_class_map = {}  # module_name → classification
        for category, groups in classified.items():
            for parent, entries in groups.items():
                module_class_map[parent] = category
                #for entry in entries:
                    #module_class_map[entry[1]] = category
                  
         
        # Print the map
        print(f"\n{'='*60}")
        print(f"MODULE → CLASSIFICATION MAP ({len(module_class_map)} entries)")
        print(f"{'='*60}")
        for mod_name in sorted(module_class_map.keys()):
            print(f"  {mod_name:40s}  →  {module_class_map[mod_name]}")
        
        
        # ----------------------------------------------------------
        # Step 4: Extract version info for application + third-party
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 4: Extracting version info")
        print(f"{'='*60}")

        package_versions = {}  # parent_name → (version, path)

        for category in ('application', 'third-party'):
            for parent, entries in classified[category].items():
                # Find the parent module entry
                parent_entry = None
                for entry in entries:
                    if entry[1] == parent:
                        parent_entry = entry
                        break
                if parent_entry is None:
                    parent_entry = entries[0]

                mod_obj = parent_entry[5]
                mod_version = "unknown"
                mod_path = "None"

                try:
                    module_obj = mod_obj.cast_to("PyModuleObject")
                    mod_dict = module_obj.get_dict2()
                    #print(mod_dict)
                    print("------------------------------------------------")
                    # --- Extract version ---
                    version_attrs = [
                        '__version__', 'VERSION', '__VERSION__',
                        '_version', 'version_short', 'version_info',
                        '__version_info__', 'VERSION_INFO',
                        '__VERSION_INFO__', 'version',
                    ]
                    # --- Extract version from parent dict ---
                    for attr in version_attrs:
                        if attr not in mod_dict:
                            continue
                        val = mod_dict[attr]
                        val_type = val.ob_type.dereference().get_name()
                        #print(f"val_type: {val_type}")

                        if val_type == "str":
                            mod_version = val.get_value()
                            break
                        elif val_type == "tuple":
                            try:
                                version_tuple = val.get_value()
                                parts = []
                                for obj in version_tuple[:3]:
                                    try:
                                        parts.append(str(obj.get_value()))
                                    except:
                                        break
                                if parts and any(p.lower() != 'none' for p in parts):
                                    mod_version = '.'.join(parts)
                                    break
                            except:
                                continue
                        elif val_type == "module":
                            # Version is a sub-module (e.g. pkg.version)
                            try:
                                ver_mod = val.cast_to("PyModuleObject")
                                ver_dict = ver_mod.get_dict2()
                                for attr2 in version_attrs:
                                    if attr2 in ver_dict:
                                        if self.get_value_type(ver_dict[attr2]) == "str":
                                            mod_version = ver_dict[attr2].get_value()
                                            break
                                if mod_version != "unknown":
                                    break
                            except:
                                continue

                    # --- Fallback: check children for version ---
                    if mod_version == "unknown":
                        for entry in entries:
                            if entry[1] == parent:
                                continue  # already checked
                            try:
                                child_mod = entry[5].cast_to("PyModuleObject")
                                child_dict = child_mod.get_dict2()
                                for attr in version_attrs:
                                    if attr not in child_dict:
                                        continue
                                    val = child_dict[attr]
                                    try:
                                        val_type = val.ob_type.dereference().get_name()
                                    except:
                                        continue
                                    if val_type == "str":
                                        mod_version = val.get_value()
                                        print(f"    version from child {entry[1]}: {mod_version}")
                                        break
                                if mod_version != "unknown":
                                    break
                            except:
                                continue
                    
                    # --- Extract path ---
                    if '__file__' in mod_dict:
                        try:
                            mod_path = mod_dict['__file__'].get_value()
                        except:
                            pass
                    elif '__path__' in mod_dict:
                        try:
                            mod_path = str(mod_dict['__path__'].get_value())
                        except:
                            pass

                except Exception as e:
                    print(f"  Error reading {parent}: {e}")

                package_versions[parent] = (mod_version, mod_path, category)
                print(f"  {parent:30s}  {mod_version:15s}  {category}")
                
        # ----------------------------------------------------------
        # Step 5: Resolve pip names → import names via PyPI
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 5: Resolving package → import name mappings via PyPI")
        print(f"{'='*60}")

        import requests
        import zipfile
        import tarfile
        import io

        # {pip_name: {'imports': [import_names], 'version': str}}
        pip_import_map = {}
        skip_packages = {'pkg_resources', 'pip', 'setuptools', 'wheel', '_distutils_hack'}
        for pkg_name, pkg_version, source_path in installed_packages:
            if pkg_name.lower() in skip_packages:
                print(f"  {pkg_name}: skipped (packaging infrastructure)")
                continue 
            import_names = set()

            try:
                resp = requests.get(
                    f"https://pypi.org/pypi/{pkg_name}/json", timeout=5
                )
                if resp.status_code != 200:
                    print(f"  {pkg_name}: PyPI returned {resp.status_code}")
                    pip_import_map[pkg_name] = {
                        'imports': [pkg_name.lower().replace('-', '_')],
                        'version': pkg_version,
                    }
                    continue

                data = resp.json()
                urls = data.get('urls', [])
                if not urls and 'releases' in data:
                    latest = data['info'].get('version')
                    if latest and latest in data['releases']:
                        urls = data['releases'][latest]

                # Find wheel and sdist URLs
                wheel_url = None
                sdist_url = None
                for u in urls:
                    if u.get('packagetype') == 'bdist_wheel' and not wheel_url:
                        wheel_url = u['url']
                    elif u.get('packagetype') == 'sdist' and not sdist_url:
                        sdist_url = u['url']

                ignore = {
                    'tests', 'test', 'docs', 'examples', 'example',
                    'scripts', 'benchmarks', 'samples', 'tools',
                    'bin', 'conf', 'etc',
                }

                # --- Try wheel first ---
                if wheel_url:
                    whl_resp = requests.get(wheel_url, timeout=10)
                    whl = zipfile.ZipFile(io.BytesIO(whl_resp.content))

                    # 1) top_level.txt
                    for fname in whl.namelist():
                        if fname.endswith('top_level.txt'):
                            content = whl.read(fname).decode('utf-8')
                            import_names = {
                                line.strip()
                                for line in content.splitlines()
                                if line.strip()
                            }
                            break

                    # 2) Infer from wheel structure
                    if not import_names:
                        for fname in whl.namelist():
                            # Skip dist-info metadata directories
                            if '.dist-info/' in fname:
                                continue
                            # Package dirs: bs4/__init__.py
                            if fname.count('/') == 1 and fname.endswith('/__init__.py'):
                                candidate = fname.split('/')[0]
                                if candidate not in ignore and not candidate.startswith('.'):
                                    import_names.add(candidate)
                            # Single-module files: foobar.py
                            elif fname.count('/') == 0 and fname.endswith('.py'):
                                candidate = fname[:-3]
                                if candidate not in ignore and not candidate.startswith('.'):
                                    import_names.add(candidate)

                # --- Fallback to sdist ---
                elif sdist_url:
                    try:
                        sdist_resp = requests.get(sdist_url, timeout=10)
                        with tarfile.open(
                            fileobj=io.BytesIO(sdist_resp.content), mode='r:gz'
                        ) as tar:
                            for member in tar.getmembers():
                                # top_level.txt inside .egg-info
                                if '.egg-info/top_level.txt' in member.name:
                                    content = tar.extractfile(member).read().decode('utf-8')
                                    import_names = {
                                        line.strip()
                                        for line in content.splitlines()
                                        if line.strip()
                                    }
                                    break

                            # Infer from sdist directory structure
                            if not import_names:
                                for member in tar.getmembers():
                                    if not member.isdir():
                                        continue
                                    parts = member.name.split('/')
                                    # Top-level dir after the package root dir
                                    if len(parts) == 2:
                                        candidate = parts[1]
                                        if (candidate not in ignore
                                                and not candidate.startswith('.')
                                                and not candidate.endswith('.egg-info')):
                                            import_names.add(candidate)
                    except Exception as e:
                        print(f"  {pkg_name}: sdist error - {e}")

            except Exception as e:
                print(f"  {pkg_name}: error - {e}")

            # Fallback: normalize pip name as import name
            if not import_names:
                import_names = {pkg_name.lower().replace('-', '_')}

            pip_import_map[pkg_name] = {
                'imports': sorted(import_names),
                'version': pkg_version,
            }
            print(f"  {pkg_name:30s} {pkg_version:10s} → {sorted(import_names)}")

        print(f"\n  Resolved {len(pip_import_map)} packages")
        
        # ----------------------------------------------------------
        # Step 6: Fill unknown versions from pip_import_map
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 6: Resolving unknown versions from installed packages")
        print(f"{'='*60}")

        for parent, (version, path, category) in package_versions.items():
            if version != "unknown":
                continue

            # Check if this module name appears in any package's import list
            for pip_name, info in pip_import_map.items():
                if parent in info['imports']:
                    old_version = version
                    package_versions[parent] = (info['version'], path, category)
                    print(f"  {parent:30s}  {info['version']:15s}  (from {pip_name})")
                    break
            else:
                print(f"  {parent:30s}  still unknown")
        

        
        # ----------------------------------------------------------
        # Step 7: Generate dependency graph
        # ----------------------------------------------------------
        dep_graph={}
        if self.config.get('dep', False):
          from volatility3.plugins.linux.dependency_generator import Dependency_Generator
          print(f"\n{'='*60}")
          print("STEP 7: Generating dependency graph")
          print(f"{'='*60}")
        
          # Detect Python version from symbol table name
          python_version = (3, 12)  # safe fallback
          try:
              st_name = all_modules[0][5].get_symbol_table_name()
              # e.g. "python3141" -> 3.14, "python3121" -> 3.12
              import re as _re
              m = _re.search(r'python(\d)(\d{1,2})\d$', st_name)
              if m:
                  python_version = (int(m.group(1)), int(m.group(2)))
                  print(f"  Detected Python version: {python_version} (from {st_name})")
          except Exception:
              pass

          dep_gen = Dependency_Generator(python_version=python_version)
          dep_graph = dep_gen.build_dependency_graph(classified, grouped)

          print(f"\n{'='*60}")
          print(f"DEPENDENCY GRAPH ({len(dep_graph)} modules)")
          print(f"{'='*60}")
          for parent in sorted(dep_graph.keys()):
              deps = dep_graph[parent]
              print(f"  {parent} → [{', '.join(deps)}]")

          

        # ----------------------------------------------------------
        # Step 8: Write CycloneDX SBOM JSON
        # ----------------------------------------------------------
        print(f"\n{'='*60}")
        print("STEP 8: Generating CycloneDX SBOM")
        print(f"{'='*60}")
        main_app_name = "Unknown Application"
        for addr, name, sources, pid, comm, mod_obj in all_modules:
            if pid == self.config['pid'][0]:
               main_app_name = comm
               break
        sbom = self.generate_mem_sbom(package_versions, dep_graph, main_app_name)

        sbom_path = f"{pid}.json"
        with open(sbom_path, 'w') as f:
            json.dump(sbom, f, indent=2)
        print(f"  Written to: {sbom_path}")
        print(f"  Components: {len(sbom['components'])}")
        print(f"  Dependencies: {len(sbom['dependencies'])}")
        return all_modules, installed_packages, dep_graph
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
        all_modules, installed_packages, dep_graph = self._collect_all()

        return renderers.TreeGrid(
            [
                ("Package", str),
                ("Version", str),
                ("Source", str),
            ],
            self._generator(installed_packages),
        )
