import re

# Module classifier for Python modules extracted from memory.
#
# Classifies each module into one of four categories:
#   - internal:     CPython internals, import machinery, dunder modules,
#                   vendored sub-modules (_vendor, extern, etc.)
#   - stdlib:       Python standard library modules
#   - third-party:  Installed packages from pip/conda/etc.
#   - application:  The main application code (__main__, __mp_main__)
#
# Classification is based on module name + file path when available.
# No network access needed — purely offline heuristics.


class Module_Classifier:

    def __init__(self):

        # Built-in C extension modules (always present, no .py file)
        self.builtin_modules = {
            'sys', 'builtins', '_thread', '_signal', '_imp', '_warnings',
            '_weakref', '_io', '_frozen_importlib', '_frozen_importlib_external',
            'marshal', 'posix', 'nt', '_codecs', 'errno', '_sre', '_abc',
            '_stat', 'atexit', '_opcode', '_collections_abc', 'itertools',
            '_operator', '_functools', '_collections', '_heapq', '_bisect',
            '_random', '_sha512', '_sha256', '_md5', '_sha1', '_sha3',
            '_blake2', '_struct', '_pickle', '_datetime', '_decimal',
            'math', 'cmath', '_json', '_csv', 'array', 'select',
            '_socket', '_ssl', '_hashlib', 'binascii', 'zlib', '_bz2',
            '_lzma', 'fcntl', 'grp', 'pwd', 'resource', 'termios',
            '_multiprocessing', '_posixsubprocess', '_ctypes', 'mmap',
            '_sqlite3', 'readline', '_curses', 'unicodedata', '_locale',
            '_contextvars', '_asyncio', '_queue', '_uuid', '_tracemalloc',
            '_symtable', '_zoneinfo', '_statistics', '_typing',
            'faulthandler', '_string', '_lsprof', 'pyexpat',
            '_elementtree', '_multibytecodec', '_codecs_cn', '_codecs_hk',
            '_codecs_iso2022', '_codecs_jp', '_codecs_kr', '_codecs_tw',
        }

        # Standard library module names (top-level)
        self.known_stdlib = {
            # Core modules
            'abc', 'aifc', 'argparse', 'ast', 'asynchat', 'asyncio',
            'asyncore', 'atexit', 'base64', 'bdb', 'binascii', 'binhex',
            'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb',
            'chunk', 'cmath', 'cmd', 'code', 'codecs', 'codeop',
            'collections', 'colorsys', 'compileall', 'concurrent',
            'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg',
            'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses',
            'datetime', 'dbm', 'decimal', 'difflib', 'dis', 'distutils',
            'doctest', 'email', 'encodings', 'enum', 'errno',
            'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch',
            'fractions', 'ftplib', 'functools', 'gc', 'genericpath',
            'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip',
            'hashlib', 'heapq', 'hmac', 'html', 'http', 'idlelib',
            'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io',
            'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3',
            'linecache', 'locale', 'logging', 'lzma', 'mailbox',
            'mailcap', 'marshal', 'math', 'mimetypes', 'mmap',
            'modulefinder', 'multiprocessing', 'netrc', 'nntplib',
            'ntpath', 'numbers', 'opcode', 'operator', 'optparse', 'os',
            'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
            'platform', 'plistlib', 'poplib', 'posix', 'posixpath',
            'pprint', 'profile', 'pstats', 'pty', 'pwd', 'py_compile',
            'pyclbr', 'pydoc', 'queue', 'quopri', 'random', 're',
            'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy',
            'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
            'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr',
            'socket', 'socketserver', 'spwd', 'sqlite3', 'sre_compile',
            'sre_constants', 'sre_parse', 'ssl', 'stat', 'statistics',
            'string', 'stringprep', 'struct', 'subprocess', 'sunau',
            'symbol', 'symtable', 'sys', 'sysconfig', 'syslog',
            'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios',
            'test', 'textwrap', 'threading', 'time', 'timeit', 'tkinter',
            'token', 'tokenize', 'trace', 'traceback', 'tracemalloc',
            'tty', 'turtle', 'types', 'typing', 'unicodedata', 'unittest',
            'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref',
            'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib',
            'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
            'zoneinfo', '__future__', '_thread', 'array', 'atexit',
            'cmath', 'mmap', 'select', 'nt',
            # Private stdlib C extensions
            '_abc', '_bisect', '_blake2', '_bz2', '_codecs', '_collections',
            '_collections_abc', '_compat_pickle', '_compression',
            '_contextvars', '_csv', '_ctypes', '_datetime', '_decimal',
            '_elementtree', '_frozen_importlib', '_frozen_importlib_external',
            '_functools', '_hashlib', '_heapq', '_imp', '_io', '_json',
            '_locale', '_lsprof', '_lzma', '_markupbase', '_md5',
            '_multibytecodec', '_multiprocessing', '_opcode', '_operator',
            '_osx_support', '_pickle', '_posixsubprocess', '_py_abc',
            '_pydecimal', '_pyio', '_queue', '_random', '_sha1', '_sha256',
            '_sha3', '_sha512', '_signal', '_sitebuiltins', '_socket',
            '_sqlite3', '_sre', '_ssl', '_stat', '_string', '_strptime',
            '_struct', '_symtable', '_sysconfigdata', '_thread',
            '_threading_local', '_tracemalloc', '_typing', '_uuid',
            '_warnings', '_weakref', '_weakrefset', '_zoneinfo',
            '_statistics', '_asyncio', '_curses',
            # Deprecated / version-specific stdlib
            '_bootlocale',  # removed in 3.10
            '_py_warnings',
            # Import system sub-modules
            'importlib', 'importlib._bootstrap', 'importlib._bootstrap_external',
            'importlib.abc', 'importlib.machinery', 'importlib.metadata',
            'importlib.resources', 'importlib.util',
            # Encoding sub-modules (always stdlib)
            'encodings.aliases', 'encodings.utf_8', 'encodings.latin_1',
            'encodings.ascii', 'encodings.idna', 'encodings.charmap',
            'encodings.cp437', 'encodings.utf_16', 'encodings.utf_32',
        }

        # Patterns that indicate stdlib sub-modules
        self.stdlib_prefixes = [
            'encodings.', 'email.', 'http.', 'html.', 'json.',
            'logging.', 'xml.', 'xmlrpc.', 'urllib.', 'unittest.',
            'multiprocessing.', 'concurrent.', 'collections.',
            'importlib.', 'ctypes.', 'sqlite3.', 'curses.',
            'distutils.', 'dbm.', 'lib2to3.', 'tkinter.',
            'asyncio.', 'test.', 'idlelib.', 'wsgiref.',
        ]

        # Patterns that indicate internal/infrastructure modules
        self.internal_patterns = [
            r'^_distutils.*',
            r'^setuptools(\.|$)',
            r'^pkg_resources(\.|$)',
            r'^pip(\.|$)',
            r'^wheel(\.|$)',
            r'.*\._vendor\..*',
            r'.*\.extern\..*',
            r'.*\.vendored\..*',
            r'^_distutils_hack$',
        ]

        # System/distro hooks — not stdlib proper, but not third-party either
        self.system_hooks = {
            'sitecustomize',       # Python site customization (site.py loads it)
            'usercustomize',       # Python user customization (site.py loads it)
            'apport_python_hook',  # Ubuntu/Debian crash reporter
            'apport',              # Ubuntu/Debian crash reporter package
            'lsb_release',         # Linux Standard Base info (Debian/Ubuntu)
        }

        # Third-party path indicators
        self.third_party_path_markers = [
            'site-packages',
            'dist-packages',
            'vendor-packages',
            'local-packages',
        ]

        # Stdlib path patterns
        self.stdlib_path_patterns = [
            re.compile(r'/lib/python\d+\.\d+/', re.IGNORECASE),
            re.compile(r'/usr/lib/python\d+\.\d+/', re.IGNORECASE),
            re.compile(r'/usr/local/lib/python\d+\.\d+/', re.IGNORECASE),
            re.compile(r'\\Python\d+\\Lib\\', re.IGNORECASE),
        ]

    # ------------------------------------------------------------------
    # Application detection
    # ------------------------------------------------------------------
    def is_application(self, module_name):
        """Check if this is the main application entry point."""
        return module_name in ('__main__', '__mp_main__')

    # ------------------------------------------------------------------
    # Internal module detection
    # ------------------------------------------------------------------
    def is_internal(self, module_name, module_path=None):
        """
        Check if module is internal infrastructure that should be
        filtered from SBOM output (import machinery, vendored deps,
        setuptools internals, etc.)
        """
        # Regex patterns
        for pattern in self.internal_patterns:
            if re.match(pattern, module_name):
                return True

        # Dunder modules (except __main__ which is application)
        if (module_name.startswith('__') and module_name.endswith('__')
                and module_name not in ('__main__', '__mp_main__')):
            return True

        # Path-based: vendored sub-directories
        if module_path and module_path != 'None':
            vendor_markers = ['/_vendor/', '/extern/', '/vendored/',
                              '/setuptools/', '/pip/', '/pkg_resources/']
            for marker in vendor_markers:
                if marker in module_path:
                    return True

        return False

    # ------------------------------------------------------------------
    # System hook detection
    # ------------------------------------------------------------------
    def is_system_hook(self, module_name):
        """Check if module is a system/distro-specific hook."""
        return module_name in self.system_hooks

    # ------------------------------------------------------------------
    # Stdlib detection
    # ------------------------------------------------------------------
    def is_stdlib(self, module_name, module_path=None):
        """Check if module is part of the Python standard library."""
        # Direct name match
        if module_name in self.known_stdlib:
            return True

        # Builtin C module
        if module_name in self.builtin_modules:
            return True

        # System hooks (sitecustomize, apport_python_hook, etc.)
        if module_name in self.system_hooks:
            return True

        # Known stdlib sub-module prefix
        for prefix in self.stdlib_prefixes:
            if module_name.startswith(prefix):
                return True

        # sys.* sub-modules
        if module_name.startswith('sys.'):
            return True

        # Path-based: in python lib dir but NOT in site-packages/dist-packages
        if module_path and module_path != 'None':
            in_third_party = any(m in module_path
                                 for m in self.third_party_path_markers)
            if not in_third_party:
                for pattern in self.stdlib_path_patterns:
                    if pattern.search(module_path):
                        return True
                # lib-dynload is always stdlib
                if 'lib-dynload' in module_path:
                    return True

        # No path and not recognized — private C extensions starting with _
        # are almost always stdlib (e.g. _bisect, _heapq, _bootlocale)
        if (not module_path or module_path == 'None'):
            if module_name.startswith('_') and '.' not in module_name:
                return True

        return False

    # ------------------------------------------------------------------
    # Main classification entry point
    # ------------------------------------------------------------------
    def classify(self, module_name, module_path=None):
        """
        Classify a module into one of:
            application, internal, stdlib, third-party.

        Args:
            module_name: the module name string (e.g. 'flask', 'os')
            module_path: optional __file__ path if available

        Returns:
            str: one of 'application', 'internal', 'stdlib', 'third-party'
        """
        # 1. Application entry points
        if self.is_application(module_name):
            return 'application'

        # 2. Internal/infrastructure (check before stdlib because
        #    setuptools.* could match distutils prefix)
        if self.is_internal(module_name, module_path):
            return 'internal'

        # 3. Standard library (includes system hooks)
        if self.is_stdlib(module_name, module_path):
            return 'stdlib'

        # 4. Everything else is third-party
        return 'third-party'

    # ------------------------------------------------------------------
    # Batch classification with path extraction
    # ------------------------------------------------------------------
    def classify_modules(self, modules):
        """
        Classify a list of module tuples from Module_Extractor.

        Args:
            modules: list of (addr, name, sources, pid, comm, mod_obj)

        Returns:
            dict with keys 'application', 'internal', 'stdlib', 'third-party',
            each mapping to a list of the same tuples.
        """
        result = {
            'application': [],
            'internal': [],
            'stdlib': [],
            'third-party': [],
        }

        for entry in modules:
            addr, name, sources, pid, comm, mod_obj = entry

            # Try to get __file__ for better classification
            module_path = self._extract_path(mod_obj)

            category = self.classify(name, module_path)
            result[category].append(entry)

        return result

    # ------------------------------------------------------------------
    # Group modules by top-level parent
    # ------------------------------------------------------------------
    def group_by_parent(self, modules):
        """
        Group modules by their top-level parent name.

        e.g. json.decoder, json.encoder → grouped under 'json'
             collections.abc → grouped under 'collections'

        Args:
            modules: list of (addr, name, sources, pid, comm, mod_obj)

        Returns:
            dict: {parent_name: [module_tuples]}
        """
        groups = {}
        for entry in modules:
            name = entry[1]
            parent = name.split('.')[0]
            if parent not in groups:
                groups[parent] = []
            groups[parent].append(entry)
        return groups

    # ------------------------------------------------------------------
    # Full analysis: classify + group
    # ------------------------------------------------------------------
    def analyze(self, modules):
        """
        Classify all modules, then group each category by parent.

        Args:
            modules: list of (addr, name, sources, pid, comm, mod_obj)

        Returns:
            dict: {
                'application': {parent: [entries]},
                'internal':    {parent: [entries]},
                'stdlib':      {parent: [entries]},
                'third-party': {parent: [entries]},
                'counts': {category: int},
            }
        """
        classified = self.classify_modules(modules)

        result = {'counts': {}}
        for category, entries in classified.items():
            result[category] = self.group_by_parent(entries)
            result['counts'][category] = len(entries)

        result['counts']['total'] = len(modules)
        result['counts']['top_level'] = sum(
            len(groups) for cat, groups in result.items() if cat != 'counts'
        )

        return result

    # ------------------------------------------------------------------
    # Helper: extract __file__ or __path__ from a module object
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_path(mod_obj):
        """Try to read __file__ or __path__ from a PyModuleObject."""
        try:
            module_obj = mod_obj.cast_to("PyModuleObject")
            mod_dict = module_obj.get_dict2()
            if '__file__' in mod_dict:
                return mod_dict['__file__'].get_value()
            elif '__path__' in mod_dict:
                return str(mod_dict['__path__'].get_value())
        except Exception:
            pass
        return None
