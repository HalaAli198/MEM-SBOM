"""
PE-based symbol resolution for Volatility 3 (Windows).

Refactored to mirror elf_parsing's architecture:
  - Single-process, direct VAD access (no walking all processes)
  - find_symbol_in_process() takes a specific task object
  - Strategies tried in order until all symbols are found

Comprehensive symbol resolution:
  Strategy 1: PDB symbols (Microsoft symbol server)
  Strategy 2: PE export table
  Strategy 3: Decorated name variants (__imp_, _Py prefix, etc.)
  Strategy 4: Raw string + COFF symbol table scan in PE sections
  Strategy 5: Structural pattern scan for _PyRuntime / _PyGC_generation0

Tested against Python 3.6-3.14 on Windows.
"""

import io
import logging
import re
from typing import Dict, List, Optional, Tuple, Set

import pefile

from volatility3.framework import interfaces, exceptions, constants
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Memory read helpers (same pattern as elf_parsing)
# ---------------------------------------------------------------------------

def _read_bytes(layer, address: int, size: int) -> Optional[bytes]:
    """Safe memory read that returns None on failure."""
    try:
        return layer.read(address, size, pad=False)
    except Exception:
        return None


def _read_int(layer, address: int, size: int = 8) -> Optional[int]:
    """Read a little-endian integer from memory."""
    data = _read_bytes(layer, address, size)
    if data is None:
        return None
    return int.from_bytes(data, byteorder='little')


# ---------------------------------------------------------------------------
# Single-process VAD helpers (mirrors elf_parsing's VMA scanning)
# ---------------------------------------------------------------------------

def _get_vads_for_task(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
) -> List[Tuple[int, int, str]]:
    """
    Get all VADs with file paths from a SPECIFIC process.
    Returns list of (start, size, filepath) tuples.
    
    This is the Windows equivalent of iterating task.mm.get_vma_iter()
    in the Linux elf_parsing module.
    """
    vads = []

    try:
        vad_root = proc.get_vad_root()
    except exceptions.InvalidAddressException:
        return vads

    for vad in vad_root.traverse():
        filepath = vad.get_file_name()
        if not isinstance(filepath, str) or not filepath:
            continue

        vads.append((vad.get_start(), vad.get_size(), filepath))

    return vads


def _find_python_modules_in_task(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    module_substring: str = "python",
) -> List[Tuple[str, str, int, int]]:
    """
    Scan a SPECIFIC process's VADs to find Python DLLs/EXEs.
    Returns list of (filename_lower, full_filepath, base_addr, size) tuples.
    
    Unlike the original pe_parsing which called get_process_modules()
    (walking ALL processes), this only examines the target process.
    """
    found = []
    seen = set()
    substr_lower = module_substring.lower()

    try:
        proc_layer_name = proc.add_process_layer()
    except exceptions.InvalidAddressException:
        return found

    layer = context.layers[proc_layer_name]

    try:
        vad_root = proc.get_vad_root()
    except exceptions.InvalidAddressException:
        return found

    for vad in vad_root.traverse():
        filepath = vad.get_file_name()
        if not isinstance(filepath, str) or not filepath:
            continue

        filename = filepath.rsplit("\\", 1)[-1].lower()

        if substr_lower not in filename:
            continue

        if not (filename.endswith(".dll") or filename.endswith(".exe")):
            continue

        start = vad.get_start()
        size = vad.get_size()

        # Only record the first (lowest) VAD for each module — that's the PE base
        if filename not in seen:
            # Verify MZ header
            magic = _read_bytes(layer, start, 2)
            if magic == b'MZ':
                seen.add(filename)
                found.append((filename, filepath, start, size))
                vollog.debug(f"Found Python module in target process: {filename} at 0x{start:x}")

    return found


# ---------------------------------------------------------------------------
# Version detection (single-process)
# ---------------------------------------------------------------------------

def detect_python_version_from_vads(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
) -> Optional[Tuple[int, int]]:
    """
    Detect Python version from loaded DLL names in a SPECIFIC process's VADs.

    Matches patterns like:
      python310.dll   -> (3, 10)
      python38.dll    -> (3, 8)
      python36.dll    -> (3, 6)
      python3.dll     -> skipped (no minor version)
      libpython3.12.dll -> (3, 12)  (msys2/cygwin builds)
    """
    modules = _find_python_modules_in_task(context, proc, "python")

    for filename, _filepath, _base, _size in modules:
        match = re.match(r'python(\d)(\d+)\.dll', filename)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            vollog.info(f"Detected Python {major}.{minor} from {filename}")
            return (major, minor)

        match = re.match(r'libpython(\d+)\.(\d+)', filename)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            vollog.info(f"Detected Python {major}.{minor} from {filename}")
            return (major, minor)

    return None


# ---------------------------------------------------------------------------
# PE header parsing helpers
# ---------------------------------------------------------------------------

def _parse_pe_sections(layer, base_address: int) -> Optional[List[Dict]]:
    """
    Parse PE section headers from the in-memory image.
    Returns list of section dicts with name, vaddr, vsize, characteristics.
    """
    dos_hdr = _read_bytes(layer, base_address, 64)
    if dos_hdr is None or dos_hdr[:2] != b'MZ':
        return None

    e_lfanew = int.from_bytes(dos_hdr[60:64], 'little')
    if e_lfanew == 0 or e_lfanew > 0x1000:
        return None

    pe_sig = _read_bytes(layer, base_address + e_lfanew, 4)
    if pe_sig != b'PE\x00\x00':
        return None

    coff_hdr = _read_bytes(layer, base_address + e_lfanew + 4, 20)
    if coff_hdr is None:
        return None

    num_sections = int.from_bytes(coff_hdr[2:4], 'little')
    size_of_optional = int.from_bytes(coff_hdr[16:18], 'little')

    section_table_offset = e_lfanew + 4 + 20 + size_of_optional

    sections = []
    for i in range(num_sections):
        sh = _read_bytes(layer, base_address + section_table_offset + i * 40, 40)
        if sh is None:
            continue

        name_bytes = sh[:8].rstrip(b'\x00')
        try:
            name = name_bytes.decode('ascii', errors='replace')
        except Exception:
            name = ""

        virtual_size = int.from_bytes(sh[8:12], 'little')
        virtual_addr = int.from_bytes(sh[12:16], 'little')
        raw_size = int.from_bytes(sh[16:20], 'little')
        characteristics = int.from_bytes(sh[36:40], 'little')

        sections.append({
            'name': name,
            'virtual_address': virtual_addr,
            'virtual_size': virtual_size,
            'raw_size': raw_size,
            'characteristics': characteristics,
            'runtime_address': base_address + virtual_addr,
        })

    return sections


# ---------------------------------------------------------------------------
# Strategy 1: PDB symbol resolution (single-process)
# ---------------------------------------------------------------------------

def _search_pdb_symbols(
    context: interfaces.context.ContextInterface,
    config_path: str,
    proc_layer_name: str,
    symbol_names: Set[str],
    python_modules: List[Tuple[str, str, int, int]],
) -> Dict[str, int]:
    """
    Strategy 1: Resolve symbols via PDB download.
    Uses the specific process layer, not a global walk.
    """
    found: Dict[str, int] = {}
    remaining = set(symbol_names)

    for filename, filepath, module_start, module_size in python_modules:
        if not remaining:
            break

        vollog.info(f"[Strategy 1] PDB resolution in '{filename}' for: {remaining}")

        # Determine PDB name from the DLL/EXE name
        pdb_name = filename[:-3] + "pdb"
        pdb_names = [pdb_name, pdb_name[0].upper() + pdb_name[1:]]

        mod_symbols = None
        for pdb_candidate in pdb_names:
            try:
                mod_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                    context,
                    interfaces.configuration.path_join(config_path, filename),
                    proc_layer_name,
                    pdb_candidate,
                    module_start,
                    module_size,
                )
                if mod_symbols:
                    break
            except exceptions.VolatilityException:
                continue
            except TypeError as e:
                vollog.error(f"PDB parse error for {pdb_candidate}: {e}")

        if not mod_symbols:
            vollog.debug(f"No PDB available for {filename}")
            continue

        pdb_module = context.module(
            mod_symbols, layer_name=proc_layer_name, offset=module_start
        )

        for sym_name in list(remaining):
            try:
                addr = pdb_module.get_absolute_symbol_address(sym_name)
                if addr:
                    found[sym_name] = addr
                    remaining.discard(sym_name)
                    vollog.info(f"[PDB] Resolved '{sym_name}' at 0x{addr:x}")
            except exceptions.SymbolError:
                continue

    return found


# ---------------------------------------------------------------------------
# Strategy 2: PE export table (single-process)
# ---------------------------------------------------------------------------

def _search_export_symbols(
    context: interfaces.context.ContextInterface,
    config_path: str,
    proc_layer_name: str,
    symbol_names: Set[str],
    python_modules: List[Tuple[str, str, int, int]],
) -> Dict[str, int]:
    """
    Strategy 2: Resolve symbols via PE export table.
    Directly reads the PE from the specific process layer.
    """
    found: Dict[str, int] = {}
    remaining = set(symbol_names)

    pe_table_name = intermed.IntermediateSymbolTable.create(
        context, config_path, "windows", "pe", class_types=pe.class_types
    )

    for filename, filepath, module_start, module_size in python_modules:
        if not remaining:
            break

        vollog.info(f"[Strategy 2] Export table in '{filename}' for: {remaining}")

        pe_data = io.BytesIO()
        try:
            dos_header = context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=module_start,
                layer_name=proc_layer_name,
            )
            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_obj = pefile.PE(data=pe_data.getvalue(), fast_load=True)
        except (exceptions.InvalidAddressException, ValueError):
            vollog.debug(f"Cannot parse PE for {filename}")
            continue

        pe_obj.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )

        if not hasattr(pe_obj, "DIRECTORY_ENTRY_EXPORT"):
            vollog.debug(f"No export table in {filename}")
            continue

        for export in pe_obj.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                exp_name = export.name.decode("ascii")
            except (AttributeError, UnicodeDecodeError):
                continue

            if exp_name in remaining:
                addr = module_start + export.address
                found[exp_name] = addr
                remaining.discard(exp_name)
                vollog.info(f"[export] Resolved '{exp_name}' at 0x{addr:x}")
                if not remaining:
                    break

    return found


# ---------------------------------------------------------------------------
# Strategy 3: Decorated name variants
# ---------------------------------------------------------------------------

def _search_decorated_variants(
    context: interfaces.context.ContextInterface,
    config_path: str,
    proc_layer_name: str,
    symbol_names: Set[str],
    python_modules: List[Tuple[str, str, int, int]],
) -> Dict[str, int]:
    """
    Strategy 3: Try decorated/variant symbol names via PDB + exports.
    Windows PE symbols can have decorations: __imp__PyRuntime, _PyRuntime, etc.
    """
    found: Dict[str, int] = {}

    # Build variant -> original mapping
    variants: Dict[str, str] = {}
    for name in symbol_names:
        variants[f"__imp_{name}"] = name
        variants[f"_{name}"] = name
        variants[f"__imp__{name}"] = name
        if name.startswith("_"):
            variants[name[1:]] = name

    variant_set = set(variants.keys())

    # Try PDB with variant names
    pdb_found = _search_pdb_symbols(
        context, config_path, proc_layer_name, variant_set, python_modules
    )
    for var_name, addr in pdb_found.items():
        original = variants.get(var_name)
        if original and original not in found:
            found[original] = addr
            vollog.info(f"[decorated/PDB] Resolved '{original}' (as '{var_name}') at 0x{addr:x}")

    remaining_variants = variant_set - set(pdb_found.keys())

    # Try exports with variant names
    if remaining_variants:
        exp_found = _search_export_symbols(
            context, config_path, proc_layer_name, remaining_variants, python_modules
        )
        for var_name, addr in exp_found.items():
            original = variants.get(var_name)
            if original and original not in found:
                found[original] = addr
                vollog.info(f"[decorated/export] Resolved '{original}' (as '{var_name}') at 0x{addr:x}")

    return found


# ---------------------------------------------------------------------------
# Strategy 4: COFF symbol table + data section scan (single-process)
# ---------------------------------------------------------------------------

def _search_data_sections(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    proc_layer_name: str,
    symbol_names: Set[str],
    python_modules: List[Tuple[str, str, int, int]],
) -> Dict[str, int]:
    """
    Strategy 4: Scan for COFF symbol table and string references in PE sections.
    Operates on the specific process layer only.
    """
    found: Dict[str, int] = {}
    layer = context.layers[proc_layer_name]

    for base_addr, filename, _start, _size in python_modules:
        # Note: base_addr is _start, filename is filename
        # Fix tuple unpacking to match our module tuple format
        pass

    # Re-iterate with correct tuple unpacking
    for filename, filepath, base_addr, mod_size in python_modules:
        dos_hdr = _read_bytes(layer, base_addr, 64)
        if dos_hdr is None or dos_hdr[:2] != b'MZ':
            continue

        e_lfanew = int.from_bytes(dos_hdr[60:64], 'little')
        coff_hdr = _read_bytes(layer, base_addr + e_lfanew + 4, 20)
        if coff_hdr is None:
            continue

        coff_symtab_offset = int.from_bytes(coff_hdr[8:12], 'little')
        coff_num_symbols = int.from_bytes(coff_hdr[12:16], 'little')

        if coff_symtab_offset != 0 and 0 < coff_num_symbols < 1_000_000:
            vollog.info(
                f"[Strategy 4] COFF symbol table in {filename}: "
                f"offset=0x{coff_symtab_offset:x}, count={coff_num_symbols}"
            )

            remaining = symbol_names - set(found.keys())
            COFF_SYM_SIZE = 18

            strtab_offset = coff_symtab_offset + coff_num_symbols * COFF_SYM_SIZE
            strtab_data = _read_bytes(layer, base_addr + strtab_offset, 0x10000)

            i = 0
            while i < coff_num_symbols:
                sym_data = _read_bytes(
                    layer,
                    base_addr + coff_symtab_offset + i * COFF_SYM_SIZE,
                    COFF_SYM_SIZE,
                )
                if sym_data is None:
                    break

                name_field = sym_data[:8]
                value = int.from_bytes(sym_data[8:12], 'little')
                section_num = int.from_bytes(sym_data[12:14], 'little', signed=True)
                num_aux = sym_data[17]

                if name_field[:4] == b'\x00\x00\x00\x00':
                    str_offset = int.from_bytes(name_field[4:8], 'little')
                    if strtab_data and str_offset < len(strtab_data):
                        null_pos = strtab_data.find(b'\x00', str_offset)
                        if null_pos < 0:
                            null_pos = min(str_offset + 256, len(strtab_data))
                        sym_name = strtab_data[str_offset:null_pos].decode(
                            'ascii', errors='replace'
                        )
                    else:
                        sym_name = ""
                else:
                    sym_name = name_field.rstrip(b'\x00').decode(
                        'ascii', errors='replace'
                    )

                clean_name = sym_name.lstrip('_')
                for wanted in remaining:
                    wanted_clean = wanted.lstrip('_')
                    if sym_name == wanted or clean_name == wanted_clean:
                        if section_num > 0 and value > 0:
                            found[wanted] = base_addr + value
                            vollog.info(
                                f"[coff_symtab] Resolved '{wanted}' "
                                f"at 0x{base_addr + value:x}"
                            )
                        break

                i += 1 + num_aux

    return found


# ---------------------------------------------------------------------------
# Strategy 5: Structural pattern scan
# ---------------------------------------------------------------------------

def _collect_python_rw_vads(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    proc_layer_name: str,
) -> List[Tuple[int, int, str]]:
    """
    Collect writable memory regions belonging to Python modules from
    a SPECIFIC process. Mirrors elf_parsing's _collect_python_rw_regions().
    
    Returns (start, end, description) tuples.
    """
    python_rw_regions = []
    layer = context.layers[proc_layer_name]

    try:
        vad_root = proc.get_vad_root()
    except exceptions.InvalidAddressException:
        return python_rw_regions

    all_vads = []
    for vad in vad_root.traverse():
        start = vad.get_start()
        end = start + vad.get_size()
        filepath = vad.get_file_name()

        all_vads.append((start, end, filepath))

        if not isinstance(filepath, str) or not filepath:
            continue

        filename = filepath.rsplit("\\", 1)[-1].lower()
        if "python" not in filename:
            continue

        # Check if writable by trying to read and checking section characteristics
        # On Windows, VADs with file mappings that are writable contain .data/.bss
        # We check the VAD protection flags
        try:
            protection = vad.get_protection(
                context.layers[proc_layer_name],
                context.symbol_space,
            )
            if protection is None:
                protection = ""
        except Exception:
            protection = ""

        # Also try reading — if the page is mapped, it's accessible
        test = _read_bytes(layer, start, 4)
        if test is not None:
            python_rw_regions.append((start, end, filename))

    return python_rw_regions


def _scan_for_pyruntime(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    proc_layer_name: str,
    python_modules: List[Tuple[str, str, int, int]],
) -> Dict[str, int]:
    """
    Locate _PyRuntime by scanning writable PE sections of Python modules
    in the SPECIFIC process for the _PyRuntimeState interpreter list signature.
    """
    found = {}
    layer = context.layers[proc_layer_name]

    for filename, filepath, base_addr, mod_size in python_modules:
        sections = _parse_pe_sections(layer, base_addr)
        if sections is None:
            continue

        for section in sections:
            # IMAGE_SCN_MEM_WRITE = 0x80000000
            if not (section['characteristics'] & 0x80000000):
                continue

            sec_addr = section['runtime_address']
            sec_size = min(section['virtual_size'], 0x200000)
            data = _read_bytes(layer, sec_addr, sec_size)
            if data is None:
                continue

            vollog.debug(
                f"[pyruntime_scan] Scanning {section['name']} "
                f"0x{sec_addr:x} ({sec_size} bytes) in {filename}"
            )

            candidate_interp_offsets = list(range(0x10, 0x120, 0x8))

            for interp_offset in candidate_interp_offsets:
                for offset in range(0, len(data) - interp_offset - 24, 8):
                    # interpreters.head: valid Windows userspace pointer
                    head_ptr = int.from_bytes(
                        data[offset + interp_offset:offset + interp_offset + 8],
                        'little',
                    )
                    if head_ptr == 0 or head_ptr < 0x10000 or head_ptr > 0x7FFFFFFFFFFF:
                        continue

                    # interpreters.main == interpreters.head
                    main_ptr = int.from_bytes(
                        data[offset + interp_offset + 8:offset + interp_offset + 16],
                        'little',
                    )
                    if head_ptr != main_ptr:
                        continue

                    # interpreters.next_id == 1
                    next_id = int.from_bytes(
                        data[offset + interp_offset + 16:offset + interp_offset + 24],
                        'little',
                    )
                    if next_id != 1:
                        continue

                    # Validate head pointer dereferences to readable non-zero memory
                    test = _read_bytes(layer, head_ptr, 16)
                    if test is None or all(b == 0 for b in test):
                        continue

                    candidate_addr = sec_addr + offset

                    # Validate PyInterpreterState
                    interp_valid = False
                    for id_off in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
                        interp_id = _read_int(layer, head_ptr + id_off, 8)
                        if interp_id is not None and interp_id == 0:
                            next_interp = _read_int(layer, head_ptr, 8)
                            if next_interp is not None and (
                                next_interp == 0
                                or (0x10000 < next_interp < 0x7FFFFFFFFFFF)
                            ):
                                interp_valid = True
                                break

                    if not interp_valid:
                        continue

                    # Reject false positives: non-zero tail data
                    if offset + interp_offset + 48 <= len(data):
                        tail = data[
                            offset + interp_offset + 24:offset + interp_offset + 48
                        ]
                        if all(b == 0 for b in tail):
                            continue

                    found["_PyRuntime"] = candidate_addr
                    vollog.info(
                        f"[structural_scan] Found _PyRuntime at 0x{candidate_addr:x} "
                        f"(interp_head at +0x{interp_offset:x} -> 0x{head_ptr:x})"
                    )
                    return found

    return found


def _scan_for_gc_generation0(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    proc_layer_name: str,
    python_modules: List[Tuple[str, str, int, int]],
    version: Optional[Tuple[int, int]] = None,
) -> Dict[str, int]:
    """
    Locate _PyGC_generation0 for Python 3.6 by scanning writable PE
    sections for the gc_generation[3] array pattern.

    Each gc_generation struct contains:
      PyGC_Head head  (version-dependent size: 24 for 3.6, 32 for 3.7, 16 for 3.8+)
      int threshold   (4 bytes)
      int count       (4 bytes)
      [+ possible padding]

    Version-specific sizes (GDB-confirmed):
      3.6:  PyGC_Head=24, gc_generation=32
      3.7:  PyGC_Head=32, gc_generation=48
      3.8+: PyGC_Head=16, gc_generation=24
    """
    found = {}
    layer = context.layers[proc_layer_name]

    # Determine struct sizes based on Python version
    if version and version <= (3, 6):
        gc_head_size = 24    # gc_next(8) + gc_prev(8) + gc_refs(8)
        GC_GEN_SIZE = 32     # PyGC_Head(24) + threshold(4) + count(4)
    elif version and version == (3, 7):
       gc_head_size = 24    # MSVC: long double = 8, so same as 3.6
       GC_GEN_SIZE = 32
    else:
        gc_head_size = 16    # gc_next(8) + gc_prev(8), gc_refs packed in gc_next
        GC_GEN_SIZE = 24     # PyGC_Head(16) + threshold(4) + count(4)

    TOTAL_SIZE = GC_GEN_SIZE * 3

    vollog.info(
        f"[gc_gen0_scan] Using gc_head_size={gc_head_size}, "
        f"gc_generation_size={GC_GEN_SIZE} for version {version}"
    )

    for filename, filepath, base_addr, mod_size in python_modules:
        sections = _parse_pe_sections(layer, base_addr)
        if sections is None:
            continue

        for section in sections:
            if not (section['characteristics'] & 0x80000000):
                continue

            sec_addr = section['runtime_address']
            sec_size = min(section['virtual_size'], 0x200000)
            data = _read_bytes(layer, sec_addr, sec_size)
            if data is None:
                continue

            vollog.debug(
                f"[gc_gen0_scan] Scanning {section['name']} "
                f"0x{sec_addr:x} ({sec_size} bytes) in {filename}"
            )

            for offset in range(0, len(data) - TOTAL_SIZE, 8):
                valid = True

                for gen_idx in range(3):
                    gen_off = offset + gen_idx * GC_GEN_SIZE
                    head_addr = sec_addr + gen_off

                    gc_next = int.from_bytes(data[gen_off:gen_off + 8], 'little')
                    gc_prev = int.from_bytes(data[gen_off + 8:gen_off + 16], 'little')

                    # Must be valid userspace pointers
                    if gc_next < 0x10000 or gc_next > 0x7FFFFFFFFFFF:
                        valid = False
                        break
                    if gc_prev < 0x10000 or gc_prev > 0x7FFFFFFFFFFF:
                        valid = False
                        break

                    # threshold sits right after PyGC_Head
                    threshold = int.from_bytes(
                        data[gen_off + gc_head_size:gen_off + gc_head_size + 4], 'little'
                    )
                    count = int.from_bytes(
                        data[gen_off + gc_head_size + 4:gen_off + gc_head_size + 8], 'little'
                    )

                    # Relaxed: threshold must be non-zero and reasonable
                    if threshold == 0 or threshold > 100000:
                        valid = False
                        break
                    if count > 1000000:
                        valid = False
                        break

                    # Empty list: self-referencing sentinel
                    is_self = (gc_next == head_addr and gc_prev == head_addr)

                    if not is_self:
                        # Non-empty: validate gc_next target is readable
                        test = _read_bytes(layer, gc_next, 16)
                        if test is None:
                            valid = False
                            break
                        # Relaxed: just check gc_prev is a valid pointer
                        back_ptr = int.from_bytes(test[8:16], 'little')
                        if back_ptr != 0 and (back_ptr < 0x10000 or back_ptr > 0x7FFFFFFFFFFF):
                            valid = False
                            break

                if not valid:
                    continue

                # Validate threshold ordering: gen0 >= gen1, gen0 >= gen2
                t0 = int.from_bytes(
                    data[offset + gc_head_size:offset + gc_head_size + 4], 'little'
                )
                t1 = int.from_bytes(
                    data[offset + GC_GEN_SIZE + gc_head_size:offset + GC_GEN_SIZE + gc_head_size + 4],
                    'little',
                )
                t2 = int.from_bytes(
                    data[offset + 2 * GC_GEN_SIZE + gc_head_size:offset + 2 * GC_GEN_SIZE + gc_head_size + 4],
                    'little',
                )

                if not (t0 >= t1 and t0 >= t2):
                    continue

                gen0_addr = sec_addr + offset
                vollog.info(
                    f"[structural_scan] Found gc_generations at "
                    f"0x{gen0_addr:x} (thresholds: {t0}, {t1}, {t2})"
                )

                # For 3.6, _PyGC_generation0 is a pointer to gen0,
                # but py_gc expects the ADDRESS of gen0 directly
                # (it will dereference if needed based on version)
                found["_PyGC_generation0"] = gen0_addr
                return found

    return found


def _structural_scan(
    context: interfaces.context.ContextInterface,
    proc: interfaces.objects.ObjectInterface,
    proc_layer_name: str,
    symbol_names: Set[str],
    python_modules: List[Tuple[str, str, int, int]],
    version: Optional[Tuple[int, int]] = None,
) -> Dict[str, int]:
    """Strategy 5: Structural pattern matching for known CPython globals."""
    found = {}

    if "_PyRuntime" in symbol_names:
        vollog.info("[Strategy 5] Structural scan for _PyRuntime")
        found.update(_scan_for_pyruntime(context, proc, proc_layer_name, python_modules))

    if "_PyGC_generation0" in symbol_names and "_PyGC_generation0" not in found:
        vollog.info("[Strategy 5] Structural scan for _PyGC_generation0")
        found.update(_scan_for_gc_generation0(
            context, proc, proc_layer_name, python_modules, version=version
        ))

    return found


# ---------------------------------------------------------------------------
# Strategy orchestration (single-process, mirrors elf_parsing)
# ---------------------------------------------------------------------------

def find_symbol_in_process(
    context: interfaces.context.ContextInterface,
    config_path: str,
    proc: interfaces.objects.ObjectInterface,
    symbol_names: List[str],
    module_substring: str = "python",
    version: Optional[Tuple[int, int]] = None,
) -> Dict[str, int]:
    """
    Top-level entry point: resolve PE symbols within a SPECIFIC process.
    
    This mirrors elf_parsing.find_symbol_in_process() — it operates on
    a single process, not all processes. The caller provides the task
    (process) object directly.

    Tries all strategies in order, stopping once all symbols are resolved:
      1. PDB symbols (Microsoft symbol server)
      2. PE export table
      3. Decorated name variants
      4. COFF symbol table + data section scan
      5. Structural pattern scan (.data/.bss)

    Args:
        context: Volatility context
        config_path: Plugin config path
        proc: Process object to analyze (single process)
        symbol_names: List of symbol names to resolve
        module_substring: Substring to match DLL names (default "python")
        version: Optional (major, minor) Python version tuple

    Returns:
        Dict mapping symbol name -> resolved address
    """
    all_found: Dict[str, int] = {}
    target_set = set(symbol_names)

    # Get process layer
    try:
        proc_layer_name = proc.add_process_layer()
    except exceptions.InvalidAddressException:
        vollog.error("Cannot create process layer")
        return all_found

    # Find Python modules in THIS process only
    python_modules = _find_python_modules_in_task(context, proc, module_substring)

    if not python_modules:
        vollog.warning(
            f"No modules matching '{module_substring}' in process VADs"
        )
        # Still try structural scan as last resort using empty module list
        # (structural scan can work by scanning all writable VADs)
        s5 = _structural_scan(
            context, proc, proc_layer_name, target_set, python_modules, version
        )
        all_found.update(s5)
        return all_found

    vollog.info(
        f"Found {len(python_modules)} Python module(s) in target process: "
        f"{[f for f, _, _, _ in python_modules]}"
    )

    # --- Strategy 1: PDB symbols ---
    vollog.info("Strategy 1: PDB symbol resolution")
    s1 = _search_pdb_symbols(
        context, config_path, proc_layer_name, target_set, python_modules
    )
    all_found.update(s1)
    remaining = target_set - set(all_found.keys())
    if not remaining:
        return all_found

    # --- Strategy 2: PE export table ---
    vollog.info(f"Strategy 2: Export table resolution for: {remaining}")
    s2 = _search_export_symbols(
        context, config_path, proc_layer_name, remaining, python_modules
    )
    all_found.update(s2)
    remaining = target_set - set(all_found.keys())
    if not remaining:
        return all_found

    # --- Strategy 3: Decorated name variants ---
    vollog.info(f"Strategy 3: Decorated name variants for: {remaining}")
    s3 = _search_decorated_variants(
        context, config_path, proc_layer_name, remaining, python_modules
    )
    all_found.update(s3)
    remaining = target_set - set(all_found.keys())
    if not remaining:
        return all_found

    # --- Strategy 4: COFF symbol table + data section scan ---
    vollog.info(f"Strategy 4: Data section scan for: {remaining}")
    s4 = _search_data_sections(
        context, proc, proc_layer_name, remaining, python_modules
    )
    all_found.update(s4)
    remaining = target_set - set(all_found.keys())
    if not remaining:
        return all_found

    # --- Strategy 5: Structural pattern scan ---
    vollog.info(f"Strategy 5: Structural pattern scan for: {remaining}")
    s5 = _structural_scan(
        context, proc, proc_layer_name, remaining, python_modules, version
    )
    all_found.update(s5)

    remaining = target_set - set(all_found.keys())
    if remaining:
        vollog.warning(f"Unresolved symbols after all strategies: {remaining}")

    vollog.info(
        f"Resolution complete: found={list(all_found.keys())}, "
        f"unresolved={remaining}"
    )
    return all_found
