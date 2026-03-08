"""
Memory-only ELF symbol resolution for Volatility 3.

Resolves ELF symbols from process memory dumps without on-disk binaries
or section headers — only kernel-mapped PT_LOAD content is needed.

Strategies (tried in order):
  1. Section headers (when within a PT_LOAD segment)
  2. PT_DYNAMIC (.dynsym/.dynstr, always mapped)
  3. LTO variants (.lto_priv suffix from GCC LTO)
  4. Mapped .symtab scan (pattern-match Elf64_Sym in loaded segments)
  5. BSS/data scan (structural match for _PyRuntimeState)

Tested against Python 3.7–3.14, ELF32/ELF64, PIE and non-PIE.
"""

import logging
from typing import Dict, Tuple, List, Optional, Set

from volatility3.framework import interfaces, exceptions, constants
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Memory read helpers
# ---------------------------------------------------------------------------

def _read_bytes(layer, address: int, size: int) -> Optional[bytes]:
    """Safe memory read that returns None on failure (unmapped, paged out)."""
    try:
        return layer.read(address, size, pad=False)
    except Exception:
        return None


def _read_int(layer, address: int, size: int = 8) -> Optional[int]:
    """Read a little-endian integer from memory. Returns None on failure."""
    data = _read_bytes(layer, address, size)
    if data is None:
        return None
    return int.from_bytes(data, byteorder='little')


# ---------------------------------------------------------------------------
# ELF header parsing
# ---------------------------------------------------------------------------

def parse_elf_header(layer, base_address: int) -> Optional[Dict]:
    """
    Parse essential ELF header fields (program/section header offsets,
    counts, entry sizes). Supports both ELF32 and ELF64.
    Returns None if the ELF magic is missing or the header is unreadable.
    """
    magic = _read_bytes(layer, base_address, 16)
    if magic is None or magic[:4] != b'\x7fELF':
        return None

    ei_class = magic[4]
    if ei_class not in (1, 2):
        return None

    is_64 = (ei_class == 2)

    if is_64:
        hdr = _read_bytes(layer, base_address, 64)
        if hdr is None or len(hdr) < 64:
            return None
        e_type      = int.from_bytes(hdr[16:18], 'little')
        e_phoff     = int.from_bytes(hdr[32:40], 'little')
        e_shoff     = int.from_bytes(hdr[40:48], 'little')
        e_phentsize = int.from_bytes(hdr[54:56], 'little')
        e_phnum     = int.from_bytes(hdr[56:58], 'little')
        e_shentsize = int.from_bytes(hdr[58:60], 'little')
        e_shnum     = int.from_bytes(hdr[60:62], 'little')
        e_shstrndx  = int.from_bytes(hdr[62:64], 'little')
    else:
        hdr = _read_bytes(layer, base_address, 52)
        if hdr is None or len(hdr) < 52:
            return None
        e_type      = int.from_bytes(hdr[16:18], 'little')
        e_phoff     = int.from_bytes(hdr[28:32], 'little')
        e_shoff     = int.from_bytes(hdr[32:36], 'little')
        e_phentsize = int.from_bytes(hdr[42:44], 'little')
        e_phnum     = int.from_bytes(hdr[44:46], 'little')
        e_shentsize = int.from_bytes(hdr[46:48], 'little')
        e_shnum     = int.from_bytes(hdr[48:50], 'little')
        e_shstrndx  = int.from_bytes(hdr[50:52], 'little')

    # ET_DYN (3) = PIE executable or shared library
    # ET_EXEC (2) = fixed-address executable
    is_pie = (e_type == 3)

    return {
        "ei_class":    ei_class,
        "is_64":       is_64,
        "e_type":      e_type,
        "is_pie":      is_pie,
        "e_phoff":     e_phoff,
        "e_phentsize": e_phentsize,
        "e_phnum":     e_phnum,
        "e_shoff":     e_shoff,
        "e_shentsize": e_shentsize,
        "e_shnum":     e_shnum,
        "e_shstrndx":  e_shstrndx,
    }


def _resolve_addr(base: int, value: int, is_pie: bool) -> int:
    """Convert ELF virtual address to runtime address (PIE-aware)."""
    return (base + value) if is_pie else value


# ---------------------------------------------------------------------------
# Program header parsing
# ---------------------------------------------------------------------------

def parse_load_segments(layer, base_address: int, elf_info: Dict) -> List[Dict]:
    """
    Walk the program header table and collect all segment descriptors.
    PT_LOAD segments define the file-to-vaddr mapping used by the kernel
    loader; PT_DYNAMIC is needed for dynamic symbol resolution.
    """
    segments = []
    is_64 = elf_info["is_64"]
    phdr_base = base_address + elf_info["e_phoff"]

    for i in range(elf_info["e_phnum"]):
        phdr = _read_bytes(layer, phdr_base + i * elf_info["e_phentsize"],
                           elf_info["e_phentsize"])
        if phdr is None:
            continue

        p_type = int.from_bytes(phdr[0:4], 'little')

        if is_64:
            p_flags  = int.from_bytes(phdr[4:8], 'little')
            p_offset = int.from_bytes(phdr[8:16], 'little')
            p_vaddr  = int.from_bytes(phdr[16:24], 'little')
            p_filesz = int.from_bytes(phdr[32:40], 'little')
            p_memsz  = int.from_bytes(phdr[40:48], 'little')
        else:
            p_offset = int.from_bytes(phdr[4:8], 'little')
            p_vaddr  = int.from_bytes(phdr[8:12], 'little')
            p_filesz = int.from_bytes(phdr[16:20], 'little')
            p_memsz  = int.from_bytes(phdr[20:24], 'little')
            p_flags  = int.from_bytes(phdr[24:28], 'little')

        segments.append({
            "type":    p_type,
            "flags":   p_flags,
            "offset":  p_offset,
            "vaddr":   p_vaddr,
            "filesz":  p_filesz,
            "memsz":   p_memsz,
        })

    return segments


def file_offset_to_vaddr(segments: List[Dict], file_offset: int, is_pie: bool,
                          base_address: int) -> Optional[int]:
    """
    Translate an ELF file offset to a runtime virtual address using
    PT_LOAD mappings. Returns None if the offset falls outside all
    loaded segments (i.e. the data is not present in the memory dump).
    """
    for seg in segments:
        if seg["type"] != 1:  # PT_LOAD
            continue
        if seg["offset"] <= file_offset < seg["offset"] + seg["filesz"]:
            vaddr = seg["vaddr"] + (file_offset - seg["offset"])
            return _resolve_addr(base_address, vaddr, is_pie)
    return None


# ---------------------------------------------------------------------------
# Strategy 1: Section header-based symbol resolution
#
# Section headers are normally not mapped into memory, but when the linker
# places them within a PT_LOAD segment, we can access .symtab/.dynsym
# directly. This provides the most complete symbol information.
# ---------------------------------------------------------------------------

def search_section_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """Resolve symbols via section headers (when mapped in a PT_LOAD segment)."""
    found = {}
    remaining = set(symbol_names)
    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]

    e_shoff     = elf_info["e_shoff"]
    e_shentsize = elf_info["e_shentsize"]
    e_shnum     = elf_info["e_shnum"]
    e_shstrndx  = elf_info["e_shstrndx"]

    if e_shoff == 0 or e_shnum == 0:
        return found

    shdr_vaddr = file_offset_to_vaddr(segments, e_shoff, is_pie, base_address)
    if shdr_vaddr is None:
        vollog.debug(f"Section headers at file offset 0x{e_shoff:x} not in any PT_LOAD segment")
        return found

    test = _read_bytes(layer, shdr_vaddr, e_shentsize)
    if test is None:
        vollog.debug(f"Section headers at 0x{shdr_vaddr:x} not readable")
        return found

    # Read .shstrtab to identify section names
    shstrtab_hdr_vaddr = shdr_vaddr + e_shstrndx * e_shentsize
    shstrtab_hdr = _read_bytes(layer, shstrtab_hdr_vaddr, e_shentsize)
    if shstrtab_hdr is None:
        return found

    if is_64:
        shstrtab_file_offset = int.from_bytes(shstrtab_hdr[24:32], 'little')
        shstrtab_size = int.from_bytes(shstrtab_hdr[32:40], 'little')
    else:
        shstrtab_file_offset = int.from_bytes(shstrtab_hdr[16:20], 'little')
        shstrtab_size = int.from_bytes(shstrtab_hdr[20:24], 'little')

    shstrtab_vaddr = file_offset_to_vaddr(segments, shstrtab_file_offset, is_pie, base_address)
    if shstrtab_vaddr is None:
        return found

    shstrtab_data = _read_bytes(layer, shstrtab_vaddr, min(shstrtab_size, 8192))
    if shstrtab_data is None:
        return found

    # Scan SHT_SYMTAB (2) and SHT_DYNSYM (11) sections
    for i in range(e_shnum):
        if not remaining:
            break

        sh_data = _read_bytes(layer, shdr_vaddr + i * e_shentsize, e_shentsize)
        if sh_data is None:
            continue

        sh_type = int.from_bytes(sh_data[4:8], 'little')
        if sh_type not in (2, 11):
            continue

        if is_64:
            sh_offset  = int.from_bytes(sh_data[24:32], 'little')
            sh_size    = int.from_bytes(sh_data[32:40], 'little')
            sh_link    = int.from_bytes(sh_data[40:44], 'little')
            sh_entsize = int.from_bytes(sh_data[56:64], 'little')
        else:
            sh_offset  = int.from_bytes(sh_data[16:20], 'little')
            sh_size    = int.from_bytes(sh_data[20:24], 'little')
            sh_link    = int.from_bytes(sh_data[28:32], 'little')
            sh_entsize = int.from_bytes(sh_data[40:44], 'little')

        if sh_entsize == 0:
            sh_entsize = 24 if is_64 else 16

        symtab_vaddr = file_offset_to_vaddr(segments, sh_offset, is_pie, base_address)
        if symtab_vaddr is None:
            continue

        # Read the associated string table (sh_link)
        strtab_hdr = _read_bytes(layer, shdr_vaddr + sh_link * e_shentsize, e_shentsize)
        if strtab_hdr is None:
            continue

        if is_64:
            strtab_file_offset = int.from_bytes(strtab_hdr[24:32], 'little')
            strtab_size = int.from_bytes(strtab_hdr[32:40], 'little')
        else:
            strtab_file_offset = int.from_bytes(strtab_hdr[16:20], 'little')
            strtab_size = int.from_bytes(strtab_hdr[20:24], 'little')

        strtab_vaddr = file_offset_to_vaddr(segments, strtab_file_offset, is_pie, base_address)
        if strtab_vaddr is None:
            continue

        strtab_data = _read_bytes(layer, strtab_vaddr, min(strtab_size, 1 << 20))
        if strtab_data is None:
            continue

        num_symbols = sh_size // sh_entsize
        section_name = "SHT_SYMTAB" if sh_type == 2 else "SHT_DYNSYM"
        vollog.info(f"Scanning {section_name} at 0x{symtab_vaddr:x} ({num_symbols} entries)")

        for j in range(num_symbols):
            sym_bytes = _read_bytes(layer, symtab_vaddr + j * sh_entsize, sh_entsize)
            if sym_bytes is None:
                continue

            st_name_idx = int.from_bytes(sym_bytes[0:4], 'little')
            if st_name_idx == 0 or st_name_idx >= len(strtab_data):
                continue

            if is_64:
                st_value = int.from_bytes(sym_bytes[8:16], 'little')
            else:
                st_value = int.from_bytes(sym_bytes[4:8], 'little')

            null_pos = strtab_data.find(b'\x00', st_name_idx)
            if null_pos < 0:
                null_pos = min(st_name_idx + 256, len(strtab_data))
            sym_name = strtab_data[st_name_idx:null_pos].decode('ascii', errors='replace')

            if sym_name in remaining:
                resolved = _resolve_addr(base_address, st_value, is_pie)
                found[sym_name] = resolved
                remaining.discard(sym_name)
                vollog.info(f"[section_headers] Resolved '{sym_name}' at 0x{resolved:x}")
                if not remaining:
                    return found

    return found


# ---------------------------------------------------------------------------
# Strategy 2: Dynamic symbol table via PT_DYNAMIC
#
# The dynamic segment is always mapped (required by the runtime linker).
# DT_SYMTAB/DT_STRTAB/DT_STRSZ entries point directly to .dynsym/.dynstr.
# This reliably finds exported symbols but not file-scope statics.
# ---------------------------------------------------------------------------

def _resolve_dynamic_ptr(base_address: int, raw_val: int, is_pie: bool) -> int:
    """Resolve a PT_DYNAMIC pointer (may already be relocated to absolute)."""
    if not is_pie:
        return raw_val
    if raw_val > base_address:
        return raw_val
    return base_address + raw_val


def search_dynamic_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """Resolve symbols via PT_DYNAMIC (.dynsym/.dynstr)."""
    found = {}
    remaining = set(symbol_names)
    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]

    # Locate PT_DYNAMIC segment
    dynamic_vaddr = None
    dynamic_memsz = None
    for seg in segments:
        if seg["type"] == 2:
            dynamic_vaddr = seg["vaddr"]
            dynamic_memsz = seg["memsz"]
            break

    if dynamic_vaddr is None:
        return found

    dynamic_addr = _resolve_addr(base_address, dynamic_vaddr, is_pie)
    dyn_entry_size = 16 if is_64 else 8

    # Parse dynamic entries: DT_STRTAB(5), DT_SYMTAB(6), DT_STRSZ(10),
    # DT_SYMENT(11), DT_HASH(4), DT_GNU_HASH(0x6ffffef5)
    dt = {}
    needed_tags = {5, 6, 10, 11, 4, 0x6ffffef5}
    offset = 0
    while offset < dynamic_memsz:
        entry = _read_bytes(layer, dynamic_addr + offset, dyn_entry_size)
        if entry is None:
            break
        if is_64:
            d_tag = int.from_bytes(entry[0:8], 'little')
            d_val = int.from_bytes(entry[8:16], 'little')
        else:
            d_tag = int.from_bytes(entry[0:4], 'little')
            d_val = int.from_bytes(entry[4:8], 'little')
        if d_tag == 0:
            break
        if d_tag in needed_tags:
            dt[d_tag] = d_val
        offset += dyn_entry_size

    symtab_raw  = dt.get(6)
    strtab_raw  = dt.get(5)
    strtab_size = dt.get(10)
    syment_size = dt.get(11)

    if None in (symtab_raw, strtab_raw, strtab_size):
        return found
    if syment_size is None:
        syment_size = 24 if is_64 else 16

    symtab_addr = _resolve_dynamic_ptr(base_address, symtab_raw, is_pie)
    strtab_addr = _resolve_dynamic_ptr(base_address, strtab_raw, is_pie)

    vollog.debug(f"Dynamic symtab=0x{symtab_addr:x}, strtab=0x{strtab_addr:x} ({strtab_size} bytes)")

    # Determine symbol count from hash tables
    num_symbols = None

    # Try DT_HASH first (nchain field = symbol count)
    dt_hash = dt.get(4)
    if dt_hash is not None:
        hash_addr = _resolve_dynamic_ptr(base_address, dt_hash, is_pie)
        hash_hdr = _read_bytes(layer, hash_addr, 8)
        if hash_hdr:
            nchain = int.from_bytes(hash_hdr[4:8], 'little')
            if 0 < nchain < 1_000_000:
                num_symbols = nchain
                vollog.debug(f"DT_HASH nchain={nchain}")

    # Fallback: DT_GNU_HASH (walk bucket chains to find max symbol index)
    dt_gnu_hash = dt.get(0x6ffffef5)
    if dt_gnu_hash is not None and num_symbols is None:
        gnu_hash_addr = _resolve_dynamic_ptr(base_address, dt_gnu_hash, is_pie)
        gnu_hdr = _read_bytes(layer, gnu_hash_addr, 16)
        if gnu_hdr:
            nbuckets  = int.from_bytes(gnu_hdr[0:4], 'little')
            symndx    = int.from_bytes(gnu_hdr[4:8], 'little')
            maskwords = int.from_bytes(gnu_hdr[8:12], 'little')
            if 0 < nbuckets < 1_000_000 and 0 < maskwords < 1_000_000:
                bloom_size = maskwords * (8 if is_64 else 4)
                buckets_offset = 16 + bloom_size
                chains_offset = buckets_offset + nbuckets * 4
                buckets_addr = gnu_hash_addr + buckets_offset
                buckets_data = _read_bytes(layer, buckets_addr, nbuckets * 4)
                if buckets_data:
                    max_bucket = 0
                    for i in range(nbuckets):
                        val = int.from_bytes(buckets_data[i*4:(i+1)*4], 'little')
                        if val > max_bucket:
                            max_bucket = val
                    if max_bucket >= symndx:
                        chain_base = gnu_hash_addr + chains_offset
                        idx = max_bucket
                        while idx < max_bucket + 100000:
                            chain_entry_addr = chain_base + (idx - symndx) * 4
                            chain_val = _read_bytes(layer, chain_entry_addr, 4)
                            if chain_val is None:
                                break
                            if int.from_bytes(chain_val, 'little') & 1:
                                num_symbols = idx + 1
                                vollog.debug(f"DT_GNU_HASH: {num_symbols} symbols")
                                break
                            idx += 1

    # Fallback: estimate from gap between symtab and strtab
    if num_symbols is None and strtab_raw > symtab_raw:
        gap = (strtab_addr - symtab_addr)
        derived = gap // syment_size
        if 0 < derived < 1_000_000:
            num_symbols = derived
            vollog.debug(f"Symbol count estimated from table gap: {num_symbols}")

    if num_symbols is None:
        num_symbols = 50000

    strtab_data = _read_bytes(layer, strtab_addr, min(strtab_size, 1 << 20))
    if strtab_data is None:
        vollog.warning(f"Cannot read dynamic strtab at 0x{strtab_addr:x}")
        return found

    # Linear scan of dynamic symbol table
    for j in range(num_symbols):
        sym_bytes = _read_bytes(layer, symtab_addr + j * syment_size, syment_size)
        if sym_bytes is None:
            continue

        st_name_idx = int.from_bytes(sym_bytes[0:4], 'little')
        if st_name_idx == 0 or st_name_idx >= len(strtab_data):
            continue

        if is_64:
            st_value = int.from_bytes(sym_bytes[8:16], 'little')
        else:
            st_value = int.from_bytes(sym_bytes[4:8], 'little')

        null_pos = strtab_data.find(b'\x00', st_name_idx)
        if null_pos < 0:
            null_pos = min(st_name_idx + 256, len(strtab_data))
        sym_name = strtab_data[st_name_idx:null_pos].decode('ascii', errors='replace')

        if sym_name in remaining:
            resolved = _resolve_addr(base_address, st_value, is_pie)
            found[sym_name] = resolved
            remaining.discard(sym_name)
            vollog.info(f"[dynamic] Resolved '{sym_name}' at 0x{resolved:x}")
            if not remaining:
                return found

    return found


# ---------------------------------------------------------------------------
# Strategy 3: LTO-renamed symbol variants
#
# GCC's Link-Time Optimization renames file-scope statics by appending
# ".lto_priv.0" or similar suffixes. We retry Strategies 1-2 with the
# suffixed names and map results back to the original symbol names.
# ---------------------------------------------------------------------------

def search_lto_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """Resolve symbols with .lto_priv suffix (GCC LTO renaming)."""
    lto_targets = set()
    original_map = {}
    for name in symbol_names:
        lto_name = name + ".lto_priv"
        lto_targets.add(lto_name)
        original_map[lto_name] = name

    lto_found = search_section_symbols(layer, base_address, elf_info, lto_targets, segments)
    remaining_lto = lto_targets - set(lto_found.keys())
    if remaining_lto:
        lto_found.update(search_dynamic_symbols(layer, base_address, elf_info, remaining_lto, segments))

    result = {}
    for lto_name, addr in lto_found.items():
        result[original_map.get(lto_name, lto_name)] = addr
    return result


# ---------------------------------------------------------------------------
# Strategy 4: Pattern-based .symtab discovery in mapped segments
#
# When section headers are absent (common in memory dumps), the .symtab
# data may still reside within a PT_LOAD segment. We locate it by:
#   1. Searching for target symbol names as raw strings in data segments
#   2. Inferring the string table boundary from surrounding null terminators
#   3. Scanning nearby memory for Elf_Sym entries with matching st_name offsets
# ---------------------------------------------------------------------------

def search_mapped_symtab(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """Last-resort symbol resolution by scanning loaded segments for raw .symtab data."""
    found = {}
    remaining = set(symbol_names)

    lto_map = {}
    for name in symbol_names:
        lto_map[name + ".lto_priv"] = name
    all_targets = remaining | set(lto_map.keys())

    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]
    sym_size = 24 if is_64 else 16

    # Collect non-executable loaded segments (where .symtab/.strtab reside)
    readable_segments = []
    for seg in segments:
        if seg["type"] != 1:
            continue
        if seg["filesz"] > 0:
            seg_vaddr = _resolve_addr(base_address, seg["vaddr"], is_pie)
            readable_segments.append((seg_vaddr, seg["filesz"], seg["flags"]))

    # Phase 1: Locate target symbol strings in data segments
    strtab_candidates = []
    for seg_vaddr, seg_size, seg_flags in readable_segments:
        if seg_flags & 1:  # Skip executable segments (PF_X)
            continue
        if seg_size < 1024:
            continue

        chunk_size = min(seg_size, 0x200000)
        data = _read_bytes(layer, seg_vaddr, chunk_size)
        if data is None:
            continue

        for target in all_targets:
            target_bytes = target.encode('ascii') + b'\x00'
            pos = 0
            while True:
                idx = data.find(target_bytes, pos)
                if idx < 0:
                    break

                # Walk backwards to find the string table boundary
                strtab_start_idx = idx
                while strtab_start_idx > 0 and strtab_start_idx > idx - 0x100000:
                    if data[strtab_start_idx] == 0 and strtab_start_idx > 0:
                        strtab_start_idx -= 1
                        continue
                    elif data[strtab_start_idx] >= 0x20 and data[strtab_start_idx] < 0x7f:
                        strtab_start_idx -= 1
                        continue
                    else:
                        strtab_start_idx += 1
                        break

                while strtab_start_idx < idx and data[strtab_start_idx] != 0:
                    strtab_start_idx += 1

                strtab_candidates.append({
                    "vaddr": seg_vaddr + strtab_start_idx,
                    "name_offset": idx - strtab_start_idx,
                    "target": target,
                    "seg_vaddr": seg_vaddr,
                    "seg_size": seg_size,
                })

                pos = idx + 1

    if not strtab_candidates:
        return found

    # Phase 2: Search for Elf_Sym entries matching the computed string offset
    for candidate in strtab_candidates:
        target = candidate["target"]
        name_offset = candidate["name_offset"]
        strtab_vaddr = candidate["vaddr"]
        seg_vaddr = candidate["seg_vaddr"]

        search_size = strtab_vaddr - seg_vaddr
        if search_size <= 0 or search_size > 0x500000:
            continue

        sym_data = _read_bytes(layer, seg_vaddr, search_size)
        if sym_data is None:
            continue

        name_offset_bytes = name_offset.to_bytes(4, 'little')

        for offset in range(0, len(sym_data) - sym_size, sym_size):
            if sym_data[offset:offset + 4] != name_offset_bytes:
                continue

            if is_64:
                st_info  = sym_data[offset + 4]
                st_value = int.from_bytes(sym_data[offset + 8:offset + 16], 'little')
            else:
                st_value = int.from_bytes(sym_data[offset + 4:offset + 8], 'little')
                st_info  = sym_data[offset + 12]

            st_bind = st_info >> 4
            st_type = st_info & 0xf

            # Validate Elf_Sym fields
            if st_bind > 2 or st_type > 4 or st_value == 0:
                continue
            if not is_pie and (st_value < 0x400000 or st_value > 0xffffffff):
                continue

            resolved = _resolve_addr(base_address, st_value, is_pie)
            if _read_bytes(layer, resolved, 8) is None:
                continue

            orig_name = lto_map.get(target, target)
            found[orig_name] = resolved
            remaining.discard(orig_name)
            vollog.info(f"[mapped_symtab] Resolved '{orig_name}' (as '{target}') at 0x{resolved:x}")

            if not remaining and not (set(lto_map.keys()) - set(found.keys())):
                return found

            break

    return found


# ---------------------------------------------------------------------------
# Strategy 5: Structural scan for _PyRuntime in .bss/.data
#
# _PyRuntimeState is a large global struct containing the interpreter
# linked list. We identify it by matching its in-memory signature:
#   - interpreters.head == interpreters.main (single-interpreter process)
#   - interpreters.next_id == 1
#   - head pointer dereferences to a valid PyInterpreterState
#
# The struct location varies by CPython version:
#   Python 3.7-3.8:  .bss  (uninitialized global)
#   Python 3.9+:     .data (statically initialized via _PyRuntimeState_INIT)
# ---------------------------------------------------------------------------

def _collect_python_rw_regions(layer, task, context) -> List[Tuple[int, int, str]]:
    """
    Collect writable memory regions belonging to the Python binary or
    libpython, including adjacent anonymous mappings (.bss continuation).
    """
    python_rw_regions = []
    all_vmas = []

    for vma in task.mm.get_vma_iter():
        vm_start = int(vma.vm_start)
        vm_end = int(vma.vm_end)
        all_vmas.append((vm_start, vm_end, vma))

        try:
            path = vma.get_name(context, task)
        except Exception:
            continue
        path_str = str(path) if path else ""
        if "python" not in path_str.lower():
            continue
        if "/bin/" not in path_str and "libpython" not in path_str.lower():
            continue
        flags = vma.get_protection()
        if 'w' in flags:
            python_rw_regions.append((vm_start, vm_end, path_str))

    # Chain adjacent anonymous VMAs (the kernel maps .bss as anonymous
    # pages immediately following the file-backed writable segment)
    python_rw_ends = {end for _, end, _ in python_rw_regions}
    for vma_start, vma_end, vma in all_vmas:
        try:
            path = vma.get_name(context, task)
        except Exception:
            path = None
        if path and "Anonymous" not in str(path):
            continue
        if vma_start in python_rw_ends:
            python_rw_regions.append((vma_start, vma_end, "anonymous(.bss)"))
            python_rw_ends.add(vma_end)

    return python_rw_regions


def scan_bss_for_pyruntime(
    layer, base_address: int, elf_info: Dict,
    task, context, proc_layer_name: str,
) -> Dict[str, int]:
    """
    Locate _PyRuntime by scanning Python's writable segments for the
    _PyRuntimeState interpreter list signature.
    """
    found = {}

    python_rw_regions = _collect_python_rw_regions(layer, task, context)
    if not python_rw_regions:
        return found

    # The interpreters sub-struct offset within _PyRuntimeState varies
    # across CPython versions; probe a range of candidate offsets
    candidate_interp_offsets = list(range(0x10, 0x120, 0x8))

    for region_start, region_end, region_path in python_rw_regions:
        scan_size = min(region_end - region_start, 0x100000)
        try:
            data = layer.read(region_start, scan_size, pad=False)
        except Exception:
            continue

        for interp_offset in candidate_interp_offsets:
            if scan_size < interp_offset + 24:
                continue

            for offset in range(0, scan_size - interp_offset - 24, 8):
                # Match interpreters.head: must be a valid userspace pointer
                head_ptr = int.from_bytes(
                    data[offset + interp_offset:offset + interp_offset + 8], 'little'
                )
                if head_ptr == 0 or head_ptr < 0x10000 or head_ptr > 0x7fffffffffff:
                    continue

                # interpreters.main must equal interpreters.head
                main_ptr = int.from_bytes(
                    data[offset + interp_offset + 8:offset + interp_offset + 16], 'little'
                )
                if head_ptr != main_ptr:
                    continue

                # interpreters.next_id must be 1
                next_id = int.from_bytes(
                    data[offset + interp_offset + 16:offset + interp_offset + 24], 'little'
                )
                if next_id != 1:
                    continue

                # Validate head pointer dereferences to non-zero readable memory
                test = _read_bytes(layer, head_ptr, 16)
                if test is None or all(b == 0 for b in test):
                    continue

                candidate_addr = region_start + offset

                # Validate PyInterpreterState: look for interp_id == 0
                # and a valid next pointer (NULL or valid userspace address)
                interp_looks_valid = False
                for id_offset in (0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
                    interp_id_val = _read_int(layer, head_ptr + id_offset, 8)
                    if interp_id_val is not None and interp_id_val == 0:
                        next_interp = _read_int(layer, head_ptr, 8)
                        if next_interp is not None and (next_interp == 0 or
                                (0x10000 < next_interp < 0x7fffffffffff)):
                            interp_looks_valid = True
                            break

                if not interp_looks_valid:
                    continue

                # Reject false positives: the region after next_id should
                # contain non-zero data (real _PyRuntimeState has additional fields)
                if offset + interp_offset + 48 <= len(data):
                    tail = data[offset + interp_offset + 24:offset + interp_offset + 48]
                    if all(b == 0 for b in tail):
                        continue

                found["_PyRuntime"] = candidate_addr
                vollog.info(
                    f"[bss_scan] Found _PyRuntime at 0x{candidate_addr:x} "
                    f"(interp_head at +0x{interp_offset:x} -> 0x{head_ptr:x})"
                )
                return found

    return found


# ---------------------------------------------------------------------------
# Strategy orchestration
# ---------------------------------------------------------------------------

def resolve_symbols(
    layer, base_address: int, symbol_names: List[str],
    task=None, context=None, proc_layer_name: str = None,
) -> Dict[str, int]:
    """
    Attempt symbol resolution through all available strategies, stopping
    early once all requested symbols are found.
    """
    target_set = set(symbol_names)
    found = {}

    elf_info = parse_elf_header(layer, base_address)
    if elf_info is None:
        vollog.warning(f"Invalid ELF header at 0x{base_address:x}")
        return found

    segments = parse_load_segments(layer, base_address, elf_info)
    vollog.info(f"Parsed {len(segments)} program headers, "
                f"{sum(1 for s in segments if s['type']==1)} PT_LOAD segments")

    # Strategy 1: Section headers
    vollog.info("Strategy 1: Section header symbol resolution")
    s1 = search_section_symbols(layer, base_address, elf_info, target_set, segments)
    found.update(s1)
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 2: Dynamic symbols
    vollog.info("Strategy 2: Dynamic symbol table resolution")
    s2 = search_dynamic_symbols(layer, base_address, elf_info, remaining, segments)
    found.update(s2)
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 3: LTO-renamed variants
    vollog.info("Strategy 3: LTO variant resolution")
    s3 = search_lto_symbols(layer, base_address, elf_info, remaining, segments)
    found.update(s3)
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 4: Mapped .symtab pattern scan
    vollog.info("Strategy 4: Mapped symtab pattern scan")
    s4 = search_mapped_symtab(layer, base_address, elf_info, remaining, segments)
    found.update(s4)
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 5: Structural scan for _PyRuntime
    if "_PyRuntime" in remaining and task is not None:
        vollog.info("Strategy 5: BSS/data structural scan for _PyRuntime")
        found.update(scan_bss_for_pyruntime(
            layer, base_address, elf_info, task, context, proc_layer_name
        ))

    remaining = target_set - set(found.keys())
    vollog.info(f"Resolution complete: found={list(found.keys())}, unresolved={remaining}")
    return found


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def find_python_module_base(
    context, proc_layer_name: str, task,
    module_substring: str = "libpython",
) -> Optional[Tuple[int, str]]:
    """
    Locate the ELF base address of a Python module (libpython or the
    python binary itself) by scanning the process VMA list for matching
    paths with valid ELF headers.
    """
    lowest_base = None
    best_path = None
    substr_lower = module_substring.lower()

    if not task.mm:
        return None

    for vma in task.mm.get_vma_iter():
        try:
            path = vma.get_name(context, task)
        except Exception:
            continue
        if not path:
            continue

        path_str = str(path)
        if substr_lower not in path_str.lower():
            continue

        vm_start = int(vma.vm_start)
        layer = context.layers[proc_layer_name]

        magic = _read_bytes(layer, vm_start, 4)
        if magic != b'\x7fELF':
            continue

        if lowest_base is None or vm_start < lowest_base:
            lowest_base = vm_start
            best_path = path_str

    return (lowest_base, best_path) if lowest_base is not None else None


def find_symbol_in_process(
    context, proc_layer_name: str, task,
    module_substring: str, symbol_names: List[str],
) -> Dict[str, int]:
    """
    Top-level entry point: resolve ELF symbols within a Python process.
    Searches both the specified module and the python binary itself
    to handle both dynamically-linked and statically-linked CPython builds.
    """
    layer = context.layers[proc_layer_name]
    all_found = {}
    remaining = list(symbol_names)

    candidates = []

    result = find_python_module_base(context, proc_layer_name, task, module_substring)
    if result is not None:
        candidates.append(result)

    # Also check the python binary itself (handles static builds)
    if module_substring.lower() != "python":
        result2 = find_python_module_base(context, proc_layer_name, task, "python")
        if result2 is not None and (not candidates or result2[0] != candidates[0][0]):
            candidates.append(result2)

    for base_address, path in candidates:
        if not remaining:
            break

        vollog.info(f"Searching ELF: {path} at 0x{base_address:x} for {remaining}")

        found = resolve_symbols(
            layer, base_address, remaining,
            task=task, context=context, proc_layer_name=proc_layer_name,
        )

        all_found.update(found)
        remaining = [s for s in remaining if s not in all_found]

    return all_found


# ---------------------------------------------------------------------------
# Standalone Volatility plugin (for direct invocation and debugging)
# ---------------------------------------------------------------------------

class ELFSymbolFinder(interfaces.plugins.PluginInterface):
    """Resolve ELF symbols from process memory without on-disk binaries."""
    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="module_name",
                description="Substring of module path (e.g. 'libpython', 'python3.8')",
                optional=False,
            ),
            requirements.StringRequirement(
                name="symbol",
                description="Comma-separated symbol names (e.g. '_PyRuntime')",
                optional=True, default="_PyRuntime",
            ),
            requirements.ListRequirement(
                name="pid", description="Filter by PID",
                element_type=int, optional=True,
            ),
        ]

    def _generator(self):
        module_substr = self.config["module_name"]
        symbol_names = [s.strip() for s in self.config.get("symbol", "_PyRuntime").split(",")]

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=filter_func
        )

        for task in tasks:
            if not task.mm:
                continue
            try:
                proc_layer_name = task.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            results = find_symbol_in_process(
                self.context, proc_layer_name, task,
                module_substring=module_substr,
                symbol_names=symbol_names,
            )

            pid = int(task.pid)
            if not results:
                yield (0, (pid, "No matching symbols found", "", ""))
            else:
                for sym_name, addr in results.items():
                    yield (0, (pid, sym_name, format_hints.Hex(addr), "FOUND"))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Symbol", str), ("Address", format_hints.Hex), ("Status", str)],
            self._generator(),
        )
