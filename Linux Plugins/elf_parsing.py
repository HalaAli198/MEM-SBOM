"""
ELF Symbol Resolution for Volatility 3

This module resolves ELF symbols using ONLY what the kernel maps into process
memory. It does NOT rely on section headers being present (they usually aren't
in memory dumps).

The kernel loads ELF content via PT_LOAD program headers. If the
.symtab and .strtab sections happen to fall within a PT_LOAD segment, their
data is in memory even though the section header table is not. We can find
them by:

  1. Parsing program headers (always in memory at known offset from ELF base)
  2. Using PT_DYNAMIC to find .dynsym/.dynstr (always works for dynamic symbols)
  3. For static symbols like 'arenas': scanning the mapped read-only
     segments for the .symtab/.strtab content by recognizing Elf64_Sym structure patterns
     
     
For statically-linked CPython (e.g. /usr/bin/python3.8):
  - PT_DYNAMIC gives us .dynsym + .dynstr
  - If the symbol isn't exported, we fall back to scanning the data segment
    for .symtab-like structures and validate candidates against Elf64_Sym layout

Usage:
    from volatility3.framework.plugins.linux import elf_parsing

    results = elf_parsing.find_symbol_in_process(
        context, proc_layer_name, task,
        module_substring="python",
        symbol_names=["arenas", "maxarenas", "usable_arenas"]
    )
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
# Thin wrappers that return None on failure instead of throwing exceptions.
# Every read from a memory dump can fail (paged out, unmapped, etc.) so we
# need safe accessors everywhere.
# ---------------------------------------------------------------------------


def _read_bytes(layer, address: int, size: int) -> Optional[bytes]:
    try:
        return layer.read(address, size, pad=False)
    except Exception:
        return None


def _read_int(layer, address: int, size: int = 8) -> Optional[int]:
    data = _read_bytes(layer, address, size)
    if data is None:
        return None
    return int.from_bytes(data, byteorder='little')


# ---------------------------------------------------------------------------
# ELF header parsing
# ---------------------------------------------------------------------------

def parse_elf_header(layer, base_address: int) -> Optional[Dict]:
    """
    Parse the ELF header at base_address. We only extract the fields we
    actually need downstream (program/section header table offsets, counts,
    entry sizes). Returns None if the magic doesn't match or the read fails.
    """
    magic = _read_bytes(layer, base_address, 16)
    if magic is None or magic[:4] != b'\x7fELF':
        return None
    
    # EI_CLASS: 1 = 32-bit, 2 = 64-bit
    ei_class = magic[4]
    if ei_class not in (1, 2):
        return None

    is_64 = (ei_class == 2)

    if is_64:
        # Elf64_Ehdr is 64 bytes
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
        # Elf32_Ehdr is 52 bytes
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

    
    # ET_DYN (3) = position-independent executable or shared library.
    # ET_EXEC (2) = traditional fixed-address executable.
    # This distinction matters for address resolution below.
    is_pie = (e_type == 3)  # ET_DYN

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
    """
    For PIE/shared libraries, symbol values are offsets from load base.
    For ET_EXEC binaries, symbol values are already absolute virtual addresses.
    """
    return (base + value) if is_pie else value


# ---------------------------------------------------------------------------
# Parse PT_LOAD segments
#
# This builds the mapping from ELF file offsets to process virtual addresses.
# The kernel only loads what PT_LOAD segments describe — everything else
# (section headers, debug info outside PT_LOAD, etc.) is NOT in memory.
# ---------------------------------------------------------------------------

def parse_load_segments(layer, base_address: int, elf_info: Dict) -> List[Dict]:
    """
    Walk the program header table and collect all segment descriptors.
    We need PT_LOAD for file-to-vaddr translation and PT_DYNAMIC for
    the dynamic symbol table.
    """
    segments = []
    is_64 = elf_info["is_64"]
    is_pie = elf_info["is_pie"]
    phdr_base = base_address + elf_info["e_phoff"]

    for i in range(elf_info["e_phnum"]):
        phdr = _read_bytes(layer, phdr_base + i * elf_info["e_phentsize"],
                           elf_info["e_phentsize"])
        if phdr is None:
            continue

        p_type = int.from_bytes(phdr[0:4], 'little')
        
        # 64-bit and 32-bit program headers have different layouts.
        # Notably, p_flags moves from offset 24 (32-bit) to offset 4 (64-bit).
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
    Translate an ELF file offset to a runtime virtual address.
    
    The kernel maps file content into memory according to PT_LOAD segments:
    if file_offset falls in [p_offset, p_offset + p_filesz), the corresponding
    memory address is p_vaddr + (file_offset - p_offset).
    
    Returns None if the offset isn't covered by any PT_LOAD — meaning that
    data simply isn't in the memory dump.
    """
    for seg in segments:
        if seg["type"] != 1:  # PT_LOAD
            continue
        if seg["offset"] <= file_offset < seg["offset"] + seg["filesz"]:
            vaddr = seg["vaddr"] + (file_offset - seg["offset"])
            return _resolve_addr(base_address, vaddr, is_pie)
    return None


# ---------------------------------------------------------------------------
# Strategy 1: Section headers -> .symtab/.dynsym
#
# Section headers live at e_shoff in the ELF file. Normally the kernel
# doesn't need them and they're beyond the last PT_LOAD, so they're NOT
# in memory. But for some builds (debug, or when the linker happens to
# place them within a loaded segment), they ARE accessible. Worth trying
# first since it gives us the full static symbol table.
# ---------------------------------------------------------------------------

def search_section_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """
    Attempt to resolve symbols via section headers.
    This only works when the section header table itself is mapped into
    memory (i.e. its file offset falls within a PT_LOAD segment).
    """
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

    # Translate section header table's file offset to a virtual address
    shdr_vaddr = file_offset_to_vaddr(segments, e_shoff, is_pie, base_address)
    if shdr_vaddr is None:
        vollog.debug(f"Section headers at file offset 0x{e_shoff:x} not in any PT_LOAD segment")
        return found

    # Sanity check: can we actually read from there?
    test = _read_bytes(layer, shdr_vaddr, e_shentsize)
    if test is None:
        vollog.debug(f"Section headers at 0x{shdr_vaddr:x} not readable in memory")
        return found

    # We need .shstrtab (the section name string table) to identify
    # which sections are .symtab vs .dynsym
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

    # Walk all section headers, looking for SHT_SYMTAB (2) and SHT_DYNSYM (11)
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
            vollog.debug(f"Symbol table at file offset 0x{sh_offset:x} not mapped")
            continue

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
            vollog.debug(f"String table at file offset 0x{strtab_file_offset:x} not mapped")
            continue
       
        strtab_data = _read_bytes(layer, strtab_vaddr, min(strtab_size, 1 << 20))
        if strtab_data is None:
            continue

        num_symbols = sh_size // sh_entsize
        section_name = "SHT_SYMTAB" if sh_type == 2 else "SHT_DYNSYM"
        vollog.info(f"Scanning {section_name} at 0x{symtab_vaddr:x} ({num_symbols} symbols)")
        
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
                vollog.info(f"[section_headers] Found '{sym_name}' at 0x{resolved:x}")
                if not remaining:
                    return found

    return found


# ---------------------------------------------------------------------------
# Strategy 2: PT_DYNAMIC -> .dynsym/.dynstr
#
# The dynamic segment is ALWAYS mapped (the runtime linker needs it).
# It contains DT_SYMTAB, DT_STRTAB, DT_STRSZ entries that point directly
# to the dynamic symbol/string tables in memory. This reliably finds any
# symbol that's exported (visible to the dynamic linker), but obmalloc
# internals like 'arenas' are usually static/local — so this alone
# won't find everything we need.
# ---------------------------------------------------------------------------
def _resolve_dynamic_ptr(base_address: int, raw_val: int, is_pie: bool) -> int:
    """
    Resolve a pointer from PT_DYNAMIC. The dynamic linker may have
    already relocated these to absolute addresses in memory.
    """
    if not is_pie:
        return raw_val
    if raw_val > base_address:
        return raw_val
    return base_address + raw_val


def search_dynamic_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    found = {}
    remaining = set(symbol_names)
    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]

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

    print(f"  symtab: raw=0x{symtab_raw:x} resolved=0x{symtab_addr:x}")
    print(f"  strtab: raw=0x{strtab_raw:x} resolved=0x{strtab_addr:x} size={strtab_size}")

    # Symbol count
    num_symbols = None

    dt_hash = dt.get(4)
    if dt_hash is not None:
        hash_addr = _resolve_dynamic_ptr(base_address, dt_hash, is_pie)
        hash_hdr = _read_bytes(layer, hash_addr, 8)
        if hash_hdr:
            nchain = int.from_bytes(hash_hdr[4:8], 'little')
            if 0 < nchain < 1_000_000:
                num_symbols = nchain
                print(f"  DT_HASH nchain={nchain}")

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
                                print(f"  DT_GNU_HASH: {num_symbols} symbols")
                                break
                            idx += 1

    if num_symbols is None and strtab_raw > symtab_raw:
        gap = (strtab_addr - symtab_addr)
        derived = gap // syment_size
        if 0 < derived < 1_000_000:
            num_symbols = derived
            print(f"  Symbol count from gap: {num_symbols}")

    if num_symbols is None:
        num_symbols = 50000

    strtab_data = _read_bytes(layer, strtab_addr, min(strtab_size, 1 << 20))
    if strtab_data is None:
        print(f"  ERROR: Cannot read strtab at 0x{strtab_addr:x} size={strtab_size}")
        return found

    print(f"  strtab read OK: {len(strtab_data)} bytes, num_symbols={num_symbols}")

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
            print(f"  FOUND '{sym_name}' at index {j}, st_value=0x{st_value:x}, resolved=0x{resolved:x}")
            if not remaining:
                return found

    return found


# ---------------------------------------------------------------------------
# Strategy 3: LTO-renamed variants
#
# GCC's Link-Time Optimization can rename static symbols by appending
# ".lto_priv.0" or similar suffixes. CPython's obmalloc globals (arenas,
# maxarenas, etc.) are file-scope statics, so with LTO enabled they may
# appear as "arenas.lto_priv" instead of just "arenas".
# ---------------------------------------------------------------------------

def search_lto_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """Try resolving symbols with .lto_priv suffix appended."""
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
# Strategy 4: Brute-force scan of mapped data for .symtab content
#
# When section headers aren't in memory (the common case for memory dumps),
# the symbol table data itself might still be present — it just depends on
# whether the linker placed .symtab within a PT_LOAD segment.
#
# We find it by searching for the target symbol names as raw strings in the
# mapped data segments, then working backwards to locate the string table
# boundary, and finally scanning nearby memory for Elf64_Sym entries whose
# st_name field matches the computed offset.
# ---------------------------------------------------------------------------


def search_mapped_symtab(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """
    Last-resort symbol resolution: scan loaded segments for raw .symtab data.
    """
    found = {}
    remaining = set(symbol_names)
    
    lto_map = {}
    for name in symbol_names:
        lto_map[name + ".lto_priv"] = name
    all_targets = remaining | set(lto_map.keys())

    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]
    sym_size = 24 if is_64 else 16

    readable_segments = []
    for seg in segments:
        if seg["type"] != 1:
            continue
        if seg["filesz"] > 0:
            seg_vaddr = _resolve_addr(base_address, seg["vaddr"], is_pie)
            readable_segments.append((seg_vaddr, seg["filesz"], seg["flags"]))

    strtab_candidates = []
    for seg_vaddr, seg_size, seg_flags in readable_segments:
        if seg_flags & 1:  # PF_X
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

                name_offset_in_strtab = idx - strtab_start_idx
                strtab_vaddr = seg_vaddr + strtab_start_idx

                strtab_candidates.append({
                    "vaddr": strtab_vaddr,
                    "name_offset": name_offset_in_strtab,
                    "target": target,
                    "seg_vaddr": seg_vaddr,
                    "seg_size": seg_size,
                })

                pos = idx + 1

    if not strtab_candidates:
        return found

    for candidate in strtab_candidates:
        target = candidate["target"]
        name_offset = candidate["name_offset"]
        strtab_vaddr = candidate["vaddr"]
        seg_vaddr = candidate["seg_vaddr"]
        seg_size = candidate["seg_size"]

        search_start = seg_vaddr
        search_end = strtab_vaddr
        search_size = search_end - search_start

        if search_size <= 0 or search_size > 0x500000:
            continue

        sym_data = _read_bytes(layer, search_start, search_size)
        if sym_data is None:
            continue

        name_offset_bytes = name_offset.to_bytes(4, 'little')

        for offset in range(0, len(sym_data) - sym_size, sym_size):
            if sym_data[offset:offset + 4] != name_offset_bytes:
                continue

            if is_64:
                st_info  = sym_data[offset + 4]
                st_value = int.from_bytes(sym_data[offset + 8:offset + 16], 'little')
                st_size  = int.from_bytes(sym_data[offset + 16:offset + 24], 'little')
            else:
                st_value = int.from_bytes(sym_data[offset + 4:offset + 8], 'little')
                st_info  = sym_data[offset + 12]
                st_size  = sym_data[offset + 8:offset + 12]

            st_bind = st_info >> 4
            st_type = st_info & 0xf

            if st_bind > 2:
                continue
            if st_type > 4:
                continue
            if st_value == 0:
                continue
            if not is_pie and (st_value < 0x400000 or st_value > 0xffffffff):
                continue

            resolved = _resolve_addr(base_address, st_value, is_pie)

            if _read_bytes(layer, resolved, 8) is None:
                continue

            orig_name = lto_map.get(target, target)
            found[orig_name] = resolved
            remaining.discard(orig_name)
            vollog.info(f"[mapped_symtab] Found '{orig_name}' (as '{target}') at 0x{resolved:x}")

            if not remaining and not (set(lto_map.keys()) - set(found.keys())):
                return found

            break

    return found


# ---------------------------------------------------------------------------
# Arena validation helpers
# ---------------------------------------------------------------------------

def _validate_single_arena_object(layer, arena_obj_addr: int) -> bool:
    """
    Validate that a 48-byte region looks like a valid arena_object.

    CPython arena_object layout (64-bit):
      +0x00  address        (8 bytes) — mmap'd base, 256KB-aligned
      +0x08  pool_address   (8 bytes) — next pool to carve, > address
      +0x10  nfreepools     (4 bytes) — 0..ntotalpools
      +0x14  ntotalpools    (4 bytes) — always <= 64 (256KB / 4KB)
      +0x18  freepools      (8 bytes) — pointer to pool_header or NULL
      +0x20  nextarena      (8 bytes) — linked list pointer or NULL
      +0x28  prevarena      (8 bytes) — linked list pointer or NULL
    """
    data = _read_bytes(layer, arena_obj_addr, 48)
    if data is None:
        return False

    arena_addr  = int.from_bytes(data[0:8], 'little')
    pool_addr   = int.from_bytes(data[8:16], 'little')
    nfreepools  = int.from_bytes(data[16:20], 'little')
    ntotalpools = int.from_bytes(data[20:24], 'little')

    # Unused slot (address == 0) is structurally valid but not "active"
    if arena_addr == 0:
        return False

    # ntotalpools: 256KB arena / 4KB pool = 64 max
    if ntotalpools == 0 or ntotalpools > 64:
        return False

    # nfreepools must be <= ntotalpools
    if nfreepools > ntotalpools:
        return False

    # pool_address must be > address (pools start after alignment padding)
    if pool_addr <= arena_addr:
        return False

    # gap between address and pool_address should be < 256KB
    if (pool_addr - arena_addr) > 0x40000:
        return False

    # address should be 256KB-aligned (mmap guarantee) or at least page-aligned
    if arena_addr & 0xFFF:
        return False

    # The mmap'd region should be readable
    if _read_bytes(layer, arena_addr, 8) is None:
        return False

    return True


def _validate_arenas_pointer(layer, candidate_addr: int) -> bool:
    """
    Validate that candidate_addr holds a pointer to the BASE of the
    arena_object array (not usable_arenas which points into the middle).
    
    The real 'arenas' pointer points to a contiguous array of arena_objects.
    We verify:
      1. The pointer dereferences to readable memory
      2. At least 3 of the first 5 slots look like valid arena_objects
         (some may be unused with address=0, but the pattern should be consistent)
      3. Consecutive valid entries have distinct, non-overlapping arena addresses
    """
    try:
        ptr_bytes = _read_bytes(layer, candidate_addr, 8)
        if ptr_bytes is None:
            return False
        ptr_val = int.from_bytes(ptr_bytes, 'little')
        
        if ptr_val < 0x10000 or ptr_val > 0x7fffffffffff:
            return False

        # The arenas array is heap-allocated (realloc), so the pointer
        # must be 16-byte aligned on 64-bit glibc
        if ptr_val & 0xF:
            return False

        # Read first 5 arena_objects (48 bytes each = 240 bytes)
        array_data = _read_bytes(layer, ptr_val, 240)
        if array_data is None:
            return False

        valid_count = 0
        seen_addresses = set()
        for i in range(5):
            off = i * 48
            arena_addr  = int.from_bytes(array_data[off:off+8], 'little')
            pool_addr   = int.from_bytes(array_data[off+8:off+16], 'little')
            nfreepools  = int.from_bytes(array_data[off+16:off+20], 'little')
            ntotalpools = int.from_bytes(array_data[off+20:off+24], 'little')

            if arena_addr == 0:
                continue  # unused slot, ok

            if not (0 < ntotalpools <= 64):
                return False
            if nfreepools > ntotalpools:
                return False
            if pool_addr <= arena_addr:
                return False
            if (pool_addr - arena_addr) > 0x40000:
                return False
            if arena_addr & 0xFFF:
                return False
            if _read_bytes(layer, arena_addr, 8) is None:
                return False
            # Each arena should map a different region
            if arena_addr in seen_addresses:
                return False
            seen_addresses.add(arena_addr)
            valid_count += 1

        # The real arenas array should have at least 3 valid entries
        # at the start. usable_arenas typically points into the middle
        # of the same array at a different offset.
        return valid_count >= 3

    except Exception:
        return False


def _count_valid_arenas_from_ptr(layer, array_base: int, max_check: int = 64) -> int:
    """
    Count how many arena_objects exist in the array starting at array_base.
    Returns the total array size (including unused slots with address=0).

    Each entry is validated strictly:
      - address must be 0 (unused) or page-aligned with readable memory
      - ntotalpools must be 0 (unused) or in [1, 64]
      - nfreepools <= ntotalpools
      - pool_address > address for active entries
      - Active entries must have distinct arena addresses

    Stops at:
      - 3+ consecutive entries that are neither valid active nor valid empty
      - Unreadable memory
    """
    count = 0
    active_count = 0
    consecutive_invalid = 0
    seen_addresses = set()

    for i in range(max_check):
        data = _read_bytes(layer, array_base + i * 48, 48)
        if data is None:
            break

        arena_addr  = int.from_bytes(data[0:8], 'little')
        pool_addr   = int.from_bytes(data[8:16], 'little')
        nfreepools  = int.from_bytes(data[16:20], 'little')
        ntotalpools = int.from_bytes(data[20:24], 'little')

        if arena_addr == 0:
            # Unused/free slot — valid structurally
            # For a truly unused slot, ntotalpools should also be 0
            # But CPython keeps ntotalpools set after dealloc, so just
            # check that pool/nfreepools are reasonable
            consecutive_invalid = 0
            count = i + 1
            continue

        # Active entry — full validation
        if ntotalpools == 0 or ntotalpools > 64:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        if nfreepools > ntotalpools:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        if pool_addr <= arena_addr:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        if (pool_addr - arena_addr) > 0x40000:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        if arena_addr & 0xFFF:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        if arena_addr in seen_addresses:
            consecutive_invalid += 1
            if consecutive_invalid >= 3:
                break
            count = i + 1
            continue

        # Passed all checks
        seen_addresses.add(arena_addr)
        consecutive_invalid = 0
        active_count += 1
        count = i + 1

    return active_count


# ---------------------------------------------------------------------------
# Strategy 5: Structural scan for the arenas pointer in .bss/.data
#
# If all ELF-based approaches fail (e.g. fully stripped binary with no
# symbol tables in any loaded segment), we can still find the obmalloc
# arenas by recognizing the arena_object array structure in memory.
#
# The 'arenas' global is a pointer in the Python binary's .data or .bss
# segment. It points to a heap-allocated array of arena_object structs
# (48 bytes each), where each entry has a recognizable pattern:
#   - address field: points to a 256KB mmap'd region
#   - pool_address: address + some offset into the arena
#   - ntotalpools: always <= 64 (256KB / 4KB)
#   - pool_address > address (pool region starts after arena base)
#
# CPython's obmalloc.c declares these globals in close proximity:
#   static unsigned int maxarenas = INITIAL_ARENA_OBJECTS;   // 4 bytes (+ padding)
#   static struct arena_object* arenas = NULL;               // 8 bytes
#   static struct arena_object* usable_arenas = NULL;        // 8 bytes
#   static struct arena_object* unused_arena_objects = NULL;  // 8 bytes
#
# The exact layout depends on compiler/version, but we can exploit the
# cluster pattern: arenas and usable_arenas both point into the same
# heap-allocated array (usable_arenas points to the first arena with
# free pools, arenas points to index 0). maxarenas is a small uint
# (typically 16-1024) located within a cache line of arenas.
#
# Our approach:
#   1. Find ALL pointers in writable Python regions that dereference to
#      valid arena_object arrays
#   2. Group candidates that point into the same array (within 48*1024 bytes
#      of each other)
#   3. The 'arenas' pointer is the one pointing to the lowest address in
#      each group (index 0 of the array)
#   4. Find 'maxarenas' by looking for a uint32 near the arenas pointer
#      whose value equals or exceeds the observed array size
# ---------------------------------------------------------------------------

def _collect_python_rw_regions(layer, task, context) -> List[Tuple[int, int, str]]:
    """
    Collect writable memory regions belonging to the Python binary or libpython.
    Also includes adjacent anonymous mappings which typically hold .bss data.
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

    # Include anonymous VMAs adjacent to Python's writable regions (.bss)
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
            python_rw_ends.add(vma_end)  # chain adjacent anonymous regions

    return python_rw_regions


def scan_bss_for_arenas(
    layer, base_address: int, elf_info: Dict,
    task, context, proc_layer_name: str,
) -> Dict[str, int]:
    """
    Find obmalloc globals (arenas, maxarenas, usable_arenas) by structural
    scanning of writable Python memory regions.

    Strategy:
      Phase 1 — Find all pointers that dereference to valid arena_object arrays.
      Phase 2 — Group candidates pointing to the same underlying array.
      Phase 3 — In each group, pick the pointer to index 0 as 'arenas'.
      Phase 4 — Find 'maxarenas' near 'arenas' using structural constraints.
      Phase 5 — Find 'usable_arenas' as the other pointer in the same group.
    """
    found = {}

    python_rw_regions = _collect_python_rw_regions(layer, task, context)
    if not python_rw_regions:
        print("  [bss_scan] No writable Python regions found")
        return found

    # -----------------------------------------------------------------------
    # Phase 1: Find all pointers to valid arena_object arrays
    # -----------------------------------------------------------------------
    # A candidate is a (bss_addr, ptr_val) where ptr_val -> arena_object array
    candidates = []

    for region_start, region_end, region_path in python_rw_regions:
        scan_size = min(region_end - region_start, 0x100000)

        for offset in range(0, scan_size - 8, 8):
            addr = region_start + offset
            try:
                ptr_bytes = layer.read(addr, 8, pad=False)
                ptr_val = int.from_bytes(ptr_bytes, 'little')

                if ptr_val < 0x10000 or ptr_val > 0x7fffffffffff:
                    continue

                # CRITICAL: The arenas array is heap-allocated via realloc().
                # glibc malloc returns 16-byte aligned pointers on 64-bit.
                # Any pointer not aligned to at least 8 bytes is NOT a valid
                # malloc'd array base and must be rejected immediately.
                if ptr_val & 0xF:
                    continue

                # Quick check: does ptr_val point to something that looks
                # like an arena_object?  Read entries [0] and [1].
                arena_data = _read_bytes(layer, ptr_val, 96)
                if arena_data is None:
                    continue

                arena_addr  = int.from_bytes(arena_data[0:8], 'little')
                pool_addr   = int.from_bytes(arena_data[8:16], 'little')
                nfreepools  = int.from_bytes(arena_data[16:20], 'little')
                ntotalpools = int.from_bytes(arena_data[20:24], 'little')

                # Validate entry[0]
                entry0_valid = False
                if arena_addr == 0:
                    # Unused slot — need entry[1] to be valid
                    pass
                else:
                    if ntotalpools == 0 or ntotalpools > 64:
                        continue
                    if nfreepools > ntotalpools:
                        continue
                    if pool_addr <= arena_addr:
                        continue
                    if (pool_addr - arena_addr) > 0x40000:
                        continue
                    # address must be page-aligned (mmap guarantee)
                    if arena_addr & 0xFFF:
                        continue
                    if _read_bytes(layer, arena_addr, 8) is None:
                        continue
                    entry0_valid = True

                # Validate entry[1]
                arena2_addr  = int.from_bytes(arena_data[48:56], 'little')
                pool2_addr   = int.from_bytes(arena_data[56:64], 'little')
                nfree2       = int.from_bytes(arena_data[64:68], 'little')
                ntotal2      = int.from_bytes(arena_data[68:72], 'little')

                entry1_valid = False
                if arena2_addr == 0:
                    pass  # unused slot
                elif (0 < ntotal2 <= 64 and nfree2 <= ntotal2
                      and pool2_addr > arena2_addr
                      and (pool2_addr - arena2_addr) <= 0x40000
                      and (arena2_addr & 0xFFF) == 0):
                    if _read_bytes(layer, arena2_addr, 8) is not None:
                        entry1_valid = True

                # Require at least one of [0],[1] to be a valid active arena
                if not entry0_valid and not entry1_valid:
                    continue

                # If entry[1] has a non-zero address but fails validation, reject
                if arena2_addr != 0 and not entry1_valid:
                    continue

                candidates.append((addr, ptr_val))
                print(f"  [bss_scan] candidate: 0x{addr:x} -> 0x{ptr_val:x}")

            except Exception:
                continue

    if not candidates:
        print("  [bss_scan] No candidates found")
        return found

    # -----------------------------------------------------------------------
    # Phase 2: Group candidates by the array they point into
    # -----------------------------------------------------------------------
    # Two pointers reference the same array if they're within
    # MAX_ARENAS * 48 bytes of each other (both point into the same
    # heap allocation). We sort by ptr_val and group.
    MAX_ARRAY_SPAN = 4096 * 48  # 192KB, way more than needed

    candidates.sort(key=lambda c: c[1])

    groups = []  # list of lists of (bss_addr, ptr_val)
    current_group = [candidates[0]]

    for i in range(1, len(candidates)):
        bss_addr, ptr_val = candidates[i]
        _, group_base = current_group[0]

        if ptr_val - group_base < MAX_ARRAY_SPAN:
            current_group.append(candidates[i])
        else:
            groups.append(current_group)
            current_group = [candidates[i]]

    groups.append(current_group)

    print(f"  [bss_scan] Found {len(groups)} candidate group(s)")
    for gi, group in enumerate(groups):
        print(f"    Group {gi}: {len(group)} pointer(s)")
        for bss_addr, ptr_val in group:
            print(f"      0x{bss_addr:x} -> 0x{ptr_val:x}")

    # -----------------------------------------------------------------------
    # Phase 3: Select the best group and identify 'arenas'
    # -----------------------------------------------------------------------
    # Score each group. The real arenas group should have:
    #   - Multiple pointers (arenas + usable_arenas at minimum)
    #   - The base pointer pointing to the array start (lowest ptr_val)
    #   - Multiple active (non-zero address) arena_objects
    #   - Pointers that are properly aligned (heap allocation = 16-byte aligned)
    #   - Pointers in the same BSS neighborhood (within a few cache lines of each other)

    best_group = None
    best_score = -1

    for group in groups:
        # The base pointer (arenas) is the one with the lowest ptr_val
        base_bss, base_ptr = group[0]  # already sorted by ptr_val

        # Count strictly validated active arenas
        active = _count_valid_arenas_from_ptr(layer, base_ptr, max_check=128)

        # Score components:
        score = 0

        # Must have at least 2 active arenas to be considered
        if active < 2:
            print(f"    Group scoring: base=0x{base_ptr:x} active={active} -> SKIP (too few)")
            continue

        # Active arena count (primary signal)
        score += active * 10

        # Groups with 2+ BSS pointers are strongly preferred
        # (arenas + usable_arenas should both exist)
        if len(group) >= 2:
            score += 50
            # Check if the other pointers are at valid offsets into the array
            # (must be at multiples of 48 bytes from the base)
            for _, other_ptr in group[1:]:
                offset = other_ptr - base_ptr
                if offset >= 0 and offset % 48 == 0:
                    score += 20  # aligned into the array

        # BSS pointer proximity: all pointers should be within ~64 bytes
        # of each other in the BSS (obmalloc globals are adjacent)
        bss_addrs = [bss for bss, _ in group]
        bss_span = max(bss_addrs) - min(bss_addrs)
        if bss_span <= 64:
            score += 30
        elif bss_span <= 256:
            score += 10

        print(f"    Group scoring: base=0x{base_ptr:x} active={active} "
              f"ptrs={len(group)} bss_span={bss_span} score={score}")

        if score > best_score:
            best_score = score
            best_group = group

    if best_group is None:
        print("  [bss_scan] No valid candidate group found")
        return found

    arenas_bss_addr, arenas_ptr_val = best_group[0]
    found["arenas"] = arenas_bss_addr
    active_arenas = _count_valid_arenas_from_ptr(layer, arenas_ptr_val, max_check=128)
    print(f"  [bss_scan] Selected arenas: 0x{arenas_bss_addr:x} -> 0x{arenas_ptr_val:x} "
          f"({active_arenas} active arenas, {len(best_group)} pointers in group, score={best_score})")

    # -----------------------------------------------------------------------
    # Phase 4: Find 'maxarenas' near 'arenas'
    # -----------------------------------------------------------------------
    # maxarenas is a uint32 that represents the allocated capacity of the
    # arena_object array. Constraints:
    #   - Located within 64 bytes of arenas (same cache line / struct region)
    #   - Value is a uint32 (not a pointer — upper 4 bytes should be 0)
    #   - Value >= number of observed valid arenas (it's the capacity)
    #   - Value is a power-of-2 multiple of INITIAL_ARENA_OBJECTS (16),
    #     because CPython doubles the array: 16, 32, 64, 128, ...
    #     OR at least >= observed count and <= 4096
    #   - The 4 bytes immediately following it should NOT look like the
    #     upper half of a pointer (to distinguish from a misaligned pointer read)

    observed_count = active_arenas
    print(f"  [bss_scan] Observed arena count for maxarenas search: {observed_count}")

    # Valid maxarenas values: must be >= observed arenas and a reasonable capacity
    # CPython doubles: 16 -> 32 -> 64 -> 128 -> 256 -> ...
    def _is_valid_maxarenas(val, observed):
        if val < observed:
            return False
        if val > 4096:
            return False
        # Check if it's a power-of-2 multiple of 16 (CPython's growth pattern)
        # 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
        if val >= 16:
            v = val
            while v > 16:
                if v % 2 != 0:
                    return False
                v //= 2
            return v == 16
        # Small initial values (shouldn't happen in practice)
        return val >= observed

    maxarenas_candidates = []  # list of (addr, value, distance)

    # Scan a wider range: [-64, +64] bytes around arenas, reading as uint32
    # We read every 4-byte aligned position (maxarenas is uint32, may be at
    # any 4-byte boundary)
    SEARCH_RANGE = 64
    for delta in range(-SEARCH_RANGE, SEARCH_RANGE + 4, 4):
        candidate_addr = arenas_bss_addr + delta
        try:
            raw = layer.read(candidate_addr, 8, pad=False)
            val_32 = int.from_bytes(raw[0:4], 'little')
            upper_32 = int.from_bytes(raw[4:8], 'little')

            # Skip if this looks like part of a pointer (upper 4 bytes non-zero
            # in a way consistent with a userspace address)
            if upper_32 != 0 and (upper_32 & 0xFFFF0000) in (0x7fff0000, 0x7f000000, 0x55550000, 0x55710000):
                continue

            if _is_valid_maxarenas(val_32, observed_count):
                maxarenas_candidates.append((candidate_addr, val_32, abs(delta)))
                print(f"    maxarenas candidate: 0x{candidate_addr:x} = {val_32} (delta={delta:+d})")

        except Exception:
            continue

    if maxarenas_candidates:
        # Prefer: closest to arenas, then exact power-of-2-of-16
        maxarenas_candidates.sort(key=lambda c: (c[2], c[1]))
        best_ma_addr, best_ma_val, best_ma_dist = maxarenas_candidates[0]
        found["maxarenas"] = best_ma_addr
        print(f"  [bss_scan] Selected maxarenas: 0x{best_ma_addr:x} = {best_ma_val} "
              f"(delta={best_ma_dist})")
    else:
        print(f"  [bss_scan] WARNING: Could not find maxarenas")

    # -----------------------------------------------------------------------
    # Phase 5: Identify 'usable_arenas' from the group
    # -----------------------------------------------------------------------
    if len(best_group) > 1:
        for bss_addr, ptr_val in best_group[1:]:
            # usable_arenas points into the same array but at a different offset
            offset_in_array = ptr_val - arenas_ptr_val
            if offset_in_array >= 0 and offset_in_array % 48 == 0:
                found["usable_arenas"] = bss_addr
                arena_index = offset_in_array // 48
                print(f"  [bss_scan] Found usable_arenas: 0x{bss_addr:x} -> 0x{ptr_val:x} "
                      f"(arena index {arena_index})")
                break

    return found


def scan_bss_for_pyruntime(
    layer, base_address: int, elf_info: Dict,
    task, context, proc_layer_name: str,
) -> Dict[str, int]:
    """
    Find _PyRuntime by scanning writable segments of the Python binary
    for the _PyRuntimeState struct signature.

    _PyRuntime lives in:
      - .bss for Python 3.7-3.8 (uninitialized global)
      - .data for Python 3.9+ (statically initialized via _PyRuntimeState_INIT)

    Key signature (3.7-3.13):
      _PyRuntime + interp_head_offset:     interpreters.head
      _PyRuntime + interp_head_offset + 8: interpreters.main  (== head for single-interp)
      _PyRuntime + interp_head_offset + 16: interpreters.next_id (== 1)
    """
    found = {}

    python_rw_regions = _collect_python_rw_regions(layer, task, context)
    if not python_rw_regions:
        return found

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
                head_ptr = int.from_bytes(
                    data[offset + interp_offset:offset + interp_offset + 8], 'little'
                )
                if head_ptr == 0 or head_ptr < 0x10000 or head_ptr > 0x7fffffffffff:
                    continue

                main_ptr = int.from_bytes(
                    data[offset + interp_offset + 8:offset + interp_offset + 16], 'little'
                )
                if head_ptr != main_ptr:
                    continue

                next_id = int.from_bytes(
                    data[offset + interp_offset + 16:offset + interp_offset + 24], 'little'
                )
                if next_id != 1:
                    continue

                test = _read_bytes(layer, head_ptr, 16)
                if test is None or all(b == 0 for b in test):
                    continue

                candidate_addr = region_start + offset

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
# Master resolution — runs all strategies in order of reliability
# ---------------------------------------------------------------------------

def resolve_symbols(
    layer, base_address: int, symbol_names: List[str],
    task=None, context=None, proc_layer_name: str = None,
) -> Dict[str, int]:
    
    """
    Try each resolution strategy until all requested symbols are found
    or we run out of options.
    """
    target_set = set(symbol_names)
    found = {}

    elf_info = parse_elf_header(layer, base_address)
    if elf_info is None:
        vollog.warning(f"Invalid ELF at 0x{base_address:x}")
        return found

    segments = parse_load_segments(layer, base_address, elf_info)
    print(f"Found {len(segments)} program headers, "
                f"{sum(1 for s in segments if s['type']==1)} PT_LOAD segments")

    # Strategy 1: section headers
    print(f"\n--- Strategy 1: Section Headers ---")
    s1 = search_section_symbols(layer, base_address, elf_info, target_set, segments)
    print(f"  Strategy 1 found: {s1}")
    for name, addr in s1.items():
        print(f"    {name} = 0x{addr:x}")
    found.update(s1)
    remaining = target_set - set(found.keys())
    print(f"  Remaining after S1: {remaining}")
    if not remaining:
        return found

    # Strategy 2: dynamic symbols
    print(f"\n--- Strategy 2: Dynamic Symbols ---")
    s2 = search_dynamic_symbols(layer, base_address, elf_info, remaining, segments)
    print(f"  Strategy 2 found: {s2}")
    for name, addr in s2.items():
        print(f"    {name} = 0x{addr:x}")
        if name == "arenas":
            valid = _validate_arenas_pointer(layer, addr)
            print(f"    validation: {'PASS' if valid else 'FAIL'}")
    found.update(s2)

    # Validate arenas after Strategy 2
    if "arenas" in found and "arenas" in remaining:
        if not _validate_arenas_pointer(layer, found["arenas"]):
            print(f"  DISCARDING invalid 'arenas' at 0x{found['arenas']:x}")
            del found["arenas"]
            if "maxarenas" in found and "maxarenas" in remaining:
                del found["maxarenas"]

    remaining = target_set - set(found.keys())
    print(f"  Remaining after S2: {remaining}")
    if not remaining:
        return found

    # Strategy 3: LTO variants
    print(f"\n--- Strategy 3: LTO Variants ---")
    s3 = search_lto_symbols(layer, base_address, elf_info, remaining, segments)
    print(f"  Strategy 3 found: {s3}")
    found.update(s3)
    remaining = target_set - set(found.keys())
    print(f"  Remaining after S3: {remaining}")
    if not remaining:
        return found

    # Strategy 4: mapped symtab scan
    print(f"\n--- Strategy 4: Mapped Symtab Scan ---")
    s4 = search_mapped_symtab(layer, base_address, elf_info, remaining, segments)
    print(f"  Strategy 4 found: {s4}")
    for name, addr in s4.items():
        print(f"    {name} = 0x{addr:x}")
        if name == "arenas":
            valid = _validate_arenas_pointer(layer, addr)
            print(f"    validation: {'PASS' if valid else 'FAIL'}")
    found.update(s4)

    # Validate arenas after Strategy 4
    if "arenas" in found and "arenas" in remaining:
        if not _validate_arenas_pointer(layer, found["arenas"]):
            print(f"  DISCARDING invalid 'arenas' at 0x{found['arenas']:x}")
            del found["arenas"]
            if "maxarenas" in found and "maxarenas" in remaining:
                del found["maxarenas"]

    remaining = target_set - set(found.keys())
    print(f"  Remaining after S4: {remaining}")
    if not remaining:
        return found

    # Strategy 5: BSS scan for arenas
    print(f"\n--- Strategy 5: BSS Scan for arenas ---")
    if "arenas" in remaining and task is not None:
        print(f"  Scanning writable Python VMAs...")
        for vma in task.mm.get_vma_iter():
            try:
                path = vma.get_name(context, task)
            except Exception:
                continue
            path_str = str(path) if path else ""
            if "python" in path_str.lower():
                flags = vma.get_protection()
                #print(f"    VMA 0x{int(vma.vm_start):x}-0x{int(vma.vm_end):x} "
                     # f"{flags} {path_str}")

        s5 = scan_bss_for_arenas(
            layer, base_address, elf_info, task, context, proc_layer_name
        )
        print(f"  Strategy 5 found: {s5}")
        for name, addr in s5.items():
            print(f"    {name} = 0x{addr:x}")
            if name == "arenas":
                ptr_bytes = _read_bytes(layer, addr, 8)
                if ptr_bytes:
                    ptr_val = int.from_bytes(ptr_bytes, 'little')
                    print(f"    arenas pointer dereference: 0x{addr:x} -> 0x{ptr_val:x}")
        found.update(s5)
    else:
        print(f"  Skipped: arenas {'not in remaining' if 'arenas' not in remaining else 'no task'}")

    # If we found arenas but not maxarenas from S5, do a targeted search
    if "arenas" in found and "maxarenas" not in found:
        print(f"\n--- Fallback: Searching for maxarenas near arenas 0x{found['arenas']:x} ---")
        arenas_addr = found["arenas"]

        # Dereference to count actual arenas for validation
        ptr_bytes = _read_bytes(layer, arenas_addr, 8)
        if ptr_bytes:
            arenas_ptr_val = int.from_bytes(ptr_bytes, 'little')
            observed = _count_valid_arenas_from_ptr(layer, arenas_ptr_val, max_check=256)
        else:
            observed = 1

        # Search nearby for a uint32 that's a valid capacity
        # Prefer closest to arenas, and require power-of-2-of-16 pattern
        maxarenas_candidates = []
        for delta in range(-64, 68, 4):
            if delta == 0:
                continue
            candidate = arenas_addr + delta
            try:
                raw = layer.read(candidate, 8, pad=False)
                val = int.from_bytes(raw[0:4], 'little')
                upper = int.from_bytes(raw[4:8], 'little')

                # Must be >= observed arenas and <= 4096
                if val < observed or val > 4096:
                    continue
                # Upper 4 bytes should be 0 (it's a uint32, not a pointer)
                if upper != 0:
                    full_val = int.from_bytes(raw, 'little')
                    if 0x10000 < full_val < 0x7fffffffffff:
                        continue

                # Check power-of-2-of-16 pattern
                is_pow2_of_16 = False
                if val >= 16:
                    v = val
                    while v > 16:
                        if v % 2 != 0:
                            break
                        v //= 2
                    is_pow2_of_16 = (v == 16)

                print(f"    delta={delta:+d} 0x{candidate:x} = {val} (upper32=0x{upper:x})"
                      f"{' [pow2x16]' if is_pow2_of_16 else ''}")

                maxarenas_candidates.append((candidate, val, abs(delta), is_pow2_of_16))

            except Exception:
                continue

        if maxarenas_candidates:
            # Prefer: power-of-2-of-16, then closest
            maxarenas_candidates.sort(key=lambda c: (not c[3], c[2], c[1]))
            best = maxarenas_candidates[0]
            found["maxarenas"] = best[0]
            print(f"  Found maxarenas at 0x{best[0]:x} = {best[1]}")

    # Strategy 6: _PyRuntime
    remaining = target_set - set(found.keys())
    if "_PyRuntime" in remaining and task is not None:
        print(f"\n--- Strategy 6: BSS Scan for _PyRuntime ---")
        found.update(scan_bss_for_pyruntime(
            layer, base_address, elf_info, task, context, proc_layer_name
        ))

    remaining = target_set - set(found.keys())
    print(f"\nresolve_symbols returning: {found}, remaining: {remaining}")
    return found

    
# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def find_python_module_base(
    context, proc_layer_name: str, task,
    module_substring: str = "libpython",
) -> Optional[Tuple[int, str]]:
    """
    Locate the ELF base address of a Python module in the process's VMA list.
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
    Top-level entry point: find symbols in a Python module within a live process.
    """
    layer = context.layers[proc_layer_name]
    all_found = {}
    remaining = list(symbol_names)

    candidates = []

    result = find_python_module_base(context, proc_layer_name, task, module_substring)
    if result is not None:
        candidates.append(result)

    if module_substring.lower() != "python":
        result2 = find_python_module_base(context, proc_layer_name, task, "python")
        if result2 is not None and (not candidates or result2[0] != candidates[0][0]):
            candidates.append(result2)

    for base_address, path in candidates:
        if not remaining:
            break

        print(f"Searching ELF: {path} at 0x{base_address:x} for {remaining}")

        found = resolve_symbols(
            layer, base_address, remaining,
            task=task, context=context, proc_layer_name=proc_layer_name,
        )

        all_found.update(found)
        remaining = [s for s in remaining if s not in all_found]

    return all_found

# ---------------------------------------------------------------------------
# Standalone plugin — can be run from the command line for debugging
# ---------------------------------------------------------------------------

class ELFSymbolFinder(interfaces.plugins.PluginInterface):
    """Find ELF symbols in process memory (memory-only parsing)."""
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
                description="Comma-separated symbols (e.g. 'arenas,maxarenas')",
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
