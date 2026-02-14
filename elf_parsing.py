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
# Strategy 1: Section headers → .symtab/.dynsym
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
        if sh_type not in (2, 11): # Walk all section headers, looking for SHT_SYMTAB (2) and SHT_DYNSYM (11)
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
            sh_entsize = 24 if is_64 else 16  # Default Elf64_Sym / Elf32_Sym size

        # The symbol table data itself also needs to be within a PT_LOAD
        symtab_vaddr = file_offset_to_vaddr(segments, sh_offset, is_pie, base_address)
        if symtab_vaddr is None:
            vollog.debug(f"Symbol table at file offset 0x{sh_offset:x} not mapped")
            continue

        # sh_link points to the associated string table section
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
       
        # Cap the read at 1MB to avoid blowing up on corrupt data
        strtab_data = _read_bytes(layer, strtab_vaddr, min(strtab_size, 1 << 20))
        if strtab_data is None:
            continue

        num_symbols = sh_size // sh_entsize
        section_name = "SHT_SYMTAB" if sh_type == 2 else "SHT_DYNSYM"
        vollog.info(f"Scanning {section_name} at 0x{symtab_vaddr:x} ({num_symbols} symbols)")
        
        # Linear scan through all symbol entries
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

            
            # Extract the null-terminated symbol name from the string table
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
# Strategy 2: PT_DYNAMIC → .dynsym/.dynstr
#
# The dynamic segment is ALWAYS mapped (the runtime linker needs it).
# It contains DT_SYMTAB, DT_STRTAB, DT_STRSZ entries that point directly
# to the dynamic symbol/string tables in memory. This reliably finds any
# symbol that's exported (visible to the dynamic linker), but obmalloc
# internals like 'arenas' are usually static/local — so this alone
# won't find everything we need.
# ---------------------------------------------------------------------------

def search_dynamic_symbols(
    layer, base_address: int, elf_info: Dict,
    symbol_names: Set[str], segments: List[Dict],
) -> Dict[str, int]:
    """
    Resolve symbols through the dynamic symbol table.
    PT_DYNAMIC is always present for dynamically-linked binaries.
    """
    found = {}
    remaining = set(symbol_names)
    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]

    # Locate the PT_DYNAMIC segment
    dynamic_vaddr = None
    dynamic_memsz = None
    for seg in segments:
        if seg["type"] == 2:  # Locate the PT_DYNAMIC segment
            dynamic_vaddr = seg["vaddr"]
            dynamic_memsz = seg["memsz"]
            break

    if dynamic_vaddr is None:
        return found

    dynamic_addr = _resolve_addr(base_address, dynamic_vaddr, is_pie)
    dyn_entry_size = 16 if is_64 else 8

    # Walk the dynamic array collecting the tags we need:
    #   DT_STRTAB (5)  = address of .dynstr
    #   DT_SYMTAB (6)  = address of .dynsym
    #   DT_STRSZ  (10) = size of .dynstr in bytes
    #   DT_SYMENT (11) = size of one Elf_Sym entry
    #   DT_HASH   (4)  = address of the symbol hash table (gives us nchain = symbol count)
    #   DT_GNU_HASH (0x6ffffef5) = GNU hash table (alternative to DT_HASH)
   
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

    symtab_raw  = dt.get(6)  # DT_SYMTAB
    strtab_raw  = dt.get(5)  # DT_STRTAB
    strtab_size = dt.get(10) # DT_STRTAB
    syment_size = dt.get(11) # DT_SYMENT

    if None in (symtab_raw, strtab_raw, strtab_size):
        return found
    if syment_size is None:
        syment_size = 24 if is_64 else 16

    # DT_SYMTAB/DT_STRTAB hold virtual addresses, not file offsets.
    # For PIE binaries these are relative to the load base.
    if is_pie:
        symtab_addr = base_address + symtab_raw
        strtab_addr = base_address + strtab_raw
    else:
        symtab_addr = symtab_raw
        strtab_addr = strtab_raw

    # Try to get an exact symbol count from DT_HASH.
    # The SYSV hash table starts with [nbucket, nchain] — nchain == number of symbols.
    num_symbols = None
    dt_hash = dt.get(4)
    if dt_hash is not None:
        hash_addr = (base_address + dt_hash) if is_pie else dt_hash
        hash_hdr = _read_bytes(layer, hash_addr, 8)
        if hash_hdr:
            num_symbols = int.from_bytes(hash_hdr[4:8], 'little')
    
    # If we can't determine the count, use a generous upper bound.
    # We'll stop early once we find everything anyway.
    if num_symbols is None:
        num_symbols = 50000

    strtab_data = _read_bytes(layer, strtab_addr, min(strtab_size, 1 << 20))
    if strtab_data is None:
        return found

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
            vollog.info(f"[dynamic] Found '{sym_name}' at 0x{resolved:x}")
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

    # Run the LTO names through the same resolution strategies
    lto_found = search_section_symbols(layer, base_address, elf_info, lto_targets, segments)
    remaining_lto = lto_targets - set(lto_found.keys())
    if remaining_lto:
        lto_found.update(search_dynamic_symbols(layer, base_address, elf_info, remaining_lto, segments))
    
    # Map the LTO names back to the original names the caller asked for
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
    
    # Also try LTO variants in the same scan
    lto_map = {}
    for name in symbol_names:
        lto_map[name + ".lto_priv"] = name
    all_targets = remaining | set(lto_map.keys())

    is_64  = elf_info["is_64"]
    is_pie = elf_info["is_pie"]
    sym_size = 24 if is_64 else 16 # sizeof(Elf64_Sym) or Elf32_Sym

    # Collect readable PT_LOAD segments — .symtab data lives in read-only segments
    readable_segments = []
    for seg in segments:
        if seg["type"] != 1:  # PT_LOAD only
            continue
        # .symtab is typically in a read-only segment (not executable)
        # Flags: PF_R=4, PF_W=2, PF_X=1
        if seg["filesz"] > 0:
            seg_vaddr = _resolve_addr(base_address, seg["vaddr"], is_pie)
            readable_segments.append((seg_vaddr, seg["filesz"], seg["flags"]))

    # Phase 1: Find our target symbol names as literal strings in the data segments.
    # This locates candidate .strtab regions.
    strtab_candidates = []
    for seg_vaddr, seg_size, seg_flags in readable_segments:
        # .symtab/.strtab are in data segments, not code — skip executable ones
        if seg_flags & 1:  # PF_X
            continue
       
        if seg_size < 1024:
            continue

        
        chunk_size = min(seg_size, 0x200000)
        data = _read_bytes(layer, seg_vaddr, chunk_size)
        if data is None:
            continue

       
        for target in all_targets:
            # Symbol names in .strtab are null-terminated
            target_bytes = target.encode('ascii') + b'\x00'
            pos = 0
            while True:
                idx = data.find(target_bytes, pos)
                if idx < 0:
                    break

                # Found the string. Now walk backwards to find where .strtab begins.
                # ELF string tables always start with a \x00 byte and contain only
                # printable ASCII separated by nulls.
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

                # Align to the first null byte (strtab convention)
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

    # Phase 2: For each candidate strtab location, search the memory BEFORE it
    # for Elf64_Sym entries. The .symtab section is typically placed just before
    # .strtab in the ELF layout, so we scan backwards looking for an entry whose
    # st_name field equals our computed offset.
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

        # Look for an Elf64_Sym entry where st_name matches our offset
        name_offset_bytes = name_offset.to_bytes(4, 'little')

        for offset in range(0, len(sym_data) - sym_size, sym_size):
            # Check if st_name field matches
            if sym_data[offset:offset + 4] != name_offset_bytes:
                continue

            # Potential match — validate the rest of the Elf64_Sym fields
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

            # Basic sanity: binding should be LOCAL/GLOBAL/WEAK)
            if st_bind > 2:
                continue
            # Type should be NOTYPE/OBJECT/FUNC/SECTION/FILE
            if st_type > 4:
                continue
            # For non-PIE, addresses should be in the expected range
            if st_value == 0:
                continue
            if not is_pie and (st_value < 0x400000 or st_value > 0xffffffff):
                continue

            resolved = _resolve_addr(base_address, st_value, is_pie)

            # Final check: the resolved address should be readable
            if _read_bytes(layer, resolved, 8) is None:
                continue

            # Map LTO name back to original
            orig_name = lto_map.get(target, target)
            found[orig_name] = resolved
            remaining.discard(orig_name)
            vollog.info(f"[mapped_symtab] Found '{orig_name}' (as '{target}') at 0x{resolved:x}")

            if not remaining and not (set(lto_map.keys()) - set(found.keys())):
                return found

            break  # Move to next candidate

    return found


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
# ---------------------------------------------------------------------------

def scan_bss_for_arenas(
    layer, base_address: int, elf_info: Dict,
    task, context, proc_layer_name: str,
) -> Dict[str, int]:
    """
    Find the arenas pointer by scanning writable segments for a pointer
    that dereferences to a valid arena_object array.
    """
    found = {}

    # Collect writable VMAs that belong to the Python binary.
    # The arenas global lives in .data or .bss, which are always writable.
    python_rw_regions = []
    for vma in task.mm.get_vma_iter():
        try:
            path = vma.get_name(context, task)
        except Exception:
            continue

        path_str = str(path) if path else ""
        vm_start = int(vma.vm_start)
        vm_end = int(vma.vm_end)

        if "python" in path_str.lower() and ("/bin/" in path_str or "libpython" in path_str.lower()):
            flags = vma.get_protection()
            if 'w' in flags:
                python_rw_regions.append((vm_start, vm_end, path_str))

    
    # .bss can overflow into an adjacent anonymous mapping (the kernel extends
    # the data segment with an anonymous page when .bss is larger than what
    # fits in the file-backed page). Include those too.
    all_vmas = []
    for vma in task.mm.get_vma_iter():
        all_vmas.append((int(vma.vm_start), int(vma.vm_end), vma))

    for vma_start, vma_end, vma in all_vmas:
        try:
            path = vma.get_name(context, task)
        except Exception:
            path = None
        if path and "Anonymous" not in str(path):
            continue
        for rw_start, rw_end, _ in list(python_rw_regions):
            if vma_start == rw_end:
                python_rw_regions.append((vma_start, vma_end, "anonymous(.bss)"))
                break

    # Scan every 8-byte-aligned pointer in the writable regions
    for region_start, region_end, region_path in python_rw_regions:
        scan_size = min(region_end - region_start, 0x100000)

        for offset in range(0, scan_size - 8, 8):
            addr = region_start + offset
            try:
                ptr_bytes = layer.read(addr, 8, pad=False)
                ptr_val = int.from_bytes(ptr_bytes, 'little')
                
                # Quick filter: must be a plausible userspace pointer
                if ptr_val < 0x10000 or ptr_val > 0x7fffffffffff:
                    continue

                # Try to read the first arena_object (48 bytes) from where this pointer leads
                arena_data = _read_bytes(layer, ptr_val, 48)
                if arena_data is None:
                    continue

                # Parse the arena_object fields and validate them
                arena_addr  = int.from_bytes(arena_data[0:8], 'little')
                pool_addr   = int.from_bytes(arena_data[8:16], 'little')
                nfreepools  = int.from_bytes(arena_data[16:20], 'little')
                ntotalpools = int.from_bytes(arena_data[20:24], 'little')

                if arena_addr == 0:
                    continue
               
                # CPython arenas are 256KB = 64 pools of 4KB each
                if not (0 < ntotalpools <= 64):
                    continue
                
                # pool_address is always above arena address
                if pool_addr <= arena_addr:
                    continue
               
                # pool_address is always above arena address
                if (pool_addr - arena_addr) > 0x80000:
                    continue
                
                # The arena memory itself should be readable
                if _read_bytes(layer, arena_addr, 8) is None:
                    continue

                # Cross-check: the second arena_object in the array should also be
                # valid (or zeroed out if unused)
                arena2_data = _read_bytes(layer, ptr_val + 48, 48)
                if arena2_data is not None:
                    arena2_addr = int.from_bytes(arena2_data[0:8], 'little')
                    ntotal2 = int.from_bytes(arena2_data[20:24], 'little')
                    # Second entry should also be valid or zero (unused)
                    if arena2_addr != 0 and (ntotal2 == 0 or ntotal2 > 64):
                        continue

                found["arenas"] = addr
                vollog.info(f"[bss_scan] Found arenas at 0x{addr:x} -> 0x{ptr_val:x}")

                # maxarenas is typically within 32 bytes of arenas in .bss.
                # It's a 4-byte integer that should be >= ntotalpools and reasonably small.
                for delta in range(-32, 33, 8):
                    if delta == 0:
                        continue
                    candidate = addr + delta
                    try:
                        val = int.from_bytes(layer.read(candidate, 4, pad=False), 'little')
                        if val >= ntotalpools and 0 < val <= 4096:
                            found["maxarenas"] = candidate
                            vollog.info(f"[bss_scan] Found maxarenas at 0x{candidate:x} = {val}")
                            break
                    except Exception:
                        continue

                return found

            except Exception:
                continue

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
    vollog.info(f"Found {len(segments)} program headers, "
                f"{sum(1 for s in segments if s['type']==1)} PT_LOAD segments")

   
    # Strategy 1: section headers (if they happen to be in a PT_LOAD)
    found.update(search_section_symbols(layer, base_address, elf_info, target_set, segments))
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 2: dynamic symbols (reliable but only exported symbols)
    found.update(search_dynamic_symbols(layer, base_address, elf_info, remaining, segments))
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 3: LTO-renamed variants (arenas.lto_priv, etc.)
    found.update(search_lto_symbols(layer, base_address, elf_info, remaining, segments))
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 4: raw data scan (find symbol strings in PT_LOAD segments)
    found.update(search_mapped_symtab(layer, base_address, elf_info, remaining, segments))
    remaining = target_set - set(found.keys())
    if not remaining:
        return found

    # Strategy 5: structural pattern matching (arena-specific heuristic)
    if "arenas" in remaining and task is not None:
        found.update(scan_bss_for_arenas(
            layer, base_address, elf_info, task, context, proc_layer_name
        ))

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
    
    We look for VMAs whose backing file path contains module_substring,
    then verify the mapping starts with the ELF magic. For shared libraries
    that are mapped at multiple VMAs (text, rodata, data, etc.), we want the
    lowest address — that's where the ELF header lives.
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
        
        # Only accept VMAs that actually start with an ELF header
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

    Tries module_substring first (e.g. "libpython" for shared-library builds),
    then falls back to "python" (for statically-linked builds where the binary
    itself contains the symbols).
    """
    layer = context.layers[proc_layer_name]

    result = find_python_module_base(context, proc_layer_name, task, module_substring)
    if result is None:
        result = find_python_module_base(context, proc_layer_name, task, "python")
    if result is None:
        vollog.warning(f"Could not find module matching '{module_substring}' or 'python'")
        return {}

    base_address, path = result
    vollog.info(f"Found Python ELF: {path} at 0x{base_address:x}")

    return resolve_symbols(
        layer, base_address, symbol_names,
        task=task, context=context, proc_layer_name=proc_layer_name,
    )


# ---------------------------------------------------------------------------
# Standalone plugin — can be run from the command line for debugging
#
# Usage:
#   vol.py -f dump.vmem linux.elf_parsing.ELFSymbolFinder \
#       --module-name python --symbol arenas,maxarenas --pid 1234
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
