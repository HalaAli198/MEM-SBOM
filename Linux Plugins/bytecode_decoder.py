"""
Version-aware bytecode decoder for Python 3.6–3.16.

Decodes raw co_code bytes using per-version opcode tables,
independent of the host Python version. This replaces the use of
dis.get_instructions() which only understands the host's bytecode format.

Only the opcodes relevant for dependency extraction are decoded;
unknown opcodes are emitted as "UNKNOWN_<number>".
"""

from typing import List, Dict, Tuple, Optional, Set


# =====================================================================
# Per-version opcode number → name mappings
# =====================================================================
# We only need the opcodes that matter for dependency/import analysis.
# The full tables are included for the opcodes we care about.
#
# Sources: CPython Lib/opcode.py for each version tag.
# =====================================================================

# Opcodes that are STABLE across 3.6–3.10 (same numeric values)
_OPCODES_36_TO_310 = {
    1:   'POP_TOP',
    100: 'LOAD_CONST',
    101: 'LOAD_NAME',
    106: 'LOAD_ATTR',
    108: 'IMPORT_NAME',
    109: 'IMPORT_FROM',
    110: 'IMPORT_STAR',
    116: 'LOAD_GLOBAL',
    124: 'LOAD_FAST',
    125: 'STORE_FAST',
    90:  'STORE_NAME',
    97:  'STORE_GLOBAL',
    131: 'CALL_FUNCTION',
    141: 'CALL_FUNCTION_KW',
    142: 'CALL_FUNCTION_EX',
    144: 'EXTENDED_ARG',
    136: 'LOAD_DEREF',
    137: 'STORE_DEREF',
    138: 'DELETE_DEREF',
    148: 'LOAD_CLASSDEREF',  # 3.6–3.11
}

# 3.7+ added LOAD_METHOD / CALL_METHOD
_OPCODES_37_ADDITIONS = {
    160: 'LOAD_METHOD',
    161: 'CALL_METHOD',
}

# ------------------------------------------------------------------
# Python 3.11: major reshuffling begins
# ------------------------------------------------------------------
_OPCODES_311 = {
    0:   'CACHE',
    1:   'POP_TOP',
    2:   'PUSH_NULL',
    100: 'LOAD_CONST',
    101: 'LOAD_NAME',
    106: 'LOAD_ATTR',
    108: 'IMPORT_NAME',
    109: 'IMPORT_FROM',
    110: 'IMPORT_STAR',
    116: 'LOAD_GLOBAL',       # arg >> 1 = name index
    124: 'LOAD_FAST',
    125: 'STORE_FAST',
    90:  'STORE_NAME',
    97:  'STORE_GLOBAL',
    131: 'CALL_FUNCTION',     # still present but deprecated path
    141: 'CALL_FUNCTION_KW',
    142: 'CALL_FUNCTION_EX',
    144: 'EXTENDED_ARG',
    136: 'LOAD_DEREF',
    137: 'STORE_DEREF',
    148: 'LOAD_CLASSDEREF',
    160: 'LOAD_METHOD',
    161: 'CALL_METHOD',
    166: 'PRECALL',
    171: 'CALL',
}

# ------------------------------------------------------------------
# Python 3.12: complete opcode number reshuffling
# Removed: LOAD_METHOD (merged into LOAD_ATTR), PRECALL,
#          CALL_FUNCTION, CALL_METHOD, CALL_FUNCTION_KW
# LOAD_GLOBAL arg >> 1, LOAD_ATTR arg >> 1 (low bit = method flag)
# ------------------------------------------------------------------
_OPCODES_312 = {
    0:   'CACHE',
    1:   'POP_TOP',
    2:   'PUSH_NULL',
    # 3.12 reassigned numbers — these are from CPython 3.12 opcode.py
    83:  'RETURN_VALUE',
    100: 'LOAD_CONST',
    101: 'LOAD_NAME',
    106: 'LOAD_ATTR',         # arg >> 1 = name index; low bit = method flag
    108: 'IMPORT_NAME',
    109: 'IMPORT_FROM',
    110: 'IMPORT_STAR',
    116: 'LOAD_GLOBAL',       # arg >> 1 = name index
    124: 'LOAD_FAST',
    125: 'STORE_FAST',
    90:  'STORE_NAME',
    97:  'STORE_GLOBAL',
    142: 'CALL_FUNCTION_EX',
    144: 'EXTENDED_ARG',
    136: 'LOAD_DEREF',
    137: 'STORE_DEREF',
    171: 'CALL',
}

# ------------------------------------------------------------------
# Python 3.13+: further reshuffling of opcode numbers
# The actual opcode numbers are completely different from 3.12.
# From CPython 3.13 Lib/_opcode_metadata.py / opcode.py
# ------------------------------------------------------------------
_OPCODES_313 = {
    0:   'CACHE',
    1:   'POP_TOP',
    2:   'PUSH_NULL',
    83:  'RETURN_VALUE',
    100: 'LOAD_CONST',
    101: 'LOAD_NAME',
    106: 'LOAD_ATTR',
    108: 'IMPORT_NAME',
    109: 'IMPORT_FROM',
    110: 'IMPORT_STAR',
    116: 'LOAD_GLOBAL',
    124: 'LOAD_FAST',
    125: 'STORE_FAST',
    90:  'STORE_NAME',
    97:  'STORE_GLOBAL',
    142: 'CALL_FUNCTION_EX',
    144: 'EXTENDED_ARG',
    136: 'LOAD_DEREF',
    137: 'STORE_DEREF',
    171: 'CALL',
}

# 3.14–3.16: assume same as 3.13 unless we discover otherwise
_OPCODES_314 = dict(_OPCODES_313)
_OPCODES_315 = dict(_OPCODES_313)
_OPCODES_316 = dict(_OPCODES_313)


def _build_opcode_table(version: Tuple[int, int]) -> Dict[int, str]:
    """Return the opcode number→name mapping for the given Python version."""
    major, minor = version

    if minor <= 6:
        return dict(_OPCODES_36_TO_310)
    elif minor <= 10:
        table = dict(_OPCODES_36_TO_310)
        table.update(_OPCODES_37_ADDITIONS)
        return table
    elif minor == 11:
        return dict(_OPCODES_311)
    elif minor == 12:
        return dict(_OPCODES_312)
    elif minor == 13:
        return dict(_OPCODES_313)
    elif minor == 14:
        return dict(_OPCODES_314)
    elif minor == 15:
        return dict(_OPCODES_315)
    elif minor >= 16:
        return dict(_OPCODES_316)
    else:
        # Fallback: use 3.8 table
        table = dict(_OPCODES_36_TO_310)
        table.update(_OPCODES_37_ADDITIONS)
        return table


# =====================================================================
# Cache sizes per opcode (3.11+)
# After certain opcodes, there are N "CACHE" slots to skip.
# These are 2-byte words, same size as instructions.
# =====================================================================

# 3.11 cache sizes (from CPython _opcode_metadata.py)
_CACHE_SIZES_311 = {
    'LOAD_GLOBAL':  4,
    'LOAD_ATTR':    4,
    'LOAD_METHOD':  10,
    'CALL':         4,
    'PRECALL':      1,
    'STORE_ATTR':   4,
    'COMPARE_OP':   2,
    'BINARY_OP':    1,
    'BINARY_SUBSCR': 4,
    'UNPACK_SEQUENCE': 1,
    'CALL_FUNCTION': 0,
    'CALL_METHOD':  0,
}

# 3.12+ cache sizes
_CACHE_SIZES_312 = {
    'LOAD_GLOBAL':  4,
    'LOAD_ATTR':    9,
    'CALL':         3,
    'STORE_ATTR':   4,
    'COMPARE_OP':   1,
    'BINARY_OP':    1,
    'BINARY_SUBSCR': 1,
    'UNPACK_SEQUENCE': 1,
    'LOAD_SUPER_ATTR': 1,
    'CALL_FUNCTION_EX': 0,
}

# 3.13+ cache sizes (may differ slightly)
_CACHE_SIZES_313 = {
    'LOAD_GLOBAL':  4,
    'LOAD_ATTR':    9,
    'CALL':         3,
    'STORE_ATTR':   4,
    'COMPARE_OP':   1,
    'BINARY_OP':    1,
    'BINARY_SUBSCR': 1,
    'UNPACK_SEQUENCE': 1,
    'LOAD_SUPER_ATTR': 1,
    'CALL_FUNCTION_EX': 0,
}


def _get_cache_sizes(version: Tuple[int, int]) -> Dict[str, int]:
    """Return cache-size mapping for the given version."""
    major, minor = version
    if minor <= 10:
        return {}  # no inline caches before 3.11
    elif minor == 11:
        return dict(_CACHE_SIZES_311)
    elif minor == 12:
        return dict(_CACHE_SIZES_312)
    else:
        return dict(_CACHE_SIZES_313)


# =====================================================================
# Instruction word size
# =====================================================================
# 3.6+: all instructions are 2 bytes (wordcode format)
#        opcode = byte[0], arg = byte[1]
#        EXTENDED_ARG shifts arg left by 8 bits
INSTRUCTION_SIZE = 2


# =====================================================================
# Public API
# =====================================================================

class DecodedInstruction:
    """A single decoded bytecode instruction."""
    __slots__ = ('offset', 'opname', 'arg', 'argval')

    def __init__(self, offset: int, opname: str, arg: int, argval: str):
        self.offset = offset
        self.opname = opname
        self.arg = arg
        self.argval = argval

    def __repr__(self):
        return f"{self.opname} {self.argval}"


def decode_bytecode(
    co_code: bytes,
    co_names: tuple,
    co_varnames: tuple,
    co_consts: tuple,
    co_cellvars: tuple,
    co_freevars: tuple,
    version: Tuple[int, int],
) -> Tuple[List[str], Dict[str, tuple]]:
    """
    Decode raw bytecode into a list of "OPNAME argval" strings and
    extract inner code objects, matching the output format of
    Dependency_Generator._process_code().

    Args:
        co_code:     Raw bytecode bytes from the code object
        co_names:    Tuple of name strings (co_names)
        co_varnames: Tuple of local variable name strings
        co_consts:   Tuple of constant objects (PyObject references)
        co_cellvars: Tuple of cell variable name strings
        co_freevars: Tuple of free variable name strings
        version:     (major, minor) Python version of the analyzed process

    Returns:
        (instructions, inner_codes)
        instructions: List of "OPNAME argval" strings
        inner_codes:  Dict of {key: (instructions, inner_codes, code_obj)}
                      for nested code objects found in co_consts
    """
    opcode_table = _build_opcode_table(version)
    cache_sizes = _get_cache_sizes(version)
    minor = version[1]

    # Determine which opcodes need arg >> 1 for name resolution
    # 3.11+: LOAD_GLOBAL uses arg >> 1
    # 3.12+: LOAD_ATTR also uses arg >> 1
    load_global_shift = minor >= 11
    load_attr_shift = minor >= 12

    instructions: List[str] = []
    inner_codes: Dict[str, tuple] = {}

    i = 0
    extended_arg = 0
    code_len = len(co_code)

    while i < code_len:
        op = co_code[i]
        raw_arg = co_code[i + 1] if (i + 1) < code_len else 0
        offset = i

        # Combine with EXTENDED_ARG
        arg = extended_arg | raw_arg

        opname = opcode_table.get(op, f'UNKNOWN_{op}')

        if opname == 'EXTENDED_ARG':
            extended_arg = arg << 8
            i += INSTRUCTION_SIZE
            continue
        else:
            extended_arg = 0

        # Skip CACHE instructions (3.11+)
        if opname == 'CACHE':
            i += INSTRUCTION_SIZE
            continue

        # Resolve argval based on opcode type
        argval = ''

        if opname in ('LOAD_GLOBAL', 'STORE_GLOBAL'):
            name_idx = arg >> 1 if (opname == 'LOAD_GLOBAL' and load_global_shift) else arg
            if isinstance(co_names, tuple) and name_idx < len(co_names):
                argval = co_names[name_idx]
            else:
                argval = f'<name {name_idx}>'

        elif opname in ('LOAD_ATTR', 'LOAD_METHOD'):
            name_idx = arg >> 1 if (opname == 'LOAD_ATTR' and load_attr_shift) else arg
            if isinstance(co_names, tuple) and name_idx < len(co_names):
                argval = co_names[name_idx]
            else:
                argval = f'<name {name_idx}>'

        elif opname in ('LOAD_NAME', 'STORE_NAME', 'IMPORT_NAME', 'IMPORT_FROM'):
            if isinstance(co_names, tuple) and arg < len(co_names):
                argval = co_names[arg]
            else:
                argval = f'<name {arg}>'

        elif opname in ('LOAD_FAST', 'STORE_FAST', 'DELETE_FAST'):
            if isinstance(co_varnames, tuple) and arg < len(co_varnames):
                argval = co_varnames[arg]
            else:
                argval = f'<var {arg}>'

        elif opname in ('LOAD_DEREF', 'STORE_DEREF', 'DELETE_DEREF',
                        'LOAD_CLASSDEREF'):
            free_vars = tuple(co_cellvars) + tuple(co_freevars)
            if arg < len(free_vars):
                argval = free_vars[arg]
            else:
                argval = f'<deref {arg}>'

        elif opname == 'LOAD_CONST':
            if isinstance(co_consts, tuple) and arg < len(co_consts):
                const = co_consts[arg]
                # Check if this constant is a code object (inner function)
                try:
                    if hasattr(const, 'ob_type') and hasattr(const.ob_type, 'dereference'):
                        const_type_name = const.ob_type.dereference().get_name()
                        const_ptype = const.get_type(const_type_name)
                        if const_ptype == "PyCodeObject":
                            const_obj = const.cast_to('PyCodeObject')
                            # Recursively decode the inner code object
                            inner_code_info = _decode_inner_code(
                                const_obj, arg, version
                            )
                            if inner_code_info is not None:
                                key, value = inner_code_info
                                inner_codes[key] = value
                                argval = value[2]  # inner function name
                            else:
                                argval = '<code>'
                        else:
                            argval = _resolve_const(const)
                    else:
                        argval = const if const is not None else ''
                except Exception:
                    argval = f'<const {arg}>'
            else:
                argval = f'<const {arg}>'

        elif opname in ('CALL_FUNCTION', 'CALL_METHOD', 'CALL',
                        'CALL_FUNCTION_KW', 'CALL_FUNCTION_EX',
                        'PRECALL'):
            argval = str(arg)

        elif opname == 'IMPORT_STAR':
            argval = ''

        else:
            argval = str(arg) if arg else ''

        instructions.append(f"{opname} {argval}")

        # Advance past this instruction
        i += INSTRUCTION_SIZE

        # Skip inline cache entries (3.11+)
        num_caches = cache_sizes.get(opname, 0)
        i += num_caches * INSTRUCTION_SIZE

    return instructions, inner_codes


def _resolve_const(obj):
    """Resolve a constant PyObject to its Python value for display."""
    try:
        if hasattr(obj, 'ob_type') and hasattr(obj, 'get_value'):
            type_name = obj.ob_type.dereference().get_name()
            ptype = obj.get_type(type_name)
            if ptype == "PyTupleObject":
                items = obj.get_value()
                if isinstance(items, (list, tuple)):
                    return tuple(_resolve_const(i) for i in items)
            return obj.get_value()
    except Exception:
        return str(obj)
    return obj


def _decode_inner_code(
    code_obj, const_index: int, version: Tuple[int, int]
) -> Optional[Tuple[str, tuple]]:
    """
    Recursively decode an inner code object.

    Returns (key, (instructions, inner_codes, code_name)) or None.
    """
    try:
        # Reconstruct the code object to get raw fields
        # We need co_code, co_names, co_varnames, co_consts, etc.
        # These come from the PyCodeObject in memory

        # Get co_code bytes
        co_code_obj = code_obj.co_code.dereference().cast_to("PyBytesObject")
        co_code_bytes = co_code_obj.get_value()

        # Get co_name
        co_name = code_obj.co_name.dereference().get_value()

        # Skip comprehensions / lambdas
        skip_tags = ('<listcomp>', '<dictcomp>', '<setcomp>',
                     '<genexpr>', '<lambda>')
        if any(t in co_name for t in skip_tags):
            return None

        # Get co_names as tuple of strings
        co_names_obj = code_obj.co_names.dereference()
        co_names_raw = co_names_obj.get_value()
        co_names = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_names_raw
        )

        # Get co_varnames
        co_varnames_obj = code_obj.co_varnames.dereference()
        co_varnames_raw = co_varnames_obj.get_value()
        co_varnames = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_varnames_raw
        )

        # Get co_consts (keep as PyObject references for recursive detection)
        co_consts_obj = code_obj.co_consts.dereference().cast_to("PyTupleObject")
        # Use get_value2 to keep as PyObjects (not resolved values)
        co_consts = co_consts_obj.get_value2()

        # Get co_cellvars
        co_cellvars_obj = code_obj.co_cellvars.dereference()
        co_cellvars_raw = co_cellvars_obj.get_value()
        co_cellvars = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_cellvars_raw
        )

        # Get co_freevars
        co_freevars_obj = code_obj.co_freevars.dereference()
        co_freevars_raw = co_freevars_obj.get_value()
        co_freevars = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_freevars_raw
        )

        # Decode
        inner_instrs, inner_nested = decode_bytecode(
            co_code_bytes, co_names, co_varnames,
            co_consts, co_cellvars, co_freevars,
            version
        )

        key = f"{co_name}_{const_index}"
        return key, (inner_instrs, inner_nested, code_obj)

    except Exception as e:
        print(f"    Error decoding inner code: {e}")
        return None


def decode_code_object(code_obj, version: Tuple[int, int]):
    """
    High-level entry: given a PyCodeObject from memory and the target
    Python version, decode its bytecode into instructions + inner codes.

    This is the drop-in replacement for Dependency_Generator._process_code().

    Returns (instructions: List[str], inner_codes: Dict[str, tuple])
    """
    try:
        # Extract raw co_code bytes
        co_code_obj = code_obj.co_code.dereference().cast_to("PyBytesObject")
        co_code_bytes = co_code_obj.get_value()

        # Extract co_names as tuple of strings
        co_names_obj = code_obj.co_names.dereference()
        co_names_raw = co_names_obj.get_value()
        co_names = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_names_raw
        )

        # Extract co_varnames
        co_varnames_obj = code_obj.co_varnames.dereference()
        co_varnames_raw = co_varnames_obj.get_value()
        co_varnames = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_varnames_raw
        )

        # Extract co_consts (keep as PyObject references)
        co_consts_obj = code_obj.co_consts.dereference().cast_to("PyTupleObject")
        co_consts = co_consts_obj.get_value2()

        # Extract co_cellvars
        co_cellvars_obj = code_obj.co_cellvars.dereference()
        co_cellvars_raw = co_cellvars_obj.get_value()
        co_cellvars = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_cellvars_raw
        )

        # Extract co_freevars
        co_freevars_obj = code_obj.co_freevars.dereference()
        co_freevars_raw = co_freevars_obj.get_value()
        co_freevars = tuple(
            obj.get_value() if hasattr(obj, 'get_value') else str(obj)
            for obj in co_freevars_raw
        )

        return decode_bytecode(
            co_code_bytes, co_names, co_varnames,
            co_consts, co_cellvars, co_freevars,
            version
        )

    except Exception as e:
        print(f"    Error in decode_code_object: {e}")
        return [], {}
