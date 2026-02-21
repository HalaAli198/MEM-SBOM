from volatility3.framework.symbols import intermed
from volatility3.framework import objects, constants
from volatility3.framework import exceptions
import struct
import types
import collections
import marshal
import textwrap
import dis
import sys
from io import StringIO
import io

Py_TPFLAGS_HEAPTYPE = 1 << 9


class Python_3_6_IntermedSymbols(intermed.IntermediateSymbolTable):
    """
    Python 3.6.15 memory structure handler for Volatility 3.
    
    Key differences from Python 3.8:
    - PyCodeObject: no co_posonlyargcount (added in 3.8 via PEP 570)
    - PyFunctionObject: no vectorcall (added in 3.8 via PEP 590)
    - PyPickleBufferObject: does not exist (added in 3.8 via PEP 574)
    - PyASCIIObject: has wstr field (deprecated later but present in 3.6)
    - PyCompactUnicodeObject: has wstr_length field
    - PyGC_Head: traditional union with gc_next/gc_prev/gc_refs
    - PyFrameObject: same basic layout, has f_exc_type/f_exc_value/f_exc_traceback
    - types.CodeType constructor: no posonlyargcount parameter
    - PyDictObject: has ma_version_tag (added in 3.6 via PEP 509)
    - String interning uses 2-bit field (SSTATE_NOT_INTERNED=0, SSTATE_INTERNED_MORTAL=1, SSTATE_INTERNED_IMMORTAL=2)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class("PyGC_Head", PyGC_Head)
        self.set_type_class("PyObject", PyObject)
        self.set_type_class("PyTypeObject", PyTypeObject)
        self.set_type_class("PyDictObject", PyDictObject)
        self.set_type_class("PyDictKeysObject", PyDictKeysObject)
        self.set_type_class("PyDictKeyEntry", PyDictKeyEntry)
        self.set_type_class("PyASCIIObject", PyASCIIObject)
        self.set_type_class("PyLongObject", PyLongObject)
        self.set_type_class("PyTupleObject", PyTupleObject)
        self.set_type_class("PyListObject", PyListObject)
        self.set_type_class("PySetObject", PySetObject)
        self.set_type_class("PyWeakReference", PyWeakReference)
        self.set_type_class("PyBytesObject", PyBytesObject)
        self.set_type_class("PyFloatObject", PyFloatObject)
        self.set_type_class("PyModuleObject", PyModuleObject)
        self.set_type_class("PyFunctionObject", PyFunctionObject)
        self.set_type_class("PyCFunctionObject", PyCFunctionObject)
        self.set_type_class("PyWrapperDescrObject", PyWrapperDescrObject)
        self.set_type_class("PyMethodDef", PyMethodDef)
        self.set_type_class("PyMemberDef", PyMemberDef)
        self.set_type_class("PyGetSetDef", PyGetSetDef)
        self.set_type_class("PyMethodDescrObject", PyMethodDescrObject)
        self.set_type_class("PyGetSetDescrObject", PyGetSetDescrObject)
        self.set_type_class("PyMemberDescrObject", PyMemberDescrObject)
        self.set_type_class("PyCodeObject", PyCodeObject)
        self.set_type_class("_ODictNode", _ODictNode)
        self.set_type_class("PyDescrObject", PyDescrObject)
        self.set_type_class("wrapperobject", wrapperobject)
        self.set_type_class("PyODictObject", PyODictObject)
        self.set_type_class("PyCellObject", PyCellObject)
        self.set_type_class("classmethod", classmethod_obj)
        self.set_type_class("staticmethod", staticmethod_obj)
        self.set_type_class("PyByteArrayObject", PyByteArrayObject)
        self.set_type_class("PyCapsule", PyCapsule)
        self.set_type_class("PyComplexObject", PyComplexObject)
        self.set_type_class("enumobject", enumobject)
        self.set_type_class("PyFrameObject", PyFrameObject)
        self.set_type_class("seqiterobject", seqiterobject)
        self.set_type_class("calliterobject", calliterobject)
        self.set_type_class("PyMethodObject", PyMethodObject)
        self.set_type_class("_PyNamespaceObject", _PyNamespaceObject)
        # NOTE: PyPickleBufferObject does NOT exist in Python 3.6 (added in 3.8 PEP 574)
        self.set_type_class("rangeobject", rangeobject)
        self.set_type_class("PySliceObject", PySliceObject)
        self.set_type_class("PyGenObject", PyGenObject)
        self.set_type_class("PyCoroObject", PyCoroObject)
        self.set_type_class("PyAsyncGenObject", PyAsyncGenObject)
        self.set_type_class("_typeobject", PyTypeObject)
        self.set_type_class("arena_object", arena_object)
        self.set_type_class("pool_header", pool_header)
        self.set_type_class("block", block)


# =============================================================================
# Arena and Pool structures (same as 3.8)
# =============================================================================

class arena_object(objects.StructType):
    @property
    def address(self):
        return self.member('address')

    @property
    def pool_address(self):
        return self.member('pool_address')

    @property
    def nfreepools(self):
        return self.member('nfreepools')

    @property
    def ntotalpools(self):
        return self.member('ntotalpools')

    @property
    def freepools(self):
        return self.member('freepools')

    @property
    def nextarena(self):
        return self.member('nextarena')

    @property
    def prevarena(self):
        return self.member('prevarena')

    def get_usage_info(self):
        total = int(self.ntotalpools)
        free = int(self.nfreepools)
        used = total - free
        usage_percent = (used / total * 100) if total > 0 else 0
        return {
            'total_pools': total,
            'free_pools': free,
            'used_pools': used,
            'usage_percent': usage_percent
        }

    def is_active(self):
        return int(self.address) != 0

    def get_summary(self):
        if not self.is_active():
            return "INACTIVE"
        info = self.get_usage_info()
        return f"Active: {info['used_pools']}/{info['total_pools']} pools ({info['usage_percent']:.1f}%)"


class pool_header(objects.StructType):
    @property
    def ref(self):
        return self.member('ref')

    @property
    def freeblock(self):
        return self.member('freeblock')

    @property
    def nextpool(self):
        return self.member('nextpool')

    @property
    def prevpool(self):
        return self.member('prevpool')

    @property
    def arenaindex(self):
        return self.member('arenaindex')

    @property
    def szidx(self):
        return self.member('szidx')

    @property
    def nextoffset(self):
        return self.member('nextoffset')

    @property
    def maxnextoffset(self):
        return self.member('maxnextoffset')

    def get_ref_count(self):
        try:
            curr_layer = self._context.layers[self.vol.layer_name]
            ref_bytes = curr_layer.read(self.vol.offset, 4)
            ref_count = int.from_bytes(ref_bytes, byteorder='little', signed=False)
            if ref_count > 1000:
                return 0
            return ref_count
        except Exception:
            return 0

    def get_block_size(self):
        # Python 3.6 size classes (SMALL_REQUEST_THRESHOLD = 512)
        # In 3.6: ALIGNMENT = 8, so size classes are 8, 16, 24, ..., 512
        size_classes = [
            8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
            136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240,
            248, 256, 264, 272, 280, 288, 296, 304, 312, 320, 328, 336, 344, 352,
            360, 368, 376, 384, 392, 400, 408, 416, 424, 432, 440, 448, 456, 464,
            472, 480, 488, 496, 504, 512
        ]
        szidx = int(self.szidx)
        if szidx == 0:
            return "Free pool"
        elif 1 <= szidx <= len(size_classes):
            return size_classes[szidx - 1]
        else:
            return f"Unknown size class {szidx}"

    def get_pool_info(self):
        block_size = self.get_block_size()
        ref_count = self.get_ref_count()
        if isinstance(block_size, int) and block_size > 0:
            usable_space = 4096 - 48
            max_blocks = usable_space // block_size
            utilization = (ref_count / max_blocks * 100) if max_blocks > 0 else 0
        else:
            max_blocks = "Unknown"
            utilization = "Unknown"
        return {
            'block_size': block_size,
            'allocated_blocks': ref_count,
            'max_blocks': max_blocks,
            'utilization_percent': utilization,
            'arena_index': int(self.arenaindex),
            'size_class': int(self.szidx),
            'nextoffset': int(self.nextoffset),
            'maxnextoffset': int(self.maxnextoffset),
            'freeblock_addr': int(self.freeblock) if self.freeblock else 0
        }

    def is_pool_active(self):
        szidx = int(self.szidx)
        if szidx == 0:
            return False
        nextoffset = int(self.nextoffset)
        maxnextoffset = int(self.maxnextoffset)
        return (szidx > 0 and szidx <= 64 and
                48 <= nextoffset <= 4096 and
                48 <= maxnextoffset <= 4096)


class block(objects.StructType):
    def read_block_data(self, size):
        curr_layer = self._context.layers[self.vol.layer_name]
        try:
            return curr_layer.read(self.vol.offset, size)
        except Exception:
            return None

    def get_block_info(self, expected_size):
        data = self.read_block_data(min(expected_size, 64))
        return {
            'address': hex(self.vol.offset),
            'size': expected_size,
            'data_preview': data[:16].hex() if data else "Unable to read",
            'readable': data is not None
        }


# =============================================================================
# PyGC_Head - Python 3.6 uses traditional gc_next/gc_prev/gc_refs union
# =============================================================================

class PyGC_Head(objects.StructType):
    @property
    def _gc_next(self):
        return self._context.object(self.vol.type_name, self.vol.layer_name,
                                    self.vol.offset + self.vol.structure.offset_by_name('_gc_next'))

    @property
    def _gc_prev(self):
        return self._context.object(self.vol.type_name, self.vol.layer_name,
                                    self.vol.offset + self.vol.structure.offset_by_name('_gc_prev'))

    def get_next(self):
        return int.from_bytes(
            self._context.layers[self.vol.layer_name].read(self.vol.offset, 8),
            byteorder='little'
        )

    def get_prev(self):
        return int.from_bytes(
            self._context.layers[self.vol.layer_name].read(self.vol.offset + 8, 8),
            byteorder='little'
        )


# =============================================================================
# PyObject base class
# =============================================================================

class PyObject(objects.StructType):
    def get_type(self, name):
        types = {
            'NoneType': 'None',
            'str': 'PyASCIIObject',
            'int': 'PyLongObject',
            'method_descriptor': 'PyMethodDescrObject',
            'tuple': 'PyTupleObject',
            'list': 'PyListObject',
            'wrapper_descriptor': 'PyWrapperDescrObject',
            'method-wrapper': 'wrapperobject',
            'set': 'PySetObject',
            'frozenset': 'PySetObject',
            'function': 'PyFunctionObject',
            'methoddef': 'PyMethodDef',
            'member_descriptor': 'PyMemberDescrObject',
            'code': 'PyCodeObject',
            'bytes': 'PyBytesObject',
            'builtin_function_or_method': 'PyCFunctionObject',
            'dict': 'PyDictObject',
            'float': 'PyFloatObject',
            'getset_descriptor': 'PyGetSetDescrObject',
            'generator': 'PyGenObject',
            'coroutine': 'PyCoroObject',
            'async_generator': 'PyAsyncGenObject',
            'module': 'PyModuleObject',
            'type': 'PyTypeObject',
            'weakref': 'PyWeakReference',
            'OrderedDict': 'PyODictObject',
            'staticmethod': 'staticmethod',
            'collections.OrderedDict': 'PyODictObject',
            'cell': 'PyCellObject',
            'classmethod': 'classmethod',
            'bytearray': 'PyByteArrayObject',
            'complex': 'PyComplexObject',
            'enumerate': 'enumobject',
            'frame': 'PyFrameObject',
            'range': 'rangeobject',
            'slice': 'PySliceObject',
            'method': 'PyMethodObject',
            'capsule': 'PyCapsule',
            # NOTE: No 'PyCapsule' for pickle_buffer - doesn't exist in 3.6
        }
        mapped_type = types.get(name)
        return mapped_type

    @property
    def ob_type(self):
        return self.member('ob_type')

    def read_cstring(self, addr, max_length=256):
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

    def _read_member(self, member_name):
        member_offset = self.vol.type_name + constants.BANG + self.vol.type.get_type(member_name).offset
        return self._context.object(
            object_type=self.vol.type_name + constants.BANG + self.vol.type.get_type(member_name).vol.type_name,
            layer_name=self.vol.layer_name,
            offset=self.vol.offset + member_offset
        )

    def cast_to(self, type_name):
        if constants.BANG in type_name:
            object_type = type_name
        else:
            symbol_table_name = self.get_symbol_table_name()
            object_type = symbol_table_name + constants.BANG + type_name
        return self._context.object(
            object_type=object_type,
            layer_name=self.vol.layer_name,
            offset=self.vol.offset,
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        value = None
        obj_type_name = self.get_type_name()
        track_for_cycles = obj_type_name not in {'int', 'bool', 'float', 'str', 'bytes', 'cell', 'NoneType', 'ellipsis'}

        if track_for_cycles:
            if visited is None:
                visited = set()
            obj_id = int(self.vol.offset)
            if obj_id in visited:
                return f"{obj_type_name}"
            visited.add(obj_id)
            if max_depth is not None and cur_depth >= max_depth:
                return f"<{self.get_type_name()} object (max recursion depth reached)>"

        type = self.get_type(obj_type_name)
        if type is None:
            tp_type = self.ob_type.dereference()
            tp_dictoffset = tp_type.tp_dictoffset

            if tp_dictoffset != 0:
                if tp_dictoffset >= 0:
                    dict_ptr_addr = self.vol.offset + tp_dictoffset
                else:
                    tp_basicsize = tp_type.tp_basicsize
                    tp_itemsize = tp_type.tp_itemsize
                    instance_size = tp_basicsize
                    if tp_itemsize > 0 and hasattr(self, 'ob_size'):
                        instance_size += self.ob_size * tp_itemsize
                    dict_ptr_addr = self.vol.offset + instance_size + tp_dictoffset

                curr_layer = self._context.layers[self.vol.layer_name]
                try:
                    dict_addr_bytes = curr_layer.read(dict_ptr_addr, 8)
                    dict_addr = int.from_bytes(dict_addr_bytes, byteorder='little')
                    if dict_ptr_addr and curr_layer.is_valid(dict_addr, 8):
                        dict_obj = self._context.object(
                            object_type=self.get_symbol_table_name() + constants.BANG + "PyDictObject",
                            layer_name=self.vol.layer_name,
                            offset=dict_addr
                        )
                        return dict_obj.get_dict2(cur_depth + 1, max_depth, visited)
                    else:
                        return f"<{obj_type_name} object at {hex(self.vol.offset)} (no __dict__)>"
                except Exception as e:
                    print(f"Exception accessing __dict__ for object at {hex(self.vol.offset)}: {str(e)}")
                    return f"<{obj_type_name} object at {hex(self.vol.offset)} (unreadable __dict__)>"
            else:
                return f"<{obj_type_name} object at {hex(self.vol.offset)} (no __dict__)>"

        elif type == 'PyDictObject':
            dict_obj = self.cast_to(type)
            return dict_obj.get_dict2(cur_depth + 1, max_depth, visited)
        elif type == 'PyModuleObject':
            module_obj = self.cast_to(type)
            return module_obj.get_dict2(cur_depth + 1, max_depth, visited)
        elif type == 'PyTupleObject':
            obj = self.cast_to(type)
            value = obj.get_value2(cur_depth + 1, max_depth, visited)
        elif type == 'PyFunctionObject':
            func_obj = self.cast_to("PyFunctionObject")
            code_obj = func_obj.func_code_obj.cast_to('PyCodeObject')
            disassembled_code = self.disassemble_bytecode(code_obj)
        elif type == 'None':
            return None
        elif type == 'Ellipsis':
            return Ellipsis
        elif type == 'PyASCIIObject':
            obj = self.cast_to(type)
            value = obj.get_value(cur_depth + 1, max_depth, visited)
        elif type == 'PyTypeObject':
            obj = self.cast_to(type)
            value = obj.get_value(cur_depth + 1, max_depth, visited)
        else:
            obj = self.cast_to(type)
            value = obj.get_value(cur_depth + 1, max_depth, visited)

        if track_for_cycles:
            visited.remove(obj_id)
        return value

    def extract_bytecode(self, code_obj):
        code_obj = code_obj.cast_to("PyCodeObject")
        return code_obj

    def safe_get_instructions(self, code):
        try:
            for instr in dis.get_instructions(code):
                yield instr
        except IndexError as e:
            print(f"IndexError during instruction decoding: {str(e)}")
            return

    def disassemble_bytecode(self, code_obj):
        try:
            code = code_obj.to_code_object()
            if code and hasattr(code, 'co_code') and code.co_code:
                disassembled_code = self.disassemble_code_with_validation(code)
                return disassembled_code
            else:
                print(f"Failed to reconstruct code object at {hex(code_obj.vol.offset)}")
                return None
        except Exception as e:
            print(f"Exception during disassembly of code object at {hex(code_obj.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def disassemble_code_with_validation(self, code):
        instructions = []
        for instr in self.safe_get_instructions(code):
            try:
                opname = instr.opname
                argval = instr.argval if instr.argval is not None else ''
                arg = instr.arg if instr.arg is not None else 0
                if instr.opname in dis.hasname:
                    if isinstance(code.co_names, tuple) and arg < len(code.co_names):
                        argval = code.co_names[arg]
                    else:
                        argval = f'<invalid name index {arg}>'
                elif instr.opname in dis.hasconst:
                    if instr.arg < len(code.co_consts):
                        argval = code.co_consts[instr.arg].get_value()
                    else:
                        argval = f'<invalid const index {instr.arg}>'
                instructions.append(f"{instr.offset}: {opname} {argval}")
            except Exception as e:
                print(f"Error processing instruction at offset {instr.offset}: {str(e)}")
                continue
        return '\n'.join(instructions)

    def get_type_name(self):
        return self.ob_type.dereference().get_name()


# =============================================================================
# Bytes
# =============================================================================

class PyBytesObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            curr_layer = self._context.layers[self.vol.layer_name]
            ob_size = self.ob_size
            base_offset = self.vol.offset + self.vol.size - 8
            try:
                byte_data = curr_layer.read(base_offset, ob_size, pad=False)
                return byte_data
            except Exception as e:
                print(f"Error reading byte data at {hex(base_offset)}: {str(e)}")
                return b''
        except Exception as e:
            print(f"Error processing PyBytesObject at {hex(self.vol.offset)}: {str(e)}")
            return b''

    def debug_memory(self, length=32):
        curr_layer = self._context.layers[self.vol.layer_name]
        base_offset = self.vol.offset + self.vol.size - 8
        for i in range(-16, length, 8):
            try:
                data = curr_layer.read(base_offset + i, 8, pad=False)
                print(f"Offset {hex(base_offset + i)}: {data.hex()} | {data}")
            except Exception as e:
                print(f"Error reading at offset {hex(base_offset + i)}: {e}")


# =============================================================================
# Type
# =============================================================================

class PyTypeObject(PyObject):
    def get_name(self):
        curr_layer = self._context.layers[self.vol.layer_name]
        tp_name_addr = self.tp_name
        type_name = self.read_cstring(tp_name_addr)
        return type_name

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return f"<type '{self.get_name()}'>"

    def get_dict(self):
        return self.tp_dict.dereference().get_dict()

    def get_bases(self):
        try:
            tp_bases_addr = self.tp_bases
            if tp_bases_addr and int(tp_bases_addr) != 0:
                bases_obj = self._context.object(
                    object_type=self.get_symbol_table_name() + constants.BANG + "PyTupleObject",
                    layer_name=self.vol.layer_name,
                    offset=int(tp_bases_addr)
                )
                return bases_obj.get_value()
            else:
                return ()
        except Exception as e:
            print(f"Error getting tp_bases for type at {hex(self.vol.offset)}: {str(e)}")
            return ()

    def get_mro(self):
        try:
            tp_mro_addr = self.tp_mro
            if tp_mro_addr and int(tp_mro_addr) != 0:
                mro_obj = self._context.object(
                    object_type=self.get_symbol_table_name() + constants.BANG + "PyTupleObject",
                    layer_name=self.vol.layer_name,
                    offset=int(tp_mro_addr)
                )
                return mro_obj.get_value()
            else:
                return ()
        except Exception as e:
            print(f"Error getting tp_mro for type at {hex(self.vol.offset)}: {str(e)}")
            return ()

    def get_size(self):
        basic_size = self.tp_basicsize
        item_size = self.tp_itemsize
        flags = self.tp_flags
        if flags & (1 << 26):  # Py_TPFLAGS_HAVE_GC
            return lambda ob_size: basic_size + item_size * ob_size
        else:
            return basic_size


# =============================================================================
# Descriptor types
# =============================================================================

class PyGetSetDescrObject(PyObject):
    @property
    def d_common(self):
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_getset(self):
        return self._read_field('d_getset', 'PyGetSetDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            name_obj = self.d_common.d_name.dereference()
            name = name_obj.get_value()
            return f"<getset_descriptor {name}>"
        except Exception as e:
            print(f"Error processing PyGetSetDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<getset_descriptor at {hex(self.vol.offset)}>"


class _ODictNode(objects.StructType):
    @property
    def key(self):
        return self.member('key')

    @property
    def value(self):
        return self.member('value')

    @property
    def next(self):
        return self.member('next')

    def get_key_value(self, cur_depth=0, max_depth=10, visited=None):
        key_obj = self.key.dereference()
        value_obj = self.value.dereference()
        key = key_obj.get_value(cur_depth + 1, max_depth, visited)
        value = value_obj.get_value(cur_depth + 1, max_depth, visited)
        return key, value


class PyMethodDef(PyObject):
    @property
    def ml_name(self):
        return self._read_field('ml_name', 'char *')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            method_name = self.read_cstring(self.ml_name)
            return method_name
        except Exception as e:
            print(f"Error processing PyMethodDef at {hex(self.vol.offset)}: {str(e)}")
            return "<unknown>"


class PyGetSetDef(objects.StructType):
    def read_cstring(self, addr, max_length=256):
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

    @property
    def name(self):
        addr = int(self.member('name'))
        return self.read_cstring(addr)

    @property
    def doc(self):
        addr = int(self.member('doc'))
        if addr != 0:
            return self.read_cstring(addr)
        else:
            return None


class PyMemberDef(objects.StructType):
    def read_cstring(self, addr, max_length=256):
        if addr == 0:
            return None
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length, pad=False)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

    @property
    def name(self):
        addr = int(self._vol['name'])
        return self.read_cstring(addr)

    @property
    def doc(self):
        addr = int(self._vol['doc'])
        return self.read_cstring(addr)


class wrapperobject(PyObject):
    @property
    def descr_ptr(self):
        return self.member('descr')

    @property
    def self_ptr(self):
        return self.member('self')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            descr_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyWrapperDescrObject",
                layer_name=self.vol.layer_name,
                offset=int(self.descr_ptr)
            )
            method_name = descr_obj.get_value(cur_depth + 1, max_depth, visited)
            self_obj = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
                layer_name=self.vol.layer_name,
                offset=int(self.self_ptr)
            )
            instance = self_obj.get_value(cur_depth + 1, max_depth, visited)
            return f"<bound method {method_name} of {instance}>"
        except Exception as e:
            print(f"Error processing wrapperobject at {hex(self.vol.offset)}: {str(e)}")
            return f"<method-wrapper at {hex(self.vol.offset)}>"


class PyDescrObject(PyObject):
    @property
    def d_name(self):
        return self._read_field('d_name', 'PyObject')

    @property
    def d_type(self):
        return self._read_field('d_type', 'PyTypeObject')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            name_obj = self.d_name.dereference()
            name = name_obj.get_value()
            return name
        except Exception as e:
            print(f"Error processing PyDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return "<descriptor>"


class _PyNamespaceObject(PyObject):
    @property
    def ns_dict(self):
        return self.member('ns_dict')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "<namespace object (cycle detected)>"
        visited.add(obj_id)
        try:
            ns_dict_obj = self.ns_dict.dereference()
            ns_dict_value = ns_dict_obj.get_dict(cur_depth + 1, max_depth, visited)
            return ns_dict_value
        except Exception as e:
            return f"<namespace object at {hex(self.vol.offset)} (error: {str(e)})>"
        finally:
            visited.remove(obj_id)


class PyCellObject(PyObject):
    @property
    def ob_ref(self):
        return self.member('ob_ref')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "<cell object (cycle detected)>"
        visited.add(obj_id)
        ob_ref_addr = self.ob_ref
        if not ob_ref_addr or int(ob_ref_addr) == 0:
            value = None
        else:
            cell_contents = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
                layer_name=self.vol.layer_name,
                offset=int(ob_ref_addr)
            )
            value = cell_contents.get_value(cur_depth + 1, max_depth, visited)
        visited.remove(obj_id)
        return value


class PyWrapperDescrObject(PyObject):
    @property
    def d_common(self):
        return self.member('d_common')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            d_common = self.d_common
            name_obj = d_common.d_name.dereference()
            method_name = name_obj.get_value(cur_depth + 1, max_depth, visited)
            type_obj = d_common.d_type.dereference()
            type_name = type_obj.get_name()
            return method_name
        except Exception as e:
            print(f"Error processing PyWrapperDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<wrapper_descriptor at {hex(self.vol.offset)}>"


class PyMemberDescrObject(PyObject):
    @property
    def d_common(self):
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_member(self):
        return self._read_field('d_member', 'PyMemberDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            name_obj = self.d_common.d_name.dereference()
            name = name_obj.get_value()
            return f"<member_descriptor {name}>"
        except Exception as e:
            print(f"Error processing PyMemberDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<member_descriptor at {hex(self.vol.offset)}>"


class PyCFunctionObject(PyObject):
    @property
    def m_ml(self):
        return self._read_field('m_ml', 'PyMethodDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            method_def = self.m_ml.dereference()
            method_name = self.read_cstring(method_def.ml_name)
            return f"<built-in function {method_name}>"
        except Exception as e:
            print(f"Error processing PyCFunctionObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<built-in function at {hex(self.vol.offset)}>"


class PyWeakReference(PyObject):
    @property
    def wr_object(self):
        return self._read_field('wr_object', 'PyObject')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            referent = self.wr_object.dereference()
            referent_value = referent.get_value()
            return f"<weakref to {referent_value}>"
        except Exception as e:
            print(f"Error processing PyWeakReference at {hex(self.vol.offset)}: {str(e)}")
            return f"<weakref at {hex(self.vol.offset)}>"


# =============================================================================
# classmethod / staticmethod
# NOTE: Renamed to avoid shadowing Python builtins
# =============================================================================

class classmethod_obj(PyObject):
    """
    Python 3.6 classmethod structure:
    struct {
        PyObject ob_base;
        PyObject *cm_callable;
        PyObject *cm_dict;
    }
    """
    @property
    def cm_callable(self):
        return self.member('cm_callable')

    @property
    def cm_dict(self):
        return self.member('cm_dict')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            callable_obj = self.cm_callable.dereference()
            callable_value = callable_obj.get_value(cur_depth + 1, max_depth, visited)
            return callable_value
        except Exception as e:
            return f"<classmethod at 0x{self.vol.offset:x} (error: {str(e)})>"


class staticmethod_obj(PyObject):
    """
    Python 3.6 staticmethod structure:
    struct {
        PyObject ob_base;
        PyObject *sm_callable;
        PyObject *sm_dict;
    }
    """
    @property
    def sm_callable(self):
        return self.member('sm_callable')

    @property
    def sm_dict(self):
        return self.member('sm_dict')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            callable_obj = self.sm_callable.dereference()
            callable_value = callable_obj.get_value(cur_depth + 1, max_depth, visited)
            return callable_value
        except Exception as e:
            return f"<staticmethod at 0x{self.vol.offset:x} (error: {str(e)})>"


# =============================================================================
# Generator / Coroutine / AsyncGen
# =============================================================================

class PyGenObject(PyObject):
    """
    Python 3.6 generator:
    struct {
        PyObject ob_base;
        struct _frame *gi_frame;
        char gi_running;
        PyObject *gi_code;
        PyObject *gi_weakreflist;
        PyObject *gi_name;
        PyObject *gi_qualname;
    }
    NOTE: No gi_exc_state in 3.6 (that was added in 3.7)
    """
    @property
    def func_name_obj(self):
        func_name_addr = self.gi_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    @property
    def func_code_obj(self):
        func_code_addr = self.gi_code
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_code_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return f"<function object (max recursion depth reached)>"
        try:
            func_name_obj = self.func_name_obj
            func_name = func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception as e:
            func_name = "<unknown function>"
            print(f"Error retrieving func_name at {hex(self.vol.offset)}: {e}")
        return f"<generator {func_name} at {hex(self.vol.offset)}>"


class PyCoroObject(PyObject):
    """
    Python 3.6 coroutine:
    struct {
        PyObject ob_base;
        struct _frame *cr_frame;
        char cr_running;
        PyObject *cr_code;
        PyObject *cr_weakreflist;
        PyObject *cr_name;
        PyObject *cr_qualname;
        PyObject *cr_origin;  -- may not be present in early 3.6, added later
    }
    NOTE: No cr_exc_state in 3.6 (added in 3.7)
    """
    @property
    def func_name_obj(self):
        func_name_addr = self.cr_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    @property
    def func_code_obj(self):
        func_code_addr = self.cr_code
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_code_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return f"<coroutine object (max recursion depth reached)>"
        try:
            func_name_obj = self.func_name_obj
            func_name = func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception as e:
            func_name = "<unknown function>"
            print(f"Error retrieving func_name at {hex(self.vol.offset)}: {e}")
        return f"<coroutine {func_name} at {hex(self.vol.offset)}>"


class PyAsyncGenObject(PyObject):
    """
    Python 3.6 async generator:
    struct {
        PyObject ob_base;
        struct _frame *ag_frame;
        char ag_running;
        PyObject *ag_code;
        PyObject *ag_weakreflist;
        PyObject *ag_name;
        PyObject *ag_qualname;
        PyObject *ag_finalizer;
        int ag_hooks_inited;
        int ag_closed;
    }
    NOTE: No ag_exc_state in 3.6 (added in 3.7)
    NOTE: No ag_running_async in 3.6 (added later)
    """
    @property
    def func_name_obj(self):
        func_name_addr = self.ag_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    @property
    def func_code_obj(self):
        func_code_addr = self.ag_code
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_code_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return f"<async_generator object (max recursion depth reached)>"
        try:
            func_name_obj = self.func_name_obj
            func_name = func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception as e:
            func_name = "<unknown function>"
            print(f"Error retrieving func_name at {hex(self.vol.offset)}: {e}")
        return f"<async_generator {func_name} at {hex(self.vol.offset)}>"


# =============================================================================
# Container types
# =============================================================================

class PyByteArrayObject(PyObject):
    @property
    def ob_bytes(self):
        return self.member('ob_bytes')

    @property
    def ob_alloc(self):
        return self.member('ob_alloc')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        curr_layer = self._context.layers[self.vol.layer_name]
        length = int(self.ob_base.ob_size)
        data_offset = int(self.ob_bytes)
        byte_data = curr_layer.read(data_offset, length)
        return byte_data


class PyCapsule(PyObject):
    @property
    def pointer(self):
        return self.member('pointer')

    @property
    def name(self):
        return self.member('name')

    @property
    def context(self):
        return self.member('context')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        name_addr = int(self.name)
        name = self.read_cstring(name_addr)
        return f"<capsule object '{name}' at {hex(self.vol.offset)}>"


class PyComplexObject(PyObject):
    @property
    def cval(self):
        return self.member('cval')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        real = self.cval.real
        imag = self.cval.imag
        return complex(real, imag)


class enumobject(PyObject):
    @property
    def en_sit(self):
        return self.member('en_sit')

    @property
    def en_result(self):
        return self.member('en_result')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return "<enumerate object>"


class PyFrameObject(PyObject):
    """
    Python 3.6 frame object.
    Same basic layout as 3.8 — has f_exc_type, f_exc_value, f_exc_traceback
    (these were removed in 3.11+ where frames became internal).
    """
    @property
    def f_code(self):
        return self.member('f_code')

    @property
    def f_lineno(self):
        return self.member('f_lineno')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        code_obj = self.f_code.dereference()
        code_name = code_obj.co_name.dereference().get_value()
        lineno = int(self.f_lineno)
        return f"<frame at line {lineno} in {code_name}>"


class seqiterobject(PyObject):
    @property
    def it_seq(self):
        return self.member('it_seq')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        seq_obj = self.it_seq.dereference()
        seq_value = seq_obj.get_value(cur_depth + 1, max_depth, visited)
        return f"<iterator over {seq_value}>"


class calliterobject(PyObject):
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return "<callable iterator object>"


class PyMethodObject(PyObject):
    @property
    def im_func(self):
        return self.member('im_func')

    @property
    def im_self(self):
        return self.member('im_self')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            func_obj = self.im_func.dereference()
            func_value = func_obj.get_value(cur_depth + 1, max_depth, visited)
            return func_value
        except Exception as e:
            return f"<method at 0x{self.vol.offset:x} (error: {str(e)})>"


class rangeobject(PyObject):
    @property
    def start(self):
        return self.member('start').dereference().get_value()

    @property
    def stop(self):
        return self.member('stop').dereference().get_value()

    @property
    def step(self):
        return self.member('step').dereference().get_value()

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return range(self.start, self.stop, self.step)


class PySliceObject(PyObject):
    @property
    def start(self):
        return self.member('start').dereference().get_value()

    @property
    def stop(self):
        return self.member('stop').dereference().get_value()

    @property
    def step(self):
        return self.member('step').dereference().get_value()

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return slice(self.start, self.stop, self.step)


# =============================================================================
# Dict
# =============================================================================

class PyDictObject(PyObject):
    @property
    def ma_values(self):
        return self.member('ma_values')

    @property
    def ma_keys(self):
        return self.member('ma_keys')

    @property
    def ma_used(self):
        return self.member('ma_used')

    def create_dict(self, keys, values):
        if not keys or not values:
            return {}
        return dict(zip(keys, values))

    def get_values(self, cur_depth=0, max_depth=None, visited=None):
        curr_layer = self._context.layers[self.vol.layer_name]
        addresses = []
        value_ptr = self.ma_values
        try:
            for i in range(self.ma_used):
                try:
                    addr_bytes = curr_layer.read(value_ptr + i * 8, 8, pad=False)
                    addr = int.from_bytes(addr_bytes, byteorder='little')
                    addresses.append(addr)
                except exceptions.InvalidAddressException:
                    addresses.append(0)
                except Exception as e:
                    addresses.append(0)
        except Exception as e:
            return addresses
        return addresses

    def get_dict(self, cur_depth=0, max_depth=100, visited=None):
        result = {}
        try:
            if self.ma_values == 0:
                keys_obj = self.ma_keys.dereference()
                if not keys_obj:
                    return {}
                keys_values_tuple = keys_obj.get_keysandvalues(cur_depth, max_depth, visited)
                if keys_values_tuple is None:
                    return {}
                keys, value_addrs = keys_values_tuple
            else:
                if not self.ma_keys:
                    return {}
                keys_obj = self.ma_keys.dereference()
                keys = keys_obj.get_keys(cur_depth, max_depth, visited) if keys_obj else None
                value_addrs = self.get_values(cur_depth, max_depth, visited)
                if keys is None:
                    return {}
                if value_addrs is None:
                    return {}

            if max_depth is None or cur_depth < max_depth:
                values = create_objects(
                    self.get_symbol_table_name(),
                    self._context,
                    self.vol.layer_name,
                    value_addrs,
                    cur_depth + 1,
                    max_depth,
                    visited
                )
            else:
                values = ['<Value (max depth reached)>' for _ in value_addrs]

            for idx, (key, val_addr) in enumerate(zip(keys, values)):
                if key is None:
                    continue
                key_str = str(key) if not isinstance(key, (dict, list, tuple)) else f"<unhashable {type(key).__name__}>"
                if val_addr is None:
                    value = None
                else:
                    value = val_addr
                try:
                    result[key_str] = value
                except TypeError:
                    key_str = repr(key)
                    result[key_str] = value
            return result
        except exceptions.InvalidAddressException:
            return {}
        except Exception as e:
            print(f"Exception in PyDictObject.get_dict at {hex(self.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}

    def get_dict2(self, cur_depth=0, max_depth=1000, visited=None):
        result = {}
        try:
            if self.ma_values == 0:
                keys_obj = self.ma_keys.dereference()
                if not keys_obj:
                    return {}
                keys_values_tuple = keys_obj.get_keysandvalues(cur_depth, max_depth, visited)
                if keys_values_tuple is None:
                    return {}
                keys, value_addrs = keys_values_tuple
            else:
                if not self.ma_keys:
                    return {}
                keys_obj = self.ma_keys.dereference()
                keys = keys_obj.get_keys(cur_depth, max_depth, visited) if keys_obj else None
                value_addrs = self.get_values(cur_depth, max_depth, visited)
                if keys is None:
                    return {}
                if value_addrs is None:
                    return {}

            if max_depth is None or cur_depth < max_depth:
                values = create_objects2(
                    self.get_symbol_table_name(),
                    self._context,
                    self.vol.layer_name,
                    value_addrs,
                    cur_depth + 1,
                    max_depth,
                    visited
                )
            else:
                values = ['<Value (max depth reached)>' for _ in value_addrs]

            for idx, (key, val_addr) in enumerate(zip(keys, values)):
                if key is None:
                    continue
                key_str = str(key) if not isinstance(key, (dict, list, tuple)) else f"<unhashable {type(key).__name__}>"
                if val_addr is None:
                    value = None
                else:
                    value = val_addr
                try:
                    result[key_str] = value
                except TypeError:
                    key_str = repr(key)
                    result[key_str] = value
            return result
        except exceptions.InvalidAddressException:
            return {}
        except Exception as e:
            print(f"Exception in PyDictObject.get_dict at {hex(self.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return {}


class PyODictObject(PyObject):
    @property
    def od_dict(self):
        return self.member('od_dict').cast_to(
            self.get_symbol_table_name() + constants.BANG + 'PyDictObject'
        )

    @property
    def ob_type(self):
        return self.od_dict.ob_type

    @property
    def od_inst_dict(self):
        return self.member('od_inst_dict')

    @property
    def od_first(self):
        return self.member('od_first')

    @property
    def od_last(self):
        return self.member('od_last')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        obj_type_name = self.get_type_name()
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return f"{obj_type_name}"
        visited.add(obj_id)

        ordered_items = []
        od_first_ptr = self.od_first
        if not od_first_ptr or int(od_first_ptr) == 0:
            visited.remove(obj_id)
            return collections.OrderedDict()

        node = self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "_ODictNode",
            layer_name=self.vol.layer_name,
            offset=int(od_first_ptr)
        )

        while node and node.vol.offset != 0:
            key, value = node.get_key_value(cur_depth + 1, max_depth, visited)
            ordered_items.append((key, value))
            next_node_addr = node.next
            if not next_node_addr or int(next_node_addr) == 0:
                break
            node = self._context.object(
                object_type=self.get_symbol_table_name() + constants.BANG + "_ODictNode",
                layer_name=self.vol.layer_name,
                offset=int(next_node_addr)
            )

        visited.remove(obj_id)
        return collections.OrderedDict(ordered_items)


# =============================================================================
# Module
# =============================================================================

class PyModuleObject(PyObject):
    @property
    def md_state(self):
        return self.member('md_state')

    @property
    def md_def(self):
        return self.member('md_def')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            module_name = self.md_name.dereference().get_value()
        except Exception:
            module_name = "Unknown"
        return f"<module '{module_name}' at {hex(self.vol.offset)}>"

    def get_dict(self, cur_depth=0, max_depth=10000, visited=None):
        if visited is None:
            visited = set()
        visited.add(self.vol.offset)
        dict_obj = self.md_dict.dereference().cast_to(
            self.get_symbol_table_name() + constants.BANG + "PyDictObject"
        )
        return dict_obj.get_dict(cur_depth + 1, max_depth, visited)

    def get_dict2(self, cur_depth=0, max_depth=10000, visited=None):
        if visited is None:
            visited = set()
        visited.add(self.vol.offset)
        dict_obj = self.md_dict.dereference().cast_to(
            self.get_symbol_table_name() + constants.BANG + "PyDictObject"
        )
        return dict_obj.get_dict2(cur_depth + 1, max_depth, visited)

    def get_name(self):
        return self.md_name.dereference().get_value()


# =============================================================================
# Dict keys
# =============================================================================

class PyDictKeysObject(PyObject):
    """
    Python 3.6 PyDictKeysObject:
    - dk_refcnt, dk_size, dk_lookup, dk_usable, dk_nentries, dk_indices[]
    - Same structure as 3.8 (compact ordered dicts were introduced in 3.6)
    - NO PyDictUnicodeEntry (that's 3.12+)
    """
    @property
    def dk_size(self):
        return self.member('dk_size')

    @property
    def dk_nentries(self):
        return self.member('dk_nentries')

    @property
    def dk_indices(self):
        return self.member('dk_indices')

    def get_indices_size(self):
        dk_size = self.dk_size
        if dk_size <= 0xff:
            return dk_size
        elif dk_size <= 0xffff:
            return dk_size * 2
        elif dk_size <= 0xffffffff:
            return dk_size * 4
        else:
            return dk_size * 8

    def get_base_address(self):
        symbol_table_name = self.get_symbol_table_name()
        indices_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyDictKeysObject'
        ).relative_child_offset('dk_indices')
        dk_indices_size = self.get_indices_size()
        return self.vol.offset + indices_offset + dk_indices_size

    def get_keysandvalues(self, cur_depth=0, max_depth=None, visited=None):
        keys = []
        values = []
        addr = self.get_base_address()
        symbol_table_name = self.get_symbol_table_name()
        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )
            addr += 24
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
                values.append(key_entry.me_value)
        return keys, values

    def get_keys(self, cur_depth=0, max_depth=None, visited=None):
        keys = []
        addr = self.get_base_address()
        symbol_table_name = self.get_symbol_table_name()
        for i in range(self.dk_nentries):
            key_entry = self._context.object(
                object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                layer_name=self.vol.layer_name,
                offset=addr,
            )
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
            addr += 24
        return keys


class PyDictKeyEntry(PyObject):
    @property
    def me_key(self):
        return self.member('me_key')

    @property
    def me_value(self):
        return self.member('me_value')

    def get_key(self, cur_depth=0, max_depth=None, visited=None):
        return self.me_key.dereference().get_value(cur_depth, max_depth, visited)


# =============================================================================
# String (Unicode)
# =============================================================================

class PyASCIIObject(PyObject):
    """
    Python 3.6 PyASCIIObject - same layout as 3.8:
    - ob_base (PyObject, 16 bytes)
    - length (8 bytes)
    - hash (8 bytes)
    - state bitfield (4 bytes): interned:2, kind:3, compact:1, ascii:1, ready:1
    - 4 bytes padding
    - wstr (8 bytes pointer)
    Total: 48 bytes on 64-bit (but GDB shows 64 bytes due to PyObject being 32 with refcnt+type)

    For compact+ascii strings, data follows immediately after the struct.
    For compact+non-ascii, data follows after PyCompactUnicodeObject (88 bytes).
    """
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        curr_layer = self._context.layers[self.vol.layer_name]

        # state is a bitfield struct, read as raw uint32
        # In Python 3.6, state is at offset after ob_base(32) + length(8) + hash(8) = 48
        # But the actual offset depends on the ISF. Let's use relative offset 32 
        # since ob_base in the ISF might be different.
        # Reading from the struct offset for the state field
        state_val = int.from_bytes(curr_layer.read(self.vol.offset + 32, 4), 'little')
        COMPACT = (state_val >> 5) & 1
        ASCII = (state_val >> 6) & 1
        KIND = (state_val >> 2) & 0b111

        length = int(self.length)

        if ASCII and COMPACT:
            # Data immediately after PyASCIIObject
            string = curr_layer.read(self.vol.offset + self.vol.size, length, pad=False)
        elif not ASCII and COMPACT:
            # Data after PyCompactUnicodeObject (88 bytes in 3.6)
            string = curr_layer.read(self.vol.offset + 72, length * KIND, pad=False)
        else:
            # Legacy/non-compact string - data via wstr pointer
            string = curr_layer.read(self.vol.offset + self.vol.size, length, pad=False)

        try:
            if KIND == 1:
                return string.decode("utf-8", errors='replace')
            elif KIND == 2:
                return string.decode("utf-16", errors='replace')
            elif KIND == 4:
                return string.decode("utf-32", errors='replace')
            else:
                return string.decode("utf-8", errors='replace')
        except UnicodeDecodeError:
            try:
                return string.decode("latin-1")
            except UnicodeDecodeError:
                return f"UNICODE_DECODE_ERROR: {string!r}"


# =============================================================================
# Code Object - KEY DIFFERENCE: no co_posonlyargcount in 3.6
# =============================================================================

class PyCodeObject(PyObject):
    """
    Python 3.6 PyCodeObject fields:
    - co_argcount
    - co_kwonlyargcount     (NO co_posonlyargcount - that's 3.8+)
    - co_nlocals
    - co_stacksize
    - co_flags
    - co_firstlineno
    - co_code
    - co_consts
    - co_names
    - co_varnames
    - co_freevars
    - co_cellvars
    - co_filename
    - co_name
    - co_lnotab
    - co_zombieframe (internal, not needed for reconstruction)
    - co_weakreflist
    """

    def to_code_object(self):
        """
        Reconstruct a Python code object from memory.
        
        CRITICAL DIFFERENCE from 3.8:
        - Python 3.6 types.CodeType does NOT take co_posonlyargcount
        - Constructor signature: CodeType(argcount, kwonlyargcount, nlocals, ...)
        """
        try:
            argcount = int(self.co_argcount)
            # NOTE: NO co_posonlyargcount in Python 3.6!
            kwonlyargcount = int(self.co_kwonlyargcount)
            nlocals = int(self.co_nlocals)
            stacksize = int(self.co_stacksize)
            flags = int(self.co_flags)

            # Extract code string
            co_code_obj = self.co_code.dereference().cast_to("PyBytesObject")
            codestring = co_code_obj.get_value()

            # Extract constants
            co_consts_obj = self.co_consts.dereference()
            co_consts_obj = co_consts_obj.cast_to("PyTupleObject")
            constants = co_consts_obj.get_value()
            constants2 = co_consts_obj.get_value2()

            # Extract names
            co_names_obj = self.co_names.dereference()
            names_objs = co_names_obj.get_value()
            names = tuple(obj.get_value() if hasattr(obj, 'get_value') else str(obj) for obj in names_objs)

            # Extract variable names
            co_varnames_obj = self.co_varnames.dereference()
            varnames_objs = co_varnames_obj.get_value()
            varnames = tuple(obj.get_value() if hasattr(obj, 'get_value') else str(obj) for obj in varnames_objs)

            # Extract filename
            filename_obj = self.co_filename.dereference()
            filename = filename_obj.get_value()

            # Extract function name
            name_obj = self.co_name.dereference()
            name = name_obj.get_value()

            firstlineno = int(self.co_firstlineno)

            # Extract line number table
            co_lnotab_obj = self.co_lnotab.dereference().cast_to("PyBytesObject")
            lnotab = co_lnotab_obj.get_value()

            # Extract free variables
            co_freevars_obj = self.co_freevars.dereference()
            freevars_objs = co_freevars_obj.get_value()
            freevars = tuple(obj.get_value() if hasattr(obj, 'get_value') else str(obj) for obj in freevars_objs)

            # Extract cell variables
            co_cellvars_obj = self.co_cellvars.dereference()
            cellvars_objs = co_cellvars_obj.get_value()
            cellvars = tuple(obj.get_value() if hasattr(obj, 'get_value') else str(obj) for obj in cellvars_objs)

            # Python 3.6 CodeType constructor - NO posonlyargcount!
            code_obj = types.CodeType(
                argcount,
                kwonlyargcount,       # <-- directly after argcount, no posonlyargcount
                nlocals,
                stacksize,
                flags,
                codestring,
                constants2,
                names,
                varnames,
                filename,
                name,
                firstlineno,
                lnotab,
                freevars,
                cellvars
            )
            return code_obj

        except Exception as e:
            print(f"Error reconstructing code object at {hex(self.vol.offset)}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def get_co_code(self):
        co_code_obj = self.co_code.dereference()
        return co_code_obj.cast_to("PyBytesObject")

    def get_bytecode(self):
        try:
            co_code_obj = self.co_code.dereference()
            return co_code_obj.get_value()
        except Exception as e:
            print(f"Error getting bytecode from PyCodeObject at {hex(self.vol.offset)}: {str(e)}")
            return None

    def get_code_info(self):
        info = []
        try:
            info.append(f"co_name: {self.co_name.dereference().get_value()}")
        except Exception:
            info.append("co_name: [Error retrieving]")
        return ", ".join(info)

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return self.get_code_info()


# =============================================================================
# Numeric types
# =============================================================================

class PyLongObject(PyObject):
    def get_sign(self, num):
        return -1 if num < 0 else int(bool(num))

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        sign = self.get_sign(self.VAR_HEAD.ob_size)
        if sign == 0:
            return 0
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        addr = self.vol.offset + self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyVarObject').size
        value = int.from_bytes(curr_layer.read(addr, 4, pad=False), byteorder='little')
        return sign * value


class PyFloatObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyFloatObject'
        ).relative_child_offset('ob_fval')
        [item] = struct.unpack('<d', curr_layer.read(self.vol.offset + data_offset, 8))
        return item


# =============================================================================
# Tuple
# =============================================================================

class PyTupleObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=None, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        try:
            data_offset = self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + 'PyTupleObject'
            ).relative_child_offset('ob_item')
        except Exception:
            return ()

        try:
            size = self.ob_base.ob_size
        except (exceptions.InvalidAddressException, exceptions.PagedInvalidAddressException):
            return ()

        if size < 0 or size > 10000:
            return ()

        addresses = []
        for i in range(size):
            try:
                addr = int.from_bytes(
                    curr_layer.read(self.vol.offset + data_offset + i * 8, 8, pad=False),
                    byteorder='little'
                )
                addresses.append(addr)
            except (exceptions.InvalidAddressException, exceptions.PagedInvalidAddressException):
                addresses.append(0)
            except Exception:
                addresses.append(0)

        if max_depth is not None and cur_depth >= max_depth:
            return tuple(['Value (max depth reached)' for _ in addresses])

        return tuple(create_objects(symbol_table_name, self._context, self.vol.layer_name, addresses))

    def get_value2(self, cur_depth=0, max_depth=None, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        try:
            data_offset = self._context.symbol_space.get_type(
                symbol_table_name + constants.BANG + 'PyTupleObject'
            ).relative_child_offset('ob_item')
        except Exception:
            return ()

        try:
            size = self.ob_base.ob_size
        except (exceptions.InvalidAddressException, exceptions.PagedInvalidAddressException):
            return ()

        if size < 0 or size > 10000:
            return ()

        addresses = []
        for i in range(size):
            try:
                addr = int.from_bytes(
                    curr_layer.read(self.vol.offset + data_offset + i * 8, 8, pad=False),
                    byteorder='little'
                )
                addresses.append(addr)
            except (exceptions.InvalidAddressException, exceptions.PagedInvalidAddressException):
                addresses.append(0)
            except Exception:
                addresses.append(0)

        if max_depth is not None and cur_depth >= max_depth:
            return tuple(['Value (max depth reached)' for _ in addresses])

        return tuple(create_objects2(symbol_table_name, self._context, self.vol.layer_name, addresses))


# =============================================================================
# Method descriptor
# =============================================================================

class PyMethodDescrObject(PyObject):
    @property
    def d_common(self):
        return self._read_field('d_common', 'PyDescrObject')

    @property
    def d_method(self):
        return self._read_field('d_method', 'PyMethodDef')

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        try:
            method_name = self.d_common.get_value()
            return f"<method_descriptor {method_name}>"
        except Exception as e:
            print(f"Error processing PyMethodDescrObject at {hex(self.vol.offset)}: {str(e)}")
            return f"<method_descriptor at {hex(self.vol.offset)}>"


# =============================================================================
# List
# =============================================================================

class PyListObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.ob_item
        addresses = []
        for i in range(self.VAR_HEAD.ob_size):
            addr = int.from_bytes(
                curr_layer.read(data_offset + i * 8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)
        return list(create_objects2(symbol_table_name, self._context, self.vol.layer_name, addresses))

    def get_value2(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.ob_item
        addresses = []
        for i in range(self.VAR_HEAD.ob_size):
            addr = int.from_bytes(
                curr_layer.read(data_offset + i * 8, 8, pad=False),
                byteorder='little'
            )
            addresses.append(addr)
        return list(create_objects2(symbol_table_name, self._context, self.vol.layer_name, addresses))


# =============================================================================
# Set
# =============================================================================

class PySetObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.table
        set_type_name = self.ob_base.ob_type.dereference().get_name()

        if self.used == 0:
            return frozenset() if set_type_name == 'frozenset' else set()

        addresses = []
        slot_count = self.mask + 1

        for i in range(slot_count):
            slot_offset = data_offset + i * 16
            try:
                slot_data = curr_layer.read(slot_offset, 16, pad=False)
                key_addr = int.from_bytes(slot_data[:8], byteorder='little')
                if key_addr == 0:
                    continue
                addresses.append(key_addr)
            except exceptions.InvalidAddressException as e:
                print(f"InvalidAddressException reading slot at {hex(slot_offset)}: {str(e)}")
            except Exception as e:
                print(f"Exception reading slot at {hex(slot_offset)}: {str(e)}")

        objects_list = create_objects(symbol_table_name, self._context, self.vol.layer_name,
                                     addresses, cur_depth=cur_depth + 1, max_depth=max_depth, visited=visited)

        hashed_values = []
        for idx, obj_val in enumerate(objects_list):
            if isinstance(obj_val, (dict, list, set, frozenset)):
                obj_str = str(obj_val)
                hashed_values.append(obj_str)
            else:
                hashed_values.append(obj_val)

        if set_type_name == 'frozenset':
            try:
                return frozenset(hashed_values)
            except TypeError:
                return frozenset(str(val) for val in hashed_values)
        else:
            try:
                return set(hashed_values)
            except TypeError:
                return set(str(val) for val in hashed_values)


# =============================================================================
# Function - KEY DIFFERENCE: no vectorcall in 3.6
# =============================================================================

class PyFunctionObject(PyObject):
    """
    Python 3.6 PyFunctionObject:
    struct {
        PyObject ob_base;
        PyObject *func_code;
        PyObject *func_globals;
        PyObject *func_defaults;
        PyObject *func_kwdefaults;
        PyObject *func_closure;
        PyObject *func_doc;
        PyObject *func_name;
        PyObject *func_dict;
        PyObject *func_weakreflist;
        PyObject *func_module;
        PyObject *func_annotations;
        PyObject *func_qualname;
    }
    
    NOTE: NO vectorcall field (added in 3.8 via PEP 590)
    """
    @property
    def func_code_obj(self):
        func_code_addr = self.func_code
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_code_addr
        )

    @property
    def func_annotations_obj(self):
        func_annotations_addr = self.func_annotations
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_annotations_addr)

    @property
    def func_dict_obj(self):
        func_dict_addr = self.func_dict
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_dict_addr)

    @property
    def func_defaults_obj(self):
        func_defaults_addr = self.func_defaults
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_defaults_addr)

    @property
    def func_globals_obj(self):
        func_globals_addr = self.func_globals
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_globals_addr
        )

    @property
    def func_doc_obj(self):
        func_doc_addr = self.func_doc
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_doc_addr
        )

    @property
    def func_kwdefaults_obj(self):
        func_kwdefaults_addr = self.func_kwdefaults
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_kwdefaults_addr
        )

    @property
    def func_module_obj(self):
        func_module_addr = self.func_module
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_module_addr
        )

    @property
    def func_qualname_obj(self):
        func_qualname_addr = self.func_qualname
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_qualname_addr
        )

    # NOTE: NO vectorcall_obj property - vectorcall doesn't exist in Python 3.6

    @property
    def func_name_obj(self):
        func_name_addr = self.func_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return f"<function object (max recursion depth reached)>"
        try:
            func_name_obj = self.func_name_obj
            func_name = func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception as e:
            func_name = "<unknown function>"
            print(f"Error retrieving func_name at {hex(self.vol.offset)}: {e}")
        return f"<function {func_name} at {hex(self.vol.offset)}>"


# =============================================================================
# Helper functions
# =============================================================================

def create_objects(symbol_table_name, context, layer_name, addresses, cur_depth=0, max_depth=10, visited=None):
    if visited is None:
        visited = set()
    arr = []
    success_count = 0
    error_count = 0

    for index, addr in enumerate(addresses):
        try:
            if addr == 0:
                arr.append(None)
                continue

            if not context.layers[layer_name].is_valid(addr, 8):
                arr.append(None)
                error_count += 1
                continue

            obj = context.object(
                object_type=symbol_table_name + constants.BANG + 'PyObject',
                layer_name=layer_name,
                offset=addr,
            )

            obj_type_name = "<unknown>"
            if hasattr(obj, 'get_type_name'):
                obj_type_name = obj.get_type_name()
            else:
                obj_type_name = str(type(obj))

            if max_depth is not None and cur_depth >= max_depth:
                arr.append(f"<{obj_type_name} object (max recursion depth reached)>")
            else:
                value = obj.get_value(cur_depth + 1, max_depth, visited)
                arr.append(value)

            success_count += 1

        except (exceptions.InvalidAddressException, Exception):
            arr.append(None)
            error_count += 1

    return arr


def create_objects2(symbol_table_name, context, layer_name, addresses, cur_depth=0, max_depth=10, visited=None):
    if visited is None:
        visited = set()
    arr = []
    success_count = 0
    error_count = 0

    for index, addr in enumerate(addresses):
        try:
            if addr == 0:
                arr.append(None)
                continue

            if not context.layers[layer_name].is_valid(addr, 8):
                arr.append(None)
                error_count += 1
                continue

            obj = context.object(
                object_type=symbol_table_name + constants.BANG + 'PyObject',
                layer_name=layer_name,
                offset=addr,
            )

            obj_type_name = "<unknown>"
            if hasattr(obj, 'get_type_name'):
                obj_type_name = obj.get_type_name()
            else:
                obj_type_name = str(type(obj))

            if max_depth is not None and cur_depth >= max_depth:
                arr.append(f"<{obj_type_name} object (max recursion depth reached)>")
            else:
                arr.append(obj)

            success_count += 1

        except (exceptions.InvalidAddressException, Exception):
            arr.append(None)
            error_count += 1

    return arr


def hex_bytes_to_text(value):
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")
    ascii_chars = []
    for byte in value:
        if byte == 0x00:
            break
        ascii_chars.append(chr(byte))
    return ''.join(ascii_chars)
