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
import io

Py_TPFLAGS_HEAPTYPE = 1 << 9

# 3.11 dict key kinds
DICT_KEYS_GENERAL = 0
DICT_KEYS_UNICODE = 1
DICT_KEYS_SPLIT = 2


class Python_3_14_IntermedSymbols(intermed.IntermediateSymbolTable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.set_type_class("PyGC_Head", PyGC_Head)
        self.set_type_class("PyObject", PyObject)
        self.set_type_class("PyTypeObject", PyTypeObject)
        self.set_type_class("PyDictObject", PyDictObject)
        self.set_type_class("PyDictKeysObject", PyDictKeysObject)
        self.set_type_class("PyDictKeyEntry", PyDictKeyEntry)
        self.set_type_class("PyDictUnicodeEntry", PyDictUnicodeEntry)
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
        self.set_type_class("PyPickleBufferObject", PyPickleBufferObject)
        self.set_type_class("rangeobject", rangeobject)
        self.set_type_class("PySliceObject", PySliceObject)
        self.set_type_class("PyGenObject", PyGenObject)
        self.set_type_class("PyCoroObject", PyCoroObject)
        self.set_type_class("PyAsyncGenObject", PyAsyncGenObject)
        self.set_type_class("_typeobject", PyTypeObject)
        self.set_type_class("arena_object", arena_object)
        self.set_type_class("pool_header", pool_header)
        self.set_type_class("block", block)


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
        size_classes = [
            8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
            144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448,
            480, 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1152, 1280, 1408,
            1536, 1664, 1792, 1920, 2048, 2304, 2560, 2816, 3072, 3328, 3584,
            3840, 4096, 4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192
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
      raw = int.from_bytes(
        self._context.layers[self.vol.layer_name].read(self.vol.offset, 8),
        byteorder='little')
      # Mask low 2 bits — Python 3.14 uses them as GC flags.
      # Safe for all versions since GC pointers are always 8-byte aligned.
      return raw & ~0x3

    def get_prev(self):
        return int.from_bytes(
            self._context.layers[self.vol.layer_name].read(self.vol.offset + 8, 8),
            byteorder='little')


class PyObject(objects.StructType):
    def get_type(self, name):
        types = {
            'NoneType': 'None', 'str': 'PyASCIIObject', 'int': 'PyLongObject',
            'method_descriptor': 'PyMethodDescrObject',
            'tuple': 'PyTupleObject', 'list': 'PyListObject',
            'wrapper_descriptor': 'PyWrapperDescrObject', 'method-wrapper': 'wrapperobject',
            'set': 'PySetObject', 'frozenset': 'PySetObject',
            'function': 'PyFunctionObject', 'methoddef': 'PyMethodDef',
            'member_descriptor': 'PyMemberDescrObject',
            'code': 'PyCodeObject', 'bytes': 'PyBytesObject',
            'builtin_function_or_method': 'PyCFunctionObject',
            'dict': 'PyDictObject', 'float': 'PyFloatObject',
            'getset_descriptor': 'PyGetSetDescrObject',
            'generator': 'PyGenObject', 'coroutine': 'PyCoroObject',
            'async_generator': 'PyAsyncGenObject',
            'module': 'PyModuleObject', 'type': 'PyTypeObject',
            'weakref': 'PyWeakReference', 'OrderedDict': 'PyODictObject',
            'staticmethod': 'staticmethod',
            'collections.OrderedDict': 'PyODictObject',
            'cell': 'PyCellObject', 'classmethod': 'classmethod',
            'bytearray': 'PyByteArrayObject',
            'complex': 'PyComplexObject', 'enumerate': 'enumobject',
            'frame': 'PyFrameObject', 'range': 'rangeobject',
            'slice': 'PySliceObject', 'method': 'PyMethodObject',
            'capsule': 'PyCapsule',
        }
        return types.get(name)

    @property
    def ob_type(self):
        return self.member('ob_type')

    def read_cstring(self, addr, max_length=256):
        curr_layer = self._context.layers[self.vol.layer_name]
        data = curr_layer.read(addr, max_length)
        cstring = data.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        return cstring

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
        track_for_cycles = obj_type_name not in {
            'int', 'bool', 'float', 'str', 'bytes', 'cell', 'NoneType', 'ellipsis'}

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
            value = func_obj.get_value(cur_depth + 1, max_depth, visited)
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

    def get_type_name(self):
        return self.ob_type.dereference().get_name()


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
                print(f"Error reading byte data at {hex(base_offset)}: {e}")
                return b''
        except Exception as e:
            print(f"Error processing PyBytesObject at {hex(self.vol.offset)}: {e}")
            return b''


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
        except Exception:
            return ()


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
        except Exception:
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
        except Exception:
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
        except Exception:
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
        except Exception:
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
            return f"<namespace object at {hex(self.vol.offset)} (error: {e})>"
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
            return method_name
        except Exception:
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
        except Exception:
            return f"<member_descriptor at {hex(self.vol.offset)}>"


class PyCFunctionObject(PyObject):
    # 3.11: added vectorcall field at the end (56 bytes total)
    @property
    def m_ml(self):
        return self._read_field('m_ml', 'PyMethodDef')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            method_def = self.m_ml.dereference()
            method_name = self.read_cstring(method_def.ml_name)
            return f"<built-in function {method_name}>"
        except Exception:
            return f"<built-in function at {hex(self.vol.offset)}>"


class PyWeakReference(PyObject):
    # 3.11: added vectorcall field at the end (64 bytes total)
    @property
    def wr_object(self):
        return self._read_field('wr_object', 'PyObject')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        try:
            referent = self.wr_object.dereference()
            referent_value = referent.get_value()
            return f"<weakref to {referent_value}>"
        except Exception:
            return f"<weakref at {hex(self.vol.offset)}>"


class classmethod_obj(PyObject):
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
            return f"<classmethod at 0x{self.vol.offset:x} (error: {e})>"


class staticmethod_obj(PyObject):
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
            return f"<staticmethod at 0x{self.vol.offset:x} (error: {e})>"


class PyGenObject(PyObject):
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
            return "<function object (max recursion depth reached)>"
        try:
            func_name = self.func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception:
            func_name = "<unknown function>"
        return f"<generator {func_name} at {hex(self.vol.offset)}>"


class PyCoroObject(PyObject):
    @property
    def func_name_obj(self):
        func_name_addr = self.cr_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return "<coroutine (max recursion depth reached)>"
        try:
            func_name = self.func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception:
            func_name = "<unknown>"
        return f"<coroutine {func_name} at {hex(self.vol.offset)}>"


class PyAsyncGenObject(PyObject):
    @property
    def func_name_obj(self):
        func_name_addr = self.ag_name
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=func_name_addr
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return "<async_generator (max recursion depth reached)>"
        try:
            func_name = self.func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception:
            func_name = "<unknown>"
        return f"<async_generator {func_name} at {hex(self.vol.offset)}>"


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
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return "<enumerate object>"


# --------------------------------------------------------------------------
# 3.11: PyFrameObject is now a thin wrapper around _PyInterpreterFrame.
# The real frame data (code, locals) lives in f_frame, not in PyFrameObject
# directly. Full frame introspection needs _PyInterpreterFrame parsing.
# --------------------------------------------------------------------------
class PyFrameObject(PyObject):
    @property
    def f_lineno(self):
        return self.member('f_lineno')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        lineno = int(self.f_lineno)
        return f"<frame at line {lineno}>"


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
            return f"<method at 0x{self.vol.offset:x} (error: {e})>"


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


class PyPickleBufferObject(PyObject):
    @property
    def view(self):
        return self.member('view')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        view = self.view
        buf_addr = int(view.buf)
        length = int(view.len)
        if buf_addr == 0 or length == 0:
            return b''
        curr_layer = self._context.layers[self.vol.layer_name]
        try:
            data = curr_layer.read(buf_addr, length)
            return data
        except Exception as e:
            return f"<Error reading buffer: {e}>"


# --------------------------------------------------------------------------
# Dict internals — these changed significantly in 3.11
# --------------------------------------------------------------------------

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
                except Exception:
                    addresses.append(0)
        except Exception:
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
                if keys is None or value_addrs is None:
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

            for key, val in zip(keys, values):
                if key is None:
                    continue
                key_str = str(key) if not isinstance(key, (dict, list, tuple)) else f"<unhashable {type(key).__name__}>"
                try:
                    result[key_str] = val
                except TypeError:
                    result[repr(key)] = val

            return result
        except exceptions.InvalidAddressException:
            return {}
        except Exception as e:
            print(f"Exception in PyDictObject.get_dict at {hex(self.vol.offset)}: {e}")
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
                if keys is None or value_addrs is None:
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

            for key, val in zip(keys, values):
                if key is None:
                    continue
                key_str = str(key) if not isinstance(key, (dict, list, tuple)) else f"<unhashable {type(key).__name__}>"
                try:
                    result[key_str] = val
                except TypeError:
                    result[repr(key)] = val

            return result
        except exceptions.InvalidAddressException:
            return {}
        except Exception as e:
            print(f"Exception in PyDictObject.get_dict2 at {hex(self.vol.offset)}: {e}")
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
    def od_first(self):
        return self.member('od_first')

    @property
    def od_last(self):
        return self.member('od_last')

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if visited is None:
            visited = set()
        obj_id = int(self.vol.offset)
        if obj_id in visited:
            return "OrderedDict"
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


# --------------------------------------------------------------------------
# 3.11: PyDictKeysObject changed — dk_size replaced with dk_log2_size,
# added dk_kind to distinguish GENERAL vs UNICODE entries.
# --------------------------------------------------------------------------
class PyDictKeysObject(PyObject):
    @property
    def dk_size(self):
        log2 = int(self.dk_log2_size)
        return 1 << log2 if log2 > 0 else 0

    @property
    def dk_nentries(self):
        return self.member('dk_nentries')

    @property
    def dk_kind(self):
        return int(self.member('dk_kind'))

    @property
    def dk_indices(self):
        return self.member('dk_indices')

    def _is_unicode_keys(self):
        return self.dk_kind != DICT_KEYS_GENERAL

    def _entry_size(self):
        # PyDictUnicodeEntry = 16 bytes, PyDictKeyEntry = 24 bytes
        return 16 if self._is_unicode_keys() else 24

    def get_indices_size(self):
        log2_ib = int(self.dk_log2_index_bytes)
        return 1 << log2_ib if log2_ib > 0 else 0

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
        entry_size = self._entry_size()
        is_unicode = self._is_unicode_keys()

        for i in range(self.dk_nentries):
            if is_unicode:
                key_entry = self._context.object(
                    object_type=symbol_table_name + constants.BANG + 'PyDictUnicodeEntry',
                    layer_name=self.vol.layer_name,
                    offset=addr,
                )
            else:
                key_entry = self._context.object(
                    object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                    layer_name=self.vol.layer_name,
                    offset=addr,
                )
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
                values.append(key_entry.me_value)
            addr += entry_size
        return keys, values

    def get_keys(self, cur_depth=0, max_depth=None, visited=None):
        keys = []
        addr = self.get_base_address()
        symbol_table_name = self.get_symbol_table_name()
        entry_size = self._entry_size()
        is_unicode = self._is_unicode_keys()

        for i in range(self.dk_nentries):
            if is_unicode:
                key_entry = self._context.object(
                    object_type=symbol_table_name + constants.BANG + 'PyDictUnicodeEntry',
                    layer_name=self.vol.layer_name,
                    offset=addr,
                )
            else:
                key_entry = self._context.object(
                    object_type=symbol_table_name + constants.BANG + 'PyDictKeyEntry',
                    layer_name=self.vol.layer_name,
                    offset=addr,
                )
            if key_entry.me_key != 0:
                keys.append(key_entry.get_key(cur_depth, max_depth, visited))
            addr += entry_size
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


class PyDictUnicodeEntry(PyObject):
    """New in 3.11: 16-byte entry (key + value, no hash) for string-keyed dicts."""
    @property
    def me_key(self):
        return self.member('me_key')

    @property
    def me_value(self):
        return self.member('me_value')

    def get_key(self, cur_depth=0, max_depth=None, visited=None):
        return self.me_key.dereference().get_value(cur_depth, max_depth, visited)


class PyASCIIObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        curr_layer = self._context.layers[self.vol.layer_name]

        # state bitfield at offset 32 (same position, but struct is now 40 bytes)
        state_val = int.from_bytes(curr_layer.read(self.vol.offset + 32, 4), 'little')
        COMPACT = (state_val >> 5) & 1
        ASCII = (state_val >> 6) & 1
        KIND = (state_val >> 2) & 0b111

        length = int(self.length)

        if ASCII and COMPACT:
            # data immediately after struct — now 40 bytes, not 48
            string = curr_layer.read(self.vol.offset + self.vol.size, length, pad=False)
        elif not ASCII and COMPACT:
            # after PyCompactUnicodeObject — now 56 bytes, not 72
            string = curr_layer.read(self.vol.offset + 56, length * KIND, pad=False)
        else:
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


# --------------------------------------------------------------------------
# 3.11: PyCodeObject is completely different from 3.8.
# co_code (PyBytesObject*) -> co_code_adaptive (inline bytes)
# co_lnotab -> co_linetable
# co_varnames/co_freevars/co_cellvars -> co_localsplusnames + co_localspluskinds
# Full to_code_object() reconstruction is not implemented for 3.11.
# --------------------------------------------------------------------------
class PyCodeObject(PyObject):
    def get_bytecode(self):
        try:
            curr_layer = self._context.layers[self.vol.layer_name]
            # co_code_adaptive is at offset 184 in 3.11
            code_start = self.vol.offset + 184
            ob_size = self.ob_base.ob_size
            if ob_size > 0 and ob_size < 65536:
                return curr_layer.read(code_start, ob_size * 2)
            return None
        except Exception as e:
            print(f"Error getting bytecode at {hex(self.vol.offset)}: {e}")
            return None

    def get_code_info(self):
        info = []
        try:
            info.append(f"co_name: {self.co_name.dereference().get_value()}")
        except Exception:
            info.append("co_name: [Error]")
        try:
            info.append(f"co_filename: {self.co_filename.dereference().get_value()}")
        except Exception:
            pass
        return ", ".join(info)

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        return self.get_code_info()

    def to_code_object(self):
        # 3.11 code object layout is too different for automatic reconstruction.
        # co_code is now inline (co_code_adaptive), co_lnotab is gone, etc.
        print(f"WARNING: to_code_object() not implemented for 3.11")
        return None


class PyLongObject(PyObject):
    # 3.12: ob_size no longer encodes sign. Now uses _PyLongValue.lv_tag:
    #   lv_tag & 3 == sign (0=positive, 1=zero, 2=negative)
    #   lv_tag >> 3 == number of digits

    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        curr_layer = self._context.layers[self.vol.layer_name]

        # lv_tag is at offset 16 (right after PyObject ob_base)
        lv_tag_bytes = curr_layer.read(self.vol.offset + 16, 8)
        lv_tag = int.from_bytes(lv_tag_bytes, byteorder='little')

        sign_bits = lv_tag & 0x3
        ndigits = lv_tag >> 3

        if sign_bits == 1:  # zero
            return 0

        # digits start at offset 24 (after ob_base(16) + lv_tag(8))
        digits_addr = self.vol.offset + 24

        value = 0
        for i in range(ndigits):
            digit_bytes = curr_layer.read(digits_addr + i * 4, 4, pad=False)
            digit = int.from_bytes(digit_bytes, byteorder='little')
            value |= digit << (30 * i)  # PyLong_SHIFT = 30 on 64-bit

        if sign_bits == 2:  # negative
            value = -value

        return value

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
            except Exception:
                addresses.append(0)

        if max_depth is not None and cur_depth >= max_depth:
            return tuple(['Value (max depth reached)' for _ in addresses])
        return tuple(create_objects2(symbol_table_name, self._context, self.vol.layer_name, addresses))


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
        except Exception:
            return f"<method_descriptor at {hex(self.vol.offset)}>"


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
        return self.get_value(cur_depth, max_depth, visited)


class PySetObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self.table

        set_type_name = self.HEAD.ob_type.dereference().get_name()
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
            except Exception:
                continue

        objects_list = create_objects(symbol_table_name, self._context, self.vol.layer_name,
                                     addresses, cur_depth=cur_depth + 1, max_depth=max_depth, visited=visited)

        hashed_values = []
        for obj_val in objects_list:
            if isinstance(obj_val, (dict, list, set, frozenset)):
                hashed_values.append(str(obj_val))
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


class PyFloatObject(PyObject):
    def get_value(self, cur_depth=0, max_depth=5, visited=None):
        symbol_table_name = self.get_symbol_table_name()
        curr_layer = self._context.layers[self.vol.layer_name]
        data_offset = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + 'PyFloatObject'
        ).relative_child_offset('ob_fval')
        [item] = struct.unpack('<d', curr_layer.read(self.vol.offset + data_offset, 8))
        return item


# --------------------------------------------------------------------------
# 3.11: PyFunctionObject layout changed — fields reordered,
# func_builtins/func_qualname/func_version added.
# --------------------------------------------------------------------------
class PyFunctionObject(PyObject):
    @property
    def func_code_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_code
        )

    @property
    def func_name_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_name
        )

    @property
    def func_globals_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_globals
        )

    @property
    def func_doc_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_doc
        )

    @property
    def func_module_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_module
        )

    @property
    def func_qualname_obj(self):
        return self._context.object(
            object_type=self.get_symbol_table_name() + constants.BANG + "PyObject",
            layer_name=self.vol.layer_name,
            offset=self.func_qualname
        )

    def get_value(self, cur_depth=0, max_depth=10, visited=None):
        if max_depth is not None and cur_depth >= max_depth:
            return "<function object (max recursion depth reached)>"
        try:
            func_name = self.func_name_obj.get_value(cur_depth + 1, max_depth, visited)
        except Exception as e:
            func_name = "<unknown function>"
        return f"<function {func_name} at {hex(self.vol.offset)}>"


# --------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------

def create_objects(symbol_table_name, context, layer_name, addresses,
                   cur_depth=0, max_depth=10, visited=None):
    if visited is None:
        visited = set()
    arr = []
    for addr in addresses:
        try:
            if addr == 0:
                arr.append(None)
                continue
            if not context.layers[layer_name].is_valid(addr, 8):
                arr.append(None)
                continue
            obj = context.object(
                object_type=symbol_table_name + constants.BANG + 'PyObject',
                layer_name=layer_name,
                offset=addr,
            )
            if max_depth is not None and cur_depth >= max_depth:
                obj_type_name = obj.get_type_name() if hasattr(obj, 'get_type_name') else str(type(obj))
                arr.append(f"<{obj_type_name} object (max recursion depth reached)>")
            else:
                value = obj.get_value(cur_depth + 1, max_depth, visited)
                arr.append(value)
        except Exception:
            arr.append(None)
    return arr


def create_objects2(symbol_table_name, context, layer_name, addresses,
                    cur_depth=0, max_depth=10, visited=None):
    if visited is None:
        visited = set()
    arr = []
    for addr in addresses:
        try:
            if addr == 0:
                arr.append(None)
                continue
            if not context.layers[layer_name].is_valid(addr, 8):
                arr.append(None)
                continue
            obj = context.object(
                object_type=symbol_table_name + constants.BANG + 'PyObject',
                layer_name=layer_name,
                offset=addr,
            )
            if max_depth is not None and cur_depth >= max_depth:
                obj_type_name = obj.get_type_name() if hasattr(obj, 'get_type_name') else str(type(obj))
                arr.append(f"<{obj_type_name} object (max recursion depth reached)>")
            else:
                arr.append(obj)
        except Exception:
            arr.append(None)
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
