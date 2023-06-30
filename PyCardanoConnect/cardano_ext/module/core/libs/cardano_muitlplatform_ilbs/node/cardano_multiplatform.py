import codecs
import numpy as np
import os
import pathlib
import wasmtime



imports = {}
imports["__wbindgen_placeholder__"] = None



cached_text_decoder = codecs.getincrementaldecoder("utf-8")(errors='strict')
encoded_bytes = b'\xc3\xa9\xc3\xa7\xc3\xa0'  # Replace with your actual encoded bytes

decoded_data = cached_text_decoder.decode(encoded_bytes)


cached_unit_memory0 = None


import ctypes
def get_unit8_memory0():
    global cached_unit_memory0

    if cached_unit_memory0 is None or len(cached_unit_memory0) == 0:
        cached_unit_memory0 = memoryview(wasm.memory)
    return cached_unit_memory0


def passArray32ToWasm0(arg, malloc):
    array_type = ctypes.c_uint32 * len(arg)
    array = array_type(*arg)
    ptr = malloc(len(arg) * 4)
    ctypes.memmove(ptr, ctypes.addressof(array), len(arg) * 4)
    WASM_VECTOR_LEN = len(arg)
    return ptr

# pass array function start________________________________________
def passArray8ToWasm0(arg, malloc):
    ptr = malloc(len(arg))
    get_unit8_memory0()[ptr:ptr + len(arg)] = arg
    global WASM_VECTOR_LEN
    WASM_VECTOR_LEN = len(arg)
    return ptr

def get_int32_memory0():
    global cached_int32_memory0
    if cached_int32_memory0 is None or cached_int32_memory0.nbytes == 0:
        cached_int32_memory0 = np.array(wasm.memory.buffer, dtype=np.int32)
    return cached_int32_memory0

def get_object(idx):
    global heap
    return heap[idx]

def drop_object(idx):
    global heap, heap_next

    if idx < 132:
        return

    heap[idx] = heap_next
    heap_next = idx


def take_object(idx):
    ret = get_object(idx)
    drop_object(idx)
    return ret



import weakref
class AddressFinalization:
    def __init__(self, cleanup_fn):
        self.cleanup_fn = cleanup_fn
        self.refs = weakref.WeakValueDictionary()

    def register(self, obj, ptr):
        self.refs[ptr] = obj

    def unregister(self, ptr):
        if ptr in self.refs:
            del self.refs[ptr]

    def cleanup(self):
        for ptr in self.refs.keys():
            self.cleanup_fn(ptr)


class Address:
    def __init__(self, ptr):
        self.ptr = ptr
        AddressFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Address(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        AddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_address_free(ptr)

    @staticmethod
    def from_bytes(data):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.address_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Address.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

imports["Address"] = Address


def make_mut_closure(arg0, arg1, dtor, f):
    state = {'a': arg0, 'b': arg1, 'cnt': 1, 'dtor': dtor}

    def real(*args):
        # First, increment the internal reference count
        # to ensure the closure environment won't be deallocated
        state['cnt'] += 1
        a = state['a']
        state['a'] = 0

        try:
            return f(a, state['b'], *args)
        finally:
            if state['cnt'] == 0:
                wasm.__wbindgen_export_2.get(state['dtor'])(a, state['b'])
                CLOSURE_DTORS.o(state)
            else:
                state['a'] = a

    real.original = state
    CLOSURE_DTORS.register(real, state, state)
    return real


heap = []

def add_heap_object(obj):
    if len(heap) == heap_next:
        heap.append(len(heap) + 1)
    idx = heap_next
    heap_next = heap[idx]
    heap[idx] = obj
    return idx


def __wbg_adapter_30(arg0, arg1, arg2):
    wasm._dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h9de9452916ac8cca(
        arg0,
        arg1,
        add_heap_object(arg2),
    )



def __wbindgen_closure_wrapper5962(arg0, arg1, arg2):
    ret = make_mut_closure(arg0, arg1, 194, __wbg_adapter_30)
    return add_heap_object(ret)





# print("imports",imports)


import pathlib




with open(pathlib.Path(__file__).parent.joinpath("/home/quotus/Cardano_Python_Ex/PyCardanoConnect/cardano_ext/module/core/libs/cardano_muitlplatform_ilbs/cardano_multiplatform_lib_bg.wasm"), "rb") as wasm_file:
    bytes = wasm_file.read()

engine = wasmtime.Engine()
store = wasmtime.Store(engine)

wasm_module = wasmtime.Module(wasm=bytes, engine=engine)
input_type = wasmtime.ValType.i32()
output_type = wasmtime.ValType.i32()

# Define the function type
func_type = wasmtime.FuncType([input_type], [output_type])
wrapper_func = wasmtime.Func(store, func_type, __wbindgen_closure_wrapper5962)
imports = {
    "__wbindgen_closure_wrapper5962": wrapper_func,
}

    
print("wasm module --------------------",type(wasm_module))
print("imports ----------------------------",type(imports))
print("store-------------------------------",type(store))

wasm_instance = wasmtime.Instance(module=wasm_module, imports=imports, store=store)
print("zzzzzzzzzzzzzzzzzzzzzzzz",wasm_instance)
wasm = wasm_instance.exports
print("-----------------------------------------------------",type(wasm))
__wasm = wasm


 