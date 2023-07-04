
import codecs
import numpy as np
import json
import traceback
import re
import wasmtime
import bech32
import struct

import wasm


from .wasms import wasm_fun




cached_text_decoder = codecs.getincrementaldecoder("utf-8")(errors='strict')
encoded_bytes = b'\xc3\xa9\xc3\xa7\xc3\xa0'  # Replace with your actual encoded bytes

decoded_data = cached_text_decoder.decode(encoded_bytes)


cached_unit_memory0 = None


def passArray32ToWasm0(arg, malloc):
    array_type = ctypes.c_uint32 * len(arg)
    array = array_type(*arg)
    ptr = malloc(len(arg) * 4)
    ctypes.memmove(ptr, ctypes.addressof(array), len(arg) * 4)
    WASM_VECTOR_LEN = len(arg)
    return ptr


def get_unit8_memory0():
    global cached_unit_memory0

    if cached_unit_memory0 is None or len(cached_unit_memory0) == 0:
        cached_unit_memory0 = memoryview(wasm.memory)
    return cached_unit_memory0

def get_string_from_wasm0(ptr, length):
    memory = get_unit8_memory0()
    data = memory[ptr:ptr+length].tobytes()
    decoded_string = data.decode("utf-8")
    return decoded_string

heap = [None] * 128
heap.extend([None, None, True, False])
heap_next = len(heap)

def add_heap_object(obj):
    global heap_next, heap

    if heap_next == len(heap):
        heap.append(len(heap) + 1 )

    idx = heap_next
    heap_next = heap[idx]

    heap[idx] = obj
    return idx

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

WASM_VECTOR_LEN = 0

cached_text_encoder = codecs.getincrementalencoder("utf-8")()

def encode_string(arg, view):
    encoded_data, bytes_written, _ = cached_text_encoder.encode(arg, final=True)
    view[:bytes_written] = encoded_data
    return bytes_written

def pass_string_to_wasm0(arg, malloc, realloc=None):
    global WASM_VECTOR_LEN

    if realloc is None:
        buf = cached_text_encoder.encode(arg, final=True)
        ptr = malloc(len(buf))
        view = get_unit8_memory0()
        view[ptr : ptr + len(buf)] = buf
        WASM_VECTOR_LEN = len(buf)
        return ptr
    len_arg = len(arg)
    ptr = malloc(len_arg)
    mem = get_unit8_memory0()

    offset = 0

    for offset in range(len_arg):
        code = ord(arg[offset])
        if code > 0x7F:
            break
        mem[ptr + offset] = code


    if offset != len_arg:
        if offset != 0:
            arg = arg[offset:]
        ptr = realloc(ptr, len_arg, len_arg = offset + len(arg) * 3)
        view = get_unit8_memory0()[ptr + offset : ptr + len_arg]
        ret = encode_string(arg, view)
        offset += ret

    WASM_VECTOR_LEN = offset
    return ptr

cached_int32_memory0 = None

def get_int32_memory0():

    buffer = memoryview(b'\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00')
    global cached_int32_memory0
    if cached_int32_memory0 is None or cached_int32_memory0.nbytes == 0:
        cached_int32_memory0 = np.frombuffer(buffer, dtype=np.int32)

    return cached_int32_memory0

def is_like_none(x):
    return x is None or x is None

def debug_string(val):
    # primitive types
    val_type = type(val).__name__
    if val_type in ["int", "float", "bool"] or val is None:
        return str(val)
    if val_type == "str":
        return f'"{val}"'
    if val_type == "Symbol":
        description = val.description
        if description is None:
            return "Symbol"
        else:
            return f'Symbol({description})'
    if val_type == "function":
        name = val.__name__
        if isinstance(name, str) and len(name) > 0:
            return f'Function({name})'
        else:
            return "Function"
    # objects
    if isinstance(val, list):
        length = len(val)
        debug = "["
        if length > 0:
            debug += debug_string(val[0])
        for i in range(1, length):
            debug += ", " + debug_string(val[i])
        debug += "]"
        return debug
    # Test for built-in
    built_in_matches = re.findall(r'\[object ([^\]]+)\]', str(type(val)))
    if len(built_in_matches) > 0:
        class_name = built_in_matches[0]
    else:
        # Failed to match the standard '[object ClassName]'
        return str(type(val))
    if class_name == "Object":
        # we're a user defined class or Object
        # json.dumps avoids problems with cycles, and is generally much
        # easier than looping through properties of `val`.
        try:
            return "Object(" + json.dumps(val) + ")"
        except:
            return "Object"
    # errors
    if isinstance(val, BaseException):
        return f'{val.__class__.__name__}: {val}\n{traceback.format_exc()}'
    # TODO we could test for more things here, like `Set`s and `Map`s.
    return class_name




# finalize function start

import weakref

CLOSURE_DTORS = {}

def finalize_callback(weak_state):
    state = weak_state()
    if state is not None:
        wasm.__wbindgen_export_2.get(state['dtor'])(state['a'], state['b'])

def register_finalization(state):
    weak_state = weakref.ref(state, finalize_callback)
    CLOSURE_DTORS[weak_state] = None

def unregister_finalization(state):
    for weak_state in CLOSURE_DTORS.keys():
        if weak_state() == state:
            del CLOSURE_DTORS[weak_state]
            break


# finalize function end

def make_mut_closure(arg0, arg1, dtor, f):
    state = {"a": arg0, "b": arg1, "cnt": 1, "dtor": dtor}

    def real(*args):
        # First, with a closure, we increment the internal reference count.
        # This ensures that the Rust closure environment won't be deallocated
        # while we're invoking it.
        state["cnt"] += 1
        a = state["a"]
        state["a"] = 0

        try:
            return f(a, state["b"], *args)
        finally:
            if state["cnt"] == 0:
                wasm.__wbindgen_export_2.get(state["dtor"])(a, state["b"])
                CLOSURE_DTORS.unregister(state)
            else:
                state["a"] = a
    
    real.original = state
    CLOSURE_DTORS.register(real, state, state)


    return real





# address class
# import atexit

# # Define a list to keep track of the pointers that need to be freed
# address_pointers = []
# # Define a function to free the memory associated with the pointers
# def free_addresses():
#     for ptr in address_pointers:
#         wasm.__wbindgen_closure_wrapper5962(ptr)

# # Register the function to be called at program exit
# atexit.register(free_addresses)

# # When you create a new address and obtain its pointer, add it to the list
# address_ptr = wasm.__wbindgen_closure_wrapper5962()

# address_pointers.append(address_ptr)

# # Use the address pointer as needed

# # When the address is no longer needed, remove it from the list
# address_pointers.remove(address_ptr)



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
        AddressFinalization.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        AddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_address_free(ptr)


    def from_bytes(data):
        try:
            store = wasmtime.Store()
            module = wasmtime.Module(store.engine, "<path_to_wasm_file>")
            instance = wasmtime.Instance(module, [])
            memory = instance.exports.get_memory("memory")

            # Allocate memory in the WebAssembly linear memory and copy the data
            ptr = memory.grow(len(data))
            memory.data_view()[ptr:ptr + len(data)] = data

            # Call the WebAssembly function
            address_from_bytes = instance.exports.get_func("address_from_bytes")
            retptr = store.externref()
            address_from_bytes(ptr, len(data), retptr)

            # Retrieve the result from WebAssembly linear memory
            result_ptr = retptr.data()
            r0 = memory.data_view()[result_ptr // 4]
            r1 = memory.data_view()[(result_ptr // 4) + 1]
            r2 = memory.data_view()[(result_ptr // 4) + 2]

            if r2:
                raise Exception(take_object(r1))  # Replace take_object with the appropriate logic

            return Address.wrap(r0)  # Replace Address.__wrap with the appropriate wrapping logic
        finally:
            # Cleanup or finalize resources if needed
            pass

    def from_bech32(bech_str):
        try:
            # Decode the Bech32 string
            hrp, data = bech32.bech32_decode(bech_str)
            
            # Convert the Bech32 data to bytes
            data_bytes = bech32.convertbits(data, len(data), 5, 8, False)
            
            # Call the necessary wasm function or handle the data accordingly
            # You would need to provide the specific logic here based on your use case

            # Return the result (assuming it is an address)
            return Address.wrap(data_bytes)  # Replace Address.__wrap with the appropriate wrapping logic
        finally:
            # Cleanup or finalize resources if needed
            pass

    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = 0
            len0 = 0
            if prefix is not None:
                ptr0 = pass_string_to_wasm0(
                    prefix,
                    wasm.__wbindgen_malloc,
                    wasm.__wbindgen_realloc,
                )
                len0 = WASM_VECTOR_LEN
            wasm.address_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)



import ctypes

# Define the callback function
def free_ed25519_key_hash(ptr):
    # Call the appropriate cleanup function
    wasm.__wbg_ed25519keyhash_free(ptr)

# Create the finalization registry
class Ed25519KeyHashFinalization:
    def __init__(self, obj, ptr):
        self.finalizer = weakref.finalize(obj, free_ed25519_key_hash, ptr)

    def unregister(self):
        self.finalizer.detach()
import ctypes
import array

class Ed25519KeyHash:
    def __init__(self, ptr):
        self.ptr = ptr
        Ed25519KeyHashFinalization.register(self, self.ptr, self)
    
    def __del__(self):
        self.free()
    
    @staticmethod
    def __wrap(ptr):
        return Ed25519KeyHash(ptr)
    
    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        Ed25519KeyHashFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_ed25519keyhash_free(ptr)
    
    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = ctypes.cast(bytes.buffer_info()[0], ctypes.c_void_p).value
            len0 = len(bytes)
            wasm.ed25519keyhash_from_bytes(retptr, ptr0, len0)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            r2 = ctypes.c_int32.from_address(retptr + 8).value
            if r2:
                raise take_object(r1)
            return Ed25519KeyHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhash_to_bytes(retptr, self.ptr)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            data = array.array("B", ctypes.string_at(r0, r1))
            wasm.__wbindgen_free(r0, r1)
            return data
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            prefix_bytes = prefix.encode("utf-8")
            ptr0 = ctypes.cast(prefix_bytes, ctypes.c_void_p).value
            len0 = len(prefix_bytes)
            wasm.ed25519keyhash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            r2 = ctypes.c_int32.from_address(retptr + 8).value
            r3 = ctypes.c_int32.from_address(retptr + 12).value
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            bech_str = ctypes.string_at(ptr1, len1).decode("utf-8")
            return bech_str
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)

    @staticmethod
    def from_hex(hex_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                hex_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc
            )
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhash_from_hex(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return Ed25519KeyHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)



# pass array function start________________________________________
def passArray8ToWasm0(arg, malloc):
    ptr = malloc(len(arg))
    get_unit8_memory0()[ptr:ptr + len(arg)] = arg
    global WASM_VECTOR_LEN
    WASM_VECTOR_LEN = len(arg)
    return ptr

# pass array function end


# get array 8
def getArrayU8FromWasm0(ptr, length):
    return get_unit8_memory0()[ptr:ptr+length]



    
def free_ed25519_key_hash(ptr):
    # Call the appropriate cleanup function
    wasm.__wbg_ed25519keyhash_free(ptr)

# Create the finalization registry
class ScriptHashFinalization:
    def __init__(self, obj, ptr):
        self.finalizer = weakref.finalize(obj, free_ed25519_key_hash, ptr)

    def unregister(self):
        self.finalizer.detach()   


class ScriptHash:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptHashFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptHashFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scripthash_free(ptr)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scripthash_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return ScriptHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhash_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                prefix,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            r3 = get_int32_memory0()[int(retptr / 4) + 3]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)

    @staticmethod
    def from_hex(hex_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                hex_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc
            )
            len0 = WASM_VECTOR_LEN
            wasm.scripthash_from_hex(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


   




import weakref


class FinalizationRegistry:
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

# asseret class__________________________________________________________________
def _assertClass(instance, klass):
    if not isinstance(instance, klass):
        raise ValueError(f"expected instance of {klass.__name__}")
    return instance.ptr
# _______________________________________________________________________________

class StakeCredential:
    def __init__(self, ptr):
        self.ptr = ptr
        FinalizationRegistry.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        FinalizationRegistry.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_stakecredential_free(ptr)

    @staticmethod
    def from_keyhash(hash):
        _assertClass(hash, Ed25519KeyHash)
        ret = wasm.stakecredential_from_keyhash(hash.ptr)
        return StakeCredential(ret)

    @staticmethod
    def from_scripthash(hash):
        _assertClass(hash, ScriptHash)
        ret = wasm.stakecredential_from_scripthash(hash.ptr)
        return StakeCredential(ret)

    def to_keyhash(self):
        ret = wasm.stakecredential_to_keyhash(self.ptr)
        return None if ret == 0 else Ed25519KeyHash(ret)

    def to_scripthash(self):
        ret = wasm.stakecredential_to_scripthash(self.ptr)
        return None if ret == 0 else ScriptHash(ret)

    def kind(self):
        ret = wasm.language_kind(self.ptr)
        return ret 

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.stakecredential_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.stakecredential_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return StakeCredential(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.stakecredential_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm





class BaseAddress:
    def __init__(self,ptr):
        self.ptr = ptr
        FinalizationRegistry.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        FinalizationRegistry.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_baseaddress_free(ptr)

    @staticmethod
    def __wrap(ptr):
        obj = BaseAddress(ptr)
        return obj
    
    @staticmethod
    def new(network, payment, stake):
        _assertClass(payment, StakeCredential)
        _assertClass(stake, StakeCredential)
        ret = wasm.baseaddress_new(network, payment.ptr, stake.ptr)
        return BaseAddress.__wrap(ret)
    
    def payment_cred(self):
        ret = wasm.baseaddress_payment_cred(self.ptr)
        return StakeCredential.__wrap(ret)
    
    def stake_cred(self):
        ret = wasm.baseaddress_stake_cred(self.ptr)
        return StakeCredential.__wrap(ret)
    
    def to_address(self):
        ret = wasm.baseaddress_to_address(self.ptr)
        return Address.__wrap(ret)
    
    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_base(addr.ptr)
        return BaseAddress.__wrap(ret) if ret != 0 else None
    



# EnterPrice Address 

class EnterpriseAddressFinalization:
    def __init__(self, ptr):
        self.ptr = ptr
        self.finalizer = weakref.finalize(self, wasm.__wbg_enterpriseaddress_free, ptr)



class EnterpriseAddress:
    def __init__(self, ptr):
        self.ptr = ptr
        EnterpriseAddressFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        EnterpriseAddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_enterpriseaddress_free(ptr)

    @staticmethod
    def new(network, payment):
        _assertClass(payment, StakeCredential)
        ret = wasm.enterpriseaddress_new(network, payment.ptr)
        return EnterpriseAddress(ret)

    def payment_cred(self):
        ret = wasm.baseaddress_payment_cred(self.ptr)
        return StakeCredential(ret)

    def to_address(self):
        ret = wasm.enterpriseaddress_to_address(self.ptr)
        return Address(ret)

    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_enterprise(addr.ptr)
        return EnterpriseAddress(ret)
    
# Reward Address 
class RewardAddressFinalization:
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


class RewardAddress:
    def __init__(self, ptr):
        self.ptr = ptr
        RewardAddressFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        RewardAddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_rewardaddress_free(ptr)

    @staticmethod
    def new(network, payment):
        _assertClass(payment, StakeCredential)
        ret = wasm.enterpriseaddress_new(network, payment.ptr)
        return RewardAddress.__wrap(ret)

    def payment_cred(self):
        ret = wasm.baseaddress_payment_cred(self.ptr)
        return StakeCredential.__wrap(ret)

    def to_address(self):
        ret = wasm.rewardaddress_to_address(self.ptr)
        return Address.__wrap(ret)

    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_reward(addr.ptr)
        return None if ret == 0 else RewardAddress.__wrap(ret)

    



# Rewarded Addresses
class RewardAddressesFinalization:
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

    



class RewardAddresses:
    def __init__(self, ptr):
        self.ptr = ptr
        RewardAddressesFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        RewardAddressesFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_rewardaddresses_free(ptr)

    @staticmethod
    def __wrap(ptr):
        obj = RewardAddresses(ptr)
        return obj


    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.rewardaddresses_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return RewardAddresses.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.rewardaddresses_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return RewardAddresses.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


class LanguagesFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Languages:
    def __init__(self, ptr):
        self.ptr = ptr
        LanguagesFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Languages(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        LanguagesFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_languages_free(ptr)

    @staticmethod
    def new():
        ret = wasm.ed25519keyhashes_new()
        return Languages.__wrap(ret)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret

    def get(self, index):
        ret = wasm.languages_get(self.ptr, index)
        return Language.__wrap(ret)

    def add(self, elem):
        _assertClass(elem, Language)
        ptr0 = elem.__destroy_into_raw()
        wasm.languages_add(self.ptr, ptr0)


# Language
class LanguageFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Language:
    def __init__(self, ptr):
        self.ptr = ptr
        LanguageFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Language(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        LanguageFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_language_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.language_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.language_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]

            if r2:
                raise take_object(r1)
            return Language.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new_plutus_v1():
        ret = wasm.language_new_plutus_v1()
        return Language.__wrap(ret)

    @staticmethod
    def new_plutus_v2():
        ret = wasm.language_new_plutus_v2()
        return Language.__wrap(ret)

    def kind(self):
        ret = wasm.language_kind(self.ptr)
        return ret
    
# int 
    
class IntFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Int:
    def __init__(self, ptr):
        self.ptr = ptr

    def __del__(self):
        self.free()

    def __wrap(cls, ptr):
        obj = cls(ptr)
        IntFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        IntFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_int_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.int_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).slice()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.int_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return Int.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new(x):
        _assertClass(x, BigNum)
        ret = wasm.int_new(x.ptr)
        return Int.__wrap(ret)

    @staticmethod
    def new_negative(x):
        _assertClass(x, BigNum)
        ret = wasm.int_new_negative(x.ptr)
        return Int.__wrap(ret)
    
    @staticmethod
    def new_i32(x):
        ret = wasm.int_new_i32(x)
        return Int.__wrap(ret)

    def is_positive(self):
        ret = wasm.int_is_positive(self.ptr)
        return ret != 0

    def as_positive(self):
        ret = wasm.int_as_positive(self.ptr)
        return BigNum.__wrap(ret) if ret != 0 else None

    def as_negative(self):
        ret = wasm.int_as_negative(self.ptr)
        return BigNum.__wrap(ret) if ret != 0 else None

    def as_i32(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.int_as_i32(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            return r1 if r0 != 0 else None
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def as_i32_or_nothing(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.int_as_i32(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            return r1 if r0 != 0 else None
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def as_i32_or_fail(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.int_as_i32_or_fail(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return r0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_str(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.int_to_str(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)

    @staticmethod
    def from_str(string):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                string,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.int_from_str(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return Int.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    

# cost model
class CostModelFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class CostModel:
    def __init__(self, ptr):
        self.ptr = ptr
        CostModelFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = CostModel(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        CostModelFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_costmodel_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.costmodel_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.costmodel_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]

            if r2:
                raise take_object(r1)
            return CostModel.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.costmodel_new()
        return CostModel.__wrap(ret)
    

    @staticmethod
    def new_plutus_v2():
        ret = wasm.costmodel_new_plutus_v2()
        return CostModel.__wrap(ret)

    def set(self, operation, cost):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(cost, Int)
            wasm.costmodel_set(retptr, self.ptr, operation, cost.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return Int.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def get(self, operation):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.costmodel_get(retptr, self.ptr, operation)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return Int.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret 



# Costmdls
class CostmdlsFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Costmdls:
    def __init__(self, ptr):
        self.ptr = ptr
        CostmdlsFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Costmdls(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        CostmdlsFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_costmdls_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.costmdls_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.costmdls_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]

            if r2:
                raise take_object(r1)
            return Costmdls.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.assets_new()
        return Costmdls.__wrap(ret)
    

    def __len__(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret

    def insert(self, key, value):
        _assertClass(key, Language)
        _assertClass(value, CostModel)
        ret = wasm.costmdls_insert(self.ptr, key.ptr, value.ptr)
        return None if ret == 0 else CostModel.__wrap(ret)

    def get(self, key):
        _assertClass(key, Language)
        ret = wasm.costmdls_get(self.ptr, key.ptr)
        return None if ret == 0 else CostModel.__wrap(ret)

    def keys(self):
        ret = wasm.costmdls_keys(self.ptr)
        return Languages.__wrap(ret)
    
# plutus List
class PlutusListFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class PlutusList:
    def __init__(self, ptr):
        self.ptr = ptr
        PlutusListFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = PlutusList(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PlutusListFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_plutuslist_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutuslist_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.plutuslist_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return PlutusList.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.plutuslist_new()
        return PlutusList.__wrap(ret)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret 

    def get(self, index):
        ret = wasm.plutuslist_get(self.ptr, index)
        return PlutusData.__wrap(ret)

    def add(self, elem):
        _assertClass(elem, PlutusData)
        wasm.plutuslist_add(self.ptr, elem.ptr)


    
# plutus map
class PlutusMapFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class PlutusMap:
    def __init__(self, ptr):
        self.ptr = ptr
        PlutusMapFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = PlutusMap(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PlutusMapFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_plutusmap_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutusmap_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.plutusmap_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return PlutusMap.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.certificates_new()
        return PlutusMap.__wrap(ret)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret 
    def insert(self, key, value):
        _assertClass(key, PlutusData)
        _assertClass(value, PlutusData)
        ret = wasm.plutusmap_insert(self.ptr, key.ptr, value.ptr)
        return None if ret == 0 else PlutusData.__wrap(ret)

    def get(self, key):
        _assertClass(key, PlutusData)
        ret = wasm.plutusmap_get(self.ptr, key.ptr)
        return None if ret == 0 else PlutusData.__wrap(ret)

    def keys(self):
        ret = wasm.plutusmap_keys(self.ptr)
        return PlutusList.__wrap(ret)



# value 
class ValueFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)



class Value:
    def __init__(self, ptr):
        self.ptr = ptr
        ValueFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Value(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ValueFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_value_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.value_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.value_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Value.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.value_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.value_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc)
            len0 = WASM_VECTOR_LEN
            wasm.value_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Value.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    @staticmethod
    def new(coin):
        _assertClass(coin, BigNum)
        ret = wasm.value_new(coin.ptr)
        return Value.__wrap(ret)


    @staticmethod
    def new_from_assets(multiasset):
        _assertClass(multiasset, MultiAsset)
        ret = wasm.value_new_from_assets(multiasset.ptr)
        return Value.__wrap(ret)
    
    @staticmethod
    def zero():
        ret = wasm.value_zero()
        return Value.__wrap(ret)

    def is_zero(self):
        ret = wasm.value_is_zero(self.ptr)
        return ret != 0

    def coin(self):
        ret = wasm.constrplutusdata_alternative(self.ptr)
        return BigNum.__wrap(ret)

    def set_coin(self, coin):
        _assertClass(coin, BigNum)
        wasm.value_set_coin(self.ptr, coin.ptr)

    def multiasset(self):
        ret = wasm.value_multiasset(self.ptr)
        return None if ret == 0 else MultiAsset.__wrap(ret)

    def set_multiasset(self, multiasset):
        _assertClass(multiasset, MultiAsset)
        wasm.value_set_multiasset(self.ptr, multiasset.ptr)

    def checked_add(self, rhs):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(rhs, Value)
            wasm.value_checked_add(retptr, self.ptr, rhs.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Value.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def checked_sub(self, rhs_value):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(rhs_value, Value)
            wasm.value_checked_sub(retptr, self.ptr, rhs_value.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Value.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def clamped_sub(self, rhs_value):
        _assertClass(rhs_value, Value)
        ret = wasm.value_clamped_sub(self.ptr, rhs_value.ptr)
        return Value.__wrap(ret)

    def compare(self, rhs_value):
        _assertClass(rhs_value, Value)
        ret = wasm.value_compare(self.ptr, rhs_value.ptr)
        return None if ret == 0xFFFFFF else ret
    

# TransactionUnspent
class PrivateKeyFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class TakeObjectException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class PrivateKey:
    def __init__(self, ptr=None):
        self.ptr = ptr
    @staticmethod
    def __wrap(cls, ptr):
        obj = cls(ptr)
        PrivateKeyFinalization.register(obj, ptr, obj)
        return obj


    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PrivateKeyFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm_fun.__wbg_privatekey_free(ptr)

    @staticmethod
    def initialize_private_key_from_bytes(bytes):
        try:
            # Allocate memory for the private key
            key_ptr = wasm_fun.wbindgen_malloc(len(bytes))

            # Copy the private key data to the allocated memory
            wasm_fun.copy_to_python_memory(bytes, key_ptr)

            # Set the private_key.ptr attribute with the pointer value
            private_key = PrivateKey()
            private_key.ptr = key_ptr

            return private_key
        except Exception as e:
            # Handle any exceptions that occur during initialization
            print("Error initializing private key from bytes:", e)


    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm_fun.wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm_fun.wbindgen_malloc)
            len0 = len(bytes)
            PrivateKey.initialize_private_key_from_bytes(retptr, ptr0, len0)  # Replace with the correct function name
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]

            if r2:
                raise take_object(r1)
            return PrivateKey.__wrap(r0)
        finally:
            wasm_fun.wbindgen_add_to_stack_pointer(16)
    
    


    

    def to_bech32(self, prefix):
        try:
            retptr = wasm_fun.wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                prefix,
                wasm_fun.wbindgen_malloc,
                wasm_fun.wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.auxiliarydatahash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm_fun.wbindgen_add_to_stack_pointer(16)
            wasm_fun.wbindgen_free(ptr1, len1)

    @staticmethod
    def generate_ed25519():
        try:
            # Allocate memory for the private key
            key_ptr = wasm_fun.wbindgen_malloc(64)
            print("key_ptr in generate_ed25519",key_ptr)

            # Call the privatekey_generate_ed25519() WebAssembly function
            wasm_fun.privatekey_generate_ed25519()

            # Get the private key bytes from the allocated memory
            private_key_bytes = get_int32_memory0()[key_ptr:key_ptr + 64]
            print("private_key_bytes",private_key_bytes)

            # Create a PrivateKey object from the generated bytes
            private_key = PrivateKey.from_bytes(private_key_bytes)
            print("private_keyiiiiiiiiiiiiiii",private_key)


            # Register the PrivateKey object for finalization
            PrivateKeyFinalization.register(private_key)

            print("private key generated:", private_key)
            return private_key
        except Exception as e:
            # Handle the exception
            print("An error occurred:", str(e))
        finally:
            wasm_fun.wbindgen_add_to_stack_pointer(16)





    
# TransactionUnspent
class TransactionUnspentOutputFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class TransactionUnspentOutput:
    def __init__(self, ptr):
        self.ptr = ptr
        TransactionUnspentOutputFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = TransactionUnspentOutput(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionUnspentOutputFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactionunspentoutput_free(ptr)

    @staticmethod
    def new(input, output):
        _assertClass(input, TransactionInput)
        _assertClass(output, TransactionOutput)
        ret = wasm.transactionunspentoutput_new(input.ptr, output.ptr)
        return TransactionUnspentOutput.__wrap(ret)

    
# Transaction hash

class TransactionHashFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class TransactionHash:
    def __init__(self, ptr):
        self.ptr = ptr
        TransactionHashFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = TransactionHash(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionHashFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactionhash_free(ptr)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.transactionhash_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return TransactionHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


# TransactionInput
class TransactionInputFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class TransactionInput:
    def __init__(self, ptr):
        self.ptr = ptr
        TransactionInputFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = TransactionInput(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionInputFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactioninput_free(ptr)


    @staticmethod
    def new(transaction_id, index):
        _assertClass(transaction_id, TransactionHash)
        _assertClass(index, BigNum)
        ret = wasm.transactioninput_new(transaction_id.ptr, index.ptr)
        return TransactionInput.__wrap(ret)






# Script Ref
class ScriptRefFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class ScriptRef:
    @staticmethod
    def __wrap(ptr):
        obj = ScriptRef()
        obj.ptr = ptr
        ScriptRefFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptRefFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scriptref_free(ptr)
    
    @staticmethod
    def new(script):
        _assertClass(script, Script)
        ret = wasm.scriptref_new(script.ptr)
        return ScriptRef.__wrap(ret)

# AssetName
class AssetNameFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class AssetName:
    @staticmethod
    def __wrap(ptr):
        obj = AssetName()
        obj.ptr = ptr
        AssetNameFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        AssetNameFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_assetname_free(ptr)

    @staticmethod
    def new(name):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(name, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.assetname_new(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return AssetName.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)





#  asset
class AssetsFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Assets:
    @staticmethod
    def __wrap(ptr):
        obj = Assets()
        obj.ptr = ptr
        AssetsFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        AssetsFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_assets_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.assets_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.assets_new()
        return Assets.__wrap(ret)


# multi asset
class MultiAssetFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class MultiAsset:
    @staticmethod
    def __wrap(ptr):
        obj = MultiAsset()
        obj.ptr = ptr
        MultiAssetFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        MultiAssetFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_multiasset_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.multiasset_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.assets_new()
        return MultiAsset.__wrap(ret)
    


    # Data hash
class DataHashFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class DataHash:
    def __init__(self, ptr):
        self.ptr = ptr

    @staticmethod
    def __wrap(ptr):
        obj = DataHash(ptr)
        DataHashFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        DataHashFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_datahash_free(ptr)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.datahash_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return DataHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.auxiliarydatahash_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                prefix,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.auxiliarydatahash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)

    @staticmethod
    def from_bech32(bech_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                bech_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.datahash_from_bech32(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return DataHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_hex(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.auxiliarydatahash_to_hex(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)

    @staticmethod
    def from_hex(hex):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                hex,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.datahash_from_hex(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return DataHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)




# Datum 
class DatumFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class Datum:
    @staticmethod
    def __wrap(ptr):
        obj = Datum()
        obj.ptr = ptr
        DatumFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        DatumFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_datum_free(ptr)

    @staticmethod
    def new_data_hash(data_hash):
        _assertClass(data_hash, DataHash)
        ret = wasm.datum_new_data_hash(data_hash.ptr)
        return Datum.__wrap(ret)
    
    @staticmethod
    def new_data(data):
        _assertClass(data, Data)
        ret = wasm.datum_new_data(data.ptr)
        return Datum.__wrap(ret)



class TransactionOutputFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class TransactionOutput:
    def __init__(self, ptr):
        self.ptr = ptr

    @classmethod
    def __wrap(cls, ptr):
        obj = cls(ptr)
        TransactionOutputFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionOutputFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactionoutput_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.transactionoutput_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).slice()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @classmethod
    def from_bytes(cls, bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.transactionoutput_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return cls.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.transactionoutput_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            r3 = get_int32_memory0()[retptr / 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.transactionoutput_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @classmethod
    def from_json(cls, json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc)
            len0 = WASM_VECTOR_LEN
            wasm.transactionoutput_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return cls.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def address(self):
        ret = wasm.transactionoutput_address(self.ptr)
        return Address.__wrap(ret)

    def amount(self):
        ret = wasm.transactionoutput_amount(self.ptr)
        return Value.__wrap(ret)

    def datum(self):
        ret = wasm.transactionoutput_datum(self.ptr)
        return Datum.__wrap(ret) if ret != 0 else None
    
    def script_ref(self):
        ret = wasm.transactionoutput_script_ref(self.ptr)
        return ScriptRef.__wrap(ret) if ret != 0 else None

    def set_datum(self, datum):
        _assertClass(datum, Datum)
        wasm.transactionoutput_set_datum(self.ptr, datum.ptr)

    def set_script_ref(self, script_ref):
        _assertClass(script_ref, ScriptRef)
        wasm.transactionoutput_set_script_ref(self.ptr, script_ref.ptr)

    @classmethod
    def new(cls, address, amount):
        _assertClass(address, Address)
        _assertClass(amount, Value)
        ret = wasm.transactionoutput_new(address.ptr, amount.ptr)
        return cls.__wrap(ret)

    def format(self):
        ret = wasm.transactionoutput_format(self.ptr)
        return ret

    def to_legacy_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.transactionoutput_to_legacy_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).slice()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)



    

    # construPlutus data
class ConstrPlutusDataFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class ConstrPlutusData:
    def __init__(self, ptr):
        self.ptr = ptr
        ConstrPlutusDataFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = ConstrPlutusData(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ConstrPlutusDataFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_constrplutusdata_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.constrplutusdata_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.constrplutusdata_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return ConstrPlutusData.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def alternative(self):
        ret = wasm.constrplutusdata_alternative(self.ptr)
        return BigNum.__wrap(ret)

    def data(self):
        ret = wasm.constrplutusdata_data(self.ptr)
        return PlutusList.__wrap(ret)

    @staticmethod
    def new(alternative, data):
        _assertClass(alternative, BigNum)
        _assertClass(data, PlutusList)
        ret = wasm.constrplutusdata_new(alternative.ptr, data.ptr)
        return ConstrPlutusData.__wrap(ret)

    
# plutus data
class PlutusDataFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class PlutusData:
    def __init__(self, ptr):
        self.ptr = ptr
        PlutusDataFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PlutusDataFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_plutusdata_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutusdata_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.plutusdata_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return PlutusData.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new_constr_plutus_data(constr_plutus_data):
        _assertClass(constr_plutus_data, ConstrPlutusData)
        ret = wasm.plutusdata_new_constr_plutus_data(constr_plutus_data.ptr)
        return PlutusData.__wrap(ret)

    @staticmethod
    def new_map(map):
        _assertClass(map, PlutusMap)
        ret = wasm.plutusdata_new_map(map.ptr)
        return PlutusData.__wrap(ret)

    @staticmethod
    def new_list(list):
        _assertClass(list, PlutusList)
        ret = wasm.plutusdata_new_list(list.ptr)
        return PlutusData.__wrap(ret)

    @staticmethod
    def new_integer(integer):
        _assertClass(integer, int)
        ret = wasm.plutusdata_new_integer(integer.ptr)
        return PlutusData.__wrap(ret)

    @staticmethod
    def new_bytes(bytes):
        ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
        len0 = WASM_VECTOR_LEN
        ret = wasm.plutusdata_new_bytes(ptr0, len0)
        return PlutusData.__wrap(ret)

    def kind(self):
        ret = wasm.plutusdata_kind(self.ptr)
        return ret

    def as_constr_plutus_data(self):
        ret = wasm.plutusdata_as_constr_plutus_data(self.ptr)
        return None if ret == 0 else ConstrPlutusData.__wrap(ret)

    def as_map(self):
        ret = wasm.plutusdata_as_map(self.ptr)
        return None if ret == 0 else PlutusMap.__wrap(ret)

    def as_list(self):
        ret = wasm.plutusdata_as_list(self.ptr)
        return None if ret == 0 else PlutusList.__wrap(ret)

    def as_integer(self):
        ret = wasm.plutusdata_as_integer(self.ptr)
        return None if ret == 0 else ret  # Assuming BigInt.__wrap() is not needed

    def as_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutusdata_as_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = None
            if r0 != 0:
                v0 = getArrayU8FromWasm0(r0, r1)[:]
                wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


# Data
class DataFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class Data:
    def __init__(self, ptr):
        self.ptr = ptr

    @staticmethod
    def __wrap(ptr):
        obj = Data(ptr)
        DataFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        DataFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_data_free(ptr)

    @staticmethod
    def new(plutus_data):
        _assertClass(plutus_data, PlutusData)
        ret = wasm.data_new(plutus_data.ptr)
        return Data.__wrap(ret)


# Transaction builder 


class TransactionBuilderFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)


class TransactionBuilder:
    def __init__(self, lucid):
        self.ptr = wasm.TransactionBuilder_new(lucid.txBuilderConfig)
        TransactionBuilderFinalization.register(self, self.ptr, self)
    
    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionBuilderFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactionbuilder_free(ptr)
    
    def add_inputs_from(self, inputs, change_address, weights):
        _assertClass(inputs, TransactionUnspentOutputs)
        _assertClass(change_address, Address)
        ptr0, len0 = passArray32ToWasm0(weights, wasm.__wbindgen_malloc)
        retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
        wasm.transactionbuilder_add_inputs_from(
            retptr,
            self.ptr,
            inputs.ptr,
            change_address.ptr,
            ptr0,
            len0,
        )
        r0 = get_int32_memory0()[retptr // 4 + 0]
        r1 = get_int32_memory0()[retptr // 4 + 1]
        if r1:
            raise take_object(r0)
    
    def add_input(self, utxo, script_witness):
        _assertClass(utxo, TransactionUnspentOutput)
        ptr0 = 0
        if not isLikeNone(script_witness):
            _assertClass(script_witness, ScriptWitness)
            ptr0 = script_witness.__destroy_into_raw()
        wasm.transactionbuilder_add_input(self.ptr, utxo.ptr, ptr0)
    
    def add_reference_input(self, utxo):
        _assertClass(utxo, TransactionUnspentOutput)
        wasm.transactionbuilder_add_reference_input(self.ptr, utxo.ptr)

    def add_plutus_data(self, plutus_data):
        _assertClass(plutus_data, PlutusData)
        wasm.transactionbuilder_add_plutus_data(self.ptr, plutus_data.ptr)

    def new(cfg):
        assert isinstance(cfg, TransactionBuilderConfig)
        ret = wasm.transactionbuilder_new(cfg.ptr)
        return TransactionBuilder.__wrap(ret)


    



        # add all of function and complete

# TransactionBuilderConfigFinalization

class TransactionBuilderConfigFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class TransactionBuilderConfig:
    @staticmethod
    def __wrap(ptr):
        obj = TransactionBuilderConfig()
        obj.ptr = ptr
        TransactionBuilderConfigFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TransactionBuilderConfigFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_transactionbuilderconfig_free(ptr)


#  Ed25519Signature 
class Ed25519KeyHashesFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)



class Ed25519KeyHashes:
    def __init__(self, ptr):
        self.ptr = ptr
        Ed25519KeyHashesFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        return Ed25519KeyHashes(ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        Ed25519KeyHashesFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_ed25519keyhashes_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhashes_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhashes_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return Ed25519KeyHashes.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhashes_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)


    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhashes_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhashes_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return Ed25519KeyHashes.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.ed25519keyhashes_new()
        return Ed25519KeyHashes.__wrap(ret)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret 

    def get(self, index):
        ret = wasm.ed25519keyhashes_get(self.ptr, index)
        return Ed25519KeyHash.__wrap(ret)

    def add(self, elem):
        _assertClass(elem, Ed25519KeyHash)
        wasm.ed25519keyhashes_add(self.ptr, elem.ptr)


# Public Key

class PublicKeyFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.weakrefs = weakref.WeakValueDictionary()

    def register(self, obj, ptr, key):
        self.weakrefs[key] = (obj, ptr)

    def unregister(self, key):
        del self.weakrefs[key]

    def cleanup(self):
        for obj, ptr in self.weakrefs.values():
            self.callback(ptr)

class PublicKey:
    def __init__(self, ptr):
        self.ptr = ptr
        PublicKeyFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PublicKeyFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_publickey_free(ptr)

    @staticmethod
    def from_bech32(bech32_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                bech32_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.publickey_from_bech32(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return PublicKey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bech32(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.publickey_to_bech32(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)

    def as_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.auxiliarydatahash_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1)[:]

            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.publickey_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]

            if r2:
                raise take_object(r1)

            return PublicKey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def verify(self, data, signature):
        ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc)
        len0 = WASM_VECTOR_LEN
        _assertClass(signature, Ed25519KeyHashes)
        ret = wasm.publickey_verify(self.ptr, ptr0, len0, signature.ptr)
        return ret != 0


    def hash(self):
        ret = wasm.publickey_hash(self.ptr)
        return Ed25519KeyHash.__wrap(ret)



# Bip32

class Bip32PublicKeyFinalization:
    def __init__(self, callback):
        self.callback = callback
        self.registry = weakref.WeakValueDictionary()

    def register(self, obj, ptr):
        self.registry[ptr] = obj

    def unregister(self, obj):
        for key in list(self.registry.keys()):
            if self.registry[key] is obj:
                del self.registry[key]
                break

    def __call__(self):
        for ptr in self.registry.keys():
            self.callback(ptr)

class Bip32PublicKey:
    def __init__(self, ptr):
        self.ptr = ptr
        Bip32PublicKeyFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        Bip32PublicKeyFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_bip32publickey_free(ptr)

    def derive(self, index):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bip32publickey_derive(retptr, self.ptr, index)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return Bip32PublicKey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_raw_key(self):
        ret = wasm.bip32publickey_to_raw_key(self.ptr)
        return PublicKey.__wrap(ret)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.bip32publickey_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return Bip32PublicKey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def as_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bip32publickey_as_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).slice()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bech32(bech32_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(
                bech32_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.bip32publickey_from_bech32(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return Bip32PublicKey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bech32(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bip32publickey_to_bech32(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)

    def chaincode(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bip32publickey_chaincode(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).slice()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)






class FinalizationRegistry:
    def __init__(self, cleanup_func):
        self.cleanup_func = cleanup_func
        self._objects = weakref.WeakSet()

    def register(self, obj, *args):
        self._objects.add(obj)

    def unregister(self, obj):
        self._objects.remove(obj)

    def cleanup(self):
        for obj in self._objects:
            self.cleanup_func(obj)

# Create an instance of the FinalizationRegistry
ByronAddressFinalization = FinalizationRegistry(lambda ptr: wasm.__wbg_byronaddress_free(ptr))


class ByronAddress:
    def __init__(self, ptr):
        self.ptr = ptr
        ByronAddressFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ByronAddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_byronaddress_free(ptr)

    def to_base58(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.byronaddress_to_base58(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.byronaddress_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.byronaddress_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return ByronAddress.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def byron_protocol_magic(self):
        ret = wasm.byronaddress_byron_protocol_magic(self.ptr)
        return ret 

    def attributes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.byronaddress_attributes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def network_id(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.byronaddress_network_id(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return r0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_base58(s):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                s,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.byronaddress_from_base58(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return ByronAddress.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def icarus_from_key(key, protocol_magic):
        _assertClass(key, Bip32PublicKey)
        ret = wasm.byronaddress_icarus_from_key(key.ptr, protocol_magic)
        return ByronAddress.__wrap(ret)

    @staticmethod
    def is_valid(s):
        ptr0 = pass_string_to_wasm0(
            s,
            wasm.__wbindgen_malloc,
            wasm.__wbindgen_realloc,
        )
        len0 = WASM_VECTOR_LEN
        ret = wasm.byronaddress_is_valid(ptr0, len0)
        return ret != 0

    def to_address(self):
        ret = wasm.byronaddress_to_address(self.ptr)
        return Address.__wrap(ret)

    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_byron(addr.ptr)
        return ByronAddress.__wrap(ret)






class ScriptAllFinalization:
    def __init__(self):
        self.registry = weakref.WeakValueDictionary()

    def register(self, ptr, cleanup_func):
        self.registry[ptr] = cleanup_func

    def unregister(self, ptr):
        if ptr in self.refs:
            del self.refs[ptr]

    def cleanup(self):
        for cleanup_func in self.registry.values():
            cleanup_func()

class ScriptAll:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptAllFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = ScriptAll()
        obj.ptr = ptr
        ScriptAllFinalization.register(obj, obj.ptr, obj)
        return obj


    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptAllFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scriptall_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptall_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scriptall_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return ScriptAll.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptall_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptall_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc)
            len0 = WASM_VECTOR_LEN
            wasm.scriptall_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return ScriptAll.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def native_scripts(self):
        ret = wasm.scriptall_native_scripts(self.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new(native_scripts):
        assert isinstance(native_scripts, NativeScript)
        ret = wasm.scriptall_new(native_scripts.ptr)
        return ScriptAll.__wrap(ret)
    

# script any
class ScriptAnyFinalization:
    def __init__(self):
        self.registry = weakref.WeakSet()

    def register(self, obj, ptr):
        self.registry.add((obj, ptr))

    def cleanup(self):
        for obj, ptr in self.registry:
            wasm.__wbg_scriptany_free(ptr)
            obj.ptr = 0


class ScriptAny:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptAnyFinalization.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptAnyFinalization.unregister(self)
        return ptr
    

    @staticmethod
    def __wrap(ptr):
        obj = ScriptAny()
        obj.ptr = ptr
        ScriptAnyFinalization.register(obj, obj.ptr, obj)
        return obj

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scriptany_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptany_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1)[:r1]
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scriptany_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptAny.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptall_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptall_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.scriptany_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptAny.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def native_scripts(self):
        ret = wasm.scriptall_native_scripts(self.ptr)
        return NativeScript.__wrap(ret)


    @staticmethod
    def new(native_scripts):
        _assertClass(native_scripts, NativeScript)
        ret = wasm.scriptall_new(native_scripts.ptr)
        return ScriptAny.__wrap(ret)


  










class ScriptPubkeyFinalization:
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


class ScriptPubkey:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptPubkeyFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = NativeScript()
        obj.ptr = ptr
        ScriptPubkeyFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptPubkeyFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scriptpubkey_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptpubkey_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scriptpubkey_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptPubkey.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptpubkey_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptpubkey_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        ptr0 = pass_string_to_wasm0(json)
        len0 = len(json)
        retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
        wasm.scriptpubkey_from_json(retptr, ptr0, len0)
        r0 = get_int32_memory0()[retptr // 4 + 0]
        r1 = get_int32_memory0()[retptr // 4 + 1]
        r2 = get_int32_memory0()[retptr // 4 + 2]
        if r2:
            raise take_object(r1)
        return ScriptPubkey.__wrap(r0)
    
    def addr_keyhash(self):
        ret = wasm.genesiskeydelegation_genesishash(self.ptr)
        return Ed25519KeyHash.__wrap(ret)

    @staticmethod
    def new(addr_keyhash):
        assert isinstance(addr_keyhash, Ed25519KeyHash)
        ret = wasm.scriptpubkey_new(addr_keyhash.ptr)
        return ScriptPubkey.__wrap(ret)
    
class ScriptNOfKFinalization:
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


class ScriptNOfK:
    def __init__(self, ptr):
        self.ptr = ptr
        self.finalization_registry = ScriptNOfKFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptNOfKFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scriptnofk_free(ptr)

    @staticmethod
    def __wrap(ptr):
        obj = ScriptNOfK()
        obj.ptr = ptr
        ScriptNOfKFinalization.register(obj, obj.ptr, obj)
        return obj

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptnofk_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scriptnofk_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptNOfK.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptnofk_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.scriptnofk_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.scriptnofk_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return ScriptNOfK.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    # def n(self):
    #     ret = wasm.networkinfo_protocol_magic(self.ptr)
    #     return ret >>> 0

    def native_scripts(self):
        ret = wasm.scriptnofk_native_scripts(self.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new(n, native_scripts):
        _assertClass(native_scripts, NativeScript)
        ret = wasm.scriptnofk_new(n, native_scripts.ptr)
        return ScriptNOfK.__wrap(ret)
    


class BignumFinalization:
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


class BigNum:
    def __init__(self, ptr):
        self.ptr = ptr
        BignumFinalization.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        BignumFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_bignum_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bignum_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.bignum_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_str(string):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                string,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.bignum_from_str(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def to_str(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.bignum_to_str(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            return get_string_from_wasm0(r0, r1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(r0, r1)
    
    @staticmethod
    def zero():
        ret = wasm.bignum_zero()
        return BigNum.__wrap(ret)
    
    def is_zero(self):
        ret = wasm.bignum_is_zero(self.ptr)
        return ret != 0
    
    def checked_mul(self, other):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(other, BigNum)
            wasm.bignum_checked_mul(retptr, self.ptr, other.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def checked_add(self, other):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(other, BigNum)
            wasm.bignum_checked_add(retptr, self.ptr, other.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def checked_sub(self, other):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(other, BigNum)
            wasm.bignum_checked_sub(retptr, self.ptr, other.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def checked_div(self, other):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(other, BigNum)
            wasm.bignum_checked_div(retptr, self.ptr, other.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def checked_div_ceil(self, other):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            _assertClass(other, BigNum)
            wasm.bignum_checked_div_ceil(retptr, self.ptr, other.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return BigNum.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def clamped_sub(self, other):
        _assertClass(other, BigNum)
        ret = wasm.bignum_clamped_sub(self.ptr, other.ptr)
        return BigNum.__wrap(ret)
    
    def compare(self, rhs_value):
        _assertClass(rhs_value, BigNum)
        ret = wasm.bignum_compare(self.ptr, rhs_value.ptr)
        return ret
    


    # time lock end 
class TimelockExpiryFinalization:
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


class TimelockExpiry:
    def __init__(self, ptr):
        self.ptr = ptr
        TimelockExpiryFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TimelockExpiryFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_timelockexpiry_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockexpiry_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.timelockexpiry_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return TimelockExpiry.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockexpiry_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockexpiry_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.timelockexpiry_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return TimelockExpiry.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def slot(self):
        ret = wasm.constrplutusdata_alternative(self.ptr)
        return BigNum.__wrap(ret)

    @staticmethod
    def new(slot):
        _assertClass(slot, BigNum)
        ret = wasm.constrplutusdata_alternative(slot.ptr)
        return TimelockExpiry.__wrap(ret)


    


# tacke start time

class TimelockStartFinalization:
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


class TimelockStart:
    def __init__(self, ptr):
        self.ptr = ptr
        TimelockStartFinalization.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        TimelockStartFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_timelockstart_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockstart_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.timelockstart_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return TimelockStart.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockexpiry_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)


    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.timelockexpiry_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.timelockstart_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return TimelockStart.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def slot(self):
        ret = wasm.constrplutusdata_alternative(self.ptr)
        return BigNum.__wrap(ret)

    @staticmethod
    def new(slot):
        _assertClass(slot, BigNum)
        ret = wasm.constrplutusdata_alternative(slot.ptr)
        return TimelockStart.__wrap(ret)










# NativeScriptFinalization
class NativeScriptFinalization:
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


class NativeScript:
    @staticmethod
    def __wrap(ptr):
        obj = NativeScript()
        obj.ptr = ptr
        NativeScriptFinalization.register(obj, obj.ptr, obj)
        return obj
    
    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        NativeScriptFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_nativescript_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.nativescript_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.nativescript_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return NativeScript(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.nativescript_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            r3 = get_int32_memory0()[int(retptr / 4) + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.nativescript_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_json(json):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                json,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.nativescript_from_json(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return NativeScript.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def hash(self, namespace):
        ret = wasm.nativescript_hash(self.ptr, namespace)
        return ScriptHash.__wrap(ret)

    @staticmethod
    def new_script_pubkey(script_pubkey):
        _assertClass(script_pubkey, ScriptPubkey)
        ret = wasm.nativescript_new_script_pubkey(script_pubkey.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new_script_all(script_all):
        _assertClass(script_all, ScriptAll)
        ret = wasm.nativescript_new_script_all(script_all.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new_script_any(script_any):
        _assertClass(script_any, ScriptAny)
        ret = wasm.nativescript_new_script_any(script_any.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new_script_n_of_k(script_n_of_k):
        _assertClass(script_n_of_k, ScriptNOfK)
        ret = wasm.nativescript_new_script_n_of_k(script_n_of_k.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new_timelock_start(timelock_start):
        _assertClass(timelock_start, TimelockStart)
        ret = wasm.nativescript_new_timelock_start(timelock_start.ptr)
        return NativeScript.__wrap(ret)

    @staticmethod
    def new_timelock_expiry(timelock_expiry):
        _assertClass(timelock_expiry, TimelockExpiry)
        ret = wasm.nativescript_new_timelock_expiry(timelock_expiry.ptr)
        return NativeScript.__wrap(ret)

    def kind(self):
        ret = wasm.nativescript_kind(self.ptr)
        return ret

    def as_script_pubkey(self):
        ret = wasm.nativescript_as_script_pubkey(self.ptr)
        return None if ret == 0 else ScriptPubkey.__wrap(ret)

    def as_script_all(self):
        ret = wasm.nativescript_as_script_all(self.ptr)
        return None if ret == 0 else ScriptAll.__wrap(ret)

    def as_script_any(self):
        ret = wasm.nativescript_as_script_any(self.ptr)
        return None if ret == 0 else ScriptAny.__wrap(ret)

    def as_script_n_of_k(self):
        ret = wasm.nativescript_as_script_n_of_k(self.ptr)
        return None if ret == 0 else ScriptNOfK.__wrap(ret)

    def as_timelock_start(self):
        ret = wasm.nativescript_as_timelock_start(self.ptr)
        return None if ret == 0 else TimelockStart.__wrap(ret)



ScriptHashNamespace = {
    "NativeScript": 0,
    0: "NativeScript",
    "PlutusV1": 1,
    1: "PlutusV1",
    "PlutusV2": 2,
    2: "PlutusV2"
}
ScriptHashNamespace = dict(ScriptHashNamespace)  # Optional: Convert to regular dictionary and freeze



# Script 
class ScriptFinalization:
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

class Script:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptFinalization.register(self, self.ptr, self)

    @staticmethod
    def __wrap(ptr):
        obj = Script(ptr)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_script_free(ptr)


    @staticmethod
    def new_plutus_v1(plutus_script):
        _assertClass(plutus_script, PlutusScript)
        ret = wasm.script_new_plutus_v1(plutus_script.ptr)
        return Script.__wrap(ret)

    @staticmethod
    def new_plutus_v2(plutus_script):
        _assertClass(plutus_script, PlutusScript)
        ret = wasm.script_new_plutus_v2(plutus_script.ptr)
        return Script.__wrap(ret)
    
    @staticmethod
    def new_native(native_script):
        _assertClass(native_script, NativeScript)
        ret = wasm.script_new_native(native_script.ptr)
        return Script.__wrap(ret)

# plutus script 

class PlutusScriptFinalization:
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


class PlutusScript:
    @staticmethod
    def __wrap(ptr):
        obj = PlutusScript()
        obj.ptr = ptr
        PlutusScriptFinalization.register(obj, obj.ptr, obj)
        return obj

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PlutusScriptFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_plutusscript_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutusscript_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.plutusscript_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return PlutusScript.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def hash(self, namespace):
        ret = wasm.plutusscript_hash(self.ptr, namespace)
        return ScriptHash.__wrap(ret)

    @staticmethod
    def new(bytes):
        ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
        len0 = WASM_VECTOR_LEN
        ret = wasm.plutusscript_new(ptr0, len0)
        return PlutusScript.__wrap(ret)

    def bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.assetname_name(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)



class PlutusScriptsFinalization:
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

class PlutusScripts:
    def __init__(self, ptr):
        self.ptr = ptr
        PlutusScriptsFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PlutusScriptsFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_plutusscripts_free(ptr)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.plutusscripts_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.plutusscripts_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr / 4 + 0]
            r1 = get_int32_memory0()[retptr / 4 + 1]
            r2 = get_int32_memory0()[retptr / 4 + 2]
            if r2:
                raise take_object(r1)
            return PlutusScripts.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def new():
        ret = wasm.assetnames_new()
        return PlutusScripts.__wrap(ret)

    def len(self):
        ret = wasm.assetnames_len(self.ptr)
        return ret 

    def get(self, index):
        ret = wasm.plutusscripts_get(self.ptr, index)
        return PlutusScript.__wrap(ret)

    def add(self, elem):
        _assertClass(elem, PlutusScript)
        wasm.assetnames_add(self.ptr, elem.ptr)





class PointerFinalization:
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

class Pointer:
    def __init__(self, ptr):
        self.ptr = ptr
        PointerFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PointerFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_pointer_free(ptr)

    @staticmethod
    def new(slot, tx_index, cert_index):
        _assertClass(slot, BigNum)
        _assertClass(tx_index, BigNum)
        _assertClass(cert_index, BigNum)
        ret = wasm.pointer_new(slot.ptr, tx_index.ptr, cert_index.ptr)
        return Pointer.__wrap(ret)

    def slot(self):
        ret = wasm.constrplutusdata_alternative(self.ptr)
        return BigNum.__wrap(ret)

    def tx_index(self):
        ret = wasm.exunits_steps(self.ptr)
        return BigNum.__wrap(ret)

    def cert_index(self):
        ret = wasm.pointer_cert_index(self.ptr)
        return BigNum.__wrap(ret)




# Pointer Address

class PointerAddressFinalization:
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


class PointerAddress:
    def __init__(self, ptr):
        self.ptr = ptr
        PointerAddressFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        PointerAddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_pointeraddress_free(ptr)

    @staticmethod
    def new(network, payment, stake):
        _assertClass(payment, StakeCredential)
        _assertClass(stake, Pointer)
        ret = wasm.pointeraddress_new(network, payment.ptr, stake.ptr)
        return PointerAddress.__wrap(ret)

    def payment_cred(self):
        ret = wasm.pointeraddress_payment_cred(self.ptr)
        return StakeCredential.__wrap(ret)

    def stake_pointer(self):
        ret = wasm.pointeraddress_stake_pointer(self.ptr)
        return Pointer.__wrap(ret)

    def to_address(self):
        ret = wasm.pointeraddress_to_address(self.ptr)
        return Address.__wrap(ret)

    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_pointer(addr.ptr)
        return None if ret == 0 else PointerAddress.__wrap(ret)


