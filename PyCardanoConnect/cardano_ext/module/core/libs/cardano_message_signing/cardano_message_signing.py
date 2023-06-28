
import codecs
import memoryview
import numpy as np
import json
import traceback
import re


wasm = None


cached_text_decoder = codecs.getincrementaldecoder("utf-8")(errors='strict', byteorder='big')

decoded_data = cached_text_decoder.decode()

cached_unit_memory0 = None



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
    global cached_int32_memory0
    if cached_int32_memory0 is None or cached_int32_memory0.nbytes == 0:
        cached_int32_memory0 = np.array(wasm.memory.buffer, dtype=np.int32)
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







