from nacl.public import PrivateKey
import ctypes
import numpy as np


class wasm_fun:
    memory = bytearray()  # The memory buffer to store allocated memory
    memory_offset = 0 

    stack_pointer = 0  # Initial stack pointer value

    import ctypes

    def copy_to_python_memory(source, dest, dest_start):
        # Create a new memory buffer
        new_memory_buffer = bytearray(len(source))
        print("new_memory_buffer---",new_memory_buffer)

        # Copy the data from the source buffer to the new memory buffer
        for i in range(len(source)):
            new_memory_buffer[i] = source[i]

        # Return the pointer to the new memory buffer
        return new_memory_buffer






    def privatekey_generate_ed25519():
        # Generate a new Ed25519 private key
        private_key = PrivateKey.generate()
        print("private key generated in wasm file", private_key)

        # Encode the private key to bytes
        private_key_bytes = private_key.encode()

        # Copy the private key data to a Python memory buffer
        memory_buffer = bytearray(len(private_key_bytes))
        wasm_fun.copy_to_python_memory(private_key_bytes, memory_buffer, 0)
        print("the funcal of ",memory_buffer)
        # Create a new memory buffer
        new_memory_buffer = bytearray(len(private_key_bytes))

        # Copy the data from the old memory buffer to the new memory buffer
        for i in range(len(private_key_bytes)):
            new_memory_buffer[i] = memory_buffer[i]

        # Return the pointer to the new memory buffer
        return new_memory_buffer



    

    @staticmethod
    def wbindgen_global_argument_ptr(new_value=None):
        global stack_pointer

        if new_value is not None:
            # Update the stack pointer with the new value
            stack_pointer = new_value
            print("stack_pointer",stack_pointer)
        # Return the current stack pointer value
            return stack_pointer

    @staticmethod
    def wbindgen_add_to_stack_pointer(value):
        # Retrieve the current stack pointer
        stack_pointer = wasm_fun.wbindgen_global_argument_ptr()

        if stack_pointer is None:
            stack_pointer = 0

        # Add the given value to the stack pointer
        new_stack_pointer = stack_pointer + value

        # Update the stack pointer
        wasm_fun.wbindgen_global_argument_ptr(new_stack_pointer)
        print("new_stack_pointer",new_stack_pointer)
        # Return   the new stack pointer value
        return new_stack_pointer
    

    def wbindgen_malloc(size):
        if size <= 0:
            return 0 
        if wasm_fun.memory_offset + size > len(wasm_fun.memory):
        # If not, expand the memory buffer by doubling its size
            new_size = max(wasm_fun.memory_offset + size, 2 * len(wasm_fun.memory))
            wasm_fun.memory += bytearray(new_size - len(wasm_fun.memory))

        # Allocate memory at the current offset
        ptr = wasm_fun.memory_offset
        wasm_fun.memory_offset += size
        print("ptr",ptr)
        return ptr
    
    def wbindgen_realloc(ptr, size):
        if size <= 0:
            return 0  # Return null pointer for zero-sized reallocations

        
        if ptr == wasm_fun.memory_offset:
            wasm_fun.memory_offset += size
            print("ptr",ptr)

            return ptr

        # Otherwise, perform a new allocation and copy the existing data to the new location
        new_ptr = wasm_fun.wbindgen_malloc(size)
        if ptr != 0:
            # Copy the existing data to the new location
            wasm_fun.memory[new_ptr:new_ptr+size] = wasm_fun.memory[ptr:ptr+size]
        print("ptr",ptr)

        return new_ptr
    

    def wbindgen_free(ptr, length):
        libc = ctypes.CDLL("libc.so.6")  # Assuming a Unix-like system
        libc.free(ptr)


    def wbindgen_export_buffer(key_ptr):
        # Store the pointer to the memory buffer in a global variable
        global exported_buffer_ptr
        exported_buffer_ptr = key_ptr

        # Return the pointer to the exported buffer
        return exported_buffer_ptr
    
    
    

    