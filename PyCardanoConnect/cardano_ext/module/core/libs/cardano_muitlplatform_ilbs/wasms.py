from nacl.public import PrivateKey

class wasm_fun:
    stack_pointer = 0  # Initial stack pointer value

    @staticmethod
    def privatekey_generate_ed25519():
        # Generate a new Ed25519 private key
        private_key = PrivateKey.generate()

        # Return the private key as a bytes object
        return private_key.encode()
    

    @staticmethod
    def wbindgen_global_argument_ptr(new_value=None):
        global stack_pointer

        if new_value is not None:
            # Update the stack pointer with the new value
            stack_pointer = new_value

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

        # Return the new stack pointer value
        return new_stack_pointer
