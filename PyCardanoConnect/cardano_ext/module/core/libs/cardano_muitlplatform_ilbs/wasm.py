import wasmtime

# Create an engine
engine = wasmtime.Engine()

# Create a store
store = wasmtime.Store(engine)

# Load the Wasm file
module = wasmtime.Module.from_file(engine, '/home/quotus/Cardano_Python_Ex/PyCardanoConnect/cardano_ext/module/core/libs/cardano_muitlplatform_ilbs/cardano_multiplatform_lib_bg.wasm')
imports_module = wasmtime.Module(engine)

imports["__wbindgen_closure_wrapper5962"] = __wbindgen_closure_wrapper5962


for import_func in imports:
    imports_module.append_import(import_func)
# Instantiate the module
instance = wasmtime.Instance(store, module, imports_module)
exports = instance.exports

exports.constrplutusdata_alternative()

