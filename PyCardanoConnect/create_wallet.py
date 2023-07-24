
import os
import asyncio

from cardano_ext.module.utlis .utils import generate_private_key
from cardano_ext.module.lucid.lucid import Lucid
async def some_function():
    lucid = await Lucid.new(None, "Preview")
    # Rest of your code that uses the `lucid` object

# Call the async function
asyncio.run(some_function())

private_key = generate_private_key()

data_string = ''.join(['{:02x}'.format(byte) for byte in private_key])
print("=================================================final private key",data_string)

with open("generatePrivateKey-1.sk", "w") as file:
    file.write(data_string)

# # Select the wallet and derive the address
address = Lucid.selectWalletFromPrivateKey(data_string)

# Write the address to a file
with open("generate wallet-1.sk", "w") as file:
    file.write(address)
