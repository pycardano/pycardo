
import os
from cardano_ext.module.utlis .utils import generate_private_key
from cardano_ext.module.lucid.lucid import Lucid
lucid = Lucid.new(None, "Preview")

private_key = generate_private_key()

with open("generatePrivateKey-1.sk", "w") as file:
    file.write(private_key)
