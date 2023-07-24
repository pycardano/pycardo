import binascii
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def from_hex(hex_str):
    return bytes.fromhex(hex_str)

def to_hex(byte_str):
    return binascii.hexlify(byte_str).decode()

def sign_data(address_hex, payload, private_key):
    protected_headers = {}
    protected_headers["alg"] = "EdDSA"
    protected_headers["address"] = from_hex(address_hex)

    unprotected_headers = {}

    to_sign = b'0x16' + b'010001' + protected_headers["address"] + from_hex(payload)
    private_key_obj = Ed25519PrivateKey.from_private_bytes(from_hex(private_key))
    signature = private_key_obj.sign(to_sign)

    return {
        "signature": to_hex(signature),
        "key": to_hex(private_key_obj.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    }

def verify_data(address_hex, key_hash, payload, signed_message):
    signature = from_hex(signed_message["signature"])
    public_key_bytes = from_hex(signed_message["key"])

    public_key_obj = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    protected_headers = {
        "alg": "EdDSA",
        "address": from_hex(address_hex)
    }

    to_verify = b'0x16' + b'010001' + protected_headers["address"] + from_hex(payload)

    try:
        public_key_obj.verify(signature, to_verify)
        return True
    except Exception:
        return False
