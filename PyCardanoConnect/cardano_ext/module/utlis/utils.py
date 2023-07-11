
from typing import Optional
import binascii
from ..core import C
from ..core.libs.cardano_muitlplatform_ilbs.wasms import wasm_fun








class Utils:
    def __init__(self,lucid):
        self.lucid = lucid

    def validator_to_address(self, validator, stake_credential=None):
        validator_hash = self.validator_to_scriptHash(validator)

        if stake_credential:
            return C.BaseAddress.new(self.lucid.network,
                    C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validator_hash)),
                    C.StakeCredential.from_keyhash(
                    C.Ed25519KeyHash.from_hex(stake_credential.hash)
                                    )
                    if stake_credential.type == "Key"
                    else C.StakeCredential.from_scripthash(
                    C.ScriptHash.from_hex(stake_credential.hash)
                                    ),

                    ).to_address().to_bech32(None)
        else:
            return C.EnterpriseAddress.new(
                self.lucid.network,  # Replace with appropriate network ID
                C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validator_hash)),
            ).to_address().to_bech32(None)
        
    def credential_to_address(self, paymentCredential, stakeCredential: Optional[str] = None):
        if stakeCredential:
            return C.BaseAddress.new(
                self.lucid.network, # Replace with appropriate network ID
                C.StakeCredential.from_keyhash(
                C.Ed25519KeyHash.from_hex(paymentCredential.hash)
                )
                if paymentCredential.type == "Key"
                else C.StakeCredential.from_scripthash(
                    C.ScriptHash.from_hex(paymentCredential.hash)
                ),
                C.StakeCredential.from_keyhash(
                C.Ed25519KeyHash.from_hex(stakeCredential.hash)
                )
                if stakeCredential.type == "Key"
                else C.StakeCredential.from_scripthash(
                C.ScriptHash.from_hex(stakeCredential.hash)
                ),
            ).to_address().to_bech32(None)
        else:
            return C.EnterpriseAddress.new(
                self.lucid.network,  # Replace with appropriate network ID
                C.StakeCredential.from_keyhash(
                    C.Ed25519KeyHash.from_hex(paymentCredential.hash)
                )
                if paymentCredential.type == "Key"
                else C.StakeCredential.from_scripthash(
                    C.ScriptHash.from_hex(paymentCredential.hash)
                ),
            ).to_address().to_bech32(None)
        
    
    def validatorToRewardAddress(self, validator):
        validatorHash = self.validatorToScriptHash(validator)
        return C.RewardAddresses.new(
            self.lucid.network,  # Replace with appropriate network ID
            C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validatorHash)),
        ).to_address().to_bech32(None)
    
    def credentialToRewardAddress(self, stakeCredential):
        return C.RewardAddresses.new(
            self.lucid.network,  # Replace with appropriate network ID
            C.StakeCredential.from_keyhash(
                C.Ed25519KeyHash.from_hex(stakeCredential.hash)
            )
            if stakeCredential.type == "Key"
            else C.StakeCredential.from_scripthash(
                C.ScriptHash.from_hex(stakeCredential.hash)
            ),
        ).to_address().to_bech32(None)
    
    
    
    def validatorToScriptHash(self, validator):
        if validator["type"] == "Native":
            return C.NativeScript.from_bytes(fromHex(validator["script"])).hash(
                C.ScriptHashNamespace.NativeScript
            ).toHex()
        elif validator["type"] == "PlutusV1":
            return C.PlutusScript.from_bytes(
                fromHex(apply_double_cbor_encoding(validator["script"]))
            ).hash(C.ScriptHashNamespace.PlutusV1).toHex()
        elif validator["type"] == "PlutusV2":
            return C.PlutusScript.from_bytes(
                fromHex(apply_double_cbor_encoding(validator["script"]))
            ).hash(C.ScriptHashNamespace.PlutusV2).toHex()
        else:
            raise Exception("No variant matched")
                                     
                                     







def fromHex(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)

def toHex(byte_array: bytes) -> str:
    return binascii.hexlify(byte_array).decode('utf-8')

# Address from Hex
def addressFromHexOrBech32(address: str) -> C.Address:
    try:
        return C.Address.from_bytes(fromHex(address))
    except:
        try:
            return C.Address.from_bech32(address)
        except:
            raise Exception("Could not deserialize address.")
        
def apply_double_cbor_encoding(script):
    try:
        cbor_script = C.PlutusScript.from_bytes(
            C.PlutusScript.from_bytes(fromHex(script)).bytes()
        )
        return script
    except Exception:
        return toHex(C.PlutusScript.new(toHex(script)).to_bytes())





# address can be in Bech32 or Hex 

class Credential:

    def __init__(self,type:str, hash:str):
        self.type = type
        self.hash = hash

class Address_details:
    def __init__(self, type: str, networkId: int, address: dict, paymentCredential: Credential, stakeCredential: Credential):
        self.type = type
        self.networkId = networkId
        self.address = address
        self.paymentCredential = paymentCredential
        self.stakeCredential = stakeCredential

def getAddressDetails(address: str) -> Optional[Address_details]:
    # BaseAddress
    try:
        parsedAddress = C.BaseAddress.from_address(addressFromHexOrBech32(address))
        payment_cred_kind = parsedAddress.payment_cred().kind()
        paymentCredential = Credential("Key", toHex(parsedAddress.payment_cred().to_keyhash().to_bytes())) if payment_cred_kind == 0 else Credential("Script", toHex(parsedAddress.payment_cred().to_scripthash().to_bytes()))
        stake_cred_kind = parsedAddress.stake_cred().kind()
        stakeCredential = Credential("Key", toHex(parsedAddress.stake_cred().to_keyhash().to_bytes())) if stake_cred_kind == 0 else Credential("Script", toHex(parsedAddress.stake_cred().to_scripthash().to_bytes()))
        return Address_details(
            "Base",
            parsedAddress.to_address().network_id(),
            {
                "bech32": parsedAddress.to_address().to_bech32(None),
                "hex": toHex(parsedAddress.to_address().to_bytes())
            },
            paymentCredential,
            stakeCredential
        )
    except:
        pass

# EnterpriseAddress 
    try:
        parsedAddress = C.EnterpriseAddress.from_address(addressFromHexOrBech32(address))
        
        payment_cred = parsedAddress.payment_cred()
        paymentCredential = None
        if payment_cred.kind() == 0:
            paymentCredential = Credential(
                credential_type="Key",
                hash=toHex(payment_cred.to_keyhash().to_bytes())
            )
        else:
            paymentCredential = Credential(
                credential_type="Script",
                hash=toHex(payment_cred.to_scripthash().to_bytes())
            )
        
        return {
            "type": "Enterprise",
            "networkId": parsedAddress.to_address().network_id(),
            "address": {
                "bech32": parsedAddress.to_address().to_bech32(None),
                "hex": toHex(parsedAddress.to_address().to_bytes())
            },
            "paymentCredential": paymentCredential
        }
    
    except Exception as _e:
        pass

# PointerAddress 
    try:
        parsed_address = C.PointerAddress.from_address(addressFromHexOrBech32(address))
        payment_cred = parsed_address.payment_cred()
        if payment_cred.kind() == 0:
            payment_credential = {
                "type": "Key",
                "hash": toHex(payment_cred.to_keyhash().to_bytes())
            }
        else:
            payment_credential = {
                "type": "Script",
                "hash": toHex(payment_cred.to_scripthash().to_bytes())
            }
        return {
            "type": "Pointer",
            "networkId": parsed_address.to_address().network_id(),
            "address": {
                "bech32": parsed_address.to_address().to_bech32(),
                "hex": toHex(parsed_address.to_address().to_bytes())
            },
            "paymentCredential": payment_credential
        }
    except:
        pass


    #  Reward Address 
    try:
        parsed_address = C.RewardAddress.from_address(addressFromHexOrBech32(address))
        payment_cred = parsed_address.payment_cred()
        if payment_cred.kind() == 0:
            stake_credential = {
                "type": "Key",
                "hash": toHex(payment_cred.to_keyhash().to_bytes())
            }
        else:
            stake_credential = {
                "type": "Script",
                "hash": toHex(payment_cred.to_scripthash().to_bytes())
            }
        return {
            "type": "Reward",
            "networkId": parsed_address.to_address().network_id(),
            "address": {
                "bech32": parsed_address.to_address().to_bech32(),
                "hex": toHex(parsed_address.to_address().to_bytes())
            },
            "stakeCredential": stake_credential
        }
    except:
        pass

    #  Limited support for Byron Address

    try:
        def parsed_address(address):
            try:
                return C.ByronAddress.from_bytes(fromHex(address))
            except Exception as _e:
                try:
                    return C.ByronAddress.from_base58(address)
                except Exception as Error:
                    raise Error("Could not deserialize address.")

        parsedAddress = parsed_address(address)

        return {
            "type": "Byron",
            "networkId": parsedAddress.network_id(),
            "address": {
                "bech32": "",
                "hex": toHex(parsedAddress.to_address().to_bytes()),
            },
        }
    except Exception as Error:
        pass

    raise Error("No address type matched for: " + address)



def assets_to_value(assets):
    multi_asset = C.MultiAsset.new()
    lovelace = assets.get("lovelace")
    units = list(assets.keys())
    policies = list(set([unit[:56] for unit in units if unit != "lovelace"]))
    
    for policy in policies:
        policy_units = [unit for unit in units if unit[:56] == policy]
        assets_value = C.Assets.new()
        
        for unit in policy_units:
            assets_value.insert(
                C.AssetName.new(fromHex(unit[56:])),
                C.BigNum.from_str(str(assets[unit])),
            )
        
        multi_asset.insert(C.ScriptHash.from_bytes(fromHex(policy)), assets_value)
    
    value = C.Value.new(C.BigNum.from_str(str(lovelace) if lovelace else "0"))
    
    if len(units) > 1 or not lovelace:
        value.set_multiasset(multi_asset)
    
    return value

def to_script_ref(script):
    if script["type"] == "Native":
        return C.ScriptRef.new(
            C.Script.new_native(C.NativeScript.from_bytes(fromHex(script["script"])))
        )
    elif script["type"] == "PlutusV1":
        return C.ScriptRef.new(
            C.Script.new_plutus_v1(
                C.PlutusScript.from_bytes(fromHex(apply_double_cbor_encoding(script["script"])))
            )
        )
    elif script["type"] == "PlutusV2":
        return C.ScriptRef.new(
            C.Script.new_plutus_v2(
                C.PlutusScript.from_bytes(fromHex(apply_double_cbor_encoding(script["script"])))
            )
        )
    else:
        raise Exception("No variant matched.")




def utxoToCore(utxo):
    address = None

    try:
        address = C.Address.from_bech32(utxo['address'])
    except:
        address = C.ByronAddress.from_base58(utxo['address']).to_address()

    output = C.TransactionOutput.new(address, assets_to_value(utxo['assets']))

    if utxo['datumHash']:
        output.set_datum(
            C.Datum.new_data_hash(C.DataHash.from_bytes(fromHex(utxo['datumHash'])))
        )
    elif utxo['datum']:
        output.set_datum(
            C.Datum.new_data(C.Data.new(C.PlutusData.from_bytes(fromHex(utxo['datum']))))
        )

    if utxo['scriptRef']:
        output.set_script_ref(to_script_ref(utxo['scriptRef']))

    txInput = C.TransactionInput.new(
        C.TransactionHash.from_bytes(fromHex(utxo['txHash'])),
        C.BigNum.from_str(str(utxo['outputIndex'])),
    )

    return C.TransactionUnspentOutput.new(txInput, output)



def generate_private_key():
    private_key = None

    try:
        # Generate a new private key
        private_key = C.PrivateKey.generate_ed25519()

    except Exception as e:
        # Handle the exception
        print("An error occurred:", str(e))

    # Return the private key
    return private_key



