from typing import Optional


class Utils:
    def __init__(self, lucid):
        self.lucid = lucid

    def validatorToAddress(
        self, validator, stakeCredential: Optional[str] = None
    ):
        validatorHash = self.validatorToScriptHash(validator)
        if stakeCredential:
            return C.BaseAddress.new(
                networkToId(self.lucid.network),
                C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validatorHash)),
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
                networkToId(self.lucid.network),
                C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validatorHash)),
            ).to_address().to_bech32(None)

    def credentialToAddress(
        self, paymentCredential, stakeCredential: Optional[str] = None
    ):
        if stakeCredential:
            return C.BaseAddress.new(
                networkToId(self.lucid.network),
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
                networkToId(self.lucid.network),
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
        return C.RewardAddress.new(
            networkToId(self.lucid.network),
            C.StakeCredential.from_scripthash(C.ScriptHash.from_hex(validatorHash)),
        ).to_address().to_bech32(None)

    def credentialToRewardAddress(self, stakeCredential):
        return C.RewardAddress.new(
            networkToId(self.lucid.network),
            C.StakeCredential.from_keyhash(
                C.Ed25519KeyHash.from_hex(stakeCredential.hash)
            )
            if stakeCredential.type == "Key"
            else C.StakeCredential.from_scripthash(
                C.ScriptHash.from_hex(stakeCredential.hash)
            ),
        ).to_address().to_bech32(None)

    def validatorToScriptHash(self, validator):
        if validator.type == "Native":
            return C.NativeScript.from_bytes(fromHex(validator.script)).hash(
                C.ScriptHashNamespace.NativeScript
            ).to_hex()
        elif validator.type == "PlutusV1":
            return C.PlutusScript.from_bytes(
                fromHex(applyDoubleCborEncoding(validator.script))
            ).hash(C
