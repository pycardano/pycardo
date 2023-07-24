from ..core.mod import C
from typing import Optional
from ..provider.emulator import Emulator
from ..plutus.time import SLOT_CONFIG_NETWORK
from ..utlis.cost_model import create_cost_models
from ..utlis.utils import Utils
from ..utlis.utils import payment_credential_of,utxoToCore

from ..type.type import UTxO ,Provider
from ..plutus.data import Data
# from .lucid import Tx
from cryptography.hazmat.primitives import serialization
import hashlib
from ..misc.sign_data import sign_data


class UTxO:
    def __init__(self, tx_hash, index, amount):
        self.tx_hash = tx_hash
        self.index = index
        self.amount = amount



class Lucid:
    def __init__(self):
        self.txBuilderConfig = None
        self.wallet = None
        self.provider = None
        self.network = "Mainnet"
        self.utils = None
        self.pub_key_hash = None

    # ... (Other methods, constructor, etc.) ...
    async def new(provider=None, network=None):
        lucid = Lucid()
        if network:
            lucid.network = network

        if provider:
            lucid.provider = Provider
            protocol_parameters = await Provider.getProtocolParameters()

            if isinstance(lucid.provider, Emulator):
                lucid.network = "Custom"
                SLOT_CONFIG_NETWORK[lucid.network] = {
                    "zeroTime": lucid.provider.now(),
                    "zeroSlot": 0,
                    "slotLength": 1000,
                }

            slot_config = SLOT_CONFIG_NETWORK.get(lucid.network, {})
            lucid.txBuilderConfig = C.TransactionBuilderConfigBuilder.new() \
                C.TransactionBuilderConfig.coins_per_utxo_byte(C.BigNum.from_str(str(protocol_parameters.coinsPerUtxoByte))) \
                .fee_algo(C.LinearFee.new(
                    C.BigNum.from_str(str(protocol_parameters.minFeeA)),
                    C.BigNum.from_str(str(protocol_parameters.minFeeB))
                )) \
                .key_deposit(C.BigNum.from_str(str(protocol_parameters.keyDeposit))) \
                .pool_deposit(C.BigNum.from_str(str(protocol_parameters.poolDeposit))) \
                .max_tx_size(protocol_parameters.maxTxSize) \
                .max_value_size(protocol_parameters.maxValSize) \
                .collateral_percentage(protocol_parameters.collateralPercentage) \
                .max_collateral_inputs(protocol_parameters.maxCollateralInputs) \
                .max_tx_ex_units(C.ExUnits.new(
                    C.BigNum.from_str(str(protocol_parameters.maxTxExMem)),
                    C.BigNum.from_str(str(protocol_parameters.maxTxExSteps))
                )) \
                .ex_unit_prices(C.ExUnitPrices.from_float(
                    protocol_parameters.priceMem,
                    protocol_parameters.priceStep
                )) \
                .slot_config(
                    C.BigNum.from_str(str(slot_config.get("zeroTime", ""))),
                    C.BigNum.from_str(str(slot_config.get("zeroSlot", ""))),
                    slot_config.get("slotLength", 0)
                ) \
                .blockfrost(
                    C.Blockfrost.new(
                        ((provider.url or "") + "/utils/txs/evaluate") if hasattr(provider, "url") else "",
                        (provider.projectId or "") if hasattr(provider, "projectId") else ""
                    )
                ) \
                .costmdls(createCostModels(protocol_parameters.costModels)) \
                .build()

        lucid.utils = Utils(lucid)
        return lucid

    def selectWalletFromPrivateKey(self, private_key):
        priv = C.PrivateKey.from_bech32(private_key)
        pub_key_hash = priv.to_public().hash()

        # Calculate the hash of the public key
        pub_key_bytes = pub_key_hash.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.pub_key_hash = hashlib.blake2b(pub_key_bytes).digest()

        self.wallet = {
            "address": self.getAddress,
            "rewardAddress": self.rewardAddress,
            "getUtxos": self.getUtxos,
            "getUtxosCore": self.getUtxosCore,
            "getDelegation": self.getDelegation,
            "signTx": self.signTx,
            "signMessage": self.sign_message(),
            "submitTx": self.submit_tx,
        }
        return self

    def getAddress(self):
        stake_credential = C.StakeCredential.from_keyhash(self.pub_key_hash)
        address = C.EnterpriseAddress.new(
            1 if self.network == "Mainnet" else 0,
            stake_credential
        ).to_address().to_bech32()
        return address

    def rewardAddress(self):
        return None

    async def getUtxos(self):
        address = self.getAddress()
        payment_credential = payment_credential_of(address)
        return await self.utxosAt(payment_credential)

    def getUtxosCore(self):
        address = self.getAddress()
        utxos = self.utxosAt(payment_credential_of(address))
        coreUtxos = C.TransactionUnspentOutputs.new()
        for utxo in utxos:
            coreUtxos.add(utxoToCore(utxo))
        return coreUtxos

    def getDelegation(self):
        return {'poolId': None, 'rewards': 0}

    def signTx(self, tx: C.Transaction, priv: bytes):
        """Signs a transaction with the given private key.

        Args:
            tx: The transaction to sign.
            priv: The private key to use for signing.

        Returns:
            The signed transaction witness set.
        """

        witness = C.make_vkey_witness(
            C.hash_transaction(tx.body()),
            priv,
        )
        tx_witness_set_builder = C.TransactionWitnessSetBuilder.new()
        C.TransactionWitnessSetBuilder.add_vkey(witness)
        return tx_witness_set_builder.build()

    def sign_message(self,private_key):
        async def sign_message(address, payload):
            address_details = self.utils.get_address_details(address)
            payment_credential, hex_address = address_details.payment_credential, address_details.address.hex

            key_hash = payment_credential.hash if payment_credential else None
            original_key_hash = self.pub_key_hash.hex()

            if not key_hash or key_hash != original_key_hash:
                raise Exception(f"Cannot sign message for address: {address}")

            return sign_data(hex_address, payload, private_key)
        return sign_message

    async def submit_tx(self, tx):
        return await self.provider.submit_tx(tx)

    