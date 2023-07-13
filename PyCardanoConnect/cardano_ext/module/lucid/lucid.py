from ..core.mod import C
from typing import Optional
from ..provider.emulator import Emulator
from ..plutus.time import SLOT_CONFIG_NETWORK
from ..utlis.cost_model import create_cost_models
from ..utlis.utils import Utils
from ..type.type import UTxO ,Provider
from ..plutus.data import Data
# from .lucid import Tx
from cryptography.hazmat.primitives import serialization
import hashlib


class UTxO:
    def __init__(self, tx_hash, index, amount):
        self.tx_hash = tx_hash
        self.index = index
        self.amount = amount



class Lucid:
    def __init__(self):
        self.txBuilderConfig: Optional[C.TransactionBuilderConfig] = None
        self.wallet = None
        self.provider = Provider
        self.network: str = "Mainnet"
        self.utils = None


    def utxosAt(self, addressOrCredential):
        # Replace the following code with your implementation to retrieve UTXOs
        utxos = []

        # Connect to the blockchain network or wallet provider API
        blockchain_client = BlockchainClient()

        # Retrieve UTXOs based on the given address or credential
        retrieved_utxos = blockchain_client.get_utxos(addressOrCredential)

        # Process the retrieved UTXO data
        for utxo_data in retrieved_utxos:
            tx_hash = utxo_data['tx_hash']
            index = utxo_data['index']
            amount = utxo_data['amount']
            utxo = UTxO(tx_hash, index, amount)
            utxos.append(utxo)

        return utxos

    @staticmethod
    async def new(provider: Optional[str] = None, network: Optional[str] = None) -> "Lucid":
        lucid = Lucid()
        if network:
            lucid.network = network
        if provider:
            lucid.provider = provider
            protocolParameters = await provider.getProtocolParameters()

            if isinstance(lucid.provider, Emulator):
                lucid.network = "Custom"
                SLOT_CONFIG_NETWORK[lucid.network] = {
                    "zeroTime": lucid.provider.now(),
                    "zeroSlot": 0,
                    "slotLength": 1000,
                }

            slotConfig = SLOT_CONFIG_NETWORK[lucid.network]
            lucid.txBuilderConfig = {
                "coins_per_utxo_byte": int(protocolParameters.coinsPerUtxoByte),
                "fee_algo": C.LinearFee(
                    int(protocolParameters.minFeeA),
                    int(protocolParameters.minFeeB),
                ),
                "key_deposit": int(protocolParameters.keyDeposit),
                "pool_deposit": int(protocolParameters.poolDeposit),
                "max_tx_size": protocolParameters.maxTxSize,
                "max_value_size": protocolParameters.maxValSize,
                "collateral_percentage": protocolParameters.collateralPercentage,
                "max_collateral_inputs": protocolParameters.maxCollateralInputs,
                "max_tx_ex_units": {
                    "max_tx_ex_mem": int(protocolParameters.maxTxExMem),
                    "max_tx_ex_steps": int(protocolParameters.maxTxExSteps),
                },
                "ex_unit_prices": {
                    "price_mem": protocolParameters.priceMem,
                    "price_step": protocolParameters.priceStep,
                },
                "slot_config": {
                    "zero_time": int(slotConfig.zeroTime),
                    "zero_slot": int(slotConfig.zeroSlot),
                    "slot_length": slotConfig.slotLength,
                },
                "blockfrost": {
                    "url": (provider.url or "") + "/utils/txs/evaluate",
                    "project_id": provider.projectId or "",
                },
                "costmdls": create_cost_models(protocolParameters.costModels),
            }
        lucid.utils = Utils(lucid)
        return lucid
    
    async def switchProvider(self, provider, network):
        if self.network == "Custom":
            raise Exception("Cannot switch when on custom network.")
        
        lucid = await Lucid.new(provider, network)
        self.txBuilderConfig = lucid.txBuilderConfig
        self.provider = provider or self.provider
        self.network = network or self.network
        self.wallet = lucid.wallet
        return self
    
    # def newTx(self) -> Tx:
    #     return Tx(self)
    # add tx functions



    async def datumOf(self, utxo:UTxO, type=None):
        if not utxo.datum:
            if not utxo.datumHash:
                raise ValueError("This UTxO does not have a datum hash.")
            utxo.datum = await self.provider.getDatum(utxo.datumHash)
        return Data.from_raw(utxo.datum, type)
    


    def selectWalletFromPrivateKey(self, private_key):
            priv = C.PrivateKey.from_bech32(private_key)
            pub_key = priv.public_key()

            # Calculate the hash of the public key
            pub_key_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.pub_key_hash = hashlib.blake2b(pub_key_bytes).digest()
            
            # Rest of your code for the selectWalletFromPrivateKey function


    def getAddress(self):
            stake_credential = C.StakeCredential.from_keyhash(self.pub_key_hash)
            address = C.EnterpriseAddress.new(
                1 if self.network == "Mainnet" else 0,
                stake_credential
            ).to_address().to_bech32()
            return address
        
    def rewardAddress():
            return None 

    def getUtxos():
            return self.utxosAt(paymentCredentialOf(self.wallet.address()))

    def getUtxosCore():
            utxos = self.utxosAt(paymentCredentialOf(self.wallet.address()))
            coreUtxos = C.TransactionUnspentOutputs.new()
            for utxo in utxos:
                coreUtxos.add(utxoToCore(utxo))
            return coreUtxos

    def getDelegation():
            return {'poolId': None, 'rewards': 0}

    def signTx(tx):
            witness = C.make_vkey_witness(
                C.hash_transaction(tx.body()),
                priv
            )
            txWitnessSetBuilder = C.TransactionWitnessSetBuilder.new()
            txWitnessSetBuilder.add_vkey(witness)
            return txWitnessSetBuilder.build()

    def signMessage(address, payload):
            addressDetails = self.utils.getAddressDetails(address)
            paymentCredential, hexAddress = addressDetails['paymentCredential'], addressDetails['address']['hex']
            keyHash = paymentCredential.hash

            originalKeyHash = pubKeyHash.to_hex()

            if not keyHash or keyHash != originalKeyHash:
                raise Exception(f"Cannot sign message for address: {address}.")

            return self.signData(hexAddress, payload, privateKey)

    def submitTx(tx):
            return self.provider.submitTx(tx)

    self.wallet = {
            'address': getAddress,
            'rewardAddress': rewardAddress,
            'getUtxos': getUtxos,
            'getUtxosCore': getUtxosCore,
            'getDelegation': getDelegation,
            'signTx': signTx,
            'signMessage': signMessage,
            'submitTx': submitTx
        }
        return self

    def getAddressDetails(self, address):
        # Implement the getAddressDetails method
        pass

    def signData(self, hexAddress, payload, privateKey):
        # Implement the signData method
        pass

    def utxosAt(self, paymentCredential):
        # Implement the utxosAt method
        pass

    # def provider.submitTx(self, tx):
    #     pass 