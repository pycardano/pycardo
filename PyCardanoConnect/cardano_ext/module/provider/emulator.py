from ..core.mod import C
import datetime
from ..utlis.cost_model import PROTOCOL_PARAMETERS_DEFAULT
from typing import Dict,  Union, Any, Optional
from ..utlis.utils import getAddressDetails 


class Delegation:
    PoolId = str or None
    Lovelace = int

    def __init__(self, poolId: Optional[PoolId], rewards: Lovelace):
        self.poolId = poolId
        self.rewards = rewards

class Credential:
    ScriptHash = str
    KeyHash = str


    def __init__(self, type: str, hash: Union[KeyHash, ScriptHash]):
        self.type = type
        self.hash = hash

class Emulator():
    ledger: Dict[str, Dict[str, Union[Dict[str, Any], bool]]]
    mempool: Dict[str, Dict[str, Union[Dict[str, Any], bool]]]
    chain: Dict[str, Dict[str, Union[bool, Dict[str, Any]]]]
    blockHeight: int
    slot: int
    time: int
    protocolParameters: Dict[str, Any]
    datumTable: Dict[str, Any]
    def __init__(self, accounts, protocolParameters=PROTOCOL_PARAMETERS_DEFAULT):
        address = None
        assets = None
        GENESIS_HASH = "00" * 32
        self.blockHeight = 0
        self.slot = 0
        self.time = int(datetime.now().timestamp() * 1000)
        self.ledger = {}
        self.mempool = {}
        self.chain = {}
        self.datumTable = {}
        self.protocolParameters = protocolParameters

        for index, account in enumerate(accounts):
            address, assets = account
            self.ledger[GENESIS_HASH + str(index)] = {
                'utxo': {
                    'txHash': GENESIS_HASH,
                    'outputIndex': index,
                    'address': address,
                    'assets': assets,
                },
                'spent': False,
            }

    def now(self):
        return self.time
    
    def awaitSlot(self, length: int) -> None:
        self.slot += length
        self.time += length * 1000
        currentHeight = self.blockHeight
        self.blockHeight = self.slot // 20

        if self.blockHeight > currentHeight:
            for outRef, data in self.mempool.items():
                utxo, spent = data["utxo"], data["spent"]
                self.ledger[outRef] = {"utxo": utxo, "spent": spent}

            for outRef, data in list(self.ledger.items()):
                spent = data["spent"]
                if spent:
                    del self.ledger[outRef]

            self.mempool = {}

    def awaitBlock(self, height: int) -> None:
        self.blockHeight += height
        self.slot += height * 20
        self.time += height * 20 * 1000

        for outRef, data in self.mempool.items():
            utxo, spent = data["utxo"], data["spent"]
            self.ledger[outRef] = {"utxo": utxo, "spent": spent}

        for outRef, data in list(self.ledger.items()):
            spent = data["spent"]
            if spent:
                del self.ledger[outRef]

        self.mempool = {}

    def getUtxos(self, addressOrCredential):
        utxos = [
            utxo["utxo"]
            for utxo in self.ledger.values()
            if (
                isinstance(addressOrCredential, str)
                and addressOrCredential == utxo["utxo"]["address"]
            )
            or (
                isinstance(addressOrCredential, Credential)
                and getAddressDetails(utxo["utxo"]["address"])["paymentCredential"]["hash"] == addressOrCredential.hash
            )
        ]
        return utxos

    def getProtocolParameters(self):
        return self.protocolParameters

    def getDatum(self, datumHash):
        return self.datumTable.get(datumHash)
    
    def getUtxosWithUnit(self, addressOrCredential, unit):
        utxos = [
            utxo["utxo"]
            for utxo in self.ledger.values()
            if (
                isinstance(addressOrCredential, str)
                and addressOrCredential == utxo["utxo"]["address"]
                and utxo["utxo"]["assets"].get(unit, 0) > 0
            )
            or (
                isinstance(addressOrCredential, Credential)
                and getAddressDetails(utxo["utxo"]["address"])["paymentCredential"]["hash"] == addressOrCredential.hash
                and utxo["utxo"]["assets"].get(unit, 0) > 0
            )
        ]
        return utxos
    

    def getUtxoByUnit(self, unit: str):
        utxos = [
            utxo["utxo"]
            for utxo in self.ledger.values()
            if utxo["utxo"]["assets"].get(unit, 0) > 0
        ]

        if len(utxos) > 1:
            raise Exception("Unit needs to be an NFT or only held by one address.")

        return utxos[0]

    def getDelegation(self, rewardAddress: C.RewardAddress) -> Delegation:
        delegation = self.chain.get(rewardAddress, {}).get("delegation", {})
        poolId = delegation.get("poolId", None)
        rewards = delegation.get("rewards", 0)
        return Delegation(poolId=poolId, rewards=rewards)

    def awaitTx(self, txHash: str) -> bool:
        if self.mempool.get(txHash + "0"):
            self.awaitBlock()
            return True
        return False
    
    def distributeRewards(self, rewards: Delegation.Lovelace):
        for rewardAddress, delegation in self.chain.items():
            registeredStake = delegation.get("registeredStake", False)
            poolId = delegation.get("delegation", {}).get("poolId")
            if registeredStake and poolId:
                delegation["delegation"]["rewards"] += rewards

        self.awaitBlock()



    def submitTx(tx):
        pass

