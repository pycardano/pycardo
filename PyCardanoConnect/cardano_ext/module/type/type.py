from typing import Optional

TxHash = str
Assets = dict
Address = str
DatumHash = Optional[str]
Datum = Optional[dict]
Script = Optional[dict]

class UTxO:
    def __init__(self, txHash: TxHash, outputIndex: int, assets: Assets, address: Address,
                 datumHash: DatumHash = None, datum: Datum = None, scriptRef: Script = None):
        self.txHash = txHash
        self.outputIndex = outputIndex
        self.assets = assets
        self.address = address
        self.datumHash = datumHash
        self.datum = datum
        self.scriptRef = scriptRef



from typing import List, Union, Dict
from dataclasses import dataclass

Address = str
Credential = Union[Address, str]
Unit = str
OutRef = dict
RewardAddress = str
DatumHash = str
TxHash = str

CostModel = Dict[str, int]
PlutusVersion = "PlutusV1" or "PlutusV2"

CostModels = Dict[PlutusVersion, CostModel]


@dataclass
class ProtocolParameters:
    def __init__(self, minFeeA: int, minFeeB: int, maxTxSize: int, maxValSize: int,
                 keyDeposit: int, poolDeposit: int, priceMem: int, priceStep: int,
                 maxTxExMem: int, maxTxExSteps: int, coinsPerUtxoByte: int,
                 collateralPercentage: float, maxCollateralInputs: int,
                 costModels: CostModels):
        self.minFeeA = minFeeA
        self.minFeeB = minFeeB
        self.maxTxSize = maxTxSize
        self.maxValSize = maxValSize
        self.keyDeposit = keyDeposit
        self.poolDeposit = poolDeposit
        self.priceMem = priceMem
        self.priceStep = priceStep
        self.maxTxExMem = maxTxExMem
        self.maxTxExSteps = maxTxExSteps
        self.coinsPerUtxoByte = coinsPerUtxoByte
        self.collateralPercentage = collateralPercentage
        self.maxCollateralInputs = maxCollateralInputs
        self.costModels = costModels


@dataclass
class Delegation:
    # Define the properties of Delegation here
    ...

@dataclass
class Transaction:
    # Define the properties of Transaction here
    ...

class Provider:
    async def getProtocolParameters(self) -> ProtocolParameters:
        # Implement getProtocolParameters method
        ...

    async def getUtxos(self, addressOrCredential: Credential) -> List[UTxO]:
        # Implement getUtxos method
        ...

    async def getUtxosWithUnit(self, addressOrCredential: Credential, unit: Unit) -> List[UTxO]:
        # Implement getUtxosWithUnit method
        ...

    async def getUtxoByUnit(self, unit: Unit) -> UTxO:
        # Implement getUtxoByUnit method
        ...

    async def getUtxosByOutRef(self, outRefs: List[OutRef]) -> List[UTxO]:
        # Implement getUtxosByOutRef method
        ...

    async def getDelegation(self, rewardAddress: RewardAddress) -> Delegation:
        # Implement getDelegation method
        ...

    async def getDatum(self, datumHash: DatumHash) -> Datum:
        # Implement getDatum method
        ...

    async def awaitTx(self, txHash: TxHash, checkInterval: int = 0) -> bool:
        # Implement awaitTx method
        ...

    async def submitTx(self, tx: Transaction) -> TxHash:
        # Implement submitTx method
        ...
