from ..core.mod import C
from typing import Optional
from ..provider.emulator import Emulator
from ..plutus.time import SLOT_CONFIG_NETWORK
from ..utlis.cost_model import create_cost_models
from ..utlis.utils import Utils
from ..type.type import UTxO ,Provider
from ..plutus.data import Data
# from .lucid import Tx


class Lucid:
    def __init__(self):
        self.txBuilderConfig: Optional[C.TransactionBuilderConfig] = None
        self.wallet = None
        self.provider = Provider
        self.network: str = "Mainnet"
        self.utils = None

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
