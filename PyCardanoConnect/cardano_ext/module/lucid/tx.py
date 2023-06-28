from core.mod import C
from lucid import Lucid
from plutus.data import Data
from utlis.utils import fromHex, utxoToCore


class Tx:
    def __init__(self, lucid: Lucid):
        self.txBuilder = C.TransactionBuilder.new(lucid.txBuilderConfig)
        self.tasks = []
        self.lucid = lucid

    def readFrom(self, utxos):
        async def process_utxo(utxo):
            if utxo['datumHash']:
                utxo['datum'] = Data.to(await Lucid.datumOf(utxo))
                # Add datum to witness set, so it can be read from validators
                plutus_data = C.PlutusData.from_bytes(fromHex(utxo['datum']))
                self.txBuilder.add_plutus_data(plutus_data)
            core_utxo = utxoToCore(utxo)
            self.txBuilder.add_reference_input(core_utxo)

        self.tasks.append(lambda: [process_utxo(utxo) for utxo in utxos])
        return self
