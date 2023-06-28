

from typing import Dict

class SlotConfig:
    def __init__(self, zeroTime: int, zeroSlot: int, slotLength: int):
        self.zeroTime = zeroTime
        self.zeroSlot = zeroSlot
        self.slotLength = slotLength

class Network:
    Mainnet = "Mainnet"
    Preview = "Preview"
    Preprod = "Preprod"
    Custom = "Custom"

SLOT_CONFIG_NETWORK: Dict[Network, SlotConfig] = {
    Network.Mainnet: SlotConfig(1596059091000, 4492800, 1000),
    Network.Preview: SlotConfig(1666656000000, 0, 1000),
    Network.Preprod: SlotConfig(1654041600000 + 1728000000, 86400, 1000),
    Network.Custom: SlotConfig(0, 0, 0)
}

def slotToBeginUnixTime(slot: int, slotConfig: SlotConfig) -> int:
    msAfterBegin = (slot - slotConfig.zeroSlot) * slotConfig.slotLength
    return slotConfig.zeroTime + msAfterBegin

def unixTimeToEnclosingSlot(unixTime: int, slotConfig: SlotConfig) -> int:
    timePassed = unixTime - slotConfig.zeroTime
    slotsPassed = timePassed // slotConfig.slotLength
    return slotsPassed + slotConfig.zeroSlot
