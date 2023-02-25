from enum import Enum


class DeviceStatus(str, Enum):
    """Device status strings for allow or block."""

    allow: str = "Allow"
    block: str = "Block"


class SupportedModules(str, Enum):
    """Supported modules are At&t and Netgear."""

    att: str = "At&t"
    netgear: str = "Netgear"
