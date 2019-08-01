from enum import Enum

from eth_utils.typing import ChecksumAddress


class ClientType(Enum):
    HUB = "HUB"
    FULL = "FULL"
    LIGHT = "LIGHT"


class ClientModel:
    def __init__(self, address: ChecksumAddress, password: str, api_key: str, client_type: ClientType):
        self.address = address
        self.password = password
        self.api_key = api_key
        self.type = client_type


