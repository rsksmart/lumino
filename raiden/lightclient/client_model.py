from enum import Enum


class ClientType(Enum):
    HUB = "HUB"
    FULL = "FULL"
    LIGHT = "LIGHT"


class ClientModel:
    def __init__(self, address: str, password: str, api_key: str, client_type: ClientType):
        self.address = address
        self.password = password
        self.api_key = api_key
        self.type = client_type


