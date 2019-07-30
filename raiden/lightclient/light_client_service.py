from raiden.storage.wal import WriteAheadLog
from .client_model import ClientModel, ClientType
from raiden.utils.typing import List, AddressHex


class LightClientService:
    def __init__(self, wal : WriteAheadLog):
        self.wal = wal
        self.light_clients: List[ClientModel] = []

    def get_light_clients_data(self) -> List[ClientModel]:
        light_clients = self.wal.storage.query_clients(str(ClientType.LIGHT.value))
        result = []
        if light_clients is not None and light_clients:
            result = [ClientModel(lc[0], lc[1], lc[2], lc[3]) for lc in light_clients]
            self.light_clients = result
        return result

    def is_handled_lc(self, client_address: AddressHex) -> bool:
        for lc in self.light_clients:
            print(lc.address)
            print(client_address)
            if lc.address == client_address:
                print("Is light client")
                return True
        return False








