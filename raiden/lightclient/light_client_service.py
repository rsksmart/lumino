from raiden.storage.wal import WriteAheadLog
from .client_model import ClientModel, ClientType
from raiden.utils.typing import List


class LightClientService:
    def __init__(self, wal : WriteAheadLog):
        self.wal = wal

    def get_light_clients_data(self) -> List[ClientModel]:
        light_clients = self.wal.storage.query_clients(str(ClientType.LIGHT.value))
        result = []
        if light_clients is not None and light_clients:
            result = [ClientModel(lc[0], lc[1], lc[2], lc[3]) for lc in light_clients]
        return result

