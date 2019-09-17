import string
from enum import Enum

from raiden.utils.typing import AddressHex, TokenNetworkID, Secret


class LightClientPaymentStatus(Enum):
    InProgress = "InProgress"
    Expired = "Expired"
    Failed = "Failed"
    Done = "Done"
    Pending = "Pending"
    Deleted = "Deleted"


class LightClientPayment:
    """ Representation of light client message send or received. """

    def __init__(
        self,
        payment_secret: Secret,
        light_client_address: AddressHex,
        partner_address: AddressHex,
        is_lc_initiator: int,
        token_network_id: TokenNetworkID,
        amount: int,
        created_on: string,
        payment_status: LightClientPaymentStatus,
        identifier: int = None

    ):
        self.payment_id = identifier
        self.payment_secret = payment_secret
        self.light_client_address = light_client_address
        self.partner_address = partner_address
        self.is_lc_initiator = is_lc_initiator
        self.token_network_id = token_network_id
        self.amount = amount
        self.created_on = created_on
        self.payment_status = payment_status


