import string
from enum import Enum
from eth_utils import to_checksum_address

from raiden.utils.typing import AddressHex, TokenNetworkID, Address


class LightClientPaymentStatus(Enum):
    InProgress = "InProgress"
    Expired = "Expired"
    Failed = "Failed"
    Done = "Done"
    Pending = "Pending"
    Deleted = "Deleted"


class LightClientPayment:
    def __init__(
        self,
        partner_address: AddressHex,
        is_lc_initiator: int,
        token_network_id: TokenNetworkID,
        amount: int,
        created_on: string,
        payment_status: LightClientPaymentStatus,
        identifier: string,
        # this is only for mapping query data from database, not used to save the payment
        creator_address: Address = None
    ):
        self.payment_id = int(identifier)
        self.partner_address = to_checksum_address(partner_address)
        self.is_lc_initiator = is_lc_initiator
        self.token_network_id = to_checksum_address(token_network_id)
        self.amount = amount
        self.created_on = created_on
        self.payment_status = payment_status
        self.creator_address = creator_address

    """ Representation of light client payment send or received. """


