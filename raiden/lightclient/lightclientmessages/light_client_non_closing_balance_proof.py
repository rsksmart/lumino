from eth_utils import to_canonical_address, encode_hex, decode_hex

from raiden.messages import Unlock
from raiden.utils import typing
from raiden.utils.typing import Signature


class LightClientNonClosingBalanceProof:
    """ Representation of light client non closing balance proof signed transaction and information. """

    def __init__(self,
                 sender: typing.AddressHex,
                 light_client_payment_id: int,
                 secret_hash: typing.SecretHash,
                 nonce: int,
                 channel_id: int,
                 token_network_address: typing.TokenNetworkAddress,
                 light_client_balance_proof: Unlock,
                 lc_balance_proof_signature: Signature,
                 internal_bp_identifier: int = None):
        self.sender = sender
        self.light_client_payment_id = light_client_payment_id
        self.secret_hash = secret_hash
        self.nonce = nonce
        self.channel_id = channel_id
        self.token_network_address = token_network_address
        self.light_client_balance_proof = light_client_balance_proof
        self.lc_balance_proof_signature = lc_balance_proof_signature
        self.internal_bp_identifier = internal_bp_identifier

    def to_dict(self):
        result = {
            "internal_bp_identifier": self.internal_bp_identifier,
            "sender": self.sender,
            "light_client_payment_id": self.light_client_payment_id,
            "secret_hash": encode_hex(self.secret_hash),
            "nonce": self.nonce,
            "channel_id": self.channel_id,
            "token_network_address": self.token_network_address,
            "lc_balance_proof_signature": self.lc_balance_proof_signature,
            "light_client_balance_proof": self.light_client_balance_proof
        }
        return result

    @classmethod
    def from_dict(cls, data):
        result = cls(
            internal_bp_identifier=data["internal_bp_identifier"],
            sender=to_canonical_address(data["sender"]),
            light_client_payment_id=data["light_client_payment_id"],
            secret_hash=decode_hex(data["secret_hash"]),
            nonce=data["nonce"],
            channel_id=data["channel_id"],
            token_network_address=to_canonical_address(data["token_network_address"]),
            lc_balance_proof_signature=data["lc_balance_proof_signature"],
            light_client_balance_proof=data["light_client_balance_proof"],
        )
        return result