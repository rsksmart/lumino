from raiden.messages import SignedBlindedBalanceProof
from raiden.utils import typing


class LightClientNonClosingBalanceProof:
    """ Representation of light client non closing balance proof signed transaction and information. """

    def __init__(self,
                 sender: typing.AddressHex,
                 light_client_payment_id: int,
                 secret_hash: typing.SecretHash,
                 nonce: int,
                 channel_id: int,
                 token_network_address: typing.TokenNetworkAddress,
                 signed_blinded_balance_proof: SignedBlindedBalanceProof,
                 internal_bp_identifier: int = None):
        self.sender = sender
        self.light_client_payment_id = light_client_payment_id
        self.secret_hash = secret_hash
        self.nonce = nonce
        self.channel_id = channel_id
        self.token_network_address = token_network_address
        self.signed_blinded_balance_proof = signed_blinded_balance_proof
        self.internal_bp_identifier = internal_bp_identifier

    def to_dict(self):
        result = {
            "internal_bp_identifier": self.internal_bp_identifier,
            "sender": self.sender,
            "light_client_payment_id": self.light_client_payment_id,
            "secret_hash": self.secret_hash,
            "nonce": self.nonce,
            "channel_id": self.channel_id,
            "token_network_address": self.token_network_address,
            "signed_blinded_balance_proof": self.signed_blinded_balance_proof.to_dict()
        }

        return result
