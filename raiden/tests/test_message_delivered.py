from eth_utils import decode_hex, to_canonical_address
from raiden.utils.signer import LocalSigner, recover

PRIVKEY = decode_hex("0xb8948740e32ba130afec6817c12fcaa716d5a8831554e974f1e40e3e95fe87c2")
signer = LocalSigner(PRIVKEY)

from raiden.messages import (
    Delivered)


def test_signature_without_secret():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 15646344508401696016
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print(message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")
