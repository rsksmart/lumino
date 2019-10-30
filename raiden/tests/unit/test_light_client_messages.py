from eth_utils import decode_hex, to_canonical_address
from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID

PRIVKEY = decode_hex("0x1bc5766d3f31e2e76dfd4d76684d8dde5671135bd30511aae20f424655d0e33b")
signer = LocalSigner(PRIVKEY)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer)


def test_reveal_secret_7():
    message = RevealSecret(message_identifier=MessageID(4813013428748786508), secret=Secret(b'0x3078323133'))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_delivered_6():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 3811663668877201681
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature 6: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_delivered_4():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 4761293901632380618
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature 4: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_signature_without_secret():

    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 195183193857160981,
        "payment_identifier": 4177147621199363798,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0xa469774ef90d4913fe48199064558564fcf891f6",
        "token": "0xd8c929f711cee10992d5d4e039319ab7ca68bfbc",
        "channel_identifier": 3,
        "transferred_amount": 0,
        "locked_amount": 1,
        "recipient": "0xaa5d80331b546bc74407009b176b675e90f65bbb",
        "locksroot": "0x9c7b6bb51b9d680187277e5e493066ea6bca2db9351f10da7a638832689ac6f0",
        "lock": {
            "type": "Lock",
            "amount": 1,
            "expiration": 145805,
            "secrethash": "0x4e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0de"
        },
        "target": "0xaa5d80331b546bc74407009b176b675e90f65bbb",
        "initiator": "0x54df5016e08e81ce7cec2d5e0ce4c30fd55b98de",
        "fee": 0
    }

    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("LT signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")

