from eth_utils import decode_hex, to_canonical_address, keccak

from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID

PRIVKEY = decode_hex("0xb8948740e32ba130afec6817c12fcaa716d5a8831554e974f1e40e3e95fe87c2")
signer = LocalSigner(PRIVKEY)

secret = Secret(b'bX\x0cM[MA,d+d7Zs^eC*IUHgng3LMze\rje')
secrethash = keccak(secret)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer)


def test_reveal_secret_7():
    print("Secret {} ".format(secret.hex()))
    print("SecretHash {} ".format(secrethash.hex()))
    message = RevealSecret(message_identifier=MessageID(4813013428748786508), secret=secret)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_delivered_6():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 599569265152083442
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
        "delivered_message_identifier": 3113270929352335381
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
        "message_identifier": 3113270929352335381,
        "payment_identifier": 2744315930604299652,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 1000000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0xe2934bbe66990d02863b659d40ff8139939d87b38d38e8a3578ecef570fdf470",
        "lock": {
            "type": "Lock",
            "amount": 1000000000000000,
            "expiration": 616238,
            "secrethash": "0x2947ad48b464ceb482736ef615cd8115deae0e117c4f42ac5085d3c52d16544b"
        },
        "target": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "initiator": "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82",
        "fee": 0
    }

    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("LT signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")
