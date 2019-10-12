from eth_utils import decode_hex, to_canonical_address
from raiden.utils.signer import LocalSigner, recover

PRIVKEY = decode_hex("0xb8948740e32ba130afec6817c12fcaa716d5a8831554e974f1e40e3e95fe87c2")
signer = LocalSigner(PRIVKEY)

from raiden.messages import (
    from_dict as message_from_dict, Delivered,
    LockedTransfer)


def test_delivered_6():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 319661190699428672
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
        "delivered_message_identifier": 9495542530436126909
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature 4: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_signature_without_secret():
    secrethash = "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 8910176013417313858,
        "payment_identifier": 18177047486640093821,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 1000000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0x0ac002a6fb80b2fb49ec4c1cfeea97b2dceecb30b61f14444f4b1bbf74e2b71b",
        "lock": {
            "type": "Lock",
            "amount": 1000000000000000,
            "expiration": 551521,
            "secrethash": "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
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
