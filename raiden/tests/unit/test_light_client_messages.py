from eth_utils import decode_hex, to_canonical_address, keccak

from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID, ChainID, Locksroot

PRIVKEY = decode_hex("0xb8948740e32ba130afec6817c12fcaa716d5a8831554e974f1e40e3e95fe87c2")
signer = LocalSigner(PRIVKEY)

secret = Secret(b'bX\x0cM[MA,d+d7Zs^eC*IUHgng3LMze\rje')
secrethash = keccak(secret)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer, Unlock)


def test_balance_proof():
    dict_data = {
        "type": "Secret",
        "chain_id": 33,
        "message_identifier": 7331028335892713299,
        "payment_identifier": 3067236291737758355,
        "secret": "0x62580c4d5b4d412c642b64375a735e65432a495548676e67334c4d7a650d6a65",
        "nonce": 2,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "channel_identifier": 1,
        "transferred_amount": 1000000000000000,
        "locked_amount": 0,
        "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000"
    }

    message = Unlock(chain_id=dict_data["chain_id"],
                     message_identifier=dict_data["message_identifier"],
                     payment_identifier=dict_data["payment_identifier"],
                     secret=decode_hex(dict_data["secret"]),
                     nonce=dict_data["nonce"],
                     token_network_address=decode_hex(dict_data["token_network_address"]),
                     channel_identifier=dict_data["channel_identifier"],
                     transferred_amount=dict_data["transferred_amount"],
                     locked_amount=dict_data["locked_amount"],
                     locksroot=decode_hex(dict_data["locksroot"]))

    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Balance Proof signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


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
        "message_identifier": 1376110454679662125,
        "payment_identifier": 3067236291737758355,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 1000000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0x78c205b7ad996ae64ac37f3f79c2a7363e09de56e69b356edb3652e37c35553a",
        "lock": {
            "type": "Lock",
            "amount": 1000000000000000,
            "expiration": 1624776,
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
