from eth_utils import decode_hex, to_canonical_address, keccak

from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID, ChainID, Locksroot

PRIVKEY = decode_hex("0x1bc5766d3f31e2e76dfd4d76684d8dde5671135bd30511aae20f424655d0e33b")
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
        "message_identifier": 5296181112217886153,
        "payment_identifier": 658552690069865136,
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
        "delivered_message_identifier": 12792016288654049179
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
        "delivered_message_identifier": 12103104860561726973
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
        "message_identifier": 13755141366067700437,
        "payment_identifier": 6179798876113273543,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0xb3df4fbd04d29a04d9d0666c009713076e364109",
        "token": "0x95aa68e40b4409f8584b6e60796f29c342e7180a",
        "channel_identifier": 2,
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
