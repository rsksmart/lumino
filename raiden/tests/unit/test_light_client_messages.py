from eth_utils import decode_hex, to_canonical_address, keccak

from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID, ChainID, Locksroot

PRIVKEY = decode_hex("0x63E5F0F39A21A5BA20AE69D02D20FAFF0F164763062D39CA183A91CC549D142A")
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
        "message_identifier": 6502535024297582148,
        "payment_identifier": 17331394733710625718,
        "secret": "0x62580c4d5b4d412c642b64375a735e65432a495548676e67334c4d7a650d6a65",
        "nonce": 2,
        "token_network_address": "0xb3df4fbd04d29a04d9d0666c009713076e364109",
        "channel_identifier": 3,
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
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_reveal_secret_7():
    print("Secret {} ".format(secret.hex()))
    print("SecretHash {} ".format(secrethash.hex()))
    message = RevealSecret(message_identifier=MessageID(4813013428748786508), secret=secret)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_delivered_6():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 4947020128022466830
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature 6: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_delivered_4():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 13755141366067700437
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature 4: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_signature_without_secret():
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 3760206314433245585,
        "payment_identifier": 11109989191733285112,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0xb3df4fbd04d29a04d9d0666c009713076e364109",
        "token": "0x95aa68e40b4409f8584b6e60796f29c342e7180a",
        "channel_identifier": 3,
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
        "initiator": "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40",
        "fee": 0
    }

    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("LT signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")
