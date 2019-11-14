from eth_utils import decode_hex, to_canonical_address, keccak

from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID

PRIVKEY = decode_hex("0x63E5F0F39A21A5BA20AE69D02D20FAFF0F164763062D39CA183A91CC549D142A")
signer = LocalSigner(PRIVKEY)

secret = Secret(b'AX\x0cM[MA,d+d7Zs^eC*IUHgng3LMze\rje')
secrethash = keccak(secret)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer, Unlock, Processed, SecretRequest)



def test_balance_proof_11():
    dict_data = {"type": "Secret", "chain_id": 33, "message_identifier": 6263041337178146650,
                 "payment_identifier": 3135462385358726574,
                 "secret": "0x41580c4d5b4d412c642b64375a735e65432a495548676e67334c4d7a650d6a65", "nonce": 2,
                 "token_network_address": "0x7351ed719de72db92a54c99ef2c4d287f69672a1", "channel_identifier": 1,
                 "transferred_amount": 1000000000000000, "locked_amount": 0,
                 "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000"}

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


def test_processed():
    message = Processed(message_identifier=MessageID(8560298362786856489))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_secret_request_5():
    dict_data = {
        "type": "SecretRequest",
        "message_identifier": 11830796048202304011,
        "payment_identifier": 17624816782097112522,
        "amount": 1000000000000000,
        "expiration": 12000000,
        "secrethash": "0x576a7856da7af831f7acb87da9451e02224bcee0800981945cfb0e581270c65e"
    }
    message = SecretRequest(message_identifier=dict_data["message_identifier"],
                            payment_identifier=dict_data["payment_identifier"],
                            secrethash=decode_hex(dict_data["secrethash"]),
                            amount=dict_data["amount"],
                            expiration=dict_data["expiration"]
    )
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("SR signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_reveal_secret_9():
    message = RevealSecret(message_identifier=MessageID(2225799524225862565), secret=Secret(decode_hex("0x62080ee2de6e9d81a563b7177d274babab1090f440e756f3d0e4756586f017c8")))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")

def test_delivered():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 8560298362786856489
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_locked_transfer_1():
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 5582513684436696034,
        "payment_identifier": 3443356287795879818,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x7351ed719de72db92a54c99ef2c4d287f69672a1",
        "token": "0x8f2872964137cc8a331ee47518cba48c5bbb367f",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 1000000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0xf7ea48a18722b8f3c3ee8233b3dec03f2a60d735b34a214374c7a8cd62544012",
        "lock": {
            "type": "Lock",
            "amount": 1000000000000000,
            "expiration": 1624776,
            "secrethash": "0x0caf4611e13f2fc32a6a36224b9603bb890ed9d6a91695a2b3565b0d9bd752f4"
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
