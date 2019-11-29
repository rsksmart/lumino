from eth_utils import decode_hex, to_canonical_address, keccak
from raiden_contracts.utils import sign_balance_proof_update_message

from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.state import balanceproof_from_envelope
from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID, Signature

PRIVKEY = decode_hex("0x63E5F0F39A21A5BA20AE69D02D20FAFF0F164763062D39CA183A91CC549D142A")
signer = LocalSigner(PRIVKEY)

secret = Secret(b'AX\x0cM[MA,d+d7Zs^eC*IUHgng3LMze\rje')
secrethash = keccak(secret)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer, Unlock, Processed, SecretRequest)


def test_balance_proof_11():
    dict_data = {"type": "Secret", "chain_id": 33, "message_identifier": 4334089825906208294,
                 "payment_identifier": 15193824610622741555,
                 "secret": "0x8c45240e576c4befd51d063549ce18859c5a2b3c356035884588a65c3dfcef4b", "nonce": 2,
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
    message = RevealSecret(message_identifier=MessageID(2226977946511089099), secret=secret)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_processed():
    message = Processed(message_identifier=MessageID(10357160083943892196))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Processed signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_delivered():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 10357160083943892196
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40")


def test_secret_request_5():
    dict_data = {
        "type": "SecretRequest",
        "message_identifier": 11859868579443731927,
        "payment_identifier": 4323273060934284161,
        "amount": 100000000000000000,
        "expiration": 12000000,
        "secrethash": "0x7be309bc15b0d513fff11a3df169fb4ad4ef68796713f66cb87fdf6a64f53d65"
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
    message = RevealSecret(message_identifier=MessageID(15943061285551736489), secret=Secret(
        decode_hex("0xa4678d1f1db376f20854619fc8aa8021f88f318e14ff600aa051e8e4ded5d023")))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature 9: " + message.signature.hex())
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


def test_update_non_closing_balance_proof():
    dict_data = {"type": "Secret", "chain_id": 33, "message_identifier": 10357160083943892196, "payment_identifier": 4323273060934284161, "secret": "0xa4678d1f1db376f20854619fc8aa8021f88f318e14ff600aa051e8e4ded5d023", "nonce": 2, "token_network_address": "0x7351ed719de72db92a54c99ef2c4d287f69672a1", "channel_identifier": 3, "transferred_amount": 100000000000000000, "locked_amount": 0, "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000", "signature": "0x5c805ba51ac4776d879c276d54c1ed97905399e227e7b9ef50aa4f36605ac25e5ab707641c4bd85a0d89549841beaf4f0e06c839ad5460aaf26d4c68b9af822c1b"}
    balance_proof_msg = Unlock.from_dict(dict_data)
    balance_proof = balanceproof_from_envelope(balance_proof_msg)
    non_closing_signature = create_balance_proof_update_signature("0x7351ed719de72db92a54c99ef2c4d287f69672a1",
                                                      3,
                                                      balance_proof.balance_hash,
                                                      2,
                                                      balance_proof.message_hash,
                                                      decode_hex(
                                                          "0x5c805ba51ac4776d879c276d54c1ed97905399e227e7b9ef50aa4f36605ac25e5ab707641c4bd85a0d89549841beaf4f0e06c839ad5460aaf26d4c68b9af822c1b"))

    our_signed_data = pack_balance_proof_update(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=balance_proof.canonical_identifier,
        partner_signature=Signature(decode_hex(
            "0x5c805ba51ac4776d879c276d54c1ed97905399e227e7b9ef50aa4f36605ac25e5ab707641c4bd85a0d89549841beaf4f0e06c839ad5460aaf26d4c68b9af822c1b"))
    )
    print(non_closing_signature.hex())
    our_recovered_address = recover(data=our_signed_data, signature=Signature(non_closing_signature))
    print(our_recovered_address)


def create_balance_proof_update_signature(
    token_network_address,
    channel_identifier,
    balance_hash,
    nonce,
    additional_hash,
    closing_signature,
    v=27,
):
    non_closing_signature = sign_balance_proof_update_message(
        "0x63E5F0F39A21A5BA20AE69D02D20FAFF0F164763062D39CA183A91CC549D142A",
        token_network_address,
        33,
        channel_identifier,
        balance_hash,
        nonce,
        additional_hash,
        closing_signature,
        v
    )
    return non_closing_signature
