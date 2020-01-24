from eth_utils import decode_hex, to_canonical_address, keccak
from raiden_contracts.utils import sign_balance_proof_update_message

from raiden.transfer.balance_proof import pack_balance_proof_update
from raiden.transfer.state import balanceproof_from_envelope
from raiden.utils import Secret
from raiden.utils.signer import LocalSigner, recover
from raiden.utils.typing import MessageID, Signature, SecretHash

PRIVKEY = decode_hex("0X15f570a7914ed27b13ba4a63cee82ad4d77bba3cc60b037abef2f1733423eb70")
signer = LocalSigner(PRIVKEY)

secret = Secret(b'AX\x0cM[MA,d+d7Zs^eC*IUHgng3LMze\rje')
secrethash = keccak(secret)

from raiden.messages import (
    RevealSecret, Delivered,
    LockedTransfer, Unlock, Processed, SecretRequest, LockExpired)


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
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_reveal_secret_7():
    print("Secret {} ".format(secret.hex()))
    print("SecretHash {} ".format(secrethash.hex()))
    message = RevealSecret(message_identifier=MessageID(2226977946511089099), secret=secret)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_processed():
    message = Processed(message_identifier=MessageID(18237677588114994956))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Processed signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_delivered():
    dict_msg = {
        "type": "Delivered",
        "delivered_message_identifier": 18237677588114994956
    }
    message = Delivered.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Delivered signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_secret_request_5():
    dict_data = {
        "type": "SecretRequest",
        "message_identifier": 9443946215632930647,
        "payment_identifier": 1322351847924173620,
        "amount": 100000000000000000,
        "expiration": 12000000,
        "secrethash": "0xaf1ca2932cb5c3e3045eedb17ce760419d2b3e5234eeefe6fd82475adeb4da10"
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
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_reveal_secret_9():
    message = RevealSecret(message_identifier=MessageID(10945162236180065780), secret=Secret(
        decode_hex("0xb8ed582d16853c82a9a9a384118fcd10889ab0a5a3224ec6008bd88582319fc3")))
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("Reveal Secret signature 9: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_locked_transfer_1():
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 12356138443097947541,
        "payment_identifier": 14437077630480195936,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0xb3df4fbd04d29a04d9d0666c009713076e364109",
        "token": "0x95aa68e40b4409f8584b6e60796f29c342e7180a",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 10,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0x300f0f594b8499a2b3a9267b8d281471d5a67e11024f9d4bb7477237d0934936",
        "lock": {
            "type": "Lock",
            "amount": 10,
            "expiration": 62697,
            "secrethash": "0x0caf4611e13f2fc32a6a36224b9603bb890ed9d6a91695a2b3565b0d9bd752f3"
        },
        "target": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "initiator": "0x920984391853d81cceec41adb48a45d40594a0ec",
        "fee": 0
    }

    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print("LT signature: " + message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_lock_expired():
    dict_data = {"type": "LockExpired", "chain_id": 33, "nonce": 2,
                 "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
                 "message_identifier": 10893010622325126424, "channel_identifier": 1,
                 "secrethash": "0x2f3a1f9425850b04e2ea7f572594fd2c6a80e3632bdd04144c825a7e49cf21e2",
                 "transferred_amount": 0, "locked_amount": 0, "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
                 "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000"}

    lock_expired = LockExpired(chain_id=dict_data["chain_id"], nonce=dict_data["nonce"],
                               message_identifier=dict_data["message_identifier"],
                               transferred_amount=dict_data["transferred_amount"],
                               locked_amount=dict_data["locked_amount"], locksroot=decode_hex(dict_data["locksroot"]),
                               channel_identifier=dict_data["channel_identifier"],
                               token_network_address=to_canonical_address(dict_data["token_network_address"]),
                               recipient=to_canonical_address(dict_data["recipient"]),
                               secrethash=SecretHash(decode_hex(dict_data["secrethash"])))
    lock_expired.sign(signer)
    data_was_signed = lock_expired._data_to_sign()
    print("Lock Expired signature: " + lock_expired.signature.hex())
    assert recover(data_was_signed, lock_expired.signature) == to_canonical_address(
        "0x920984391853d81CCeeC41AdB48a45D40594A0ec")


def test_update_non_closing_balance_proof():
    dict_data = {"type": "Secret", "chain_id": 33, "message_identifier": 11519063203689793209,
                 "payment_identifier": 14479511804263315584,
                 "secret": "0x061c302034fa6a4882788a7ff3834b4e3e8bafbdc572fab8d34113e9e32e5cd8", "nonce": 12,
                 "token_network_address": "0x013b47e5eb40a476dc0e9a212d376899288561a2", "channel_identifier": 22,
                 "transferred_amount": 60000000, "locked_amount": 0,
                 "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                 "signature": "0x16820ee8ea32b053e4bb837f528b08e6d4e4afb6c468db4a39dc72cba32f2ff51e5db385b72b524c1c44d4801a06d13216ce3a5261db27847b90e3c4bacf82d11c"}
    # dict_data = {"type": "Secret", "chain_id": 33, "message_identifier": 18237677588114994956, "payment_identifier": 1322351847924173620, "secret": "0xa4678d1f1db376f20854619fc8aa8021f88f318e14ff600aa051e8e4ded5d023", "nonce": 2, "token_network_address": "0x7351ed719de72db92a54c99ef2c4d287f69672a1", "channel_identifier": 3, "transferred_amount": 100000000000000000, "locked_amount": 0, "locksroot": "0x0000000000000000000000000000000000000000000000000000000000000000", "signature": "0x5c805ba51ac4776d879c276d54c1ed97905399e227e7b9ef50aa4f36605ac25e5ab707641c4bd85a0d89549841beaf4f0e06c839ad5460aaf26d4c68b9af822c1b"}
    balance_proof_msg = Unlock.from_dict(dict_data)
    balance_proof = balanceproof_from_envelope(balance_proof_msg)
    non_closing_signature = create_balance_proof_update_signature("0x013b47e5eb40a476dc0e9a212d376899288561a2",
                                                                  22,
                                                                  balance_proof.balance_hash,
                                                                  12,
                                                                  balance_proof.message_hash,
                                                                  decode_hex(
                                                                      "0x16820ee8ea32b053e4bb837f528b08e6d4e4afb6c468db4a39dc72cba32f2ff51e5db385b72b524c1c44d4801a06d13216ce3a5261db27847b90e3c4bacf82d11c"))

    our_signed_data = pack_balance_proof_update(
        nonce=balance_proof.nonce,
        balance_hash=balance_proof.balance_hash,
        additional_hash=balance_proof.message_hash,
        canonical_identifier=balance_proof.canonical_identifier,
        partner_signature=Signature(decode_hex(
            "0x16820ee8ea32b053e4bb837f528b08e6d4e4afb6c468db4a39dc72cba32f2ff51e5db385b72b524c1c44d4801a06d13216ce3a5261db27847b90e3c4bacf82d11c"))
    )

    print("Update non consling blanace proof signature " + non_closing_signature.hex())
    our_recovered_address = recover(data=our_signed_data, signature=Signature(non_closing_signature))
    assert our_recovered_address == to_canonical_address("0x920984391853d81CCeeC41AdB48a45D40594A0ec")


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
