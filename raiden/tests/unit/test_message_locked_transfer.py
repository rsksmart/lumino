from eth_utils import decode_hex, to_canonical_address

from raiden.utils.signer import LocalSigner, recover

PRIVKEY = decode_hex("0x51dd3591fb7ce95b0bd77ca14a5236a4989d399c80b8150d3799dd0afcb14282")
signer = LocalSigner(PRIVKEY)

from raiden.messages import (
    from_dict as message_from_dict,
    LockedTransfer)


def test_our_signed_msg():
    # Signed data
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 12248562144413481135,
        "payment_identifier": 11640634370223461850,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 100000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0x3985b475b7e3af72cdbcd2e41b22951c168b0e2ff41bcc9548ee98d14ec86784",
        "lock": {
            "type": "Lock",
            "amount": 100000000000000,
            "expiration": 195730,
            "secrethash": "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
        },
        "target": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "initiator": "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82",
        "fee": 0,
        "signature": "0x68b12d6de97e2be66a5d013a7118264ab696a45ebe7f9ef590c88286ba7804154e0a1418d78712d4aa227c33af23ebae2ff8114a7e3f3d9efb7e342235eba5941b"
    }
    # Construct message from dict (this includes and creates a sender field  according to signature)
    message = message_from_dict(dict_msg)
    assert message.signature == decode_hex(
        "0x68b12d6de97e2be66a5d013a7118264ab696a45ebe7f9ef590c88286ba7804154e0a1418d78712d4aa227c33af23ebae2ff8114a7e3f3d9efb7e342235eba5941b")

    # TODO this assert condition.
    assert recover(message._data_to_sign(), message.signature) != to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_working_raiden():
    # Signed data
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 1492744266262786169,
        "payment_identifier": 5037359832394936637,
        "payment_hash_invoice": "0x",
        "nonce": 9,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 3,
        "transferred_amount": 100000000000000000,
        "locked_amount": 200000000000000000,
        "recipient": "0x5fd79c7dd13a67361f22dafdd3127c4ae639ec3b",
        "locksroot": "0x277d40c5b54433ce56255ca389d11207cc8ce64cac9fc2725cd30d0d1ce624a9",
        "lock": {
            "type": "Lock",
            "amount": 200000000000000000,
            "expiration": 252207,
            "secrethash": "0xde3a845acb01d53d24d0848ccc420e4f700e0bc67f007b7aa098880ab9fa131a"
        },
        "target": "0x5fd79c7dd13a67361f22dafdd3127c4ae639ec3b",
        "initiator": "0xa358b95b3ee75e426d89f91d65a27e8d83bbf995",
        "fee": 0,
        "signature": "0x6f6ca17a6660dc4203409e3671dd7dc653d6ac01bc53cf5ba0259adb7766333b1a0850d4adff075735a2f7e4c6a20cb3271fbc86af5ad9ad87fe8752002bf9401b"
    }
    # Construct message from dict (this includes and creates a sender field  according to signature)
    message = message_from_dict(dict_msg)
    assert message.signature == decode_hex(
        "0x6f6ca17a6660dc4203409e3671dd7dc653d6ac01bc53cf5ba0259adb7766333b1a0850d4adff075735a2f7e4c6a20cb3271fbc86af5ad9ad87fe8752002bf9401b")
    assert recover(message._data_to_sign(), message.signature) == to_canonical_address(
        "0xa358b95B3ee75e426d89F91d65a27E8d83bBF995")


def test_signature():
    # Unsigned message
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 12248562144413481135,
        "payment_identifier": 11640634370223461850,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x877ec5961d18d3413fabbd67696b758fe95408d6",
        "token": "0xff10e500973a0b0071e2263421e4af60425834a6",
        "channel_identifier": 1,
        "transferred_amount": 0,
        "locked_amount": 100000000000000,
        "recipient": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "locksroot": "0x3985b475b7e3af72cdbcd2e41b22951c168b0e2ff41bcc9548ee98d14ec86784",
        "lock": {
            "type": "Lock",
            "amount": 100000000000000,
            "expiration": 195730,
            "secrethash": "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
        },
        "target": "0x29021129f5d038897f01bd4bc050525ca01a4758",
        "initiator": "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82",
        "fee": 0
    }
    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    assert message.signature == decode_hex(
        "0x65309af4b47e9bde1b567c790424dd8a0036712ec9d29e6651208a568cce50ad53fbc7672c85f98831810e77c6558469364086bdfd8f858e927af91986b710431b")
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")


def test_signature_without_secret():
    secrethash = "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
    dict_msg = {
        "type": "LockedTransfer",
        "chain_id": 33,
        "message_identifier": 14747618820028812404,
        "payment_identifier": 16050003401382756056,
        "payment_hash_invoice": "0x",
        "nonce": 1,
        "token_network_address": "0x2864a97e7701a08d53f24f9e9fa6727988733f12",
        "token": "0x58cf17e106686e1554177030980829cfd4cb7196",
        "channel_identifier": 22,
        "transferred_amount": 0,
        "locked_amount": 100000000000000000,
        "recipient": "0x5a88c15f3ed1bee03c7e85355faed29d202744c6",
        "locksroot": "0x80c5a4985caf413bb97d97af2e5a4d800f970778b8cf5a5b6b2212e8faa8ff67",
        "lock": {
            "type": "Lock",
            "amount": 100000000000000000,
            "expiration": 375359,
            "secrethash": "0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"
        },
        "target": "0x5a88c15f3ed1bee03c7e85355faed29d202744c6",
        "initiator": "0x6d369723521b4080a19457d5fdd2194d633b0c3a",
        "fee": 0
    }

    message = LockedTransfer.from_dict_unsigned(dict_msg)
    message.sign(signer)
    data_was_signed = message._data_to_sign()
    print(message.signature.hex())
    assert recover(data_was_signed, message.signature) == to_canonical_address(
        "0x09fcbe7ceb49c944703b4820e29b0541edfe7e82")
