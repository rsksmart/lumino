import json
from eth_utils import decode_hex, to_canonical_address
from raiden.utils.signer import recover


def test_recover_address_from_matrix_server_domain_and_signature():
    account = to_canonical_address('0x09fcbe7ceb49c944703b4820e29b0541edfe7e82')
    values = {
        'type': 'LockedTransfer',
        'chain_id': '33',
        'message_identifier': '6653222977791419296',
        'payment_identifier': '10696603058662885795',
        'payment_hash_invoice': '0x',
        'nonce': '1',
        'token_network_address': '0x877ec5961d18d3413fabbd67696b758fe95408d6',
        'token': '0xff10e500973a0b0071e2263421e4af60425834a6',
        'channel_identifier': '1',
        'transferred_amount': '0',
        'locked_amount': '100000000000000',
        'recipient': '0x29021129f5d038897f01bd4bc050525ca01a4758',
        'locksroot': '0xb3e1ee18bb1bbce8185e211d0c3552b5aaeb05dc1308d5bd71e43e930f303027',
        'lock': {
            'type': 'Lock',
            'amount': '100000000000000',
            'expiration': '50103',
            'secrethash': '0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc'
        },
        'target': '0x29021129f5d038897f01bd4bc050525ca01a4758',
        'initiator': '0x09fcbe7ceb49c944703b4820e29b0541edfe7e82',
        'fee': '0'
    }
#    javascript = '{"type":"LockedTransfer","chain_id":33,"message_identifier":6653222977791419000,"payment_identifier":10696603058662885000,"payment_hash_invoice":"0x","nonce":1,"token_network_address":"0x877ec5961d18d3413fabbd67696b758fe95408d6","token":"0xff10e500973a0b0071e2263421e4af60425834a6","channel_identifier":1,"transferred_amount":0,"locked_amount":100000000000000,"recipient":"0x29021129f5d038897f01bd4bc050525ca01a4758","locksroot":"0xb3e1ee18bb1bbce8185e211d0c3552b5aaeb05dc1308d5bd71e43e930f303027","lock":{"type":"Lock","amount":100000000000000,"expiration":50103,"secrethash":"0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"},"target":"0x29021129f5d038897f01bd4bc050525ca01a4758","initiator":"0x09fcbe7ceb49c944703b4820e29b0541edfe7e82","fee":0}'
    data = json.dumps(values, separators=(',', ':'))
 #   assert javascript == data
    acc_priv = decode_hex(
        '0x51e6366130508b41650d9d895d83d61b9dcc216d61a11e4aee931872f87b6405358d937b401b4afeaad0136f5d656d26079094d37081eda6ff942c7214354eb81b')
    assert recover(data=data.encode(), signature=acc_priv) == account
