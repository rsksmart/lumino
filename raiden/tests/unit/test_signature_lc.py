import json
from eth_utils import decode_hex, to_canonical_address
from raiden.utils.signer import recover


def test_recover_address_from_matrix_server_domain_and_signature():
    account = to_canonical_address('0x09fcbe7ceb49c944703b4820e29b0541edfe7e82')
    values = {
        'type': 'LockedTransfer',
        'chain_id': '33',
        'message_identifier': '12248562144413481135',
        'payment_identifier': '11640634370223461850',
        'payment_hash_invoice': '0x',
        'nonce': '1',
        'token_network_address': '0x877ec5961d18d3413fabbd67696b758fe95408d6',
        'token': '0xff10e500973a0b0071e2263421e4af60425834a6',
        'channel_identifier': '1',
        'transferred_amount': '0',
        'locked_amount': '100000000000000',
        'recipient': '0x29021129f5d038897f01bd4bc050525ca01a4758',
        'locksroot': '0x3985b475b7e3af72cdbcd2e41b22951c168b0e2ff41bcc9548ee98d14ec86784',
        'lock': {
            'type': 'Lock',
            'amount': '100000000000000',
            'expiration': '195730',
            'secrethash': '0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc'
        },
        'target': '0x29021129f5d038897f01bd4bc050525ca01a4758',
        'initiator': '0x09fcbe7ceb49c944703b4820e29b0541edfe7e82',
        'fee': '0'
    }
#    javascript = '{"type":"LockedTransfer","chain_id":33,"message_identifier":6653222977791419000,"payment_identifier":10696603058662885000,"payment_hash_invoice":"0x","nonce":1,"token_network_address":"0x877ec5961d18d3413fabbd67696b758fe95408d6","token":"0xff10e500973a0b0071e2263421e4af60425834a6","channel_identifier":1,"transferred_amount":0,"locked_amount":100000000000000,"recipient":"0x29021129f5d038897f01bd4bc050525ca01a4758","locksroot":"0xb3e1ee18bb1bbce8185e211d0c3552b5aaeb05dc1308d5bd71e43e930f303027","lock":{"type":"Lock","amount":100000000000000,"expiration":50103,"secrethash":"0x3e6d58ba381898cf1a0ff6fbe65a3805419063ea9eb6ff6bc6f0dde45032d0dc"},"target":"0x29021129f5d038897f01bd4bc050525ca01a4758","initiator":"0x09fcbe7ceb49c944703b4820e29b0541edfe7e82","fee":0}'
    data = json.dumps(values, separators=(',', ':'))
 #   assert javascript == data
    msg_signature = decode_hex(
        '0x68b12d6de97e2be66a5d013a7118264ab696a45ebe7f9ef590c88286ba7804154e0a1418d78712d4aa227c33af23ebae2ff8114a7e3f3d9efb7e342235eba5941b')
    assert recover(data=data.encode(), signature=msg_signature) == account
