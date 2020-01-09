from binascii import hexlify

from eth_utils import decode_hex, encode_hex, to_canonical_address, to_normalized_address, to_checksum_address
from gevent import os

from raiden.api.rest import RestAPI
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.mocks import make_raiden_service_mock
from raiden.utils.signer import LocalSigner, Signer, recover
from ecies import encrypt, decrypt


def test_signer_sign_seed_retry():
    # Rsk Address 0x6d369723521B4080A19457D5Fdd2194d633B0c3A
    privkey = decode_hex('0x51dd3591fb7ce95b0bd77ca14a5236a4989d399c80b8150d3799dd0afcb14282')
    message = 'seed'

    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0xd5adc7e384a8e080e187a4de4d0a51820a3585f7c44ddf39f32f94ea58a6611b"
    )

    signer = LocalSigner(privkey)

    # signer: Signer = LocalSigner(privkey)

    print(f'SEED SIGNATURE: {encode_hex(signer.sign(message.encode()))}')

    result = signer.sign(message.encode())[-32:]

    assert result == signature


def test_signer_sign_display_user_matrix_client():
    privkey = decode_hex('0x51dd3591fb7ce95b0bd77ca14a5236a4989d399c80b8150d3799dd0afcb14282')

    rsk_address = "0x6d369723521B4080A19457D5Fdd2194d633B0c3A"
    rsk_address_normalized = to_normalized_address(rsk_address)
    matrix_server_domain = "transport02.raiden.network"

    message_to_sign = f'@{rsk_address_normalized}:{matrix_server_domain}'

    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0xbf289bbf32bbd20d7532f5ec39f3ab3e3d02bb82497c7de80edae06beb05f"
        "c327c63463d360d501c81f9e9d002744f7c0c67443536473558199e56d584f9cc341c"
    )

    signer: Signer = LocalSigner(privkey)

    result = signer.sign(message_to_sign.encode())

    print(f'DISPLAY_NAME_SIGNATURE: {encode_hex(signer.sign(message_to_sign.encode()))}')

    assert result == signature


def test_recover_address_from_display_user_and_signature():
    rsk_address = "0x6d369723521B4080A19457D5Fdd2194d633B0c3A"
    rsk_address_normalized = to_normalized_address(rsk_address)
    matrix_server_domain = "transport02.raiden.network"

    original_message = f'@{rsk_address_normalized}:{matrix_server_domain}'
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0xbf289bbf32bbd20d7532f5ec39f3ab3e3d02bb82497c7de80edae06beb05f"
        "c327c63463d360d501c81f9e9d002744f7c0c67443536473558199e56d584f9cc341c"
    )

    assert recover(data=original_message.encode(), signature=signature) == to_canonical_address(rsk_address_normalized)


def test_signer_sign_matrix_server_domain():
    # Rsk Address 0x6d369723521B4080A19457D5Fdd2194d633B0c3A
    privkey = decode_hex('0x51dd3591fb7ce95b0bd77ca14a5236a4989d399c80b8150d3799dd0afcb14282')

    message = 'transport02.raiden.network'

    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "a5c73a3717f8d466bd8fde0d2e2a358e0e67307e09bab65f8cc83e7de5a7af3b2293"
        "16addd32333cf04a5045bf2a740c91a090bdafd88bb92d26de34068f6c841b"
    )

    signer: Signer = LocalSigner(privkey)

    result = signer.sign(message.encode())

    print(f'PASSWORD_SIGNATURE: {encode_hex(signer.sign(message.encode()))}')

    assert result == signature


def test_recover_address_from_matrix_server_domain_and_signature():
    rsk_address = "0x6d369723521B4080A19457D5Fdd2194d633B0c3A"
    rsk_address_normalized = to_normalized_address(rsk_address)
    matrix_server_domain = "transport02.raiden.network"
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "a5c73a3717f8d466bd8fde0d2e2a358e0e67307e09bab65f8cc83e7de5a7af3b2293"
        "16addd32333cf04a5045bf2a740c91a090bdafd88bb92d26de34068f6c841b"
    )

    assert recover(data=matrix_server_domain.encode(), signature=signature) == \
           to_canonical_address(rsk_address_normalized)


def test_encrypt_and_descrypt_signature():
    # Rsk Address 0x67a03d727b61a4ffd3721f79d52a3baea1b63ea0
    pubkey = 'e00f009e7d4308ac39216bbe964d7ac933ac4dfce8b0c369848f4fcae4664fca2dab' \
             '9a0e3e9db5eef5fb3de25f78dd0161f707a0075a179b1419d72121aa0c80'
    privkey = '3f5d3cda6320fd57f4d47e50c3404e7e43cfb60968d7ef13eb6873760b445e47'
    # This is a result after sign the following data transport02.raiden.network, with this privkey and encode_hex
    signed_data = b'0x30f852f75ea11df467e8a518e3e7ceec9e106f4c2c50027e3277e239af06a' \
                  b'f0730fef7b16f32943b62b03fe0e479a555d5bf7686318327b9c15f514a99da07f11c'

    encrypt_data = encrypt(pubkey, signed_data)
    descrypt_data = decrypt(privkey, encrypt_data)

    assert signed_data == descrypt_data


def test_descrypt_signature_with_saved_ecrypt_data():
    # Rsk Address 0x67a03d727b61a4ffd3721f79d52a3baea1b63ea0
    privkey = '3f5d3cda6320fd57f4d47e50c3404e7e43cfb60968d7ef13eb6873760b445e47'
    # This is a result after sign the following data transport02.raiden.network, with this privkey and encode_hex
    signed_data = b'0x30f852f75ea11df467e8a518e3e7ceec9e106f4c2c50027e3277e239af06a' \
                  b'f0730fef7b16f32943b62b03fe0e479a555d5bf7686318327b9c15f514a99da07f11c'

    # Saved encrypt data
    saved_encrypt_data = bytes.fromhex(
        '047151cb8d5d7de30bc4a50dfd4217d35a5f6fceb25d28b29bf422cf2ce50d329c4cacf009'
        '7f465d943e74d0ab63c942e2af5482cc66a39d59151a9a06252f20bf6fb16cc947e9ea609e'
        'ae8d5484fb3e4dddabe5d4548763e6cab6e908698b42d9bee0ce3c5a4a07c9f11861fc406f'
        'd78cfdb72b85c44360c09b78e132d6159c804b679e1b472155819f2cee7aeb5e6ac03d377a'
        '3a8f2d940fc106e6e035fb2f469100544c82152dc6f8dfce3f1f7c7fbbfea340668f3fa5d0'
        '249b2121b25f57ab38056f6163b879cd2946ec0a8f3aa63bcd2d6df3dd2d83dfba842b7354'
        'cbf7dc611ec675')

    descrypt_data = decrypt(privkey, saved_encrypt_data)

    assert signed_data == descrypt_data


def test_light_client_onboarding_new_user():
    channel_identifier = 1
    payment_network_identifier = make_address()
    token_network_identifier = make_address()
    participant = make_address()
    raiden = make_raiden_service_mock(
        payment_network_identifier=payment_network_identifier,
        token_network_identifier=token_network_identifier,
        channel_identifier=channel_identifier,
        partner=participant,
    )
    pubhex = '0xc11b7ba56c50e93d0cd2b868a04489de8c0d4bbbf53871e0dcf1cbcbbfdbae4c55c4ba944a7708d7923a1c52b3ed983b51730155854df9c52aa4c09818477b34'

    address = '0x5F4df703Da966E12d3068E1aCbe930f2E363c732'

    signed_password = '0xabafc6f1928f4c633eff8e7829b09f4af54faeee458f2e84b8bb5167' \
                      'aac6f43b2631706700869979d0bff416f00d95139be7f2feac566f478ed24efcf0f43d011c'

    signed_display_name = '0x4bc11cb02137565e95272f2df389d4b894da6865ba05b999ce331d' \
                          'fdb145ec015470034bcdff5e4adaac7617eea46d7642e3ab0ce0caf2c165696a0d20f40b731c'

    signed_seed_retry = '0x5cfdfe57a782ca9a4f56ba3ce809238db6246afc7fd17090f1bbd' \
                        'ccad5b120a841ea4d798627c42c2e1e261ec79591879edab4e7bbb2a062a95fdd83a753e9121b'

    address = to_checksum_address(address)

    encrypt_signed_password = encrypt(pubhex, signed_password.encode())
    encrypt_signed_display_name = encrypt(pubhex, signed_display_name.encode())
    encrypt_signed_seed_retry = encrypt(pubhex, signed_seed_retry.encode())

    api_key = hexlify(os.urandom(20))
    api_key = api_key.decode("utf-8")

    result = raiden.wal.storage.save_light_client(
        api_key=api_key,
        address=address,
        encrypt_signed_password=encrypt_signed_password.hex(),
        encrypt_signed_display_name=encrypt_signed_display_name.hex(),
        encrypt_signed_seed_retry=encrypt_signed_seed_retry.hex())

    assert result is not None