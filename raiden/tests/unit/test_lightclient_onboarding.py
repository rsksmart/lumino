from eth_utils import decode_hex, encode_hex, to_canonical_address
from raiden.utils.signer import LocalSigner, Signer, recover
from ecies import encrypt, decrypt


def test_signer_sign_matrix_server_domain():
    #Rsk Address 0x67a03d727b61a4ffd3721f79d52a3baea1b63ea0
    privkey = decode_hex('0x3f5d3cda6320fd57f4d47e50c3404e7e43cfb60968d7ef13eb6873760b445e47')

    message = 'transport02.raiden.network'

    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0x30f852f75ea11df467e8a518e3e7ceec9e106f4c2c50027e3277e239af06af0730fe"
        "f7b16f32943b62b03fe0e479a555d5bf7686318327b9c15f514a99da07f11c"
    )

    signer: Signer = LocalSigner(privkey)

    result = signer.sign(message.encode())

    assert result == signature


def test_recover_address_from_matrix_server_domain_and_signature():
    account = to_canonical_address("0x67a03d727b61a4ffd3721f79d52a3baea1b63ea0")
    message = 'transport02.raiden.network'
    # generated with Metamask's web3.personal.sign
    signature = decode_hex(
        "0x30f852f75ea11df467e8a518e3e7ceec9e106f4c2c50027e3277e239af06af073"
        "0fef7b16f32943b62b03fe0e479a555d5bf7686318327b9c15f514a99da07f11c"
    )

    assert recover(data=message.encode(), signature=signature) == account


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
