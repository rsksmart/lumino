from eth_utils import encode_hex, decode_hex
from raiden.utils.signer import LocalSigner

private_key = decode_hex('0x1bc5766d3f31e2e76dfd4d76684d8dde5671135bd30511aae20f424655d0e33b')
display_name_to_sign = "@0x54df5016e08e81ce7cec2d5e0ce4c30fd55b98de:transport02.raiden.network"
password_to_sign = "transport02.raiden.network"
seed_retry = "seed"

signer = LocalSigner(private_key)

print(f'signed_seed_retry: {encode_hex(signer.sign(seed_retry.encode()))}')
print(f'signed_display_name: {encode_hex(signer.sign(display_name_to_sign.encode()))}')
print(f'signed_password: {encode_hex(signer.sign(password_to_sign.encode()))}')