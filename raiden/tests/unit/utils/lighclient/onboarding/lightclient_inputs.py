from eth_utils import encode_hex, decode_hex
from raiden.utils.signer import LocalSigner

private_key = decode_hex('0x51dd3591fb7ce95b0bd77ca14a5236a4989d399c80b8150d3799dd0afcb14282')
display_name_to_sign = "@0x6d369723521b4080a19457d5fdd2194d633b0c3a:transport01.raiden.network"
password_to_sign = "transport01.raiden.network"
seed_retry = "seed"

signer = LocalSigner(private_key)

print(f'signed_seed_retry: {encode_hex(signer.sign(seed_retry.encode()))}')
print(f'signed_display_name: {encode_hex(signer.sign(display_name_to_sign.encode()))}')
print(f'signed_password: {encode_hex(signer.sign(password_to_sign.encode()))}')




