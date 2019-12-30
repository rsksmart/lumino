from eth_utils import encode_hex, decode_hex
from raiden.utils.signer import LocalSigner

private_key = decode_hex('0x63E5F0F39A21A5BA20AE69D02D20FAFF0F164763062D39CA183A91CC549D142A')
display_name_to_sign = "@0x7ca28d3d760b4aa2b79e8d42cbdc187c7df9af40:raidentransport.mycryptoapi.com"
password_to_sign = "raidentransport.mycryptoapi.com"
seed_retry = "seed"

signer = LocalSigner(private_key)

print(f'signed_seed_retry: {encode_hex(signer.sign(seed_retry.encode()))}')
print(f'signed_display_name: {encode_hex(signer.sign(display_name_to_sign.encode()))}')
print(f'signed_password: {encode_hex(signer.sign(password_to_sign.encode()))}')




