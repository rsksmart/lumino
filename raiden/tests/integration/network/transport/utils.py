import secrets

from coincurve import PublicKey
from eth_typing import Address
from eth_utils import to_canonical_address, to_checksum_address
from sha3 import keccak_256


def generate_address() -> Address:
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    checksummed_addr = to_checksum_address(addr)
    return to_canonical_address(checksummed_addr)
