import re


def is_rns_address(address)->bool:
    if isinstance(address, bytes):
        return re.search(r'\.', address.hex())
    else:
        return re.search(r'\.', address)

