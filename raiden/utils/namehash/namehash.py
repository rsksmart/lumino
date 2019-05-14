import codecs
import functools

from sha3 import keccak_256 as sha3_256


def is_bytes(value):
    return isinstance(value, (bytes, bytearray))


def combine(f, g):
    return lambda x: f(g(x))


def compose(*functions):
    return functools.reduce(combine, functions, lambda x: x)


def sha3(value):
    return sha3_256(value).digest()


def _sub_hash(value, label):
    return sha3(value + sha3(label))


def namehash(name, encoding=None):
    """
    Implementation of the namehash algorithm from EIP137.
    """
    node = b'\x00' * 32
    if name:
        if encoding is None:
            if is_bytes(name):
                encoded_name = name
            else:
                encoded_name = codecs.encode(name, 'utf8')
        else:
            encoded_name = codecs.encode(name, encoding)

        labels = encoded_name.split(b'.')

        return compose(*(
            functools.partial(_sub_hash, label=label)
            for label
            in labels
        ))(node)
    return node