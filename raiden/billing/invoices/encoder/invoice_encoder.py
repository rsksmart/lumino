from decimal import Decimal
from raiden.billing.invoices.util.bech32 import CHARSET, bech32_encode, bech32_decode
from binascii import unhexlify
from raiden.billing.invoices.invoice import Invoice
from raiden.billing.invoices.util.encoding_util import u5_to_bitarray, base58_prefix_map, bitarray_to_u5
from eth_utils import decode_hex

import bitstring
import hashlib
import secp256k1
import base58


def parse_options(options):
    """ Convert options into Lumino Invoice and pass it to the encoder
       """
    invoice = Invoice()
    invoice.currency = options.currency
    invoice.fallback = options.fallback if options.fallback else None
    if options.amount:
        invoice.amount = options.amount
    if options.timestamp:
        invoice.date = int(options.timestamp)

    invoice.paymenthash = decode_hex(options.paymenthash)

    if options.description:
        invoice.tags.append(('d', options.description))
    if options.description_hashed:
        invoice.tags.append(('h', options.description_hashed))
    if options.expires:
        invoice.tags.append(('x', options.expires))

    if options.fallback:
        invoice.tags.append(('f', options.fallback))

    if options.beneficiary:
        invoice.tags.append(('n', options.beneficiary))

    if options.token:
        invoice.tags.append(('t', options.token))

    for r in options.route:
        print("R " + r)
        splits = r.split('/')
        route = []
        while len(splits) >= 5:
            route.append((unhexlify(splits[0]),
                          unhexlify(splits[1]),
                          int(splits[2]),
                          int(splits[3]),
                          int(splits[4])))
            splits = splits[5:]
        assert (len(splits) == 0)
        invoice.tags.append(('r', route))

    return invoice


def encode_invoice(addr, privkey):

    if addr.amount:
        amount = Decimal(str(addr.amount))
        # the minimum amount for an invoice is the equivalent of 1 millisatoshi, in wei
        # this is done for compatibility reasons with Lightning Invoices
        if amount < 10000000:
            raise ValueError("cannot generate invoice, amount {} is too low to comply with BOLT #11".format(
                addr.amount))

        amount = addr.currency + shorten_amount(amount)
    else:
        amount = addr.currency if addr.currency else ''

    hrp = 'lm' + amount

    # Start with the timestamp
    data = bitstring.pack('uint:35', addr.date)

    # print("TimeStamp " + data) not work

    # Payment hash
    data += tagged_bytes('p', addr.paymenthash)
    tags_set = set()

    for k, v in addr.tags:

        # BOLT #11:
        #
        # A writer MUST NOT include more than one `d`, `h`, `n` or `x` fields,
        if k in ('d', 'h', 'n', 'x'):
            if k in tags_set:
                raise ValueError("Duplicate '{}' tag".format(k))

        if k == 'r':
            route = bitstring.BitArray()
            for step in v:
                pubkey, channel, feebase, feerate, cltv = step
                route.append(bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:32',
                                                                                                       feebase) + bitstring.pack(
                    'intbe:32', feerate) + bitstring.pack('intbe:16', cltv))
            data += tagged('r', route)
        elif k == 'f':
            data += encode_fallback(v, addr.currency)
        elif k == 'd':
            data += tagged_bytes('d', v.encode())
        elif k == 'x':
            # Get minimal length by trimming leading 5 bits at a time.
            expirybits = bitstring.pack('intbe:64', v)[4:64]
            while expirybits.startswith('0b00000'):
                expirybits = expirybits[5:]
            data += tagged('x', expirybits)
        elif k == 'h':
            data += tagged_bytes('h', hashlib.sha256(v.encode('utf-8')).digest())
        elif k == 'n':
            data += tagged_bytes('n', v)
        elif k == 't':
            data += tagged_bytes('t', v)
        else:
            # FIXME: Support unknown tags?
            raise ValueError("Unknown tag {}".format(k))

        tags_set.add(k)

    # BOLT #11:
    #
    # A writer MUST include either a `d` or `h` field, and MUST NOT include
    # both.
    if 'd' in tags_set and 'h' in tags_set:
        raise ValueError("Cannot include both 'd' and 'h'")
    if not 'd' in tags_set and not 'h' in tags_set:
        raise ValueError("Must include either 'd' or 'h'")

    # We actually sign the hrp, then data (padded to 8 bits with zeroes).
    privkey = secp256k1.PrivateKey(bytes(unhexlify(privkey)))
    sig = privkey.ecdsa_sign_recoverable(bytearray([ord(c) for c in hrp]) + data.tobytes())
    # This doesn't actually serialize, but returns a pair of values :(
    sig, recid = privkey.ecdsa_recoverable_serialize(sig)
    data += bytes(sig) + bytes([recid])

    # print("Data after sig " + bitarray_to_u5(data)) no funca
    return bech32_encode(hrp, bitarray_to_u5(data))


# BOLT #11:
#
# A writer MUST encode `amount` as a positive decimal integer with no
# leading zeroes, SHOULD use the shortest representation possible.
def shorten_amount(amount):
    """ Given an amount in bitcoin, shorten it
    """
    # Convert to pico initially
    amount = int(amount * 10**12)
    units = ['p', 'n', 'u', 'm', '']
    for unit in units:
        if amount % 1000 == 0:
            amount //= 1000
        else:
            break
    return str(amount) + unit


# Tagged field containing bytes
def tagged_bytes(char, l):
    return tagged(char, bitstring.BitArray(l))


# Tagged field containing BitArray
def tagged(char, l):
    # Tagged fields need to be zero-padded to 5 bits.
    while l.len % 5 != 0:
        l.append('0b0')
    return bitstring.pack("uint:5, uint:5, uint:5",
                          CHARSET.find(char),
                          (l.len / 5) / 32, (l.len / 5) % 32) + l


def encode_fallback(fallback, currency):
    """ Encode all supported fallback addresses.
    """
    if currency == 'bc' or currency == 'tb':
        fbhrp, witness = bech32_decode(fallback)
        if fbhrp:
            if fbhrp != currency:
                raise ValueError("Not a bech32 address for this currency")
            wver = witness[0]
            if wver > 16:
                raise ValueError("Invalid witness version {}".format(witness[0]))
            wprog = u5_to_bitarray(witness[1:])
        else:
            addr = base58.b58decode_check(fallback)
            if is_p2pkh(currency, addr[0]):
                wver = 17
            elif is_p2sh(currency, addr[0]):
                wver = 18
            else:
                raise ValueError("Unknown address type for {}".format(currency))
            wprog = addr[1:]
        return tagged('f', bitstring.pack("uint:5", wver) + wprog)
    else:
        raise NotImplementedError("Support for currency {} not implemented".format(currency))


def is_p2pkh(currency, prefix):
    return prefix == base58_prefix_map[currency][0]


def is_p2sh(currency, prefix):
    return prefix == base58_prefix_map[currency][1]