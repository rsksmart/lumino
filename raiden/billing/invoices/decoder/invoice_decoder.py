from raiden.billing.invoices.util.bech32 import bech32_decode, CHARSET, bech32_encode
from raiden.billing.invoices.util.encoding_util import u5_to_bitarray, base58_prefix_map, bitarray_to_u5
from raiden.billing.invoices.invoice import Invoice
from raiden.billing.invoices.constants.errors import BAD_BECH32_CHECKSUM, PREFIX_ERROR, SIGNATURE_LENGTH, INVALID_SIGNATURE

import bitstring
import re
from decimal import Decimal
import base58
import hashlib
import secp256k1
from binascii import hexlify


def decode_invoice(coded_invoice, verbose=True):
    hrp, data = bech32_decode(coded_invoice)
    if not hrp:
        raise ValueError(BAD_BECH32_CHECKSUM)

    # BOLT #11:
    #
    # A reader MUST fail if it does not understand the `prefix`.
    if not hrp.startswith('lm'):
        raise ValueError(PREFIX_ERROR)

    data = u5_to_bitarray(data);

    # Final signature 65 bytes, split it off.
    if len(data) < 65 * 8:
        raise ValueError(SIGNATURE_LENGTH)
    sigdecoded = data[-65 * 8:].tobytes()
    data = bitstring.ConstBitStream(data[:-65 * 8])

    invoice = Invoice()
    invoice.pubkey = None

    m = re.search("[^\d]+", hrp[2:])
    if m:
        invoice.currency = m.group(0)
        amountstr = hrp[2 + m.end():]
        # BOLT #11:
        #
        # A reader SHOULD indicate if amount is unspecified, otherwise it MUST
        # multiply `amount` by the `multiplier` value (if any) to derive the
        # amount required for payment.
        if amountstr != '':
            invoice.amount = unshorten_amount(amountstr)
    print("DECODE_INVOICE()", invoice.amount)

    invoice.date = data.read(35).uint

    while data.pos != data.len:
        tag, tagdata, data = pull_tagged(data)

        # BOLT #11:
        #
        # A reader MUST skip over unknown fields, an `f` field with unknown
        # `version`, or a `p`, `h`, or `n` field which does not have
        # `data_length` 52, 52, or 53 respectively.
        data_length = len(tagdata) / 5

        if tag == 'r':
            # BOLT #11:
            #
            # * `r` (3): `data_length` variable.  One or more entries
            # containing extra routing information for a private route;
            # there may be more than one `r` field, too.
            #    * `pubkey` (264 bits)
            #    * `short_channel_id` (64 bits)
            #    * `feebase` (32 bits, big-endian)
            #    * `feerate` (32 bits, big-endian)
            #    * `cltv_expiry_delta` (16 bits, big-endian)
            route = []
            s = bitstring.ConstBitStream(tagdata)
            while s.pos + 264 + 64 + 32 + 32 + 16 < s.len:
                route.append((s.read(264).tobytes(),
                              s.read(64).tobytes(),
                              s.read(32).intbe,
                              s.read(32).intbe,
                              s.read(16).intbe))
            invoice.tags.append(('r', route))
        elif tag == 'f':
            fallback = parse_fallback(tagdata, invoice.currency)
            if fallback:
                invoice.tags.append(('f', fallback))
            else:
                # Incorrect version.
                invoice.unknown_tags.append((tag, tagdata))
                continue

        elif tag == 'd':
            invoice.tags.append(('d', trim_to_bytes(tagdata).decode('utf-8')))

        elif tag == 'h':
            if data_length != 52:
                invoice.unknown_tags.append((tag, tagdata))
                continue
            invoice.tags.append(('h', trim_to_bytes(tagdata)))

        elif tag == 'x':
            invoice.tags.append(('x', tagdata.uint))

        elif tag == 'p':
            if data_length != 52:
                invoice.unknown_tags.append((tag, tagdata))
                continue
            invoice.paymenthash = trim_to_bytes(tagdata)

        elif tag == 'n':
            if data_length != 53:
                invoice.unknown_tags.append((tag, tagdata))
                continue
            invoice.pubkey = secp256k1.PublicKey(flags=secp256k1.ALL_FLAGS)
            invoice.pubkey.deserialize(trim_to_bytes(tagdata))
        else:
            invoice.unknown_tags.append((tag, tagdata))

    if verbose:
        print('hex of signature data (32 byte r, 32 byte s): {}'
              .format(hexlify(sigdecoded[0:64])))
        print('recovery flag: {}'.format(sigdecoded[64]))
        print('hex of data for signing: {}'
              .format(hexlify(bytearray([ord(c) for c in hrp])
                              + data.tobytes())))
        print('SHA256 of above: {}'.format(
            hashlib.sha256(bytearray([ord(c) for c in hrp]) + data.tobytes()).hexdigest()))

    # BOLT #11:
    #
    # A reader MUST check that the `signature` is valid (see the `n` tagged
    # field specified below).
    if invoice.pubkey:  # Specified by `n`
        # BOLT #11:
        #
        # A reader MUST use the `n` field to validate the signature instead of
        # performing signature recovery if a valid `n` field is provided.
        invoice.signature = invoice.pubkey.ecdsa_deserialize_compact(sigdecoded[0:64])
        if not invoice.pubkey.ecdsa_verify(bytearray([ord(c) for c in hrp]) + data.tobytes(), invoice.signature):
            raise ValueError(INVALID_SIGNATURE)
    else:  # Recover pubkey from signature.
        invoice.pubkey = secp256k1.PublicKey(flags=secp256k1.ALL_FLAGS)
        invoice.signature = invoice.pubkey.ecdsa_recoverable_deserialize(
            sigdecoded[0:64], sigdecoded[64])
        invoice.pubkey.public_key = invoice.pubkey.ecdsa_recover(
            bytearray([ord(c) for c in hrp]) + data.tobytes(), invoice.signature)

    return invoice


def unshorten_amount(amount):
    """ Given a shortened amount, convert it into a decimal
    """
    # BOLT #11:
    # The following `multiplier` letters are defined:
    #
    #* `m` (milli): multiply by 0.001
    #* `u` (micro): multiply by 0.000001
    #* `n` (nano): multiply by 0.000000001
    #* `p` (pico): multiply by 0.000000000001
    print("UNSHORTEN_AMOUNT BEGIN", amount)
    units = {
        'p': 10**12,
        'n': 10**9,
        'u': 10**6,
        'm': 10**3,
    }
    unit = str(amount)[-1]
    # BOLT #11:
    # A reader SHOULD fail if `amount` contains a non-digit, or is followed by
    # anything except a `multiplier` in the table above.
    if not re.fullmatch("\d+[pnum]?", str(amount)):
        raise ValueError("Invalid amount '{}'".format(amount))

    if unit in units.keys():
        return Decimal(amount[:-1]) / units[unit]
    else:
        print("UNSHORTEN_AMOUNT END", Decimal(amount))
        return Decimal(amount)


# Try to pull out tagged data: returns tag, tagged data and remainder.
def pull_tagged(stream):
    tag = stream.read(5).uint
    length = stream.read(5).uint * 32 + stream.read(5).uint
    return (CHARSET[tag], stream.read(length * 5), stream)


def parse_fallback(fallback, currency):
    if currency == 'bc' or currency == 'tb':
        wver = fallback[0:5].uint
        if wver == 17:
            addr=base58.b58encode_check(bytes([base58_prefix_map[currency][0]])
                                        + fallback[5:].tobytes())
        elif wver == 18:
            addr=base58.b58encode_check(bytes([base58_prefix_map[currency][1]])
                                        + fallback[5:].tobytes())
        elif wver <= 16:
            addr=bech32_encode(currency, bitarray_to_u5(fallback))
        else:
            return None
    else:
        addr=fallback.tobytes()
    return addr


# Discard trailing bits, convert to bytes.
def trim_to_bytes(barr):
    # Adds a byte if necessary.
    b = barr.tobytes()
    if barr.len % 8 != 0:
        return b[:-1]
    return b


def get_tags_dict(tags):
    tags_dict = {}
    for tags in tags:
        key = tags[0]
        value = tags[1]
        if key == 'x':
            tags_dict['expires'] = value
        elif key == 'd':
            tags_dict['description'] = value

    return tags_dict


def get_unknown_tags_dict(unknown_tags):
    unknown_tags_dict = {}
    for unknown_tag in unknown_tags:
        key = unknown_tag[0]
        value = unknown_tag[1]
        if key == 'n':
            unknown_tags_dict['target_address'] = value
        elif key == 't':
            unknown_tags_dict['token_address'] = value

    return unknown_tags_dict
