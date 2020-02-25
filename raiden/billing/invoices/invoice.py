import time
from binascii import hexlify


class Invoice:
    def __init__(self, paymenthash=None, amount=None, currency=None, tags=None, date=None):
        self.date = int(time.time()) if not date else int(date)
        self.tags = [] if not tags else tags
        self.unknown_tags = []
        self.paymenthash=paymenthash
        self.signature = None
        self.pubkey = None
        self.currency = currency
        self.amount = amount

    def __str__(self):
        return "Invoice[{}, amount={}{} tags=[{}]]".format(
            hexlify(self.pubkey.serialize()).decode('utf-8'),
            self.amount, self.currency,
            ", ".join([k + '=' + str(v) for k, v in self.tags])
        )