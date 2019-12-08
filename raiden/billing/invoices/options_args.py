class OptionsArgs:
    def __init__(self,
                 timestamp,
                 currency,
                 fallback,
                 amount,
                 paymenthash,
                 description,
                 description_hashed,
                 expires,
                 route,
                 privkey,
                 beneficiary,
                 token):
        self.timestamp = timestamp
        self.currency = currency
        self.fallback = fallback
        self.amount = amount
        self.paymenthash = paymenthash
        self.description = description
        self.description_hashed = description_hashed
        self.expires = expires
        self.route = route
        self.privkey = privkey
        self.beneficiary = beneficiary
        self.token = token