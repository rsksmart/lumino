from raiden.utils.typing import TokenAmount, Locksroot, BlockHash


class FlatList(list):
    """
    This class inherits from list and has the same interface as a list-type.
    However, there is a 'data'-attribute introduced, that is required for the encoding of the list!
    The fields of the encoding-Schema must match the fields of the Object to be encoded!
    """

    @property
    def data(self):
        return list(self)

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, list(self))


class AddressList(FlatList):
    pass


class PartnersPerTokenList(FlatList):
    pass


class Address:
    def __init__(self, token_address):
        self.address = token_address


class PartnersPerToken:
    def __init__(self, partner_address, channel):
        self.partner_address = partner_address
        self.channel = channel


class DashboardGraphItem:
    def __init__(self, event_type_code, event_type_class_name, event_type_label, quantity, log_time, month_of_year_code,
                 month_of_year_label):
        self.event_type_code = event_type_code
        self.event_type_class_name = event_type_class_name
        self.event_type_label = event_type_label
        self.quantity = quantity
        self.log_time = log_time
        self.month_of_year_code = month_of_year_code
        self.month_of_year_label = month_of_year_label


class DashboardTableItem:
    identifier = 0
    log_time = ""
    amount = 0
    initiator = ""
    target = ""


class DashboardGeneralItem:
    quantity = 0
    event_type_code = 0
    event_type_class_name = ""


class SettlementParameters:
    """" Object to store settlement parameters for internal use """
    def __init__(self,
                 transferred_amount: TokenAmount,
                 locked_amount: TokenAmount,
                 locksroot: Locksroot,
                 partner_transferred_amount: TokenAmount,
                 partner_locked_amount: TokenAmount,
                 partner_locksroot: Locksroot,
                 block_identifier: BlockHash):
        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot
        self.partner_transferred_amount = partner_transferred_amount
        self.partner_locked_amount = partner_locked_amount
        self.partner_locksroot = partner_locksroot
        self.block_identifier = block_identifier
