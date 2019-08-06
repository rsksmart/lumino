from eth_utils import encode_hex

from raiden.encoding.messages import DEFAULT_PAYMENT_INVOICE_HASH
from raiden.billing.invoices.constants.invoice_status import InvoiceStatus
from raiden.billing.invoices.util.time_util import is_invoice_expired
from raiden.billing.invoices.constants.errors import INVOICE_NOT_EXISTS, INVOICE_EXPIRED, INVOICE_PAID

IS_VALID_KEY = 'is_valid'
MSG_KEY = 'msg'
STATUS_KEY = 'status'


def handle_received_invoice(storage, payment_hash_invoice):
    result = {IS_VALID_KEY: True}
    payment_hash_invoice_hex = encode_hex(payment_hash_invoice)

    if not payment_hash_invoice_hex == DEFAULT_PAYMENT_INVOICE_HASH:
        invoice = storage.query_invoice(payment_hash_invoice_hex)
        if invoice is None:
            result[IS_VALID_KEY] = False
            result[MSG_KEY] = INVOICE_NOT_EXISTS
        elif invoice[STATUS_KEY] == InvoiceStatus.PENDING.value:
            storage.update_invoice({'payment_hash' : payment_hash_invoice_hex,
                                    STATUS_KEY : InvoiceStatus.PAID.value})
        elif is_invoice_expired(invoice['expiration_date']):
            result[IS_VALID_KEY] = False
            result[MSG_KEY] = INVOICE_EXPIRED
        elif invoice[STATUS_KEY] == InvoiceStatus.PAID.value:
            result[IS_VALID_KEY] = False
            result[MSG_KEY] = INVOICE_PAID

    return result


def handle_receive_events_with_payments(storage, payment_hash_invoice, event_type, payment_identifier):
    # Get invoice by payment_hash_invoice
    invoice = storage.query_invoice(encode_hex(payment_hash_invoice))
    if invoice is not None:
        # Get event associate
        state_event = storage.get_payment_event(payment_identifier, event_type)

        data_invoice_payment = {'state_event_id': state_event['identifier'],
                                'invoice_id': invoice['identifier']}

        # Associate payment with invoice
        storage.write_invoice_payments(data_invoice_payment)


