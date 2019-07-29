from eth_utils import encode_hex

from raiden.encoding.messages import DEFAULT_PAYMENT_INVOICE_HASH
from raiden.billing.invoices.constants.invoice_status import InvoiceStatus
from raiden.billing.invoices.util.time_util import is_invoice_expired


def handle_received_invoice(storage, payment_hash_invoice):
    result = {'is_valid': True}
    payment_hash_invoice_hex = encode_hex(payment_hash_invoice)

    if not payment_hash_invoice_hex == DEFAULT_PAYMENT_INVOICE_HASH:
        invoice = storage.query_invoice(payment_hash_invoice_hex)
        if invoice is None:
            result['is_valid'] = False
            result['msg'] = "It is not possible to complete the payment. " \
                            "The invoice you are trying to pay not issued by this node."
        elif invoice['status'] == InvoiceStatus.PENDING.value:
            storage.update_invoice({"payment_hash" : payment_hash_invoice_hex,
                                    "status" : InvoiceStatus.PAID.value})
        elif is_invoice_expired(invoice["expiration_date"]):
            result['is_valid'] = False
            result['msg'] = "Payment couldn't be completed (The invoice has expired)."

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


