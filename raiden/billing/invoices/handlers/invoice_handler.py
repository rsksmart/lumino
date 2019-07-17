from eth_utils import encode_hex

from raiden.encoding.messages import DEFAULT_PAYMENT_INVOICE_HASH
from raiden.billing.invoices.constants.invoice_status import InvoiceStatus


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

    return result


