from raiden.messages import Message, LockedTransfer, RevealSecret, Unlock, SecretRequest, RefundTransfer, LockExpired, \
    Processed
from raiden.transfer.architecture import SendMessageEvent
from raiden.transfer.events import SendProcessed
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendLockedTransferLight, SendSecretReveal, \
    SendBalanceProof, SendBalanceProofLight, SendSecretRequest, SendRefundTransfer, SendLockExpired
from raiden.utils.typing import MYPY_ANNOTATION


def message_from_sendevent(send_event: SendMessageEvent) -> Message:
    if type(send_event) == SendLockedTransfer:
        assert isinstance(send_event, SendLockedTransfer), MYPY_ANNOTATION
        message = LockedTransfer.from_event(send_event)
    elif type(send_event) == SendLockedTransferLight:
        assert isinstance(send_event, SendLockedTransferLight), MYPY_ANNOTATION
        message = send_event.signed_locked_transfer
    elif type(send_event) == SendSecretReveal:
        assert isinstance(send_event, SendSecretReveal), MYPY_ANNOTATION
        message = RevealSecret.from_event(send_event)
    elif type(send_event) == SendBalanceProof:
        assert isinstance(send_event, SendBalanceProof), MYPY_ANNOTATION
        message = Unlock.from_event(send_event)
    elif type(send_event) == SendBalanceProofLight:
        assert isinstance(send_event, SendBalanceProofLight), MYPY_ANNOTATION
        message = send_event.signed_balance_proof
    elif type(send_event) == SendSecretRequest:
        assert isinstance(send_event, SendSecretRequest), MYPY_ANNOTATION
        message = SecretRequest.from_event(send_event)
    elif type(send_event) == SendRefundTransfer:
        assert isinstance(send_event, SendRefundTransfer), MYPY_ANNOTATION
        message = RefundTransfer.from_event(send_event)
    elif type(send_event) == SendLockExpired:
        assert isinstance(send_event, SendLockExpired), MYPY_ANNOTATION
        message = LockExpired.from_event(send_event)
    elif type(send_event) == SendProcessed:
        assert isinstance(send_event, SendProcessed), MYPY_ANNOTATION
        message = Processed.from_event(send_event)
    else:
        raise ValueError(f"Unknown event type {send_event}")

    return message