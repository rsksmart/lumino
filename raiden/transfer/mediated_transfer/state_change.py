# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

from eth_utils import to_canonical_address, to_checksum_address
from raiden.messages import RevealSecret, Unlock, LockedTransfer, SecretRequest, LockExpired, RefundTransfer

from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    BalanceProofStateChange,
    StateChange,
)
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
    TransferDescriptionWithoutSecretState)
from raiden.transfer.state import BalanceProofSignedState, RouteState, NettingChannelState
from raiden.utils import pex, sha3
from raiden.utils.serialization import deserialize_bytes, serialize_bytes
from raiden.utils.typing import (
    Address,
    Any,
    BlockExpiration,
    Dict,
    List,
    MessageID,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
)


# Note: The init states must contain all the required data for trying doing
# useful work, ie. there must /not/ be an event for requesting new data.


class ActionInitInitiator(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        transfer_description: A state object containing the transfer details.
        routes: A list of possible routes provided by a routing service.
    """

    def __init__(
        self, transfer_description: TransferDescriptionWithSecretState, routes: List[RouteState]
    ) -> None:
        if not isinstance(transfer_description, TransferDescriptionWithSecretState):
            raise ValueError("transfer must be an TransferDescriptionWithSecretState instance.")

        self.transfer = transfer_description
        self.routes = routes

    def __repr__(self) -> str:
        return "<ActionInitInitiator transfer:{}>".format(self.transfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitInitiator)
            and self.transfer == other.transfer
            and self.routes == other.routes
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"transfer": self.transfer, "routes": self.routes}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitInitiator":
        return cls(transfer_description=data["transfer"], routes=data["routes"])


class ActionInitInitiatorLight(StateChange):
    """ Initial state of a new mediated transfer.

    Args:
        transfer_description: A state object containing the transfer light details.
        routes: A list of possible routes provided by a routing service.
    """

    def __init__(
        self, transfer_description: TransferDescriptionWithoutSecretState, current_channel: NettingChannelState,
        signed_locked_transfer: LockedTransfer, is_retry_route: bool = False
    ) -> None:
        if not isinstance(transfer_description, TransferDescriptionWithoutSecretState):
            raise ValueError("transfer must be an TransferDescriptionWithoutSecretState instance.")

        self.transfer = transfer_description
        self.current_channel = current_channel
        self.signed_locked_transfer = signed_locked_transfer
        self.is_retry_route = is_retry_route

    def __repr__(self) -> str:
        return "<ActionInitInitiatorLight transfer:{}>".format(self.transfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitInitiatorLight)
            and self.transfer == other.transfer
            and self.current_channel == other.current_channel
            and self.signed_locked_transfer == other.signed_locked_transfer
            and self.is_retry_route == other.is_retry_route
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"transfer": self.transfer, "current_channel": self.current_channel, "signed_locked_transfer": self.signed_locked_transfer, "is_retry_route": str(self.is_retry_route)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitInitiatorLight":
        return cls(transfer_description=data["transfer"], current_channel=data["current_channel"],
                   signed_locked_transfer=data["signed_locked_transfer"], is_retry_route=data["is_retry_route"])


class ActionInitMediator(BalanceProofStateChange):
    """ Initial state for a new mediator.

    Args:
        routes: A list of possible routes provided by a routing service.
        from_route: The payee route.
        from_transfer: The payee transfer.
    """

    def __init__(
        self,
        routes: List[RouteState],
        from_route: RouteState,
        from_transfer: LockedTransferSignedState,
    ) -> None:

        if not isinstance(from_route, RouteState):
            raise ValueError("from_route must be a RouteState instance")

        if not isinstance(from_transfer, LockedTransferSignedState):
            raise ValueError("from_transfer must be a LockedTransferSignedState instance")

        super().__init__(from_transfer.balance_proof)
        self.routes = routes
        self.from_route = from_route
        self.from_transfer = from_transfer

    def __repr__(self) -> str:
        return "<ActionInitMediator from_route:{} from_transfer:{}>".format(
            self.from_route, self.from_transfer
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitMediator)
            and self.routes == other.routes
            and self.from_route == other.from_route
            and self.from_transfer == other.from_transfer
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "routes": self.routes,
            "from_route": self.from_route,
            "from_transfer": self.from_transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitMediator":
        return cls(
            routes=data["routes"],
            from_route=data["from_route"],
            from_transfer=data["from_transfer"],
        )


class ActionInitTarget(BalanceProofStateChange):
    """ Initial state for a new target.

    Args:
        route: The payee route.
        transfer: The payee transfer.
    """

    def __init__(self, route: RouteState, transfer: LockedTransferSignedState) -> None:
        if not isinstance(route, RouteState):
            raise ValueError("route must be a RouteState instance")

        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be a LockedTransferSignedState instance")

        super().__init__(transfer.balance_proof)
        self.route = route
        self.transfer = transfer

    def __repr__(self) -> str:
        return "<ActionInitTarget route:{} transfer:{}>".format(self.route, self.transfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitTarget)
            and self.route == other.route
            and self.transfer == other.transfer
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route": self.route,
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitTarget":
        return cls(route=data["route"], transfer=data["transfer"])


class ActionInitTargetLight(BalanceProofStateChange):
    """ Initial state for a new target that is a handled light client.

    Args:
        route: The payee route.
        transfer: The payee transfer.
    """

    def __init__(self, route: RouteState, transfer: LockedTransferSignedState,
                 signed_lockedtransfer: LockedTransfer) -> None:
        if not isinstance(route, RouteState):
            raise ValueError("route must be a RouteState instance")

        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be a LockedTransferSignedState instance")

        super().__init__(transfer.balance_proof)
        self.route = route
        self.transfer = transfer
        self.signed_lockedtransfer = signed_lockedtransfer

    def __repr__(self) -> str:
        return "<ActionInitTargetLight route:{} transfer:{} signed_lockedtransfer:{}>".format(self.route, self.transfer,
                                                                                              self.signed_lockedtransfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitTargetLight)
            and self.route == other.route
            and self.transfer == other.transfer
            and self.signed_lockedtransfer == other.signed_lockedtransfer
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route": self.route,
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
            "signed_lockedtransfer": self.signed_lockedtransfer
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitTargetLight":
        return cls(route=data["route"], transfer=data["transfer"], signed_lockedtransfer=data["signed_lockedtransfer"])


class ReceiveTransferCancelRoute(BalanceProofStateChange):
    """ A mediator sends us a refund due to a failed route """

    def __init__(
        self,
        balance_proof: BalanceProofSignedState,
        transfer: LockedTransferSignedState,
        sender: Address,
    ) -> None:
        super().__init__(balance_proof)
        self.transfer = transfer
        self.sender = sender

    def to_dict(self) -> Dict[str, Any]:
        return {
            "balance_proof": self.balance_proof,
            "transfer": self.transfer,
            "sender": to_checksum_address(self.sender),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveTransferCancelRoute":
        return cls(
            balance_proof=data["balance_proof"],
            transfer=data["transfer"],
            sender=to_canonical_address(data["sender"]),
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveTransferCancelRoute)
            and self.balance_proof == other.balance_proof
            and self.transfer == other.transfer
            and self.sender == other.sender
            and super().__eq__(other)
        )


class ReceiveLockExpired(BalanceProofStateChange):
    """ A LockExpired message received. """

    def __init__(
        self,
        balance_proof: BalanceProofSignedState,
        secrethash: SecretHash,
        message_identifier: MessageID,
    ) -> None:
        super().__init__(balance_proof)
        self.secrethash = secrethash
        self.message_identifier = message_identifier

    def __repr__(self) -> str:
        return "<ReceiveLockExpired sender:{} balance_proof:{}>".format(
            pex(self.sender), self.balance_proof
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveLockExpired)
            and self.secrethash == other.secrethash
            and self.message_identifier == other.message_identifier
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "balance_proof": self.balance_proof,
            "secrethash": serialize_bytes(self.secrethash),
            "message_identifier": str(self.message_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveLockExpired":
        return cls(
            balance_proof=data["balance_proof"],
            secrethash=SecretHash(deserialize_bytes(data["secrethash"])),
            message_identifier=MessageID(int(data["message_identifier"])),
        )


class ReceiveLockExpiredLight(BalanceProofStateChange):
    """ A LockExpired message received. """

    def __init__(
        self,
        balance_proof: BalanceProofSignedState,
        secrethash: SecretHash,
        message_identifier: MessageID,
        lock_expired: LockExpired
    ) -> None:
        super().__init__(balance_proof)
        self.secrethash = secrethash
        self.message_identifier = message_identifier
        self.lock_expired = lock_expired

    def __repr__(self) -> str:
        return "<ReceiveLockExpiredLight sender:{} balance_proof:{}>".format(
            pex(self.sender), self.balance_proof
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveLockExpiredLight)
            and self.secrethash == other.secrethash
            and self.message_identifier == other.message_identifier
            and self.lock_expired == other.lock_expired
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "balance_proof": self.balance_proof,
            "secrethash": serialize_bytes(self.secrethash),
            "message_identifier": str(self.message_identifier),
            "lock_expired": self.lock_expired.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveLockExpiredLight":
        return cls(
            balance_proof=data["balance_proof"],
            secrethash=SecretHash(deserialize_bytes(data["secrethash"])),
            message_identifier=MessageID(int(data["message_identifier"])),
            lock_expired=LockExpired.from_dict(data["lock_expired"])
        )


class ReceiveSecretRequest(AuthenticatedSenderStateChange):
    """ A SecretRequest message received. """

    def __init__(
        self,
        payment_identifier: PaymentID,
        amount: PaymentAmount,
        expiration: BlockExpiration,
        secrethash: SecretHash,
        sender: Address,
    ) -> None:
        super().__init__(sender)
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.revealsecret = None

    def __repr__(self) -> str:
        return "<ReceiveSecretRequest paymentid:{} amount:{} secrethash:{} sender:{}>".format(
            self.payment_identifier, self.amount, pex(self.secrethash), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretRequest)
            and self.payment_identifier == other.payment_identifier
            and self.amount == other.amount
            and self.secrethash == other.secrethash
            and self.sender == other.sender
            and self.revealsecret == other.revealsecret
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payment_identifier": str(self.payment_identifier),
            "amount": str(self.amount),
            "expiration": str(self.expiration),
            "secrethash": serialize_bytes(self.secrethash),
            "sender": to_checksum_address(self.sender),
            "revealsecret": self.revealsecret,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveSecretRequest":
        instance = cls(
            payment_identifier=PaymentID(int(data["payment_identifier"])),
            amount=PaymentAmount(int(data["amount"])),
            expiration=BlockExpiration(int(data["expiration"])),
            secrethash=SecretHash(deserialize_bytes(data["secrethash"])),
            sender=to_canonical_address(data["sender"]),
        )
        instance.revealsecret = data["revealsecret"]
        return instance


class ReceiveSecretRequestLight(AuthenticatedSenderStateChange):
    """ A secret request message received for a light client """

    def __init__(
        self,
        payment_identifier: PaymentID,
        amount: PaymentAmount,
        expiration: BlockExpiration,
        secrethash: SecretHash,
        sender: Address,
        recipient: Address,
        secret_request_message: SecretRequest
    ) -> None:
        super().__init__(sender)
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.secret_request_message = secret_request_message
        self.recipient = recipient
        self.revealsecret = None

    def __repr__(self) -> str:
        return "<ReceiveSecretRequestLight paymentid:{} amount:{} secrethash:{} sender:{} recipient:{} >".format(
            self.payment_identifier, self.amount, pex(self.secrethash), pex(self.sender), pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretRequestLight)
            and self.payment_identifier == other.payment_identifier
            and self.amount == other.amount
            and self.secrethash == other.secrethash
            and self.sender == other.sender
            and self.recipient == other.recipient
            and self.revealsecret == other.revealsecret
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payment_identifier": str(self.payment_identifier),
            "amount": str(self.amount),
            "expiration": str(self.expiration),
            "secrethash": serialize_bytes(self.secrethash),
            "sender": to_checksum_address(self.sender),
            "recipient": to_checksum_address(self.recipient),
            "revealsecret": self.revealsecret,
            "secret_request_message": self.secret_request_message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveSecretRequestLight":
        instance = cls(
            payment_identifier=PaymentID(int(data["payment_identifier"])),
            amount=PaymentAmount(int(data["amount"])),
            expiration=BlockExpiration(int(data["expiration"])),
            secrethash=SecretHash(deserialize_bytes(data["secrethash"])),
            sender=to_canonical_address(data["sender"]),
            recipient=to_canonical_address(data["recipient"]),
            secret_request_message=data["secret_request_message"]
        )
        instance.revealsecret = data["revealsecret"]
        return instance


class ReceiveSecretReveal(AuthenticatedSenderStateChange):
    """ A SecretReveal message received. """

    def __init__(self, secret: Secret, sender: Address) -> None:
        super().__init__(sender)
        secrethash = sha3(secret)

        self.secret = secret
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<ReceiveSecretReveal secrethash:{} sender:{}>".format(
            pex(self.secrethash), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretReveal)
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": serialize_bytes(self.secret),
            "secrethash": serialize_bytes(self.secrethash),
            "sender": to_checksum_address(self.sender),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveSecretReveal":
        instance = cls(
            secret=Secret(deserialize_bytes(data["secret"])),
            sender=to_canonical_address(data["sender"]),
        )
        instance.secrethash = deserialize_bytes(data["secrethash"])
        return instance


class ReceiveSecretRevealLight(AuthenticatedSenderStateChange):
    """ A SecretReveal light client message received. """

    def __init__(self, secret: Secret, sender: Address, recipient: Address, secret_reveal_message: RevealSecret) -> None:
        super().__init__(sender)
        secrethash = sha3(secret)

        self.secret = secret
        self.secrethash = secrethash
        self.recipient = recipient
        self.secret_reveal_message = secret_reveal_message

    def __repr__(self) -> str:
        return "<ReceiveSecretRevealLight secrethash:{} sender:{} recipient: {}>".format(
            pex(self.secrethash), pex(self.sender), pex(self.recipient)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretRevealLight)
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and self.recipient == other.recipient
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": serialize_bytes(self.secret),
            "secrethash": serialize_bytes(self.secrethash),
            "sender": to_checksum_address(self.sender),
            "recipient": to_checksum_address(self.recipient),
            "secret_reveal_message": self.secret_reveal_message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveSecretRevealLight":
        instance = cls(
            secret=Secret(deserialize_bytes(data["secret"])),
            sender=to_canonical_address(data["sender"]),
            recipient=to_canonical_address(data["recipient"]),
            secret_reveal_message=data["secret_reveal_message"]
        )
        instance.secrethash = deserialize_bytes(data["secrethash"])
        return instance


class ActionTransferReroute(BalanceProofStateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """

    def __init__(
        self, transfer: LockedTransferSignedState, secret: Secret
    ) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        secrethash = sha3(secret)

        super().__init__(transfer.balance_proof)
        self.transfer = transfer
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self) -> str:
        return "<ActionTransferReroute sender:{} transfer:{}>".format(
            pex(self.sender), self.transfer
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionTransferReroute)
            and self.sender == other.sender
            and self.transfer == other.transfer
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": serialize_bytes(self.secret),
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionTransferReroute":
        instance = cls(
            transfer=data["transfer"],
            secret=Secret(deserialize_bytes(data["secret"])),
        )
        return instance



class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """

    def __init__(self, transfer: LockedTransferSignedState) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        super().__init__(transfer.balance_proof)
        self.transfer = transfer

    def __repr__(self) -> str:
        return "<ReceiveTransferRefund sender:{} transfer:{}>".format(
            pex(self.sender), self.transfer
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveTransferRefund)
            and self.transfer == other.transfer
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveTransferRefund":
        instance = cls(transfer=data["transfer"])
        return instance


class ActionSendSecretRevealLight(AuthenticatedSenderStateChange):
    """ A SecretReveal message must be sent from a light client. """

    def __init__(self, reveal_secret: RevealSecret, sender: Address, receiver: Address) -> None:
        super().__init__(sender)
        self.receiver = receiver
        self.reveal_secret = reveal_secret

    def __repr__(self) -> str:
        return "<ActionSendSecretRevealLight reveal_secret:{} sender:{}>".format(
            pex(self.reveal_secret.__repr__()), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionSendSecretRevealLight)
            and self.reveal_secret.__eq__(other.reveal_secret)
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reveal_secret": self.reveal_secret,
            "sender": to_checksum_address(self.sender),
            "receiver": to_checksum_address(self.receiver)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionSendSecretRevealLight":
        instance = cls(
            reveal_secret=data["reveal_secret"],
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"])
        )
        return instance


class ActionSendSecretRequestLight(AuthenticatedSenderStateChange):
    """ A SecretRequest message must be sent from a  light client. """

    def __init__(self, secret_request: SecretRequest, sender: Address, receiver: Address) -> None:
        super().__init__(sender)
        self.receiver = receiver
        self.secret_request = secret_request

    def __repr__(self) -> str:
        return "<ActionSendSecretRequestLight reveal_secret:{} sender:{}>".format(
            pex(self.secret_request.__repr__()), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionSendSecretRequestLight)
            and self.secret_request.__eq__(other.secret_request)
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_request": self.secret_request.to_dict(),
            "sender": to_checksum_address(self.sender),
            "receiver": to_checksum_address(self.receiver)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionSendSecretRequestLight":
        instance = cls(
            secret_request=SecretRequest.from_dict(data["secret_request"]),
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"])
        )
        return instance


class ActionSendLockExpiredLight(AuthenticatedSenderStateChange):
    """ A LockExpired message must be sent from a  light client. """

    def __init__(self, signed_lock_expired: LockExpired, sender: Address, receiver: Address, payment_id: int) -> None:
        super().__init__(sender)
        self.receiver = receiver
        self.signed_lock_expired = signed_lock_expired
        self.payment_id = payment_id

    def __repr__(self) -> str:
        return "<ActionSendLockExpiredLight lock_expired:{} sender:{}>".format(
            pex(self.signed_lock_expired.__repr__()), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionSendLockExpiredLight)
            and self.signed_lock_expired.__eq__(other.signed_lock_expired)
            and self.payment_id == other.payment_id
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lock_expired": self.signed_lock_expired.to_dict(),
            "sender": to_checksum_address(self.sender),
            "receiver": to_checksum_address(self.receiver),
            "payment_id": self.payment_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionSendLockExpiredLight":
        instance = cls(
            signed_lock_expired=LockExpired.from_dict(data["lock_expired"]),
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"]),
            payment_id=data["payment_id"]
        )
        return instance


class ActionSendUnlockLight(AuthenticatedSenderStateChange):
    """ An Unlock message must be sent to a light client. """

    def __init__(self, unlock: Unlock, sender: Address, receiver: Address) -> None:
        super().__init__(sender)
        self.receiver = receiver
        self.unlock = unlock

    def __repr__(self) -> str:
        return "<ActionSendUnlockLight unlock:{} sender:{}>".format(
            pex(self.unlock.__repr__()), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionSendUnlockLight)
            and self.unlock.__eq__(other.unlock)
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unlock": self.unlock.to_dict(),
            "sender": to_checksum_address(self.sender),
            "receiver": to_checksum_address(self.receiver)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionSendUnlockLight":
        instance = cls(
            unlock=data["unlock"],
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"])
        )
        return instance


class StoreRefundTransferLight(StateChange):
    """ Initial state of a refund transfer reception.

    Args:
        transfer: a message object that represents the refund transfer sent to a light client
    """

    def __init__(
        self, transfer: RefundTransfer
    ) -> None:
        if not isinstance(transfer, RefundTransfer):
            raise ValueError("transfer must be an RefundTransfer instance.")

        self.transfer = transfer

    def __repr__(self) -> str:
        return "<StoreRefundTransferLight transfer:{}>".format(self.transfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, StoreRefundTransferLight)
            and self.transfer == other.transfer
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"transfer": self.transfer.to_dict()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StoreRefundTransferLight":
        return cls(transfer=RefundTransfer.from_dict(data["transfer"]))

