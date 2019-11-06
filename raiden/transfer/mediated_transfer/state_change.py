# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes

from eth_utils import to_canonical_address, to_checksum_address
from raiden.messages import RevealSecret, Unlock, LockedTransfer, SecretRequest

from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    BalanceProofStateChange,
    StateChange,
)
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
    TransferDescriptionWithoutSecretState)
from raiden.transfer.state import BalanceProofSignedState, RouteState
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
        self, transfer_description: TransferDescriptionWithoutSecretState, routes: List[RouteState],
        signed_locked_transfer: LockedTransfer
    ) -> None:
        if not isinstance(transfer_description, TransferDescriptionWithoutSecretState):
            raise ValueError("transfer must be an TransferDescriptionWithoutSecretState instance.")

        self.transfer = transfer_description
        self.routes = routes
        self.signed_locked_transfer = signed_locked_transfer

    def __repr__(self) -> str:
        return "<ActionInitInitiatorLight transfer:{}>".format(self.transfer)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitInitiatorLight)
            and self.transfer == other.transfer
            and self.routes == other.routes
            and self.signed_locked_transfer == other.signed_locked_transfer
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"transfer": self.transfer, "routes": self.routes, "signed_locked_transfer": self.signed_locked_transfer}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitInitiatorLight":
        return cls(transfer_description=data["transfer"], routes=data["routes"], signed_locked_transfer=data["signed_locked_transfer"])


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
        secret_request_message: SecretRequest
    ) -> None:
        super().__init__(sender)
        self.payment_identifier = payment_identifier
        self.amount = amount
        self.expiration = expiration
        self.secrethash = secrethash
        self.secret_request_message = secret_request_message
        self.revealsecret = None

    def __repr__(self) -> str:
        return "<ReceiveSecretRequestLight paymentid:{} amount:{} secrethash:{} sender:{}>".format(
            self.payment_identifier, self.amount, pex(self.secrethash), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretRequestLight)
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

    def __init__(self, secret: Secret, sender: Address, secret_reveal_message: RevealSecret) -> None:
        super().__init__(sender)
        secrethash = sha3(secret)

        self.secret = secret
        self.secrethash = secrethash
        self.secret_reveal_message = secret_reveal_message

    def __repr__(self) -> str:
        return "<ReceiveSecretRevealLight secrethash:{} sender:{}>".format(
            pex(self.secrethash), pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveSecretRevealLight)
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
            "secret_reveal_message": self.secret_reveal_message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveSecretRevealLight":
        instance = cls(
            secret=Secret(deserialize_bytes(data["secret"])),
            sender=to_canonical_address(data["sender"]),
            secret_reveal_message=data["secret_reveal_message"]
        )
        instance.secrethash = deserialize_bytes(data["secrethash"])
        return instance

class ReceiveTransferRefundCancelRoute(BalanceProofStateChange):
    """ A RefundTransfer message received by the initiator will cancel the current
    route.
    """

    def __init__(
        self, routes: List[RouteState], transfer: LockedTransferSignedState, secret: Secret
    ) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        secrethash = sha3(secret)

        super().__init__(transfer.balance_proof)
        self.transfer = transfer
        self.routes = routes
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self) -> str:
        return "<ReceiveTransferRefundCancelRoute sender:{} transfer:{}>".format(
            pex(self.sender), self.transfer
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveTransferRefundCancelRoute)
            and self.sender == other.sender
            and self.transfer == other.transfer
            and self.routes == other.routes
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": serialize_bytes(self.secret),
            "routes": self.routes,
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveTransferRefundCancelRoute":
        instance = cls(
            routes=data["routes"],
            transfer=data["transfer"],
            secret=Secret(deserialize_bytes(data["secret"])),
        )
        return instance


class ReceiveTransferRefund(BalanceProofStateChange):
    """ A RefundTransfer message received. """

    def __init__(self, transfer: LockedTransferSignedState, routes: List[RouteState]) -> None:
        if not isinstance(transfer, LockedTransferSignedState):
            raise ValueError("transfer must be an instance of LockedTransferSignedState")

        super().__init__(transfer.balance_proof)
        self.transfer = transfer
        self.routes = routes

    def __repr__(self) -> str:
        return "<ReceiveTransferRefund sender:{} transfer:{}>".format(
            pex(self.sender), self.transfer
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveTransferRefund)
            and self.transfer == other.transfer
            and self.routes == other.routes
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "routes": self.routes,
            "transfer": self.transfer,
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveTransferRefund":
        instance = cls(routes=data["routes"], transfer=data["transfer"])
        return instance


class ActionSendSecretRevealLight(AuthenticatedSenderStateChange):
    """ A SecretReveal message must be sent to a light client. """

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
            "reveal_secret": self.reveal_secret.to_dict(),
            "sender": to_checksum_address(self.sender),
            "receiver": to_checksum_address(self.receiver)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionSendSecretRevealLight":
        instance = cls(
            reveal_secret=RevealSecret(data["reveal_secret"]),
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"])
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