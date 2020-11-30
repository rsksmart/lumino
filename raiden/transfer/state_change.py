# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes
from random import Random

from eth_utils import to_canonical_address, to_checksum_address

from raiden.lightclient.lightclientmessages.light_client_non_closing_balance_proof import \
    LightClientNonClosingBalanceProof
from raiden.messages import Unlock
from raiden.transfer.architecture import (
    AuthenticatedSenderStateChange,
    BalanceProofStateChange,
    ContractReceiveStateChange,
    StateChange,
)
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import (
    BalanceProofSignedState,
    NettingChannelState,
    PaymentNetworkState,
    TokenNetworkState,
    TransactionChannelNewBalance,
)
from raiden.transfer.utils import pseudo_random_generator_from_json
from raiden.utils import pex, sha3
from raiden.utils.serialization import (
    deserialize_blockhash,
    deserialize_bytes,
    deserialize_locksroot,
    deserialize_secret,
    deserialize_secret_hash,
    deserialize_transactionhash,
    serialize_bytes,
)
from raiden.utils.typing import (
    Address,
    Any,
    BlockGasLimit,
    BlockHash,
    BlockNumber,
    ChainID,
    ChannelID,
    Dict,
    FeeAmount,
    Locksroot,
    MessageID,
    Nonce,
    PaymentID,
    PaymentNetworkID,
    Secret,
    SecretHash,
    SecretRegistryAddress,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_Secret,
    T_SecretHash,
    T_SecretRegistryAddress,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkID,
    TransactionHash,
    TransferID,
    AddressHex)


class Block(StateChange):
    """ Transition used when a new block is mined.
    Args:
        block_number: The current block_number.
    """

    def __init__(
        self, block_number: BlockNumber, gas_limit: BlockGasLimit, block_hash: BlockHash
    ) -> None:
        if not isinstance(block_number, T_BlockNumber):
            raise ValueError("block_number must be of type block_number")

        self.block_number = block_number
        self.gas_limit = gas_limit
        self.block_hash = block_hash

    def __repr__(self) -> str:
        return (
            f"<Block "
            f"number={self.block_number} gas_limit={self.gas_limit} "
            f"block_hash={pex(self.block_hash)}"
            f">"
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, Block)
            and self.block_number == other.block_number
            and self.gas_limit == other.gas_limit
            and self.block_hash == other.block_hash
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_number": str(self.block_number),
            "gas_limit": self.gas_limit,
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        return cls(
            block_number=BlockNumber(int(data["block_number"])),
            gas_limit=data["gas_limit"],
            block_hash=deserialize_blockhash(data["block_hash"]),
        )


class ActionUpdateTransportAuthData(StateChange):
    """ Holds the last "timestamp" at which we synced
    with the transport. The timestamp could be a date/time value
    or any other value provided by the transport backend.
    Can be used later to filter the messages which have not been processed.
    """

    def __init__(self, auth_data: str, address: Address):
        self.auth_data = auth_data
        self.address = address

    def __repr__(self) -> str:
        return "<ActionUpdateTransportAuthData value:{} address:{}>".format(self.auth_data, self.address)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionUpdateTransportAuthData)
            and self.auth_data == other.auth_data
            and self.address == other.address
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_data": str(self.auth_data),
            "address": to_checksum_address(self.address),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionUpdateTransportAuthData":
        if "address" not in data:
            data["address"] = b'00000000000000000000'

        return cls(
            auth_data=data["auth_data"],
            address=to_canonical_address(data["address"])
        )


class ActionCancelPayment(StateChange):
    """ The user requests the transfer to be cancelled.
    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, payment_identifier: PaymentID) -> None:
        self.payment_identifier = payment_identifier

    def __repr__(self) -> str:
        return "<ActionCancelPayment identifier:{}>".format(self.payment_identifier)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionCancelPayment)
            and self.payment_identifier == other.payment_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"payment_identifier": str(self.payment_identifier)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionCancelPayment":
        return cls(payment_identifier=PaymentID(int(data["payment_identifier"])))


class ActionChannelClose(StateChange):
    """ User is closing an existing channel. """

    def __init__(self, canonical_identifier: CanonicalIdentifier,
                 participant1: AddressHex,
                 participant2: AddressHex,
                 signed_close_tx: str = None
                 ) -> None:
        self.canonical_identifier = canonical_identifier
        self.signed_close_tx = signed_close_tx
        self.participant1 = participant1
        self.participant2 = participant2

    @property
    def chain_identifier(self) -> ChainID:
        return self.canonical_identifier.chain_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkID:
        return TokenNetworkID(self.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    def __repr__(self) -> str:
        return "<ActionChannelClose channel_identifier:{} signed_close_tx:{} participant1:{} participant2:{}>".format(
            self.channel_identifier,
            self.signed_close_tx,
            self.participant1,
            self.participant2)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionChannelClose)
            and self.canonical_identifier == other.canonical_identifier
            and self.signed_close_tx == other.signed_close_tx
            and self.participant1 == other.participant1
            and self.participant2 == other.participant2
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"canonical_identifier": self.canonical_identifier.to_dict(),
                "signed_close_tx": self.signed_close_tx,
                "participant1": to_checksum_address(self.participant1),
                "participant2": to_checksum_address(self.participant2)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionChannelClose":

        if not "participant1" in data:
            data["participant1"] = ""
        if not "participant2" in data:
            data["participant2"] = ""

        return cls(
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            signed_close_tx=data["signed_close_tx"],
            participant1=AddressHex(data["participant1"]),
            participant2=AddressHex(data["participant2"])
        )


class ActionChannelSetFee(StateChange):
    def __init__(self, canonical_identifier: CanonicalIdentifier, mediation_fee: FeeAmount):
        self.canonical_identifier = canonical_identifier
        self.mediation_fee = mediation_fee

    def __repr__(self) -> str:
        return f"<ActionChannelSetFee id:{self.canonical_identifier} fee:{self.mediation_fee}>"

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionChannelSetFee)
            and self.canonical_identifier == other.canonical_identifier
            and self.mediation_fee == other.mediation_fee
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"canonical_identifier": self.canonical_identifier, "fee": str(self.mediation_fee)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionChannelSetFee":
        return cls(
            canonical_identifier=data["canonical_identifier"],
            mediation_fee=FeeAmount(int(data["mediation_fee"])),
        )

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier


class ActionCancelTransfer(StateChange):
    """ The user requests the transfer to be cancelled.

    This state change can fail, it depends on the node's role and the current
    state of the transfer.
    """

    def __init__(self, transfer_identifier: TransferID) -> None:
        self.transfer_identifier = transfer_identifier

    def __repr__(self) -> str:
        return "<ActionCancelTransfer identifier:{}>".format(self.transfer_identifier)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionCancelTransfer)
            and self.transfer_identifier == other.transfer_identifier
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {"transfer_identifier": str(self.transfer_identifier)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionCancelTransfer":
        return cls(transfer_identifier=data["transfer_identifier"])


class ContractReceiveChannelNew(ContractReceiveStateChange):
    """ A new channel was created and this node IS a participant. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        channel_state: NettingChannelState,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.channel_state = channel_state

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.channel_state.canonical_identifier.token_network_address)

    @property
    def channel_identifier(self) -> ChannelID:
        return self.channel_state.canonical_identifier.channel_identifier

    def __repr__(self) -> str:
        return "<ContractReceiveChannelNew token_network:{} state:{} block:{}>".format(
            pex(self.token_network_identifier), self.channel_state, self.block_number
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelNew)
            and self.channel_state == other.channel_state
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "channel_state": self.channel_state,
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelNew":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            channel_state=data["channel_state"],
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveChannelClosed(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was closed. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        transaction_from: Address,
        canonical_identifier: CanonicalIdentifier,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.transaction_from = transaction_from
        self.canonical_identifier = canonical_identifier

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelClosed"
            " token_network:{} channel:{} closer:{} closed_at:{}"
            ">"
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.transaction_from),
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelClosed)
            and self.transaction_from == other.transaction_from
            and self.canonical_identifier == other.canonical_identifier
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "transaction_from": to_checksum_address(self.transaction_from),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelClosed":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            transaction_from=to_canonical_address(data["transaction_from"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveChannelClosedLight(ContractReceiveStateChange):
    """ A channel to which a handled light client participant was closed. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        transaction_from: Address,
        canonical_identifier: CanonicalIdentifier,
        block_number: BlockNumber,
        block_hash: BlockHash,
        closing_participant: Address,
        non_closing_participant: Address,
        latest_update_non_closing_balance_proof_data: LightClientNonClosingBalanceProof
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.transaction_from = transaction_from
        self.canonical_identifier = canonical_identifier
        self.closing_participant = closing_participant
        self.non_closing_participant = non_closing_participant
        self.latest_update_non_closing_balance_proof_data = latest_update_non_closing_balance_proof_data

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelClosedLight"
            " token_network:{} channel:{} closer:{} closing_participant:{} non_closing_participant:{} closed_at:{}"
            ">"
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.transaction_from),
            pex(self.closing_participant),
            pex(self.non_closing_participant),
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelClosedLight)
            and self.transaction_from == other.transaction_from
            and self.canonical_identifier == other.canonical_identifier
            and self.closing_participant == other.closing_participant
            and self.non_closing_participant == other.non_closing_participant
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        latest_update_non_closing_balance_proof_data = None
        if self.latest_update_non_closing_balance_proof_data is not None:
            latest_update_non_closing_balance_proof_data = self.latest_update_non_closing_balance_proof_data.to_dict()
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "transaction_from": to_checksum_address(self.transaction_from),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "closing_participant": to_checksum_address(self.closing_participant),
            "non_closing_participant": to_checksum_address(self.non_closing_participant),
            "latest_update_non_closing_balance_proof_data": latest_update_non_closing_balance_proof_data
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelClosedLight":
        latest_update_non_closing_balance_proof_data = None
        if data["latest_update_non_closing_balance_proof_data"] is not None:
            latest_update_non_closing_balance_proof_data = LightClientNonClosingBalanceProof.from_dict(data["latest_update_non_closing_balance_proof_data"])
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            transaction_from=to_canonical_address(data["transaction_from"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
            closing_participant=to_canonical_address(data["closing_participant"]),
            non_closing_participant=to_canonical_address(data["non_closing_participant"]),
            latest_update_non_closing_balance_proof_data=latest_update_non_closing_balance_proof_data
        )


class ActionInitChain(StateChange):
    def __init__(
        self,
        pseudo_random_generator: Random,
        block_number: BlockNumber,
        block_hash: BlockHash,
        our_address: Address,
        chain_id: ChainID,
    ) -> None:
        if not isinstance(block_number, T_BlockNumber):
            raise ValueError("block_number must be of type BlockNumber")

        if not isinstance(block_hash, T_BlockHash):
            raise ValueError("block_hash must be of type BlockHash")

        if not isinstance(chain_id, int):
            raise ValueError("chain_id must be int")

        self.block_number = block_number
        self.block_hash = block_hash
        self.chain_id = chain_id
        self.our_address = our_address
        self.pseudo_random_generator = pseudo_random_generator

    def __repr__(self) -> str:
        return "<ActionInitChain block_number:{} block_hash:{} chain_id:{}>".format(
            self.block_number, pex(self.block_hash), self.chain_id
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionInitChain)
            and self.pseudo_random_generator.getstate() == other.pseudo_random_generator.getstate()
            and self.block_number == other.block_number
            and self.block_hash == other.block_hash
            and self.our_address == other.our_address
            and self.chain_id == other.chain_id
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "our_address": to_checksum_address(self.our_address),
            "chain_id": self.chain_id,
            "pseudo_random_generator": self.pseudo_random_generator.getstate(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionInitChain":
        pseudo_random_generator = pseudo_random_generator_from_json(data)

        return cls(
            pseudo_random_generator=pseudo_random_generator,
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=deserialize_blockhash(data["block_hash"]),
            our_address=to_canonical_address(data["our_address"]),
            chain_id=data["chain_id"],
        )


class ActionNewTokenNetwork(StateChange):
    """ Registers a new token network.
    A token network corresponds to a channel manager smart contract.
    """

    def __init__(
        self, payment_network_identifier: PaymentNetworkID, token_network: TokenNetworkState
    ):
        if not isinstance(token_network, TokenNetworkState):
            raise ValueError("token_network must be a TokenNetworkState instance.")

        self.payment_network_identifier = payment_network_identifier
        self.token_network = token_network

    def __repr__(self) -> str:
        return "<ActionNewTokenNetwork network:{} token:{}>".format(
            pex(self.payment_network_identifier), self.token_network
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionNewTokenNetwork)
            and self.payment_network_identifier == other.payment_network_identifier
            and self.token_network == other.token_network
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "token_network": self.token_network,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionNewTokenNetwork":
        return cls(
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            token_network=data["token_network"],
        )


class ContractReceiveChannelNewBalance(ContractReceiveStateChange):
    """ A channel to which this node IS a participant had a deposit. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        deposit_transaction: TransactionChannelNewBalance,
        block_number: BlockNumber,
        block_hash: BlockHash,
        participant: AddressHex
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.canonical_identifier = canonical_identifier
        self.deposit_transaction = deposit_transaction
        self.participant = participant

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelNewBalance"
            " token_network:{} channel:{} transaction:{} block_number:{} participant:{}"
            ">"
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            self.deposit_transaction,
            self.block_number,
            self.participant
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelNewBalance)
            and self.canonical_identifier == other.canonical_identifier
            and self.deposit_transaction == other.deposit_transaction
            and self.participant == other.participant
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "deposit_transaction": self.deposit_transaction,
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "participant": to_checksum_address(self.participant)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelNewBalance":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            deposit_transaction=data["deposit_transaction"],
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
            participant=AddressHex(data["participant"])
        )


class ContractReceiveChannelSettled(ContractReceiveStateChange):
    """ A channel to which this node IS a participant was settled. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        our_onchain_locksroot: Locksroot,
        partner_onchain_locksroot: Locksroot,
        block_number: BlockNumber,
        block_hash: BlockHash,
        participant1: Address
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.our_onchain_locksroot = our_onchain_locksroot
        self.partner_onchain_locksroot = partner_onchain_locksroot
        self.canonical_identifier = canonical_identifier
        self.participant1 = participant1

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelSettled token_network:{} channel:{} settle_block:{}>"
        ).format(pex(self.token_network_identifier), self.channel_identifier, self.block_number)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelSettled)
            and self.canonical_identifier == other.canonical_identifier
            and self.our_onchain_locksroot == other.our_onchain_locksroot
            and self.partner_onchain_locksroot == other.partner_onchain_locksroot
            and self.participant1 == other.participant1
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "our_onchain_locksroot": serialize_bytes(self.our_onchain_locksroot),
            "partner_onchain_locksroot": serialize_bytes(self.partner_onchain_locksroot),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "participant1": to_checksum_address(self.participant1)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelSettled":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            our_onchain_locksroot=deserialize_locksroot(data["our_onchain_locksroot"]),
            partner_onchain_locksroot=deserialize_locksroot(data["partner_onchain_locksroot"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
            participant1=to_canonical_address(data["participant1"])
        )


class ContractReceiveChannelSettledLight(ContractReceiveStateChange):
    """ A channel to which this node as a hub handles one of the participants was settled. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        our_onchain_locksroot: Locksroot,
        partner_onchain_locksroot: Locksroot,
        block_number: BlockNumber,
        block_hash: BlockHash,
        participant1: Address,
        participant2: Address
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.our_onchain_locksroot = our_onchain_locksroot
        self.partner_onchain_locksroot = partner_onchain_locksroot
        self.canonical_identifier = canonical_identifier
        self.participant1 = participant1
        self.participant2 = participant2

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelSettledLight token_network:{} channel:{} settle_block:{}>"
        ).format(pex(self.token_network_identifier), self.channel_identifier, self.block_number)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelSettledLight)
            and self.canonical_identifier == other.canonical_identifier
            and self.our_onchain_locksroot == other.our_onchain_locksroot
            and self.partner_onchain_locksroot == other.partner_onchain_locksroot
            and self.participant1 == other.participant1
            and self.participant2 == other.participant2
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "our_onchain_locksroot": serialize_bytes(self.our_onchain_locksroot),
            "partner_onchain_locksroot": serialize_bytes(self.partner_onchain_locksroot),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
            "participant1": to_checksum_address(self.participant1),
            "participant2": to_checksum_address(self.participant2)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelSettledLight":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            our_onchain_locksroot=deserialize_locksroot(data["our_onchain_locksroot"]),
            partner_onchain_locksroot=deserialize_locksroot(data["partner_onchain_locksroot"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
            participant1=to_canonical_address(data["participant1"]),
            participant2 = to_canonical_address(data["participant2"])
        )


class ActionLeaveAllNetworks(StateChange):
    """ User is quitting all payment networks. """

    def __repr__(self) -> str:
        return "<ActionLeaveAllNetworks>"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, ActionLeaveAllNetworks)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @classmethod
    def from_dict(cls, _data: Dict[str, Any]) -> "ActionLeaveAllNetworks":
        return cls()


class ActionChangeNodeNetworkState(StateChange):
    """ The network state of `node_address` changed. """

    def __init__(self, node_address: Address, network_state: str) -> None:
        if not isinstance(node_address, T_Address):
            raise ValueError("node_address must be an address instance")

        self.node_address = node_address
        self.network_state = network_state

    def __repr__(self) -> str:
        return "<ActionChangeNodeNetworkState node:{} state:{}>".format(
            pex(self.node_address), self.network_state
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ActionChangeNodeNetworkState)
            and self.node_address == other.node_address
            and self.network_state == other.network_state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_address": to_checksum_address(self.node_address),
            "network_state": self.network_state,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionChangeNodeNetworkState":
        return cls(
            node_address=to_canonical_address(data["node_address"]),
            network_state=data["network_state"],
        )


class ContractReceiveNewPaymentNetwork(ContractReceiveStateChange):
    """ Registers a new payment network.
    A payment network corresponds to a registry smart contract.
    """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        payment_network: PaymentNetworkState,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ):
        if not isinstance(payment_network, PaymentNetworkState):
            raise ValueError("payment_network must be a PaymentNetworkState instance")

        super().__init__(transaction_hash, block_number, block_hash)

        self.payment_network = payment_network

    def __repr__(self) -> str:
        return "<ContractReceiveNewPaymentNetwork network:{} block:{}>".format(
            self.payment_network, self.block_number
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveNewPaymentNetwork)
            and self.payment_network == other.payment_network
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "payment_network": self.payment_network,
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveNewPaymentNetwork":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            payment_network=data["payment_network"],
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveNewTokenNetwork(ContractReceiveStateChange):
    """ A new token was registered with the payment network. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        payment_network_identifier: PaymentNetworkID,
        token_network: TokenNetworkState,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ):
        if not isinstance(token_network, TokenNetworkState):
            raise ValueError("token_network must be a TokenNetworkState instance")

        super().__init__(transaction_hash, block_number, block_hash)

        self.payment_network_identifier = payment_network_identifier
        self.token_network = token_network

    def __repr__(self) -> str:
        return "<ContractReceiveNewTokenNetwork payment_network:{} network:{} block:{}>".format(
            pex(self.payment_network_identifier), self.token_network, self.block_number
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveNewTokenNetwork)
            and self.payment_network_identifier == other.payment_network_identifier
            and self.token_network == other.token_network
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "payment_network_identifier": to_checksum_address(self.payment_network_identifier),
            "token_network": self.token_network,
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveNewTokenNetwork":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            payment_network_identifier=to_canonical_address(data["payment_network_identifier"]),
            token_network=data["token_network"],
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveSecretReveal(ContractReceiveStateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        secret_registry_address: SecretRegistryAddress,
        secrethash: SecretHash,
        secret: Secret,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        if not isinstance(secret_registry_address, T_SecretRegistryAddress):
            raise ValueError("secret_registry_address must be of type SecretRegistryAddress")
        if not isinstance(secrethash, T_SecretHash):
            raise ValueError("secrethash must be of type SecretHash")
        if not isinstance(secret, T_Secret):
            raise ValueError("secret must be of type Secret")

        super().__init__(transaction_hash, block_number, block_hash)

        self.secret_registry_address = secret_registry_address
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self) -> str:
        return (
            "<ContractReceiveSecretReveal"
            " secret_registry:{} secrethash:{} secret:{} block:{}"
            ">"
        ).format(
            pex(self.secret_registry_address),
            pex(self.secrethash),
            pex(self.secret),
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveSecretReveal)
            and self.secret_registry_address == other.secret_registry_address
            and self.secrethash == other.secrethash
            and self.secret == other.secret
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "secret_registry_address": to_checksum_address(self.secret_registry_address),
            "secrethash": serialize_bytes(self.secrethash),
            "secret": serialize_bytes(self.secret),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveSecretReveal":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            secret_registry_address=to_canonical_address(data["secret_registry_address"]),
            secrethash=deserialize_secret_hash(data["secrethash"]),
            secret=deserialize_secret(data["secret"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveSecretRevealLight(ContractReceiveStateChange):
    """ A new secret was registered with the SecretRegistry contract. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        secret_registry_address: SecretRegistryAddress,
        secrethash: SecretHash,
        secret: Secret,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        if not isinstance(secret_registry_address, T_SecretRegistryAddress):
            raise ValueError("secret_registry_address must be of type SecretRegistryAddress")
        if not isinstance(secrethash, T_SecretHash):
            raise ValueError("secrethash must be of type SecretHash")
        if not isinstance(secret, T_Secret):
            raise ValueError("secret must be of type Secret")

        super().__init__(transaction_hash, block_number, block_hash)

        self.secret_registry_address = secret_registry_address
        self.secrethash = secrethash
        self.secret = secret

    def __repr__(self) -> str:
        return (
            "<ContractReceiveSecretRevealLight"
            " secret_registry:{} secrethash:{} secret:{} block:{}"
            ">"
        ).format(
            pex(self.secret_registry_address),
            pex(self.secrethash),
            pex(self.secret),
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveSecretRevealLight)
            and self.secret_registry_address == other.secret_registry_address
            and self.secrethash == other.secrethash
            and self.secret == other.secret
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "secret_registry_address": to_checksum_address(self.secret_registry_address),
            "secrethash": serialize_bytes(self.secrethash),
            "secret": serialize_bytes(self.secret),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveSecretRevealLight":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            secret_registry_address=to_canonical_address(data["secret_registry_address"]),
            secrethash=deserialize_secret_hash(data["secrethash"]),
            secret=deserialize_secret(data["secret"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveChannelBatchUnlock(ContractReceiveStateChange):
    """ All the locks were claimed via the blockchain.

    Used when all the hash time locks were unlocked and a log ChannelUnlocked is emitted
    by the token network contract.
    Note:
        For this state change the contract caller is not important but only the
        receiving address. `participant` is the address to which the `unlocked_amount`
        was transferred. `returned_tokens` was transferred to the channel partner.
    """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        participant: Address,
        partner: Address,
        locksroot: Locksroot,
        unlocked_amount: TokenAmount,
        returned_tokens: TokenAmount,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        canonical_identifier.validate()

        if not isinstance(participant, T_Address):
            raise ValueError("participant must be of type address")

        if not isinstance(partner, T_Address):
            raise ValueError("partner must be of type address")

        super().__init__(transaction_hash, block_number, block_hash)

        self.canonical_identifier = canonical_identifier
        self.participant = participant
        self.partner = partner
        self.locksroot = locksroot
        self.unlocked_amount = unlocked_amount
        self.returned_tokens = returned_tokens

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveChannelBatchUnlock "
            " token_network:{} participant:{} partner:{}"
            " locksroot:{} unlocked:{} returned:{} block:{}"
            ">"
        ).format(
            self.token_network_identifier,
            self.participant,
            self.partner,
            self.locksroot,
            self.unlocked_amount,
            self.returned_tokens,
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveChannelBatchUnlock)
            and self.canonical_identifier == other.canonical_identifier
            and self.participant == other.participant
            and self.partner == other.partner
            and self.locksroot == other.locksroot
            and self.unlocked_amount == other.unlocked_amount
            and self.returned_tokens == other.returned_tokens
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "participant": to_checksum_address(self.participant),
            "partner": to_checksum_address(self.partner),
            "locksroot": serialize_bytes(self.locksroot),
            "unlocked_amount": str(self.unlocked_amount),
            "returned_tokens": str(self.returned_tokens),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveChannelBatchUnlock":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            participant=to_canonical_address(data["participant"]),
            partner=to_canonical_address(data["partner"]),
            locksroot=deserialize_locksroot(data["locksroot"]),
            unlocked_amount=TokenAmount(int(data["unlocked_amount"])),
            returned_tokens=TokenAmount(int(data["returned_tokens"])),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=deserialize_blockhash(data["block_hash"]),
        )


class ContractReceiveRouteNew(ContractReceiveStateChange):
    """ New channel was created and this node is NOT a participant. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        participant1: Address,
        participant2: Address,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:

        if not isinstance(participant1, T_Address):
            raise ValueError("participant1 must be of type address")

        if not isinstance(participant2, T_Address):
            raise ValueError("participant2 must be of type address")

        canonical_identifier.validate()
        super().__init__(transaction_hash, block_number, block_hash)

        self.canonical_identifier = canonical_identifier
        self.participant1 = participant1
        self.participant2 = participant2

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return (
            "<ContractReceiveRouteNew" " token_network:{} id:{} node1:{}" " node2:{} block:{}>"
        ).format(
            pex(self.token_network_identifier),
            self.channel_identifier,
            pex(self.participant1),
            pex(self.participant2),
            self.block_number,
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveRouteNew)
            and self.canonical_identifier == other.canonical_identifier
            and self.participant1 == other.participant1
            and self.participant2 == other.participant2
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "participant1": to_checksum_address(self.participant1),
            "participant2": to_checksum_address(self.participant2),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveRouteNew":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            participant1=to_canonical_address(data["participant1"]),
            participant2=to_canonical_address(data["participant2"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveRouteClosed(ContractReceiveStateChange):
    """ A channel was closed and this node is NOT a participant. """

    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)
        canonical_identifier.validate()
        self.canonical_identifier = canonical_identifier

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return "<ContractReceiveRouteClosed token_network:{} id:{} block:{}>".format(
            pex(self.token_network_identifier), self.channel_identifier, self.block_number
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveRouteClosed)
            and self.canonical_identifier == other.canonical_identifier
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveRouteClosed":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ContractReceiveUpdateTransfer(ContractReceiveStateChange):
    def __init__(
        self,
        transaction_hash: TransactionHash,
        canonical_identifier: CanonicalIdentifier,
        nonce: Nonce,
        block_number: BlockNumber,
        block_hash: BlockHash,
    ) -> None:
        super().__init__(transaction_hash, block_number, block_hash)

        self.canonical_identifier = canonical_identifier
        self.nonce = nonce

    @property
    def channel_identifier(self) -> ChannelID:
        return self.canonical_identifier.channel_identifier

    @property
    def token_network_identifier(self) -> TokenNetworkAddress:
        return TokenNetworkAddress(self.canonical_identifier.token_network_address)

    def __repr__(self) -> str:
        return f"<ContractReceiveUpdateTransfer nonce:{self.nonce} block:{self.block_number}>"

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ContractReceiveUpdateTransfer)
            and self.canonical_identifier == other.canonical_identifier
            and self.nonce == other.nonce
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_hash": serialize_bytes(self.transaction_hash),
            "canonical_identifier": self.canonical_identifier.to_dict(),
            "nonce": str(self.nonce),
            "block_number": str(self.block_number),
            "block_hash": serialize_bytes(self.block_hash),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContractReceiveUpdateTransfer":
        return cls(
            transaction_hash=deserialize_transactionhash(data["transaction_hash"]),
            canonical_identifier=CanonicalIdentifier.from_dict(data["canonical_identifier"]),
            nonce=Nonce(int(data["nonce"])),
            block_number=BlockNumber(int(data["block_number"])),
            block_hash=BlockHash(deserialize_bytes(data["block_hash"])),
        )


class ReceiveUnlockLight(BalanceProofStateChange):
    def __init__(
        self, message_identifier: MessageID, secret: Secret, balance_proof: BalanceProofSignedState,
        signed_unlock: Unlock, recipient: Address
    ) -> None:
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError("balance_proof must be an instance of BalanceProofSignedState")

        super().__init__(balance_proof)

        secrethash: SecretHash = SecretHash(sha3(secret))

        self.message_identifier = message_identifier
        self.secret = secret
        self.secrethash = secrethash
        self.signed_unlock = signed_unlock
        self.recipient = recipient

    def __repr__(self) -> str:
        return "<ReceiveUnlockLight msgid:{} secrethash:{} balance_proof:{} recipient:{}>".format(
            self.message_identifier, pex(self.secrethash), self.balance_proof, self.recipient
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveUnlockLight)
            and self.message_identifier == other.message_identifier
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and self.recipient == other.recipient
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_identifier": str(self.message_identifier),
            "secret": serialize_bytes(self.secret),
            "balance_proof": self.balance_proof,
            "signed_unlock": self.signed_unlock,
            "recipient": to_checksum_address(self.recipient)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveUnlockLight":
        return cls(
            message_identifier=MessageID(int(data["message_identifier"])),
            secret=deserialize_secret(data["secret"]),
            balance_proof=data["balance_proof"],
            signed_unlock=data["signed_unlock"],
            recipient=data["recipient"]
        )


class ReceiveUnlock(BalanceProofStateChange):
    def __init__(
        self, message_identifier: MessageID, secret: Secret, balance_proof: BalanceProofSignedState
    ) -> None:
        if not isinstance(balance_proof, BalanceProofSignedState):
            raise ValueError("balance_proof must be an instance of BalanceProofSignedState")

        super().__init__(balance_proof)

        secrethash: SecretHash = SecretHash(sha3(secret))

        self.message_identifier = message_identifier
        self.secret = secret
        self.secrethash = secrethash

    def __repr__(self) -> str:
        return "<ReceiveUnlock msgid:{} secrethash:{} balance_proof:{}>".format(
            self.message_identifier, pex(self.secrethash), self.balance_proof
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveUnlock)
            and self.message_identifier == other.message_identifier
            and self.secret == other.secret
            and self.secrethash == other.secrethash
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_identifier": str(self.message_identifier),
            "secret": serialize_bytes(self.secret),
            "balance_proof": self.balance_proof,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveUnlock":
        return cls(
            message_identifier=MessageID(int(data["message_identifier"])),
            secret=deserialize_secret(data["secret"]),
            balance_proof=data["balance_proof"],
        )


class ReceiveDelivered(AuthenticatedSenderStateChange):
    def __init__(self, sender: Address, message_identifier: MessageID) -> None:
        super().__init__(sender)

        self.message_identifier = message_identifier

    def __repr__(self) -> str:
        return "<ReceiveDelivered msgid:{} sender:{}>".format(
            self.message_identifier, pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveDelivered)
            and self.message_identifier == other.message_identifier
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": to_checksum_address(self.sender),
            "message_identifier": str(self.message_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveDelivered":
        return cls(
            sender=to_canonical_address(data["sender"]),
            message_identifier=MessageID(int(data["message_identifier"])),
        )


class ReceiveProcessed(AuthenticatedSenderStateChange):
    def __init__(self, sender: Address, message_identifier: MessageID) -> None:
        super().__init__(sender)
        self.message_identifier = message_identifier

    def __repr__(self) -> str:
        return "<ReceiveProcessed msgid:{} sender:{}>".format(
            self.message_identifier, pex(self.sender)
        )

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ReceiveProcessed)
            and self.message_identifier == other.message_identifier
            and super().__eq__(other)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": to_checksum_address(self.sender),
            "message_identifier": str(self.message_identifier),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReceiveProcessed":
        return cls(
            sender=to_canonical_address(data["sender"]),
            message_identifier=MessageID(int(data["message_identifier"])),
        )
