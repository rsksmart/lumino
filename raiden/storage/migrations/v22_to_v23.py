import json

from raiden.exceptions import ChannelNotFound
from raiden.storage.sqlite import SQLiteStorage
import json
from typing import TYPE_CHECKING, Tuple, TypeVar

from eth_utils import to_checksum_address

from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.typing import Any, Callable, ChainID, Dict, List, Optional, Union


SOURCE_VERSION = 22
TARGET_VERSION = 23


def upgrade_v22_to_v23(
    storage: SQLiteStorage,
    old_version: int,
    current_version: int,  # pylint: disable=unused-argument
    **kwargs,  # pylint: disable=unused-argument
) -> int:
    return TARGET_VERSION
