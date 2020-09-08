import os
import sys
from typing import Any, Callable, Dict, TextIO
from urllib.parse import urlparse

import click
import filelock
import structlog
from eth_utils import to_canonical_address, to_normalized_address
from web3 import HTTPProvider, Web3
from definitions import ROOT_DIR
import json
from eth_utils import encode_hex

from raiden.network.transport.matrix.utils import get_available_servers_from_config, server_is_available
from raiden.storage import serialize, sqlite

from raiden.accounts import AccountManager
from raiden.constants import (
    MONITORING_BROADCASTING_ROOM,
    PATH_FINDING_BROADCASTING_ROOM,
    RAIDEN_DB_VERSION,
    Environment,
    RoutingMode,
)
from raiden.exceptions import RaidenError
from raiden.message_handler import MessageHandler
from raiden.network.blockchain_service import BlockChainService
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.transport import MatrixTransport
from raiden.network.transport.matrix import MatrixLightClientTransport, NodeTransport
from raiden.raiden_event_handler import RaidenEventHandler
from raiden.settings import (
    DEFAULT_MATRIX_KNOWN_SERVERS,
    DEFAULT_NAT_KEEPALIVE_RETRIES,
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
)
from raiden.ui.checks import (
    check_ethereum_client_is_supported,
    check_ethereum_has_accounts,
    check_ethereum_network_id,
    check_sql_version,
    check_synced,
)
from raiden.ui.prompt import (
    prompt_account,
    unlock_account_with_passwordfile,
    unlock_account_with_passwordprompt,
)
from raiden.ui.startup import (
    setup_contracts_or_exit,
    setup_environment,
    setup_proxies_or_exit,
    setup_udp_or_exit,
)
from raiden.utils import BlockNumber, pex, split_endpoint
from raiden.utils.cli import get_matrix_servers
from raiden.utils.typing import Address, Optional, PrivateKey, Tuple
from raiden_contracts.constants import ID_TO_NETWORKNAME
from raiden_contracts.contract_manager import ContractManager

log = structlog.get_logger(__name__)


def _setup_matrix(config):
    if config["transport"]["matrix"].get("available_servers") is None:
        # fetch list of known servers from raiden-network/raiden-tranport repo
        available_servers_url = DEFAULT_MATRIX_KNOWN_SERVERS[config["environment_type"]]
        available_servers = get_matrix_servers(available_servers_url)
        log.debug("Fetching available matrix servers", available_servers=available_servers)
        config["transport"]["matrix"]["available_servers"] = available_servers

    # TODO: This needs to be adjusted once #3735 gets implemented
    # Add PFS broadcast room if enabled
    if config["services"]["pathfinding_service_address"] is not None:
        if PATH_FINDING_BROADCASTING_ROOM not in config["transport"]["matrix"]["global_rooms"]:
            config["transport"]["matrix"]["global_rooms"].append(PATH_FINDING_BROADCASTING_ROOM)

    # Add monitoring service broadcast room if enabled
    if config["services"]["monitoring_enabled"] is True:
        config["transport"]["matrix"]["global_rooms"].append(MONITORING_BROADCASTING_ROOM)

    try:

        database_path = config["database_path"]

        database_dir = os.path.dirname(config["database_path"])
        os.makedirs(database_dir, exist_ok=True)

        storage = sqlite.SerializedSQLiteStorage(
            database_path=database_path, serializer=serialize.JSONSerializer()
        )

        light_clients = storage.get_all_light_clients()

        light_client_transports = []
        for light_client in light_clients:

            current_server_name = None

            if light_client["current_server_name"]:
                current_server_name = light_client["current_server_name"]
                available_servers = get_available_servers_from_config(config["transport"]["matrix"])
                if not server_is_available(current_server_name, available_servers):
                    # we flag the light client as pending for deletion because it's associated to a server that
                    # is not available anymore so we need to force a new on-boarding, the next request from that LC will
                    # delete it and respond with an error to control the re-onboard
                    storage.flag_light_client_as_pending_for_deletion(light_client["address"])
                    log.info("No available server with name " + current_server_name +
                             ", LC has been flagged for deletion from DB, on-boarding is needed for LC with address: " +
                             light_client["address"])
                    continue

            light_client_transport = get_matrix_light_client_instance(
                light_client['address'],
                config["transport"]["matrix"],
                light_client['password'],
                light_client['display_name'],
                light_client['seed_retry'],
                current_server_name)

            light_client_transports.append(light_client_transport)

        hub_transport = MatrixTransport(config["address"], config["transport"]["matrix"])

        node_transport = NodeTransport(hub_transport, light_client_transports)

    except RaidenError as ex:
        click.secho(f"FATAL: {ex}", fg="red")
        sys.exit(1)

    return node_transport


def get_matrix_light_client_instance(
    address,
    config,
    password,
    display_name,
    seed_retry,
    current_server_name: str = None
):
    light_client_transport = MatrixLightClientTransport(
        address,
        config,
        password,
        display_name,
        seed_retry,
        current_server_name
    )
    return light_client_transport


def _setup_web3(eth_rpc_endpoint):
    web3 = Web3(HTTPProvider(eth_rpc_endpoint))

    try:
        node_version = web3.version.node  # pylint: disable=no-member
    except ConnectTimeout:
        raise EthNodeCommunicationError("Couldn't connect to the ethereum node")
    except ValueError:
        raise EthNodeInterfaceError(
            'The underlying ethereum node does not have the web3 rpc interface '
            'enabled. Please run it with --rpcapi eth,net,web3,txpool for geth '
            'and --jsonrpc-apis=eth,net,web3,parity for parity.',
        )

    supported, _ = is_supported_client(node_version)
    if not supported:
        click.secho(
            'You need a Byzantium enabled ethereum node. Parity >= 1.7.6, Geth >= 1.7.2 or RSK -= 0.6.0',
            fg='red',
        )
        sys.exit(1)
    return web3

def get_account_and_private_key(
    account_manager: AccountManager, address: Optional[Address], password_file: Optional[TextIO]
) -> Tuple[Address, PrivateKey]:
    if not address:
        address_hex = prompt_account(account_manager)
    else:
        address_hex = to_normalized_address(address)

    if password_file:
        privatekey_bin = unlock_account_with_passwordfile(
            account_manager=account_manager, address_hex=address_hex, password_file=password_file
        )
    else:
        privatekey_bin, pubkey_bin = unlock_account_with_passwordprompt(
            account_manager=account_manager, address_hex=address_hex
        )

    return to_canonical_address(address_hex), privatekey_bin, pubkey_bin


def rpc_normalized_endpoint(eth_rpc_endpoint: str) -> str:
    parsed_eth_rpc_endpoint = urlparse(eth_rpc_endpoint)

    if parsed_eth_rpc_endpoint.scheme:
        return eth_rpc_endpoint

    return f"http://{eth_rpc_endpoint}"


def run_app(
    address: Address,
    keystore_path: str,
    gas_price: Callable,
    eth_rpc_endpoint: str,
    tokennetwork_registry_contract_address: Address,
    one_to_n_contract_address: Address,
    secret_registry_contract_address: Address,
    service_registry_contract_address: Address,
    endpoint_registry_contract_address: Address,
    user_deposit_contract_address: Address,
    listen_address: str,
    mapped_socket,
    max_unresponsive_time: int,
    api_address: str,
    rpc: bool,
    sync_check: bool,
    console: bool,
    password_file: TextIO,
    web_ui: bool,
    datadir: str,
    transport: str,
    matrix_server: str,
    network_id: int,
    environment_type: Environment,
    unrecoverable_error_should_crash: bool,
    pathfinding_service_address: str,
    pathfinding_max_paths: int,
    enable_monitoring: bool,
    resolver_endpoint: str,
    routing_mode: RoutingMode,
    config: Dict[str, Any],
    **kwargs: Any,  # FIXME: not used here, but still receives stuff in smoketest
):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-argument

    from raiden.app import App

    if transport == "udp" and not mapped_socket:
        raise RuntimeError("Missing socket")

    if datadir is None:
        datadir = os.path.join(os.path.expanduser("~"), ".raiden")

    account_manager = AccountManager(keystore_path)
    web3 = Web3(HTTPProvider(rpc_normalized_endpoint(eth_rpc_endpoint)))

    check_sql_version()
    check_ethereum_has_accounts(account_manager)
    check_ethereum_client_is_supported(web3)
    check_ethereum_network_id(network_id, web3)

    (address, privatekey_bin, pubkey_bin) = get_account_and_private_key(
        account_manager, address, password_file
    )

    (listen_host, listen_port) = split_endpoint(listen_address)
    (api_host, api_port) = split_endpoint(api_address)

    print("Private key: " + encode_hex(privatekey_bin))
    print("Public key: " + encode_hex(pubkey_bin))

    config["address"] = address
    config["pubkey"] = pubkey_bin
    config["privatekey"] = privatekey_bin
    config["transport"]["udp"]["host"] = listen_host
    config["transport"]["udp"]["port"] = listen_port
    config["console"] = console
    config["rpc"] = rpc
    config["web_ui"] = rpc and web_ui
    config["api_host"] = api_host
    config["api_port"] = api_port
    config["resolver_endpoint"] = resolver_endpoint
    if mapped_socket:
        config["socket"] = mapped_socket.socket
        config["transport"]["udp"]["external_ip"] = mapped_socket.external_ip
        config["transport"]["udp"]["external_port"] = mapped_socket.external_port
    config["transport_type"] = transport
    config["transport"]["matrix"]["server"] = matrix_server
    config["transport"]["udp"]["nat_keepalive_retries"] = DEFAULT_NAT_KEEPALIVE_RETRIES
    timeout = max_unresponsive_time / DEFAULT_NAT_KEEPALIVE_RETRIES
    config["transport"]["udp"]["nat_keepalive_timeout"] = timeout
    config["unrecoverable_error_should_crash"] = unrecoverable_error_should_crash
    config["services"]["pathfinding_max_paths"] = pathfinding_max_paths
    config["services"]["monitoring_enabled"] = enable_monitoring
    config["chain_id"] = network_id

    setup_environment(config, environment_type)

    contracts = setup_contracts_or_exit(config, network_id)

    rpc_client = JSONRPCClient(
        web3,
        privatekey_bin,
        gas_price_strategy=gas_price,
        block_num_confirmations=DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
        uses_infura="infura.io" in eth_rpc_endpoint,
    )

    blockchain_service = BlockChainService(
        jsonrpc_client=rpc_client, contract_manager=ContractManager(config["contracts_path"])
    )

    if sync_check:
        check_synced(blockchain_service)

    proxies = setup_proxies_or_exit(
        config=config,
        tokennetwork_registry_contract_address=tokennetwork_registry_contract_address,
        secret_registry_contract_address=secret_registry_contract_address,
        endpoint_registry_contract_address=endpoint_registry_contract_address,
        user_deposit_contract_address=user_deposit_contract_address,
        service_registry_contract_address=service_registry_contract_address,
        blockchain_service=blockchain_service,
        contracts=contracts,
        routing_mode=routing_mode,
        pathfinding_service_address=pathfinding_service_address,
    )

    database_path = os.path.join(
        datadir,
        f"node_{pex(address)}",
        f"netid_{network_id}",
        f"network_{pex(proxies.token_network_registry.address)}",
        f"v{RAIDEN_DB_VERSION}_log.db",
    )
    config["database_path"] = database_path

    print(
        "\nYou are connected to the '{}' network and the DB path is: {}".format(
            ID_TO_NETWORKNAME.get(network_id, network_id), database_path
        )
    )

    # FIXME mmartinez this must be checksummed or compared on a standard way
    # running_network = {"network_id": network_id,
    #                    "token_network_registry": encode_hex(tokennetwork_registry_contract_address),
    #                    "secret_registry": encode_hex(secret_registry_contract_address),
    #                    "endpoint_registry": encode_hex(endpoint_registry_contract_address)}

    #  check_network_params(running_network)

    discovery = None
    if transport == "udp":
        transport, discovery = setup_udp_or_exit(
            config, blockchain_service, address, contracts, endpoint_registry_contract_address
        )
    elif transport == "matrix":
        transport = _setup_matrix(config)
    else:
        raise RuntimeError(f'Unknown transport type "{transport}" given')

    raiden_event_handler = RaidenEventHandler()

    message_handler = MessageHandler()

    try:
        start_block = 0
        if "TokenNetworkRegistry" in contracts:
            start_block = contracts["TokenNetworkRegistry"]["block_number"]

        raiden_app = App(
            config=config,
            chain=blockchain_service,
            query_start_block=BlockNumber(start_block),
            default_one_to_n_address=one_to_n_contract_address,
            default_registry=proxies.token_network_registry,
            default_secret_registry=proxies.secret_registry,
            default_service_registry=proxies.service_registry,
            transport=transport,
            raiden_event_handler=raiden_event_handler,
            message_handler=message_handler,
            discovery=discovery,
            user_deposit=proxies.user_deposit,
        )
    except RaidenError as e:
        click.secho(f"FATAL: {e}", fg="red")
        sys.exit(1)

    try:
        raiden_app.start()
    except RuntimeError as e:
        click.secho(f"FATAL: {e}", fg="red")
        sys.exit(1)
    except filelock.Timeout:
        name_or_id = ID_TO_NETWORKNAME.get(network_id, network_id)
        click.secho(
            f"FATAL: Another Raiden instance already running for account "
            f"{to_normalized_address(address)} on network id {name_or_id}",
            fg="red",
        )
        sys.exit(1)

    return raiden_app


def check_network_params(running_network):
    config_path = os.path.join(ROOT_DIR, 'config.json')

    with open(config_path) as json_data_file:
        config_data = json.load(json_data_file)

    network_data = _get_network_info(running_network["network_id"], config_data)
    if network_data:
        # Running Mainnet or Testnet. Validate smart contracts addresses
        if not validate_network_contracts(network_data, running_network):
            click.secho(
                "One or more of the specified smart contract addresses does not match with the configured ones",
                fg="red",
            )
            sys.exit(1)
    else:
        # Running custom network
        print("You are running a custom network")


def _get_network_info(network_id, config_data):
    for network in config_data['networks'].values():
        if network["network_id"] == network_id:
            return network
    return None


def validate_network_contracts(config_network, running_network):
    if running_network['token_network_registry'] == config_network['token_network_registry'] and \
       running_network['secret_registry'] == config_network['secret_registry'] and \
       running_network['endpoint_registry'] == config_network['endpoint_registry']:
        return True
    return False




