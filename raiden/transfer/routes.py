from raiden.transfer.state import (
    NODE_NETWORK_REACHABLE,
    RouteState,
)

from raiden.utils.typing import ChannelID, List, NodeNetworkStateMap


def filter_reachable_routes(
    route_states: List[RouteState], nodeaddresses_to_networkstates: NodeNetworkStateMap
) -> List[RouteState]:
    """ This function makes sure we use reachable routes only. """

    return [
        route
        for route in route_states
        if nodeaddresses_to_networkstates.get(route.node_address) == NODE_NETWORK_REACHABLE
    ]


def filter_acceptable_routes(
    route_states: List[RouteState], blacklisted_channel_ids: List[ChannelID]
) -> List[RouteState]:
    """ Keeps only routes whose forward_channel is not in the list of blacklisted channels """

    return [
        route for route in route_states if route.channel_identifier not in blacklisted_channel_ids
    ]


def prune_route_table(
    route_states: List[RouteState], selected_route: RouteState
) -> List[RouteState]:
    """ Given a selected route, returns a filtered route table that
    contains only routes using the same forward channel and removes our own
    address in the process.
    """
    return [
        RouteState(node_address=rs.node_address, channel_identifier=selected_route.channel_identifier)
        for rs in route_states
        if rs.channel_identifier == selected_route.channel_identifier
    ]
