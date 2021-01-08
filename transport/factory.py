from transport.layer import Layer as TransportLayer
from transport.matrix.layer import MatrixLayer as MatrixTransportLayer
from transport.rif_comms.layer import Layer as RIFCommsTransportLayer


class Factory:
    """
    Factory is a class used to choose between transport layer implementations for Lumino and create an instance.
    """

    @staticmethod
    def create(transport_type: str, config: dict) -> TransportLayer:
        if transport_type == RIFCommsTransportLayer.transport_type:
            return RIFCommsTransportLayer(config)
        elif transport_type == MatrixTransportLayer.transport_type:
            return MatrixTransportLayer(config)
