from transport.matrix.layer import MatrixLayer as MatrixTransportLayer
from transport.rif_comms.layer import RifCommsLayer as RifCommsTransportLayer


class Factory:
    """
    Factory is a class used to choose between transport layer implementations for Lumino.
    """

    @staticmethod
    def create(transport_type : str, config : dict):
        if transport_type == "rif-comms":
            return RifCommsTransportLayer(config)
        elif transport_type == "matrix":
            return MatrixTransportLayer(config)

