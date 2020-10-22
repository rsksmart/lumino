from raiden.network.transport.matrix.layer import MatrixLayer as MatrixTransportLayer


class Factory:
    """
    Factory is a class used to choose between transport layer implementations for Lumino.
    """

    @staticmethod
    def create(transport_type : str, config : dict):
        if transport_type == "rif-comms":
            raise Exception("not implemented yet!")
        elif transport_type == "matrix":
            return MatrixTransportLayer(config)

