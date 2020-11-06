# make it possible to run raiden with 'python -m raiden'
import grpc

from transport.rif_comms.proto import api_pb2_grpc


def main():
    import gevent.monkey

    gevent.monkey.patch_all()
    from raiden.ui.cli import run

    # auto_envvar_prefix on a @click.command will cause all options to be
    # available also through environment variables prefixed with given prefix
    # http://click.pocoo.org/6/options/#values-from-environment-variables
    channel = grpc.insecure_channel("localhost:5013")
    stub = api_pb2_grpc.CommunicationsApiStub(channel)
    stub.ConnectToCommunicationsNode(api_pb2_grpc.api__pb2.RskAddress(address="0x2aCc95758f8b5F583470bA265Eb685a8f45fC9D5"))

    print("LocatePeerId")
    response = stub.LocatePeerId(api_pb2_grpc.api__pb2.RskAddress(address="0x2aCc95758f8b5F583470bA265Eb685a8f45fC9D5"))
    run(auto_envvar_prefix="RAIDEN")  # pylint: disable=no-value-for-parameter






if __name__ == "__main__":
    main()
