# make it possible to run raiden with 'python -m raiden'
import grpc

from transport.rif_comms.proto import api_pb2_grpc
from transport.rif_comms.proto.api_pb2 import RskAddress
from transport.rif_comms.proto.api_pb2_grpc import CommunicationsApiStub


def main():
    import gevent.monkey

    gevent.monkey.patch_all()
    from raiden.ui.cli import run

    # the following lines are needed to use grpc with monkey patched gevent. see:
    # - https://github.com/grpc/grpc/pull/14561
    # - https://github.com/vinays/grpc-gevent-mokey
    import grpc._cython.cygrpc
    grpc._cython.cygrpc.init_grpc_gevent()

    # auto_envvar_prefix on a @click.command will cause all options to be
    # available also through environment variables prefixed with given prefix
    # http://click.pocoo.org/6/options/#values-from-environment-variables
    run(auto_envvar_prefix="RAIDEN")  # pylint: disable=no-value-for-parameter


if __name__ == "__main__":
    main()
