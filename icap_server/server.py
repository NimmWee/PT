import argparse
import socketserver

from .crypto import InvalidContainer
from .protocol import ProtocolError, adapt, error_response, success_response


class ICAPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(self.server.request_timeout)
        try:
            http, body = adapt(self.rfile)
            response = success_response(http, body)
        except ProtocolError as exc:
            response = error_response(exc.code)
        except InvalidContainer:
            response = error_response(400)
        except TimeoutError:
            response = error_response(408)
        except OSError:
            # A disconnected peer cannot receive a response; the next connection can.
            return
        try:
            self.wfile.write(response)
        except OSError:
            pass


class ICAPServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, address, *, request_timeout=5.0):
        self.request_timeout = request_timeout
        super().__init__(address, ICAPHandler)


def build_parser():
    parser = argparse.ArgumentParser(description='ICAP RESPMOD /decrypt server')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=1344)
    return parser


def main():
    args = build_parser().parse_args()
    with ICAPServer((args.host, args.port)) as server:
        host, port = server.server_address
        print(f'Listening on {host}:{port} (/decrypt)', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
