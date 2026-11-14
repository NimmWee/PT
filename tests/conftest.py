import threading

import pytest

from icap_server.server import ICAPServer


@pytest.fixture(scope='session')
def server_address():
    # Bind port 0, avoiding port races and any manually started server.
    with ICAPServer(('127.0.0.1', 0), request_timeout=0.5) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            yield server.server_address
        finally:
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive(), 'test server did not stop'
