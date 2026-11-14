import pytest

from tests.wire import assert_error


ERROR_RESPONSE = (
    b'ICAP/1.0 400 Bad Request\r\n'
    b'ISTag: "test"\r\n'
    b'Connection: close\r\n'
    b'Encapsulated: null-body=0\r\n\r\n'
)


@pytest.mark.parametrize('status', [
    b'HTTP/1.1 400 Bad Request',
    b'ICAP/9.9 400 Bad Request',
    b'ICAP/1.0 0400 Bad Request',
], ids=['http-protocol', 'wrong-icap-version', 'four-digit-status'])
def test_error_rejects_invalid_status_line(status):
    response = status + ERROR_RESPONSE[ERROR_RESPONSE.index(b'\r\n'):]
    with pytest.raises(AssertionError):
        assert_error(response, 400)


@pytest.mark.parametrize('duplicate', [
    b'Encapsulated: res-hdr=0, res-body=1\r\n',
    b'eNcApSuLaTeD: null-body=1\r\n',
    b'ISTag: "conflicting"\r\n',
    b'Connection: keep-alive\r\n',
], ids=['encapsulated', 'mixed-case-encapsulated', 'istag', 'connection'])
def test_error_rejects_duplicate_icap_headers(duplicate):
    # Put the conflicting value first: a dict-overwrite bug would hide it.
    response = ERROR_RESPONSE.replace(b'ISTag:', duplicate + b'ISTag:', 1)
    with pytest.raises(AssertionError):
        assert_error(response, 400)


def test_error_accepts_valid_icap_response():
    assert_error(ERROR_RESPONSE, 400)
