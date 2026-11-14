import socket

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tests.wire import assert_error, assert_success, exchange, http_headers, request


def encrypt(plain, key=bytes(range(32)), aad=None, *, nonce=bytes(range(12))):
    return b'ENC1' + nonce + AESGCM(key).encrypt(nonce, plain, aad)


def check_recovery(address):
    body = b'next connection\x00\xff'
    assert_success(exchange(address, request(body)), http_headers(body), body)


@pytest.mark.parametrize('body', [b'', b'E', b'ENC', b'enc1', b'prefixENC1',
                                b'\x00\xff\xfe\r\n0\r\n\r\n', bytes(range(256))])
def test_plain_body(server_address, body):
    assert_success(exchange(server_address, request(body)), http_headers(body), body)


@pytest.mark.parametrize('chunk_size', [1, 2, 3, 4, 5, 7, 11, 12, 15, 16, 17, 31, 32, 255, 4096])
def test_encrypted_chunk_boundaries(server_address, chunk_size):
    plain = bytes(range(256)) + b'\xff\x00ENC1\r\n'
    body = encrypt(plain)
    parts = [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)]
    assert_success(exchange(server_address, request(body, parts=parts)), http_headers(plain), plain)


def test_response_offsets_and_headers(server_address):
    plain = b'x'
    body = encrypt(plain)
    incoming = (
        b'HTTP/1.0 418 Teapot\r\nx-same: a\r\nContent-Length: '
        + str(len(body)).encode() + b'\r\nx-same: b\r\n\r\n'
    )
    expected = incoming.replace(b'Content-Length: ' + str(len(body)).encode(), b'Content-Length: 1')
    assert_success(exchange(server_address, request(body, http=incoming)), expected, plain)


def test_empty_plaintext(server_address):
    assert_success(exchange(server_address, request(encrypt(b''))), http_headers(b''), b'')


def test_different_valid_nonce(server_address):
    plain = b'other nonce\x00\xff'
    body = encrypt(plain, nonce=bytes(reversed(range(12))))
    assert_success(exchange(server_address, request(body)), http_headers(plain), plain)


def test_decrypted_marker_is_not_processed_again(server_address):
    plain = b'ENC1\x00\xff'
    assert_success(exchange(server_address, request(encrypt(plain))), http_headers(plain), plain)


def test_complete_request_without_half_close(server_address):
    plain = b'no half-close\x00\xff'
    response = exchange(server_address, request(encrypt(plain)), half_close=False)
    assert_success(response, http_headers(plain), plain)


def test_fragmented_tcp(server_address):
    plain = bytes(range(256))
    body = encrypt(plain)
    # Each ICAP field, size line and nonce may span TCP writes.
    assert_success(exchange(server_address, request(body), fragments=1), http_headers(plain), plain)


@pytest.mark.parametrize('encrypted', [False, True])
def test_large_binary(server_address, encrypted):
    plain = bytes(range(256)) * 4096
    body = encrypt(plain) if encrypted else plain
    parts = [body[i:i + 8191] for i in range(0, len(body), 8191)]
    assert_success(exchange(server_address, request(body, parts=parts)), http_headers(plain), plain)


@pytest.mark.parametrize('length', [4, 31], ids=['marker-only', 'one-byte-short'])
def test_invalid_container_then_valid(server_address, length):
    body = b'ENC1' + bytes(length - 4)
    assert_error(exchange(server_address, request(body)), 400)
    check_recovery(server_address)


def test_invalid_tag_at_minimum_container_size(server_address):
    body = bytearray(encrypt(b''))
    body[-1] ^= 1
    assert len(body) == 32
    assert_error(exchange(server_address, request(bytes(body))), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('case', ['nonce', 'ciphertext', 'tag', 'wrong_key', 'aad', 'truncated', 'extra'])
def test_authentication_then_valid(server_address, case):
    body = bytearray(encrypt(b'\x00\xffsecret'))
    if case in ('nonce', 'ciphertext', 'tag'):
        body[{'nonce': 4, 'ciphertext': 16, 'tag': -1}[case]] ^= 1
    elif case == 'wrong_key':
        body = encrypt(b'plain', key=bytes(32))
    elif case == 'aad':
        body = encrypt(b'plain', aad=b'unexpected AAD')
    elif case == 'truncated':
        body = body[:-1]
    else:
        body += b'x'
    assert_error(exchange(server_address, request(bytes(body))), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('changes,code', [
    ({'method': b'OPTIONS'}, 405), ({'method': b'REQMOD'}, 405),
    ({'version': b'ICAP/2.0'}, 400), ({'uri': b'icap://localhost/other'}, 404),
    ({'uri': b'/decrypt'}, 400), ({'uri': b'http://localhost/decrypt'}, 400),
    ({'extra': b'Preview: 0\r\n'}, 400),
])
def test_bad_icap_request(server_address, changes, code):
    assert_error(exchange(server_address, request(b'abc', **changes)), code)
    check_recovery(server_address)


@pytest.mark.parametrize('encapsulated', [b'', b'res-hdr=1, res-body=100',
    b'req-hdr=0, res-hdr=10, res-body=100', b'res-hdr=0, res-body=-1',
    b'res-hdr=0, res-body=1', b'res-hdr=0, res-body=9999',
    b'res-hdr=0, res-body=x', b'res-hdr=0, null-body=100',
    b'res-hdr=0, res-body=100, res-body=100'])
def test_bad_encapsulation(server_address, encapsulated):
    assert_error(exchange(server_address, request(b'x', encapsulated=encapsulated)), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('delta', [-1, 1], ids=['one-byte-before', 'one-byte-after'])
def test_adjacent_http_body_offsets(server_address, delta):
    body = b'x'
    offset = len(http_headers(body)) + delta
    encapsulated = b'res-hdr=0, res-body=' + str(offset).encode()
    assert_error(exchange(server_address, request(body, encapsulated=encapsulated)), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('http', [b'HTTP/1.1 200 OK\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'garbage\r\nContent-Length: 1\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nBad Header: value\r\nContent-Length: 1\r\n\r\n'])
def test_bad_http_headers(server_address, http):
    assert_error(exchange(server_address, request(b'x', http=http)), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('declared', [0, 2], ids=['too-short', 'too-long'])
def test_length_mismatch(server_address, declared):
    assert_error(exchange(server_address, request(b'x', http=http_headers(b'x', length=declared))), 400)
    check_recovery(server_address)


@pytest.mark.parametrize('declared,chunks', [
    (1, b'Z\r\nx\r\n0\r\n\r\n'),
    (1, b'-1\r\n'),
    (1, b'+1\r\nx\r\n0\r\n\r\n'),
    (1, b'1\r\nxXX0\r\n\r\n'),
    (2, b'2\r\nx'),
    (1, b'1\r\nx\r\n'),
    (1, b'0\r\n'),
    (1, b'1;ext=1\r\nx\r\n0\r\n\r\n'),
    (1, b'0\r\nTrailer: nope\r\n\r\n'),
], ids=[
    'non-hex-size', 'negative-size', 'signed-size', 'missing-data-crlf',
    'eof-inside-data', 'missing-zero-chunk', 'missing-final-crlf',
    'unsupported-extension', 'unsupported-trailer',
])
def test_bad_chunk_framing(server_address, declared, chunks):
    wire = request(b'x', http=http_headers(b'x', length=declared))
    wire = wire[:-len(b'1\r\nx\r\n0\r\n\r\n')] + chunks
    assert_error(exchange(server_address, wire), 400)
    check_recovery(server_address)


def test_case_insensitive_headers(server_address):
    body = b'\xff\x00'
    wire = request(body).replace(b'Encapsulated:', b'eNcApSuLaTeD:')
    assert_success(exchange(server_address, wire), http_headers(body), body)


def test_timeout_then_valid(server_address):
    with socket.create_connection(server_address, timeout=4) as client:
        client.settimeout(4)
        client.sendall(b'RESPMOD ')
        data = bytearray()
        while piece := client.recv(4096):
            data.extend(piece)
    assert_error(bytes(data), 408)
    check_recovery(server_address)


def test_partial_header_then_valid(server_address):
    assert_error(exchange(server_address, b'RESPMOD icap://localhost/decrypt ICAP/1.0\r\nHost:'), 400)
    check_recovery(server_address)


def test_duplicate_encapsulated(server_address):
    assert_error(exchange(server_address, request(b'x', extra=b'Encapsulated: res-hdr=0, res-body=1\r\n')), 400)
    check_recovery(server_address)
