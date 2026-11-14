import re
import socket


def http_headers(body, *, length=None):
    size = len(body) if length is None else length
    return (b'HTTP/1.1 201 Created\r\nX-Repeat: first\r\n'
            b'cOnTeNt-LeNgTh:\t' + str(size).encode() + b'  \r\n'
            b'X-Repeat: second\r\nContent-Type: application/octet-stream\r\n'
            b'X-Binary: \xff\x80\r\n\r\n')


def chunked(parts):
    return b''.join(f'{len(p):X}\r\n'.encode() + p + b'\r\n' for p in parts if p) + b'0\r\n\r\n'


def request(body=b'', *, parts=None, http=None, encapsulated=None,
            method=b'RESPMOD', uri=b'icap://localhost/decrypt', version=b'ICAP/1.0', extra=b''):
    http = http_headers(body) if http is None else http
    encapsulated = (b'res-hdr=0, res-body=' + str(len(http)).encode()
                    if encapsulated is None else encapsulated)
    return (method + b' ' + uri + b' ' + version + b'\r\nHost: localhost\r\n'
            b'Connection: close\r\nEncapsulated: ' + encapsulated + b'\r\n' + extra + b'\r\n'
            + http + chunked([body] if parts is None else parts))


def exchange(address, wire, *, fragments=None, half_close=True):
    with socket.create_connection(address, timeout=4) as client:
        client.settimeout(4)
        if fragments:
            for offset in range(0, len(wire), fragments):
                client.sendall(wire[offset:offset + fragments])
        else:
            client.sendall(wire)
        if half_close:
            client.shutdown(socket.SHUT_WR)
        data = bytearray()
        while piece := client.recv(65536):
            data.extend(piece)
        return bytes(data)


def split_response(wire):
    head, payload = wire.split(b'\r\n\r\n', 1)
    lines = head.split(b'\r\n')
    assert re.fullmatch(
        rb'ICAP/1\.0 [0-9]{3} [\t\x20-\x7e\x80-\xff]*', lines[0]
    ), 'Invalid ICAP status line'
    fields = {}
    for line in lines[1:]:
        name, value = line.split(b':', 1)
        name = name.lower()
        assert name not in fields, 'Duplicate ICAP response header'
        fields[name] = value.strip()
    assert re.fullmatch(rb'"[^"\r\n]+"', fields[b'istag'])
    assert fields[b'connection'].lower() == b'close'
    return lines[0], fields, payload


def assert_success(wire, expected_headers, expected_body):
    status, fields, payload = split_response(wire)
    assert status == b'ICAP/1.0 200 OK'
    assert fields[b'encapsulated'] == b'res-hdr=0, res-body=' + str(len(expected_headers)).encode()
    assert payload[:len(expected_headers)] == expected_headers
    remaining = payload[len(expected_headers):]
    actual = bytearray()
    while True:
        size_line, remaining = remaining.split(b'\r\n', 1)
        assert re.fullmatch(rb'[0-9a-fA-F]+', size_line)
        size = int(size_line, 16)
        if size == 0:
            assert remaining == b'\r\n'  # terminal CRLF and no surplus bytes
            break
        assert len(remaining) >= size + 2
        actual.extend(remaining[:size])
        assert remaining[size:size + 2] == b'\r\n'
        remaining = remaining[size + 2:]
    assert bytes(actual) == expected_body


def assert_error(wire, code=None):
    status, fields, payload = split_response(wire)
    actual_code = int(status.split()[1])
    assert 400 <= actual_code < 500
    if code is not None:
        assert actual_code == code
    assert fields[b'encapsulated'] == b'null-body=0'
    assert payload == b''
