from email.utils import formatdate
import re
from typing import BinaryIO
from urllib.parse import urlsplit

from .crypto import decrypt_body

MAX_HEADER_BYTES = 65536
ISTAG = b'"enc1-aes256gcm-v1"'
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class ProtocolError(ValueError):
    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code


def read_line(stream: BinaryIO) -> bytes:
    line = stream.readline(MAX_HEADER_BYTES + 1)
    if len(line) > MAX_HEADER_BYTES or not line.endswith(b'\r\n'):
        raise ProtocolError('Missing CRLF, truncated or oversized line')
    return line


def read_head(stream: BinaryIO) -> bytes:
    result = bytearray()
    while True:
        line = read_line(stream)
        result.extend(line)
        if len(result) > MAX_HEADER_BYTES:
            raise ProtocolError('Header section too large')
        if line == b'\r\n':
            return bytes(result)


def read_exact(stream: BinaryIO, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = stream.read(min(count - len(result), 65536))
        if not part:
            raise ProtocolError('Truncated message')
        result.extend(part)
    return bytes(result)


def parse_head(raw: bytes) -> tuple[bytes, list[bytes]]:
    if not raw.endswith(b'\r\n\r\n'):
        raise ProtocolError('Header terminator missing at Encapsulated offset')
    lines = raw[:-4].split(b'\r\n')
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        if not colon or not TOKEN.fullmatch(name):
            raise ProtocolError('Malformed header name')
        if any((c < 32 and c != 9) or c == 127 for c in value):
            raise ProtocolError('Control character in header')
    return lines[0], lines[1:]


def values(headers: list[bytes], name: bytes) -> list[bytes]:
    return [line.partition(b':')[2].strip(b' \t') for line in headers
            if line.partition(b':')[0].lower() == name]


def single(headers: list[bytes], name: bytes) -> bytes:
    found = values(headers, name)
    if len(found) != 1 or not found[0]:
        raise ProtocolError('Missing or duplicate required header')
    return found[0]


def decimal(raw: bytes) -> int:
    if not re.fullmatch(rb'[0-9]+', raw):
        raise ProtocolError('Expected decimal integer')
    try:
        return int(raw)
    except ValueError as exc:
        raise ProtocolError('Decimal integer too long') from exc


def body_offset(head: bytes) -> int:
    start, headers = parse_head(head)
    parts = start.split(b' ')
    if len(parts) != 3 or parts[2] != b'ICAP/1.0':
        raise ProtocolError('Expected ICAP/1.0 request line')
    if parts[0] != b'RESPMOD':
        raise ProtocolError('Only RESPMOD is supported', 405)
    try:
        uri = urlsplit(parts[1].decode('ascii'))
        if uri.scheme != 'icap' or not uri.hostname or uri.fragment:
            raise ValueError('Absolute ICAP URI required')
    except (UnicodeError, ValueError) as exc:
        raise ProtocolError('Invalid ICAP URI') from exc
    if uri.path != '/decrypt':
        raise ProtocolError('Unknown service', 404)
    single(headers, b'host')
    if values(headers, b'preview') or values(headers, b'transfer-encoding'):
        raise ProtocolError('Preview and Transfer-Encoding are unsupported')
    match = re.fullmatch(
        rb'res-hdr=0\s*,\s*res-body=([0-9]+)',
        single(headers, b'encapsulated'), re.I,
    )
    if not match:
        raise ProtocolError('Expected res-hdr=0, res-body=N')
    offset = decimal(match[1])
    if not 4 <= offset <= MAX_HEADER_BYTES:
        raise ProtocolError('HTTP header offset outside supported bounds')
    return offset


def read_chunks(stream: BinaryIO, expected_length: int) -> bytes:
    body = bytearray()
    while True:
        size_line = read_line(stream)[:-2]
        if not re.fullmatch(rb'[0-9a-fA-F]+', size_line):
            raise ProtocolError('Invalid chunk size; extensions are unsupported')
        size = int(size_line, 16)
        if not size:
            if read_line(stream) != b'\r\n':
                raise ProtocolError('Trailers are unsupported')
            if len(body) != expected_length:
                raise ProtocolError('Content-Length does not match chunked body')
            return bytes(body)
        if size > expected_length - len(body):
            raise ProtocolError('Chunked body exceeds Content-Length')
        body.extend(read_exact(stream, size))
        if read_exact(stream, 2) != b'\r\n':
            raise ProtocolError('Missing chunk data CRLF')


def adapt(stream: BinaryIO) -> tuple[bytes, bytes]:
    offset = body_offset(read_head(stream))
    raw_http = read_exact(stream, offset)
    status, headers = parse_head(raw_http)
    if not re.fullmatch(rb'HTTP/1\.[01] [0-9]{3}(?: [^\r\n]*)?', status):
        raise ProtocolError('Invalid HTTP status line')
    length = decimal(single(headers, b'content-length'))
    if values(headers, b'transfer-encoding'):
        raise ProtocolError('HTTP Transfer-Encoding is unsupported')
    body = read_chunks(stream, length)
    plain = decrypt_body(body)
    if not body.startswith(b'ENC1'):
        return raw_http, body
    # Replace only the decimal value; preserve the header name, whitespace and order.
    updated = []
    for line in headers:
        if line.partition(b':')[0].lower() == b'content-length':
            match = re.fullmatch(rb'([^:]+:[ \t]*)[0-9]+([ \t]*)', line)
            line = match[1] + str(len(plain)).encode('ascii') + match[2]
        updated.append(line)
    return b'\r\n'.join([status, *updated]) + b'\r\n\r\n', plain


def response_head(code: int, encapsulated: bytes) -> bytes:
    reasons = {200: b'OK', 400: b'Bad Request', 404: b'Not Found',
               405: b'Method Not Allowed', 408: b'Request Timeout'}
    return (b'ICAP/1.0 ' + str(code).encode('ascii') + b' ' + reasons[code]
            + b'\r\nISTag: ' + ISTAG + b'\r\nDate: ' + formatdate(usegmt=True).encode('ascii')
            + b'\r\nConnection: close\r\nEncapsulated: ' + encapsulated + b'\r\n\r\n')


def error_response(code: int) -> bytes:
    return response_head(code, b'null-body=0')


def success_response(http: bytes, body: bytes) -> bytes:
    head = response_head(200, b'res-hdr=0, res-body=' + str(len(http)).encode('ascii'))
    chunk = (f'{len(body):x}\r\n'.encode('ascii') + body + b'\r\n') if body else b''
    return head + http + chunk + b'0\r\n\r\n'
