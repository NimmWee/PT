import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from icap_server.crypto import InvalidContainer, decrypt_body


def test_known_vector():
    sealed = bytes.fromhex('47fd9f5884b5421687c451ef7d2f2cac3a8f8d6e7d4d282ed7')
    assert decrypt_body(b'ENC1' + bytes(range(12)) + sealed) == b'\x00\xffICAP\x80\r\n'


@pytest.mark.parametrize('body', [b'', b'E', b'ENC', b'enc1', bytes(range(256))])
def test_unmarked_body(body):
    assert decrypt_body(body) == body


@pytest.mark.parametrize('plain', [b'', b'hello', bytes(range(256)), b'ENC1\x00\xff'])
def test_decrypt(plain):
    nonce = bytes(range(12))
    encrypted = AESGCM(bytes(range(32))).encrypt(nonce, plain, None)
    assert decrypt_body(b'ENC1' + nonce + encrypted) == plain


@pytest.mark.parametrize('length', [4, 31], ids=['marker-only', 'one-byte-short'])
def test_short_container(length):
    with pytest.raises(InvalidContainer):
        decrypt_body(b'ENC1' + bytes(length - 4))


@pytest.mark.parametrize('index', [4, 15, 16, -1])
def test_tampered_container(index):
    nonce = bytes(range(12))
    body = bytearray(b'ENC1' + nonce + AESGCM(bytes(range(32))).encrypt(nonce, b'x', None))
    body[index] ^= 1
    with pytest.raises(InvalidContainer):
        decrypt_body(bytes(body))
