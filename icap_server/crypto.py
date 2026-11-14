from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TEST_KEY = bytes.fromhex(
    '000102030405060708090a0b0c0d0e0f'
    '101112131415161718191a1b1c1d1e1f'
)


class InvalidContainer(ValueError):
    """An ENC1 container is truncated or fails GCM authentication."""


def decrypt_body(body: bytes) -> bytes:
    if not body.startswith(b'ENC1'):
        return body
    # 4 marker + 12 nonce + at least 0 ciphertext + 16 tag.
    if len(body) < 32:
        raise InvalidContainer('ENC1 container is shorter than 32 bytes')
    try:
        return AESGCM(TEST_KEY).decrypt(body[4:16], body[16:], None)
    except InvalidTag as exc:
        raise InvalidContainer('ENC1 authentication failed') from exc
