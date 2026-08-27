"""Kerberos string-to-key implementations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ETYPE_KEY_LENGTHS: Final = {17: 16, 18: 32, 19: 16, 20: 32}
AES128_KEY_LENGTH: Final = 16
AES256_KEY_LENGTH: Final = 32
AES128_SHA2_ENCTYPE: Final = 19
ETYPE_NAMES: Final = {
    19: b"aes128-cts-hmac-sha256-128",
    20: b"aes256-cts-hmac-sha384-192",
}


def _nfold(data: bytes, nbits: int) -> bytes:
    """Implement the n-fold operation from RFC 3961 section 6.1."""
    nbytes = nbits // 8
    if not data:
        return bytes(nbytes)
    input_length = len(data)
    lcm = input_length * nbytes // math.gcd(input_length, nbytes)

    def rotate_right(value: bytes, byte_length: int) -> bytes:
        remainder = 13 % (byte_length * 8)
        result = bytearray(len(value))
        value_int = int.from_bytes(value, "big")
        mask = (1 << (byte_length * 8)) - 1
        rotated = ((value_int >> remainder) | (value_int << (byte_length * 8 - remainder))) & mask
        result[:] = rotated.to_bytes(byte_length, "big")
        return bytes(result)

    folded = bytearray()
    current = data
    for _ in range(lcm // input_length):
        folded.extend(current)
        current = rotate_right(current, input_length)

    result = bytearray(nbytes)
    for offset in range(0, lcm, nbytes):
        values = [result[index] + folded[offset + index] for index in range(nbytes)]
        while any(value & ~0xFF for value in values):
            values = [
                (values[(index + 1) % nbytes] >> 8) + (values[index] & 0xFF)
                for index in range(nbytes)
            ]
        result = bytearray(values)
    return bytes(result)


def _aes_dk(key: bytes, constant: bytes, length: int) -> bytes:
    """Derive key material using the RFC 3961 AES DR function."""
    block = _nfold(constant, 128)
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    result = bytearray()
    while len(result) < length:
        block = encryptor.update(block)
        result.extend(block[: length - len(result)])
    return bytes(result)


def _sha2_kdf(key: bytes, label: bytes, length_bits: int, context: bytes = b"") -> bytes:
    """Implement RFC 8009 section 3 KDF-HMAC-SHA2."""
    if len(key) == AES128_KEY_LENGTH:
        algorithm = hashlib.sha256
    elif len(key) == AES256_KEY_LENGTH:
        algorithm = hashlib.sha384
    else:
        raise ValueError("unsupported RFC 8009 key length")
    message = (1).to_bytes(4, "big") + label + b"\x00"
    if context:
        message += context
    message += length_bits.to_bytes(4, "big")
    return hmac.new(key, message, algorithm).digest()[: math.ceil(length_bits / 8)]


def string2key(
    password: str | bytes,
    salt: str | bytes,
    enctype: int,
    iterations: int | None = None,
) -> bytes:
    """Derive a Kerberos long-term key for an enctype."""
    if enctype not in ETYPE_KEY_LENGTHS:
        raise ValueError(f"unsupported enctype: {enctype}")
    password_bytes = password.encode() if isinstance(password, str) else password
    salt_bytes = salt.encode() if isinstance(salt, str) else salt
    length = ETYPE_KEY_LENGTHS[enctype]
    if enctype in (17, 18):
        iterations = 4096 if iterations is None else iterations
        algorithm = hashes.SHA1()
        pbkdf_salt = salt_bytes
    else:
        iterations = 32768 if iterations is None else iterations
        algorithm = hashes.SHA256() if enctype == AES128_SHA2_ENCTYPE else hashes.SHA384()
        pbkdf_salt = ETYPE_NAMES[enctype] + b"\x00" + salt_bytes
    tkey = PBKDF2HMAC(
        algorithm=algorithm,
        length=length,
        salt=pbkdf_salt,
        iterations=iterations,
    ).derive(password_bytes)
    if enctype in (17, 18):
        return _aes_dk(tkey, b"kerberos", length)
    return _sha2_kdf(tkey, b"kerberos", length * 8)


string_to_key = string2key


def derive_krbtgt_key(master_key: str | bytes, enctype: int) -> bytes:
    """Derive the deterministic krbtgt key from a provider master key."""
    if enctype not in ETYPE_KEY_LENGTHS:
        raise ValueError(f"unsupported enctype: {enctype}")
    key = base64.b64decode(master_key) if isinstance(master_key, str) else master_key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=ETYPE_KEY_LENGTHS[enctype],
        salt=None,
        info=f"krbtgt-{enctype}".encode(),
    ).derive(key)
