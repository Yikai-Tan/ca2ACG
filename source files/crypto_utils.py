import os
import struct
import hmac as hmac_stdlib

# Cryptography library imports (hazmat primitives)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


# Constants
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
HKDF_SALT_SIZE = 16
AES_IV_SIZE = 16
AES_BLOCK_SIZE_BITS = 128
NONCE_SIZE = 32
HMAC_DIGEST_SIZE = 32
MSG_LENGTH_PREFIX_SIZE = 4


# Key Derivation
# Uses HKDF-SHA256 to derive independent AES and HMAC keys from a master secret.
# Different `info` domain separators ensure cryptographic key independence.

def derive_keys(shared_secret: bytes, salt: bytes) -> tuple:
    """Derive AES-256 and HMAC-SHA256 keys from shared secret using HKDF."""
    hkdf_aes = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"aes-encryption-key",
    )
    aes_key = hkdf_aes.derive(shared_secret)

    hkdf_hmac = HKDF(
        algorithm=hashes.SHA256(),
        length=HMAC_KEY_SIZE,
        salt=salt,
        info=b"hmac-authentication-key",
    )
    hmac_key = hkdf_hmac.derive(shared_secret)

    return aes_key, hmac_key


def derive_at_rest_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a separate AES-256 key for encrypting files at rest."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"at-rest-encryption-key",
    )
    return hkdf.derive(shared_secret)


# AES-256-CBC Encryption & Decryption
# Uses PKCS7 padding and a fresh random IV per encryption call.
# Must be paired with HMAC (Encrypt-then-MAC) for integrity.

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """Encrypt plaintext using AES-256-CBC with PKCS7 padding. Returns (iv, ciphertext)."""
    iv = os.urandom(AES_IV_SIZE)

    padder = padding.PKCS7(AES_BLOCK_SIZE_BITS).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv, ciphertext


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext and remove PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# HMAC-SHA256 Message Authentication
# Implements the MAC step of Encrypt-then-MAC over (IV || ciphertext).

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute an HMAC-SHA256 tag over the given data."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify an HMAC-SHA256 tag using constant-time comparison."""
    computed_mac = compute_hmac(key, data)
    return hmac_stdlib.compare_digest(computed_mac, expected_mac)


# Length-Prefixed TCP Message Framing
# Wire format: [4-byte big-endian uint32 length] [payload]

def send_msg(sock, data: bytes) -> None:
    """Send a length-prefixed message over a TCP socket."""
    length_prefix = struct.pack(">I", len(data))
    sock.sendall(length_prefix + data)


def recv_msg(sock) -> bytes:
    """Receive a length-prefixed message from a TCP socket."""
    raw_length = _recv_exact(sock, MSG_LENGTH_PREFIX_SIZE)
    if not raw_length:
        raise ConnectionError(
            "Connection closed while reading message length prefix."
        )

    msg_length = struct.unpack(">I", raw_length)[0]

    data = _recv_exact(sock, msg_length)
    if not data:
        raise ConnectionError(
            f"Connection closed while reading message payload "
            f"(expected {msg_length} bytes)."
        )

    return data


def _recv_exact(sock, num_bytes: int) -> bytes:
    """Receive exactly num_bytes from a TCP socket, looping until complete."""
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            return b""
        buffer.extend(chunk)
    return bytes(buffer)


# RSA Key & Shared Secret Loading

def load_private_key(path: str):
    """Load an RSA private key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )


def load_public_key(path: str):
    """Load an RSA public key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_shared_secret(path: str) -> bytes:
    """Load the master shared secret from a binary file."""
    with open(path, "rb") as f:
        return f.read()
