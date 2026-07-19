# >>>>> GCM SWAP: START >>>>>
import os
import struct

# Cryptography library imports (hazmat primitives)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
# InvalidTag is raised by GCM decryption when the tag doesn't match —
# this IS the integrity check now, built into the cipher itself.
from cryptography.exceptions import InvalidTag


# Constants
AES_KEY_SIZE = 32
HKDF_SALT_SIZE = 16
# GCM nonces are 12 bytes (96 bits) by convention — this is the size GCM is
# designed and optimized for, unlike CBC's 16-byte IV.
AES_GCM_NONCE_SIZE = 12
NONCE_SIZE = 32
MSG_LENGTH_PREFIX_SIZE = 4
# HMAC_KEY_SIZE, AES_BLOCK_SIZE_BITS, HMAC_DIGEST_SIZE removed — they were
# only needed for the old separate-HMAC and PKCS7-padding machinery, which
# GCM replaces entirely.


# Key Derivation
# Uses HKDF-SHA256 to derive the AES key from a master secret.
# NOTE: previously this also derived a separate HMAC key. GCM produces its
# own authentication tag as part of encryption, so a second, separately
# managed HMAC key is no longer needed — one less key to derive, store,
# and keep straight.

def derive_keys(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive an AES-256 key from the shared secret using HKDF."""
    hkdf_aes = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"aes-encryption-key",
    )
    return hkdf_aes.derive(shared_secret)
# <<<<< GCM SWAP: END <<<<<


def derive_at_rest_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a separate AES-256 key for encrypting files at rest."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"at-rest-encryption-key",
    )
    return hkdf.derive(shared_secret)


# >>>>> GCM SWAP: START >>>>>
# AES-256-GCM Encryption & Decryption
# GCM is an AEAD (Authenticated Encryption with Associated Data) mode:
# encryption and integrity-checking happen together, in one primitive.
# No padding needed (unlike CBC), and no separate HMAC needed either —
# the "tag" IS the integrity proof.

# >>>>> AAD ADD: START >>>>>
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
    """Encrypt plaintext using AES-256-GCM. Returns (nonce, ciphertext, tag).
    aad (Additional Authenticated Data) is NOT encrypted -- it stays
    readable -- but IS covered by the tag, so it can't be tampered with
    without decryption failing, same as the ciphertext itself."""
    nonce = os.urandom(AES_GCM_NONCE_SIZE)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # encryptor.tag is only available AFTER finalize() — it's computed from
    # everything that was encrypted, and is what the receiver checks against.
    return nonce, ciphertext, encryptor.tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM ciphertext. `aad` must be byte-for-byte identical
    to what was used during encryption, or this raises InvalidTag -- exactly
    like a tampered ciphertext would. Raises InvalidTag if the data was
    tampered with or corrupted — this call IS the integrity check, there's
    no separate verify step to remember."""
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(aad)
    return decryptor.update(ciphertext) + decryptor.finalize()
# <<<<< AAD ADD: END <<<<<
# <<<<< GCM SWAP: END <<<<<


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
    """Load a passphrase-encrypted RSA private key from a PEM file.

    The passphrase is read from the KEY_PASSPHRASE environment variable so it
    is never hardcoded in the source tree.
    """
    pw = os.environ.get("KEY_PASSPHRASE")
    if not pw:
        raise RuntimeError(
            "KEY_PASSPHRASE environment variable is not set.\n"
            "  Set it before running, e.g.:  export KEY_PASSPHRASE='your-passphrase'"
        )
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=pw.encode("utf-8"),
        )


def load_public_key(path: str):
    """Load an RSA public key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_shared_secret(path: str) -> bytes:
    """Load the master shared secret from a binary file."""
    with open(path, "rb") as f:
        return f.read()


# RSA-OAEP Key Wrapping (Key Transport)
# Client wraps a fresh random session key with the server's PUBLIC key.
# Only the server, holding the matching PRIVATE key, can unwrap it.

from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding

def rsa_wrap_key(server_public_key, key_material: bytes) -> bytes:
    """Encrypt (wrap) a symmetric key with the server's RSA public key using OAEP."""
    return server_public_key.encrypt(
        key_material,
        _asym_padding.OAEP(
            mgf=_asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_unwrap_key(server_private_key, wrapped_key: bytes) -> bytes:
    """Decrypt (unwrap) a symmetric key with the server's RSA private key using OAEP."""
    return server_private_key.decrypt(
        wrapped_key,
        _asym_padding.OAEP(
            mgf=_asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
