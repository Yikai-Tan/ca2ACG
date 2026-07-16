# >>>>> GCM SWAP: START >>>>>
"""
RSA challenge-response auth, AES-256-GCM
encryption (built-in authentication, no separate HMAC), and RSA-PSS signatures.

"""
# <<<<< GCM SWAP: END <<<<<

import os
import sys
import json
import base64
import socket

# Cryptographic Primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# Shared Utilities
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto_utils


# Client Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999

# Key Material Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOY_DIR = os.path.join(SCRIPT_DIR, "..", "deployment files")

CLIENT_PRIVATE_KEY_PATH = os.path.join(DEPLOY_DIR, "client_private.pem")
CLIENT_PUBLIC_KEY_PATH  = os.path.join(DEPLOY_DIR, "client_public.pem")
SHARED_SECRET_PATH      = os.path.join(DEPLOY_DIR, "shared_secret.key")


# RSA Challenge-Response Authentication

def perform_handshake(sock, client_private_key) -> bool:
    """Respond to the server's RSA challenge-response authentication."""
    print("[HANDSHAKE] Waiting for server challenge (nonce)...")

    try:
        nonce = crypto_utils.recv_msg(sock)
    except ConnectionError as e:
        print(f"[HANDSHAKE] [FAIL] Connection error: {e}")
        return False

    print(f"[HANDSHAKE] Received {len(nonce)}-byte nonce: {nonce.hex()[:40]}...")

    print("[HANDSHAKE] Signing nonce with RSA-PSS (SHA-256)...")
    signature = client_private_key.sign(
        nonce,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print(f"[HANDSHAKE] Signature generated ({len(signature)} bytes).")

    crypto_utils.send_msg(sock, signature)
    print("[HANDSHAKE] Signature sent. Awaiting server verification result...")

    try:
        result = crypto_utils.recv_msg(sock)
    except ConnectionError as e:
        print(f"[HANDSHAKE] [FAIL] Connection error: {e}")
        return False

    if result == b"AUTH_OK":
        print("[HANDSHAKE] [OK] Server accepted our identity -- authentication passed!")
        return True
    else:
        print("[HANDSHAKE] [FAIL] Server REJECTED our identity -- authentication failed!")
        print("[HANDSHAKE]   Check that client_private.pem matches the server's")
        print("[HANDSHAKE]   copy of client_public.pem.")
        return False


# RSA Digital Signature (Non-Repudiation)

def sign_file(private_key, file_data: bytes) -> bytes:
    """Sign file contents with RSA-PSS for non-repudiation."""
    signature = private_key.sign(
        file_data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


# Encrypt, MAC, Sign, and Transmit

def transfer_file(sock, filepath: str, client_private_key, shared_secret: bytes) -> bool:
    """Encrypt a file with AES-256-CBC, authenticate with HMAC-SHA256, sign with RSA-PSS, and send."""
    filename = os.path.basename(filepath)
    print(f"\n[TRANSFER] Preparing to send: '{filename}'")

    # Read file
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print(f"[TRANSFER] [FAIL] File not found: {filepath}")
        return False
    except PermissionError:
        print(f"[TRANSFER] [FAIL] Permission denied: {filepath}")
        return False

    print(f"[TRANSFER] File loaded: {len(file_data):,} bytes")

    # RSA-PSS signature (sign original plaintext before encryption)
    print("[TRANSFER] Generating RSA-PSS signature (non-repudiation)...")
    file_signature = sign_file(client_private_key, file_data)
    print(f"[TRANSFER] [OK] RSA signature generated ({len(file_signature)} bytes)")

    # >>>>> GCM SWAP: START >>>>>
    # Derive AES key via HKDF (fresh salt per transfer).
    # Only one key now -- no separate HMAC key needed.
    print("[TRANSFER] Deriving session key via HKDF-SHA256...")
    salt = os.urandom(crypto_utils.HKDF_SALT_SIZE)
    aes_key = crypto_utils.derive_keys(shared_secret, salt)
    print(f"[TRANSFER]   Session salt: {salt.hex()}")
    print(f"[TRANSFER]   [OK] AES-256 key derived (info='aes-encryption-key')")

    # AES-256-GCM encryption -- produces ciphertext AND an authentication
    # tag in one call. No padding, no separate MAC step.
    print("[TRANSFER] Encrypting file with AES-256-GCM...")
    iv, ciphertext, tag = crypto_utils.aes_gcm_encrypt(aes_key, file_data)
    print(f"[TRANSFER]   Nonce:      {iv.hex()}")
    print(f"[TRANSFER]   Tag:        {tag.hex()}")
    print(f"[TRANSFER]   Ciphertext: {len(ciphertext):,} bytes")

    # Build and send JSON payload -- "hmac" field replaced by "tag"
    payload = {
        "salt":       salt.hex(),
        "iv":         iv.hex(),
        "tag":        tag.hex(),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "filename":   filename,
        "signature":  base64.b64encode(file_signature).decode("utf-8"),
    }
    # <<<<< GCM SWAP: END <<<<<

    payload_json = json.dumps(payload, indent=None)
    payload_bytes = payload_json.encode("utf-8")

    print(f"\n[TRANSFER] Sending payload ({len(payload_bytes):,} bytes)...")
    crypto_utils.send_msg(sock, payload_bytes)
    print("[TRANSFER] [OK] Payload sent. Awaiting server confirmation...")

    # Wait for server confirmation
    try:
        result = crypto_utils.recv_msg(sock)

        if result == b"TRANSFER_OK":
            print("[TRANSFER] [OK] Server confirmed successful receipt and storage!")
            return True
        # >>>>> GCM SWAP: START >>>>>
        elif result == b"TAG_FAIL":
            print("[TRANSFER] [FAIL] Server reported GCM tag verification failure!")
            print("[TRANSFER]   The data may have been tampered with in transit,")
            print("[TRANSFER]   or the shared secrets don't match.")
            return False
        # <<<<< GCM SWAP: END <<<<<
        else:
            decoded = result.decode("utf-8", errors="replace")
            print(f"[TRANSFER] [FAIL] Unexpected server response: {decoded}")
            return False

    except ConnectionError:
        print("[TRANSFER] [FAIL] Connection lost while waiting for confirmation.")
        return False


# Main Entry Point

def main():
    """Parse arguments, load keys, connect, authenticate, and transfer the file."""
    print("=" * 64)
    print("  +======================================================+")
    # >>>>> GCM SWAP: START >>>>>
    print("  |         SECURE FILE TRANSFER CLIENT v1.0            |")
    print("  |   AES-256-GCM + RSA-PSS Signatures                 |")
    # <<<<< GCM SWAP: END <<<<<
    print("  +======================================================+")
    print("=" * 64)

    if len(sys.argv) < 2:
        print("\n  Usage: python client.py <file_to_send>")
        print("  Example: python client.py report.pdf")
        print("  Example: python client.py \"C:\\Documents\\data.txt\"")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"\n[ERROR] File not found: {filepath}")
        sys.exit(1)

    print(f"\n[INIT] File to transfer: {filepath}")
    print(f"[INIT] File size: {os.path.getsize(filepath):,} bytes")

    # Load cryptographic key material
    print("\n[INIT] Loading cryptographic keys...")

    try:
        client_private_key = crypto_utils.load_private_key(CLIENT_PRIVATE_KEY_PATH)
        print(f"[INIT]   [OK] Client private key loaded: "
              f"{os.path.basename(CLIENT_PRIVATE_KEY_PATH)}")

        shared_secret = crypto_utils.load_shared_secret(SHARED_SECRET_PATH)
        print(f"[INIT]   [OK] Shared secret loaded:      "
              f"{os.path.basename(SHARED_SECRET_PATH)} ({len(shared_secret)} bytes)")

    except FileNotFoundError as e:
        print(f"\n[INIT] [FAIL] ERROR: Key file not found: {e}")
        print("[INIT]   Have you run setup_keys.py yet?")
        print("[INIT]   Run: python \"deployment files/setup_keys.py\"")
        sys.exit(1)

    print("[INIT] [OK] All keys loaded successfully.")

    # Connect to server
    print(f"\n[CONN] Connecting to {SERVER_HOST}:{SERVER_PORT}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CONN] [OK] TCP connection established!")

        if not perform_handshake(sock, client_private_key):
            print("\n[CONN] [FAIL] Authentication failed -- aborting transfer.")
            sock.close()
            sys.exit(1)

        if transfer_file(sock, filepath, client_private_key, shared_secret):
            print("\n" + "=" * 64)
            print("  [OK] FILE TRANSFERRED SUCCESSFULLY!")
            print("=" * 64)
        else:
            print("\n" + "=" * 64)
            print("  [FAIL] FILE TRANSFER FAILED")
            print("=" * 64)
            sys.exit(1)

    except ConnectionRefusedError:
        print(f"[CONN] [FAIL] Connection REFUSED -- is the server running on "
              f"{SERVER_HOST}:{SERVER_PORT}?")
        print("[CONN]   Start the server first: python \"source files/server.py\"")
        sys.exit(1)
    except ConnectionResetError:
        print("[CONN] [FAIL] Connection RESET by server -- possible auth failure.")
        sys.exit(1)
    except Exception as e:
        print(f"[CONN] [FAIL] Unexpected error: {type(e).__name__}: {e}")
        sys.exit(1)
    finally:
        sock.close()
        print("[CONN] Connection closed.")


if __name__ == "__main__":
    main()
