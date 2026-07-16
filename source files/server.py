# >>>>> GCM SWAP: START >>>>>
"""
Secure File Transfer Server -- receives encrypted files over TCP,
verifies integrity via AES-GCM, and stores them encrypted at rest with RSA signatures.

Contributed by: [Member Name]
"""
# <<<<< GCM SWAP: END <<<<<

import os
import sys
import json
import base64
import socket
import datetime

# Cryptographic primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature, InvalidTag

# Shared crypto utilities
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto_utils


# Server Configuration
HOST = "127.0.0.1"
PORT = 9999

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOY_DIR = os.path.join(SCRIPT_DIR, "..", "deployment files")

SERVER_PRIVATE_KEY_PATH = os.path.join(DEPLOY_DIR, "server_private.pem")
CLIENT_PUBLIC_KEY_PATH  = os.path.join(DEPLOY_DIR, "client_public.pem")
SHARED_SECRET_PATH      = os.path.join(DEPLOY_DIR, "shared_secret.key")

RECEIVED_DIR = os.path.join(SCRIPT_DIR, "..", "received_files")


# RSA Challenge-Response Authentication

def perform_handshake(conn, client_public_key) -> bool:
    """Execute RSA challenge-response authentication with the client."""
    print("[HANDSHAKE] Starting RSA challenge-response authentication...")

    nonce = os.urandom(crypto_utils.NONCE_SIZE)
    print(f"[HANDSHAKE] Generated {crypto_utils.NONCE_SIZE}-byte nonce: "
          f"{nonce.hex()[:40]}...")

    crypto_utils.send_msg(conn, nonce)
    print("[HANDSHAKE] Nonce sent to client. Awaiting signed response...")

    try:
        signature = crypto_utils.recv_msg(conn)
    except ConnectionError as e:
        print(f"[HANDSHAKE] [FAIL] Connection error while receiving signature: {e}")
        return False

    print(f"[HANDSHAKE] Received signature ({len(signature)} bytes). Verifying...")

    try:
        client_public_key.verify(
            signature,
            nonce,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        print("[HANDSHAKE] [OK] RSA-PSS signature verified -- client authenticated!")
        crypto_utils.send_msg(conn, b"AUTH_OK")
        return True

    except InvalidSignature:
        print("[HANDSHAKE] [FAIL] RSA-PSS signature verification FAILED!")
        print("[HANDSHAKE] [FAIL] Possible impersonation attempt detected.")
        print("[HANDSHAKE] [FAIL] Closing connection immediately.")

        try:
            crypto_utils.send_msg(conn, b"AUTH_FAIL")
        except Exception:
            pass

        return False


# Receive File + AES-GCM Verification

def receive_and_store_file(conn, shared_secret: bytes) -> bool:
    """Receive an encrypted file, decrypt+verify with AES-GCM, and store encrypted at rest."""
    print("\n[TRANSFER] Waiting for file transfer payload...")

    # Receive and parse JSON payload
    try:
        raw_payload = crypto_utils.recv_msg(conn)
        payload = json.loads(raw_payload.decode("utf-8"))
    except ConnectionError as e:
        print(f"[TRANSFER] [FAIL] Connection error while receiving payload: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"[TRANSFER] [FAIL] Malformed JSON payload: {e}")
        return False

    # >>>>> GCM SWAP: START >>>>>
    # Decode binary fields from transport encoding.
    # "hmac" is gone -- replaced by "tag", the GCM authentication tag.
    try:
        salt           = bytes.fromhex(payload["salt"])
        iv             = bytes.fromhex(payload["iv"])  # this is the GCM nonce
        tag            = bytes.fromhex(payload["tag"])
        ciphertext     = base64.b64decode(payload["ciphertext"])
        filename       = payload["filename"]
        file_signature = base64.b64decode(payload["signature"])
    except (KeyError, ValueError) as e:
        print(f"[TRANSFER] [FAIL] Malformed payload fields: {e}")
        return False

    print(f"[TRANSFER] Received payload for file: '{filename}'")
    print(f"[TRANSFER]   Salt:       {salt.hex()}")
    print(f"[TRANSFER]   Nonce:      {iv.hex()}")
    print(f"[TRANSFER]   Tag:        {tag.hex()}")
    print(f"[TRANSFER]   Ciphertext: {len(ciphertext):,} bytes")
    print(f"[TRANSFER]   Signature:  {len(file_signature)} bytes")

    # Re-derive the AES key using HKDF (only one key now -- no HMAC key).
    print("[TRANSFER] Re-deriving AES key via HKDF-SHA256...")
    aes_key = crypto_utils.derive_keys(shared_secret, salt)
    print("[TRANSFER] [OK] Key derived successfully.")

    # Decrypt + verify in one step (AES-GCM).
    # There is no separate "check first, then decrypt" phase anymore --
    # aes_gcm_decrypt() IS the integrity check. If the tag doesn't match,
    # it raises InvalidTag instead of returning anything, so there's no
    # way to accidentally skip the check.
    print("[TRANSFER] Decrypting + verifying with AES-256-GCM...")
    try:
        plaintext = crypto_utils.aes_gcm_decrypt(aes_key, iv, ciphertext, tag)
    except InvalidTag:
        print("[TRANSFER] +===============================================+")
        print("[TRANSFER] |  [FAIL] GCM TAG VERIFICATION FAILED!             |")
        print("[TRANSFER] |  Data integrity compromised -- aborting.     |")
        print("[TRANSFER] +===============================================+")
        print("[TRANSFER] Possible causes:")
        print("[TRANSFER]   - Ciphertext tampered with in transit")
        print("[TRANSFER]   - Nonce or tag modified by an attacker")
        print("[TRANSFER]   - Client and server have different shared secrets")

        try:
            crypto_utils.send_msg(conn, b"TAG_FAIL")
        except Exception:
            pass
        return False

    print(f"[TRANSFER] [OK] Decrypted + verified {len(plaintext):,} bytes of original file data.")
    # <<<<< GCM SWAP: END <<<<<

    # Store file encrypted at rest
    print("[TRANSFER] Re-encrypting file for at-rest storage...")

    os.makedirs(RECEIVED_DIR, exist_ok=True)

    at_rest_salt = os.urandom(crypto_utils.HKDF_SALT_SIZE)
    at_rest_key = crypto_utils.derive_at_rest_key(shared_secret, at_rest_salt)

    # >>>>> GCM SWAP: START >>>>>
    # Same GCM swap applies here -- the stored file now gets its own
    # authentication tag too, so tampering with the .enc file on disk
    # (not just in transit) becomes detectable.
    at_rest_iv, at_rest_ciphertext, at_rest_tag = crypto_utils.aes_gcm_encrypt(
        at_rest_key, plaintext
    )

    # Save format: [salt][nonce][tag][ciphertext] -- tag is always 16 bytes
    enc_filepath = os.path.join(RECEIVED_DIR, filename + ".enc")
    with open(enc_filepath, "wb") as f:
        f.write(at_rest_salt)
        f.write(at_rest_iv)
        f.write(at_rest_tag)
        f.write(at_rest_ciphertext)
    print(f"[TRANSFER] [OK] Encrypted file saved: {enc_filepath}")
    # <<<<< GCM SWAP: END <<<<<

    # Store RSA signature for non-repudiation
    sig_filepath = os.path.join(RECEIVED_DIR, filename + ".sig")
    with open(sig_filepath, "wb") as f:
        f.write(file_signature)
    print(f"[TRANSFER] [OK] RSA signature saved: {sig_filepath}")
    print(f"[TRANSFER]   (Non-repudiation: client cannot deny sending this file)")

    try:
        crypto_utils.send_msg(conn, b"TRANSFER_OK")
    except Exception:
        pass

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[TRANSFER] [OK] File '{filename}' received and stored successfully!")
    print(f"[TRANSFER]   Timestamp:      {timestamp}")
    print(f"[TRANSFER]   Encrypted file: {enc_filepath}")
    print(f"[TRANSFER]   Signature file: {sig_filepath}")

    return True


# Main Server Loop

def main():
    """Initialize the server, load keys, and listen for incoming connections."""
    print("=" * 64)
    print("  +======================================================+")
    # >>>>> GCM SWAP: START >>>>>
    print("  |         SECURE FILE TRANSFER SERVER v1.0            |")
    print("  |   AES-256-GCM + RSA-PSS Signatures                 |")
    # <<<<< GCM SWAP: END <<<<<
    print("  +======================================================+")
    print("=" * 64)

    # Load cryptographic key material
    print("\n[INIT] Loading cryptographic key material...")

    try:
        server_private_key = crypto_utils.load_private_key(SERVER_PRIVATE_KEY_PATH)
        print(f"[INIT]   [OK] Server private key loaded: {os.path.basename(SERVER_PRIVATE_KEY_PATH)}")

        client_public_key = crypto_utils.load_public_key(CLIENT_PUBLIC_KEY_PATH)
        print(f"[INIT]   [OK] Client public key loaded:  {os.path.basename(CLIENT_PUBLIC_KEY_PATH)}")

        shared_secret = crypto_utils.load_shared_secret(SHARED_SECRET_PATH)
        print(f"[INIT]   [OK] Shared secret loaded:      {os.path.basename(SHARED_SECRET_PATH)} "
              f"({len(shared_secret)} bytes)")

    except FileNotFoundError as e:
        print(f"\n[INIT] [FAIL] ERROR: Key file not found: {e}")
        print("[INIT]   Have you run setup_keys.py yet?")
        print("[INIT]   Run: python \"deployment files/setup_keys.py\"")
        sys.exit(1)

    print("[INIT] [OK] All cryptographic artifacts loaded successfully.\n")

    # Create and bind TCP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"[INIT] Server listening on {HOST}:{PORT}")
    print("[INIT] Press Ctrl+C to shut down.\n")
    print("=" * 64)
    print(" Waiting for client connections...")
    print("=" * 64)

    # Connection-handling loop
    try:
        while True:
            conn, addr = server_socket.accept()
            client_address = f"{addr[0]}:{addr[1]}"

            print(f"\n{'=' * 64}")
            print(f"[CONN] New connection from {client_address}")
            print(f"{'=' * 64}")

            try:
                if not perform_handshake(conn, client_public_key):
                    print(f"[CONN] [FAIL] Authentication failed for {client_address}.")
                    print(f"[CONN] Socket closed immediately (security policy).")
                    conn.close()
                    continue

                if receive_and_store_file(conn, shared_secret):
                    print(f"\n[CONN] [OK] Transfer from {client_address} complete!")
                else:
                    print(f"\n[CONN] [FAIL] Transfer from {client_address} failed.")

            except Exception as e:
                print(f"[CONN] [FAIL] Unexpected error: {type(e).__name__}: {e}")

            finally:
                conn.close()
                print(f"[CONN] Connection from {client_address} closed.")
                print(f"{'=' * 64}\n")

    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Received Ctrl+C -- shutting down gracefully...")
    finally:
        server_socket.close()
        print("[SHUTDOWN] Server socket closed. Goodbye!")


# Entry point
if __name__ == "__main__":
    main()
