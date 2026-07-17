"""
Secure File Transfer Server -- receives encrypted files over TCP,
verifies HMAC integrity, and stores them encrypted at rest with RSA signatures.

Contributed by: [Member Name]
"""

import os
import sys
import json
import base64
import socket
import datetime

# Cryptographic primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature

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
SERVER_STORE_KEY_PATH   = os.path.join(DEPLOY_DIR, "server_store.key")

RECEIVED_DIR = os.path.join(SCRIPT_DIR, "..", "received_files")


# RSA Challenge-Response Authentication

def perform_handshake(conn, client_public_key, server_private_key) -> bool:
    """Execute RSA challenge-response authentication with the client."""
    print("[HANDSHAKE] Starting RSA challenge-response authentication...")

    nonce = os.urandom(crypto_utils.NONCE_SIZE)
    print(f"[HANDSHAKE] Generated {crypto_utils.NONCE_SIZE}-byte nonce: "
          f"{nonce.hex()[:40]}...")

    crypto_utils.send_msg(conn, nonce)
    print("[HANDSHAKE] Nonce sent to client. Awaiting client nonce + signature...")

    try:
        client_nonce = crypto_utils.recv_msg(conn)   # client's challenge to us
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

        # Mutual auth: sign the client's nonce with OUR private key so the
        # client can confirm it is talking to the genuine server.
        server_sig = server_private_key.sign(
            client_nonce,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        crypto_utils.send_msg(conn, server_sig)
        print("[HANDSHAKE] [OK] Sent our signature over client nonce (mutual auth).")
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


# Receive File + Encrypt-then-MAC Verification

def receive_and_store_file(conn, server_private_key, client_public_key, store_key: bytes) -> bool:
    """Receive an encrypted file, verify HMAC, decrypt, and store encrypted at rest."""
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

    # Decode binary fields from transport encoding
    try:
        wrapped_key    = base64.b64decode(payload["wrapped_key"])
        salt           = bytes.fromhex(payload["salt"])
        iv             = bytes.fromhex(payload["iv"])
        received_hmac  = bytes.fromhex(payload["hmac"])
        ciphertext     = base64.b64decode(payload["ciphertext"])
        filename       = payload["filename"]
        file_signature = base64.b64decode(payload["signature"])
    except (KeyError, ValueError) as e:
        print(f"[TRANSFER] [FAIL] Malformed payload fields: {e}")
        return False

    # NOTE: the filename is authenticated by the HMAC below, so we must MAC the
    # value exactly as received. Sanitizing happens only AFTER the MAC verifies.
    raw_filename = filename

    print(f"[TRANSFER] Received payload for file: '{filename}'")
    print(f"[TRANSFER]   Salt:       {salt.hex()}")
    print(f"[TRANSFER]   IV:         {iv.hex()}")
    print(f"[TRANSFER]   HMAC:       {received_hmac.hex()[:40]}...")
    print(f"[TRANSFER]   Ciphertext: {len(ciphertext):,} bytes")
    print(f"[TRANSFER]   Signature:  {len(file_signature)} bytes")

    # Unwrap the session key with the server's RSA private key (RSA-OAEP)
    print("[TRANSFER] Unwrapping session key with server private key...")
    try:
        session_key = crypto_utils.rsa_unwrap_key(server_private_key, wrapped_key)
    except Exception as e:
        print(f"[TRANSFER] [FAIL] Session key unwrap failed: {e}")
        return False
    print(f"[TRANSFER] [OK] Session key recovered ({len(session_key)} bytes).")

    # Derive AES + HMAC keys from the recovered session key via HKDF
    aes_key, hmac_key = crypto_utils.derive_keys(session_key, salt)
    print("[TRANSFER] [OK] AES + HMAC keys derived.")

    # Verify HMAC before decryption (Encrypt-then-MAC)
    print("[TRANSFER] +===============================================+")
    print("[TRANSFER] |  VERIFYING HMAC (Encrypt-then-MAC)          |")
    print("[TRANSFER] +===============================================+")

    # Recompute the MAC over ALL payload fields (must match client exactly)
    hmac_data = wrapped_key + salt + iv + ciphertext + raw_filename.encode("utf-8")

    if not crypto_utils.verify_hmac(hmac_key, hmac_data, received_hmac):
        print("[TRANSFER] +===============================================+")
        print("[TRANSFER] |  [FAIL] HMAC VERIFICATION FAILED!                |")
        print("[TRANSFER] |  Data integrity compromised -- aborting.     |")
        print("[TRANSFER] +===============================================+")
        print("[TRANSFER] Possible causes:")
        print("[TRANSFER]   - Ciphertext tampered with in transit")
        print("[TRANSFER]   - IV modified by an attacker")
        print("[TRANSFER]   - Client and server have different shared secrets")

        try:
            crypto_utils.send_msg(conn, b"HMAC_FAIL")
        except Exception:
            pass
        return False

    print("[TRANSFER] [OK] HMAC verified -- all payload fields authentic!")

    # Now that the filename is proven authentic, sanitize it to prevent path
    # traversal (e.g. "../../etc/x") before it is ever used in a file path.
    filename = os.path.basename(raw_filename)
    if not filename or filename in (".", ".."):
        print("[TRANSFER] [FAIL] Invalid filename in payload -- rejecting.")
        return False
    print("[TRANSFER]   (No tampering detected; safe to proceed with decryption)")

    # Decrypt ciphertext (AES-256-CBC)
    print("[TRANSFER] Decrypting file data with AES-256-CBC...")
    try:
        plaintext = crypto_utils.aes_cbc_decrypt(aes_key, iv, ciphertext)
    except ValueError as e:
        print(f"[TRANSFER] [FAIL] Decryption failed (padding error): {e}")
        print("[TRANSFER]   This should not happen after HMAC verification.")
        print("[TRANSFER]   Possible implementation bug or key mismatch.")
        return False

    print(f"[TRANSFER] [OK] Decrypted {len(plaintext):,} bytes of original file data.")

    # Verify the client's RSA-PSS signature over the plaintext BEFORE storing.
    # Without this check, "non-repudiation" is meaningless -- we would be
    # storing an unverified blob. Reject the file if the signature is invalid.
    print("[TRANSFER] Verifying client's RSA-PSS signature (non-repudiation)...")
    try:
        client_public_key.verify(
            file_signature,
            plaintext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("[TRANSFER] [OK] Signature valid -- sender authenticity confirmed.")
    except InvalidSignature:
        print("[TRANSFER] [FAIL] File signature INVALID -- rejecting file!")
        try:
            crypto_utils.send_msg(conn, b"SIG_FAIL")
        except Exception:
            pass
        return False

    # Store file encrypted at rest
    print("[TRANSFER] Re-encrypting file for at-rest storage...")

    os.makedirs(RECEIVED_DIR, exist_ok=True)

    at_rest_salt = os.urandom(crypto_utils.HKDF_SALT_SIZE)
    at_rest_key = crypto_utils.derive_at_rest_key(store_key, at_rest_salt)

    at_rest_iv, at_rest_ciphertext = crypto_utils.aes_cbc_encrypt(
        at_rest_key, plaintext
    )

    # Save format: [salt][IV][ciphertext]
    enc_filepath = os.path.join(RECEIVED_DIR, filename + ".enc")
    with open(enc_filepath, "wb") as f:
        f.write(at_rest_salt)
        f.write(at_rest_iv)
        f.write(at_rest_ciphertext)
    print(f"[TRANSFER] [OK] Encrypted file saved: {enc_filepath}")

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
    print("  |         SECURE FILE TRANSFER SERVER v1.0            |")
    print("  |   AES-256-CBC + HMAC-SHA256 + RSA-PSS Signatures   |")
    print("  +======================================================+")
    print("=" * 64)

    # Load cryptographic key material
    print("\n[INIT] Loading cryptographic key material...")

    try:
        server_private_key = crypto_utils.load_private_key(SERVER_PRIVATE_KEY_PATH)
        print(f"[INIT]   [OK] Server private key loaded: {os.path.basename(SERVER_PRIVATE_KEY_PATH)}")

        client_public_key = crypto_utils.load_public_key(CLIENT_PUBLIC_KEY_PATH)
        print(f"[INIT]   [OK] Client public key loaded:  {os.path.basename(CLIENT_PUBLIC_KEY_PATH)}")

        store_key = crypto_utils.load_shared_secret(SERVER_STORE_KEY_PATH)
        print(f"[INIT]   [OK] Store key loaded:          {os.path.basename(SERVER_STORE_KEY_PATH)} "
              f"({len(store_key)} bytes)")

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
                if not perform_handshake(conn, client_public_key, server_private_key):
                    print(f"[CONN] [FAIL] Authentication failed for {client_address}.")
                    print(f"[CONN] Socket closed immediately (security policy).")
                    conn.close()
                    continue

                if receive_and_store_file(conn, server_private_key, client_public_key, store_key):
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
