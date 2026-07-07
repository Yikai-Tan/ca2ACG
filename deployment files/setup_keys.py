"""
Key Generation & Provisioning Script

"""

import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Constants
RSA_KEY_SIZE = 2048          # RSA key size in bits
RSA_PUBLIC_EXPONENT = 65537  # Standard public exponent (Fermat prime F4)
SHARED_SECRET_LENGTH = 32    # 256 bits of entropy for the master secret


def generate_rsa_keypair(private_path: str, public_path: str, label: str) -> None:
    """Generate an RSA-2048 key pair and save both keys as PEM files."""
    print(f"\n  Generating {RSA_KEY_SIZE}-bit RSA key pair for {label}...")

    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )

    # Save private key in PEM/PKCS#8 format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(private_path, "wb") as f:
        f.write(private_pem)
    print(f"    [+] Private key saved: {os.path.basename(private_path)}")

    # Save public key in PEM/X.509 format
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(public_path, "wb") as f:
        f.write(public_pem)
    print(f"    [+] Public key saved:  {os.path.basename(public_path)}")


def generate_shared_secret(secret_path: str) -> None:
    """Generate a cryptographically secure random shared secret and save it."""
    print(f"\n  Generating {SHARED_SECRET_LENGTH}-byte ({SHARED_SECRET_LENGTH * 8}-bit) "
          f"master shared secret...")

    secret = os.urandom(SHARED_SECRET_LENGTH)

    with open(secret_path, "wb") as f:
        f.write(secret)
    print(f"    [+] Shared secret saved: {os.path.basename(secret_path)}")
    print(f"    [i] Secret entropy: {SHARED_SECRET_LENGTH * 8} bits")


def main():
    """Generate all cryptographic artifacts and save to the script directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("=" * 64)
    print("  Secure File Transfer -- Cryptographic Key Generation")
    print("=" * 64)
    print(f"  Output directory: {script_dir}")

    # Step 1: Generate CLIENT RSA key pair
    print("-" * 40)
    generate_rsa_keypair(
        private_path=os.path.join(script_dir, "client_private.pem"),
        public_path=os.path.join(script_dir, "client_public.pem"),
        label="CLIENT",
    )

    # Step 2: Generate SERVER RSA key pair
    print("-" * 40)
    generate_rsa_keypair(
        private_path=os.path.join(script_dir, "server_private.pem"),
        public_path=os.path.join(script_dir, "server_public.pem"),
        label="SERVER",
    )

    # Step 3: Generate the master shared secret
    print("-" * 40)
    generate_shared_secret(
        secret_path=os.path.join(script_dir, "shared_secret.key"),
    )

    # Output
    print("\n" + "=" * 64)
    print("  [OK] All cryptographic artifacts generated successfully!")
    print("=" * 64)
    print("\n  Generated files:")
    print("    - client_private.pem   (CLIENT RSA private key)")
    print("    - client_public.pem    (CLIENT RSA public key)")
    print("    - server_private.pem   (SERVER RSA private key)")
    print("    - server_public.pem    (SERVER RSA public key)")
    print("    - shared_secret.key    (Master shared secret for HKDF)")
    print("\n  IMPORTANT: Keep private keys and shared_secret.key confidential!")
    print("  Next step: Start server.py, then run client.py.\n")


if __name__ == "__main__":
    main()
