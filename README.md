# ACG CA2 Assignment 2

## Project Structure

```text
Project/
├── .gitignore
│
├── source files/
│   ├── crypto_utils.py             Shared cryptographic utilities
│   ├── client.py                   File transfer client
│   └── server.py                   File transfer server
│
└── deployment files/
    ├── setup_keys.py               Key generation script

```

---

## How to Use

Create and install environment (VENV)

#### Set Key Passphrase (required in every terminal)
Private keys are stored encrypted. The passphrase is read from the `KEY_PASSPHRASE` environment variable.
```bash
export KEY_PASSPHRASE='your-passphrase-here'      # Linux/macOS
set KEY_PASSPHRASE=your-passphrase-here           # Windows CMD
$env:KEY_PASSPHRASE='your-passphrase-here'        # Windows PowerShell
```

#### Key Creation
```bash
python "deployment files/setup_keys.py"
```

#### Server Run (Terminal 1)
```bash
python "source files/server.py"
```

#### Client Run (Terminal 2)
```bash
python "source files/client.py" <path_to_file>
#Eg
python "source files/client.py" "C:\Users\JaneDoe\Documents\my_assignment.pdf"
```

#### Output
in ./received_files
- `<filename>.enc`: The file encrypted at-rest.
- `<filename>.sig`: The RSA digital signature of the original file.

---

## Implementation Overview

- **Authentication**: Mutual challenge-response handshake using RSA-PSS digital signatures. Each party signs a random nonce chosen by the other.
- **Key Transport**: A fresh AES-256 session key is generated per transfer and wrapped to the server's public key using RSA-OAEP. No symmetric key is pre-shared.
- **Key Derivation (KDF)**: HKDF-SHA256 derives independent keys for AES encryption and HMAC authentication using distinct domain separators.
- **Transport Security**: Encrypt-then-MAC using AES-256-CBC and HMAC-SHA256. The HMAC tag is verified in constant time before decryption.
- **At-Rest Protection**: Files are saved on disk encrypted with an independent AES-256 key.
- **Non-Repudiation**: The client generates an RSA digital signature of the original file, which the server verifies before storing alongside the encrypted file.
- **Key Protection**: RSA private keys are written encrypted and cannot be loaded without the passphrase.

## Cryptographic Design

| Feature | Algorithm | Rationale |
|---|---|---|
| **Handshake / Non-Repudiation** | RSA-2048 / PSS | NIST-compliant key size; PSS padding offers randomized encoding and formal security proofs. |
| **Key Transport** | RSA-2048 / OAEP | Wraps the per-transfer session key; OAEP avoids the padding attacks affecting PKCS#1 v1.5. |
| **Key Derivation (KDF)** | HKDF-SHA256 | Derives distinct session keys from a single session key using domain separations. |
| **Symmetric Encryption** | AES-256-CBC | Confirms confidentiality with random, unique IVs generated per encryption. |
| **Authentication / Integrity** | HMAC-SHA256 | Authenticates all payload fields (wrapped_key \|\| salt \|\| IV \|\| ciphertext \|\| filename) to prevent tampering and oracle attacks. |
| **Constant-Time Verification** | `compare_digest` | Mitigates timing side-channel attacks during HMAC validation. |
| **Private Key Protection** | BestAvailableEncryption | Protects private keys against offline theft. |